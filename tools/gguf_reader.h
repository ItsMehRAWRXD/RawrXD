// ============================================================================
// gguf_reader.h - THE authoritative universal GGUF reader for Deep2
// ============================================================================
// Single shared contract for every tool that needs to read a model's weights.
// Works regardless of model: GGUF v1/v2/v3 headers, nested metadata arrays,
// and every ggml quantization type (Q/K-quants, IQ*, BF16, MXFP4, F32...).
// Tensors are exposed with absolute file offsets and byte sizes so callers can
// mmap zero-copy and dequantize with ggml's own kernels.
//
// Both gguf_universal_probe and deep2_decode_probe consume this header; it is
// the only place GGUF parsing is allowed to live.
// ============================================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include "ggml.h"

namespace gguf {

enum GgufV : uint32_t {
    GF_UINT8 = 0, GF_INT8 = 1, GF_UINT16 = 2, GF_INT16 = 3,
    GF_UINT32 = 4, GF_INT32 = 5, GF_FLOAT32 = 6, GF_BOOL = 7,
    GF_STRING = 8, GF_ARRAY = 9, GF_UINT64 = 10, GF_INT64 = 11, GF_FLOAT64 = 12,
};

struct Tensor {
    std::string name;
    std::vector<uint64_t> dims;
    uint32_t type = 0;
    uint64_t rel_offset = 0;
    size_t offset = 0;   // absolute byte offset in the file
    size_t bytes = 0;
    ggml_type gtype = GGML_TYPE_COUNT;

    size_t nbytes() const { return bytes; }
    uint64_t numel() const {
        uint64_t n = 1;
        for (auto d : dims) n *= d;
        return n;
    }
};

class File {
public:
    std::string path;
    const uint8_t* base = nullptr;
    size_t size = 0;
    uint32_t version = 0;
    uint64_t tensor_count = 0;
    uint64_t kv_count = 0;
    std::vector<Tensor> tensors;
    std::map<std::string, std::string> meta;
    std::set<uint32_t> unsupported_types;  // GGUF type ids this ggml lacks
    bool ok = false;

    bool open(const std::string& p) {
        path = p;
#ifdef _WIN32
        HANDLE h = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
        HANDLE m = CreateFileMappingA(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!m) { CloseHandle(h); return false; }
        base = static_cast<const uint8_t*>(
            MapViewOfFile(m, FILE_MAP_READ, 0, 0, static_cast<SIZE_T>(sz.QuadPart)));
        map_ = m;
        size = static_cast<size_t>(sz.QuadPart);
#else
        int fd = ::open(p.c_str(), O_RDONLY);
        if (fd < 0) return false;
        struct stat st{};
        if (::fstat(fd, &st) != 0) { ::close(fd); return false; }
        base = static_cast<const uint8_t*>(
            ::mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0));
        size = (size_t)st.st_size;
#endif
        if (!base) return false;
        ok = parse();
        return ok;
    }

    void close() {
#ifdef _WIN32
        if (base) UnmapViewOfFile(base);
        if (map_) CloseHandle(map_);
#else
        if (base) ::munmap(const_cast<uint8_t*>(base), size);
#endif
        base = nullptr;
    }

    bool need(size_t n) const { return pos + n <= size; }

    template <typename T>
    T readLE() {
        if (!need(sizeof(T))) { pos = size; return T{}; }
        T v{};
        std::memcpy(&v, base + pos, sizeof(T));
        pos += sizeof(T);
        return v;
    }
    std::string readString() {
        const uint64_t n = readLE<uint64_t>();
        if (!need((size_t)n)) { pos = size; return {}; }
        std::string s(reinterpret_cast<const char*>(base + pos), (size_t)n);
        pos += (size_t)n;
        return s;
    }
    bool skipValue(uint32_t type, int depth) {
        if (depth > 16) return false;
        if (type == GF_STRING) { readString(); return pos <= size; }
        if (type == GF_ARRAY) {
            const uint32_t et = readLE<uint32_t>();
            const uint64_t n = readLE<uint64_t>();
            for (uint64_t i = 0; i < n; ++i)
                if (!skipValue(et, depth + 1)) return false;
            return pos <= size;
        }
        switch (type) {
            case GF_UINT8: case GF_INT8: case GF_BOOL: pos += 1; break;
            case GF_UINT16: case GF_INT16: pos += 2; break;
            case GF_UINT32: case GF_INT32: case GF_FLOAT32: pos += 4; break;
            case GF_UINT64: case GF_INT64: case GF_FLOAT64: pos += 8; break;
            default: return false;
        }
        return need(0);
    }

    bool parse() {
        if (!need(24)) return false;
        const uint32_t magic = readLE<uint32_t>();
        if (magic != 0x46554747u) return false;  // 'GGUF'
        version = readLE<uint32_t>();
        tensor_count = readLE<uint64_t>();
        kv_count = readLE<uint64_t>();
        if (!kv_count) return false;

        for (uint64_t i = 0; i < kv_count; ++i) {
            const std::string key = readString();
            if (pos >= size) return false;
            const uint32_t t = readLE<uint32_t>();
            if (!skipValue(t, 0)) {
                // Nested arrays must be skipped recursively; a failure here
                // means the file is truncated or not really GGUF.
                return false;
            }
        }
        for (uint64_t i = 0; i < tensor_count; ++i) {
            Tensor t;
            t.name = readString();
            const uint32_t nd = readLE<uint32_t>();
            if (nd == 0 || nd > 8) return false;
            t.dims.resize(nd);
            for (auto& d : t.dims) d = readLE<uint64_t>();
            t.type = readLE<uint32_t>();
            t.rel_offset = readLE<uint64_t>();
            t.gtype = (ggml_type)t.type;
            tensors.push_back(t);
        }
        const size_t data_start = align32(pos);
        for (auto& t : tensors) {
            if (t.type >= (uint32_t)GGML_TYPE_COUNT) {
                unsupported_types.insert(t.type);
                continue;
            }
            const ggml_type_traits* tr = ggml_get_type_traits(t.gtype);
            if (!tr || tr->type_size == 0) continue;
            const int64_t blck = tr->blck_size > 0 ? tr->blck_size : 1;
            t.bytes = (size_t)(t.numel() * (uint64_t)tr->type_size / (uint64_t)blck);
            t.offset = data_start + (size_t)t.rel_offset;
            if ((uint64_t)t.offset + t.bytes > (uint64_t)size) {
                t.bytes = 0;  // out of range: reported via t.bytes == 0
            }
        }
        // Metadata values are re-read here as strings (cheap, and the metadata
        // section is small) so callers can query arch/dims by name.
        pos = 24;
        for (uint64_t i = 0; i < kv_count; ++i) {
            const std::string key = readString();
            const uint32_t t = readLE<uint32_t>();
            std::string val;
            if (!readScalarOrArrayHead(t, val)) break;
            meta[key] = val;
        }
        return true;
    }

    const Tensor* find(const std::string& name) const {
        for (const auto& t : tensors)
            if (t.name == name) return &t;
        return nullptr;
    }
    const std::string& meta_of(const std::string& key) const {
        static const std::string empty;
        auto it = meta.find(key);
        return it == meta.end() ? empty : it->second;
    }

    // Read one metadata scalar (or an array head) as a string.
    bool readScalarOrArrayHead(uint32_t type, std::string& out) {
        if (type == GF_STRING) { out = readString(); return true; }
        if (type == GF_UINT32) { out = std::to_string(readLE<uint32_t>()); return true; }
        if (type == GF_INT32) { out = std::to_string(readLE<int32_t>()); return true; }
        if (type == GF_FLOAT32) { out = std::to_string(readLE<float>()); return true; }
        if (type == GF_BOOL) { out = readLE<uint8_t>() ? "true" : "false"; return true; }
        if (type == GF_UINT64) { out = std::to_string(readLE<uint64_t>()); return true; }
        if (type == GF_UINT16) { out = std::to_string(readLE<uint16_t>()); return true; }
        if (type == GF_FLOAT64) { out = std::to_string(readLE<double>()); return true; }
        if (type == GF_ARRAY) {
            const uint32_t et = readLE<uint32_t>();
            const uint64_t n = readLE<uint64_t>();
            out = "array<" + std::to_string(et) + ">x" + std::to_string(n);
            for (uint64_t i = 0; i < n; ++i)
                if (!skipValue(et, 1)) return false;
            return true;
        }
        return skipValue(type, 0);
    }

    // Read a metadata string array fully (e.g. tokenizer.ggml.tokens).
    bool readStringArray(const std::string& key, std::vector<std::string>& out) {
        pos = 24;
        for (uint64_t i = 0; i < kv_count; ++i) {
            const std::string k = readString();
            const uint32_t t = readLE<uint32_t>();
            if (k == key && t == GF_ARRAY) {
                const uint32_t et = readLE<uint32_t>();
                const uint64_t n = readLE<uint64_t>();
                if (et != GF_STRING) return false;
                out.reserve(n);
                for (uint64_t j = 0; j < n; ++j) out.push_back(readString());
                return true;
            }
            if (!skipValue(t, 0)) return false;
        }
        return false;
    }

private:
    static size_t align32(size_t v) { return (v + 31u) & ~size_t(31); }
#ifdef _WIN32
    HANDLE map_ = nullptr;
#else
    int fd_ = -1;
#endif
    size_t pos = 0;
};

}  // namespace gguf
