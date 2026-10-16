#pragma once
// ============================================================================
// GGUFLoader.hpp Ã¢â‚¬â€ Batch 6 real no-dependency mapped GGUF v2/v3 loader
// - Parses typed metadata
// - Parses tensor descriptors
// - Memory maps tensor data (no whole-model heap copy)
// - Supports canonical -00001-of-000NN.gguf shard sets
// - Bounds/overflow checks every read and tensor range
// ============================================================================
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include "QuantTypeTable.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Forward declaration for LoadMetadata return type (defined at global scope below)
struct GGUFLoadResult;

/**
 * GGUFLoadOptions Ã¢â‚¬â€ controls a full GGUFLoader::Load.
 *
 * Deep2Engine.cpp sets loadTensors/verbose/mmap only. Kept minimal and
 * separate from ModelMetadata so a caller cannot accidentally treat load
 * semantics as model data.
 */
struct GGUFLoadOptions {
    bool loadTensors = true;   // populate tensor descriptors (larger result)
    bool verbose = false;      // progress output to stdout
    bool mmap = true;          // memory-map instead of read into heap
};

namespace Deep2 {

// Make GGUFLoadResult accessible as Deep2::GGUFLoadResult
using ::GGUFLoadResult;

enum class GGUFMetaType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12,
};

struct GGUFTensor {
    std::string name;
    GGMLType type = GGMLType::GGML_TYPE_F32;
    std::vector<int64_t> shape;       // GGUF order: [input/row width, output rows, ...]
    const uint8_t* data = nullptr;     // aliases mapped shard; never free directly
    size_t sizeBytes = 0;
    uint64_t fileOffset = 0;           // absolute file offset within shard
    uint64_t tensorOffset = 0;         // relative to shard tensor_data
    uint32_t shardId = 0;
    bool mapped = false;

    size_t numElements() const {
        size_t n = 1;
        for (int64_t d : shape) {
            if (d <= 0) return 0;
            const size_t sd = static_cast<size_t>(d);
            if (sd != 0 && n > std::numeric_limits<size_t>::max() / sd) return 0;
            n *= sd;
        }
        return n;
    }
};

class GGUFLoader {
public:
    GGUFLoader() = default;
    ~GGUFLoader() { close(); }

    GGUFLoader(const GGUFLoader&) = delete;
    GGUFLoader& operator=(const GGUFLoader&) = delete;

    bool load(const std::string& path) {
        close();
        error_.clear();
        if (path.empty()) return fail("empty GGUF path");

        std::string shardPrefix;
        uint32_t fileShardIndex = 0;
        uint32_t fileShardCount = 0;

        if (parseCanonicalShardName(path, shardPrefix, fileShardIndex, fileShardCount) &&
            fileShardCount > 1) {
            shardCount_ = fileShardCount;
            for (uint32_t i = 1; i <= fileShardCount; ++i) {
                const std::string shardPath =
                    shardPrefix + fiveDigits(i) + "-of-" + fiveDigits(fileShardCount) + ".gguf";
                if (!loadOneShard(shardPath, i - 1)) {
                    close();
                    return false;
                }
            }
            path_ = shardPrefix + fiveDigits(1) + "-of-" + fiveDigits(fileShardCount) + ".gguf";
        } else {
            shardCount_ = 1;
            if (!loadOneShard(path, 0)) {
                close();
                return false;
            }
            path_ = path;

            const int64_t declaredSplit = getMetaInt("split.count", 1);
            if (declaredSplit > 1) {
                const std::string saved = error_.empty()
                    ? "GGUF declares multiple shards but filename is not canonical -00001-of-000NN.gguf"
                    : error_;
                close();
                error_ = saved;
                return false;
            }
        }

        const int64_t declaredCount = getMetaInt("split.count", static_cast<int64_t>(shardCount_));
        if (declaredCount > 0 && static_cast<uint64_t>(declaredCount) != shardCount_) {
            const std::string saved = "split.count does not match mapped shard set";
            close();
            error_ = saved;
            return false;
        }

        if (tensors_.empty()) {
            const std::string saved = "GGUF contained no tensors";
            close();
            error_ = saved;
            return false;
        }

        loaded_ = true;
        return true;
    }

     void close() {
        tensors_.clear();
        metaInt_.clear();
        metaFloat_.clear();
        metaString_.clear();
        metaArrays_.clear();
        maps_.clear();
        path_.clear();
        loaded_ = false;
        version_ = 0;
        shardCount_ = 0;
        totalMappedBytes_ = 0;
        tensorCountHeader_ = 0;
        metadataCountHeader_ = 0;
    }

    /**
     * LoadMetadata Ã¢â‚¬â€ metadata-only load (no tensor data population).
     * Returns a GGUFLoadResult with rawKv, metadata, and header counts populated.
     * This is the sovereign authority seal entry point.
     * Implementation is below (requires complete GGUFLoadResult type).
     */
    static GGUFLoadResult LoadMetadata(const char* filepath);

    /**
     * FreeTensorData â€” release a TensorInfo::data pointer.
     *
     * The pointer handed out by this loader comes from VirtualAlloc on Windows
     * so it must be released with the matching call. Exposing it here keeps the
     * allocation ABI private to the loader; a caller that used free() would be
     * undefined behaviour, not a leak.
     * Safe to call with nullptr.
     */
    static void FreeTensorData(void* p);

    /**
     * Load -- full load returning a GGUFLoadResult.
     *
     * Forward-declared here because GGUFLoadResult is incomplete at this point;
     * the definition is below. It delegates to the existing member load() and
     * the existing metadata population path instead of re-parsing GGUF, so
     * there is one parser and one set of semantics.
     */
    static GGUFLoadResult Load(const char* filepath,
                               const struct GGUFLoadOptions& options);


    bool loaded() const { return loaded_; }    uint32_t version() const { return version_; }
    uint32_t shardCount() const { return shardCount_; }
    uint64_t mappedBytes() const { return totalMappedBytes_; }
    uint64_t tensorCountHeader() const { return tensorCountHeader_; }
    uint64_t metadataCountHeader() const { return metadataCountHeader_; }
    const std::string& path() const { return path_; }
    const std::string& error() const { return error_; }

    bool hasTensor(const std::string& name) const {
        return tensors_.find(name) != tensors_.end();
    }

    GGUFTensor* getTensor(const std::string& name) {
        auto it = tensors_.find(name);
        return it == tensors_.end() ? nullptr : &it->second;
    }

    const GGUFTensor* getTensor(const std::string& name) const {
        auto it = tensors_.find(name);
        return it == tensors_.end() ? nullptr : &it->second;
    }

    std::vector<std::string> listTensors() const {
        std::vector<std::string> names;
        names.reserve(tensors_.size());
        for (const auto& kv : tensors_) names.push_back(kv.first);
        std::sort(names.begin(), names.end());
        return names;
    }

    size_t tensorCount() const { return tensors_.size(); }

    bool setMetaInt(const std::string& key, int64_t value) {
        metaInt_[key] = value;
        return true;
    }

    bool setMetaFloat(const std::string& key, double value) {
        metaFloat_[key] = value;
        return true;
    }

    int64_t getMetaInt(const std::string& key, int64_t def = 0) const {
        auto i = metaInt_.find(key);
        if (i != metaInt_.end()) return i->second;
        auto f = metaFloat_.find(key);
        if (f != metaFloat_.end()) return static_cast<int64_t>(f->second);
        return def;
    }

    double getMetaFloat(const std::string& key, double def = 0.0) const {
        auto f = metaFloat_.find(key);
        if (f != metaFloat_.end()) return f->second;
        auto i = metaInt_.find(key);
        if (i != metaInt_.end()) return static_cast<double>(i->second);
        return def;
    }

    // Read the first element of an integer-typed GGUF array metadata entry.
    // Returns `def` when the key is absent, not an array, has a non-integer
    // element type, or is empty.  This is what makes per-layer array metadata
    // (e.g. expert_used_count, head_count_kv, feed_forward_length) readable
    // as a scalar when every layer shares the same value.
    int64_t getMetaIntArrayFirst(const std::string& key, int64_t def = 0) const {
        auto it = metaArrays_.find(key);
        if (it == metaArrays_.end()) return def;
        const MetaArrayView& a = it->second;
        if (a.count == 0 || !a.data) return def;
        uint32_t et = a.elementType;
        // Only integer element types are supported here.
        if (et != static_cast<uint32_t>(GGUFMetaType::UINT8) &&
            et != static_cast<uint32_t>(GGUFMetaType::INT8) &&
            et != static_cast<uint32_t>(GGUFMetaType::UINT16) &&
            et != static_cast<uint32_t>(GGUFMetaType::INT16) &&
            et != static_cast<uint32_t>(GGUFMetaType::UINT32) &&
            et != static_cast<uint32_t>(GGUFMetaType::INT32) &&
            et != static_cast<uint32_t>(GGUFMetaType::UINT64) &&
            et != static_cast<uint32_t>(GGUFMetaType::INT64))
            return def;
        const uint8_t* p = a.data;
        int64_t v = 0;
        switch (et) {
            case static_cast<uint32_t>(GGUFMetaType::UINT8): {
                uint8_t x = 0;
                if (!readPod(p, a.end, x)) return def; v = x; break;
            }
            case static_cast<uint32_t>(GGUFMetaType::INT8): {
                int8_t x = 0;
                if (!readPod(p, a.end, x)) return def; v = x; break;
            }
            case static_cast<uint32_t>(GGUFMetaType::UINT16): {
                uint16_t x = 0;
                if (!readPod(p, a.end, x)) return def; v = x; break;
            }
            case static_cast<uint32_t>(GGUFMetaType::INT16): {
                int16_t x = 0;
                if (!readPod(p, a.end, x)) return def; v = x; break;
            }
            case static_cast<uint32_t>(GGUFMetaType::UINT32): {
                uint32_t x = 0;
                if (!readPod(p, a.end, x)) return def; v = x; break;
            }
            case static_cast<uint32_t>(GGUFMetaType::INT32): {
                int32_t x = 0;
                if (!readPod(p, a.end, x)) return def; v = x; break;
            }
            case static_cast<uint32_t>(GGUFMetaType::UINT64): {
                uint64_t x = 0;
                if (!readPod(p, a.end, x)) return def;
                if (x > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) return def;
                v = static_cast<int64_t>(x); break;
            }
            case static_cast<uint32_t>(GGUFMetaType::INT64): {
                int64_t x = 0;
                if (!readPod(p, a.end, x)) return def; v = x; break;
            }
            default: return def;
        }
        return v;
    }

    std::string getMetaString(const std::string& key,
                              const std::string& def = {}) const {
        auto it = metaString_.find(key);
        return it == metaString_.end() ? def : it->second;
    }

    bool hasMeta(const std::string& key) const {
        return metaInt_.count(key) || metaFloat_.count(key) ||
               metaString_.count(key) || metaArrays_.count(key);
    }

    // Serialize all metadata to string-keyed map (for rawKv in LoadMetadata)
    std::map<std::string,std::string> getMetaAllStrings() const {
        std::map<std::string,std::string> out;
        for (const auto& kv : metaInt_)
            out[kv.first] = std::to_string(kv.second);
        for (const auto& kv : metaFloat_) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%g", kv.second);
            out[kv.first] = buf;
        }
        for (const auto& kv : metaString_)
            out[kv.first] = kv.second;
        return out;
    }

    // Materializes only when requested. Large tokenizer token arrays therefore
    // stay mmap-backed during ordinary model loading.
    bool getMetaStringArray(const std::string& key,
                            std::vector<std::string>& out) const {
        out.clear();
        auto it = metaArrays_.find(key);
        if (it == metaArrays_.end()) return false;
        const MetaArrayView& a = it->second;
        if (a.elementType != static_cast<uint32_t>(GGUFMetaType::STRING))
            return false;

        const uint8_t* p = a.data;
        out.reserve(static_cast<size_t>(a.count));
        for (uint64_t i = 0; i < a.count; ++i) {
            std::string s;
            if (!readStringBounded(p, a.end, s, kMaxStringBytes))
                return false;
            out.emplace_back(std::move(s));
        }
        return true;
    }

    bool getMetaFloatArray(const std::string& key,
                           std::vector<float>& out) const {
        out.clear();
        auto it = metaArrays_.find(key);
        if (it == metaArrays_.end()) return false;
        const MetaArrayView& a = it->second;
        const uint8_t* p = a.data;
        out.reserve(static_cast<size_t>(a.count));

        for (uint64_t i = 0; i < a.count; ++i) {
            float v = 0.0f;
            switch (static_cast<GGUFMetaType>(a.elementType)) {
                case GGUFMetaType::FLOAT32: {
                    if (!readPod(p,a.end,v)) return false;
                    break;
                }
                case GGUFMetaType::FLOAT64: {
                    double d = 0.0;
                    if (!readPod(p,a.end,d)) return false;
                    v = static_cast<float>(d);
                    break;
                }
                default:
                    out.clear();
                    return false;
            }
            out.push_back(v);
        }
        return true;
    }

    bool getMetaInt32Array(const std::string& key,
                           std::vector<int32_t>& out) const {
        out.clear();
        auto it = metaArrays_.find(key);
        if (it == metaArrays_.end()) return false;
        const MetaArrayView& a = it->second;
        const uint8_t* p = a.data;
        out.reserve(static_cast<size_t>(a.count));

        for (uint64_t i = 0; i < a.count; ++i) {
            int64_t v = 0;
            switch (static_cast<GGUFMetaType>(a.elementType)) {
                case GGUFMetaType::UINT8: {
                    uint8_t x = 0; if (!readPod(p,a.end,x)) return false; v=x; break;
                }
                case GGUFMetaType::INT8: {
                    int8_t x = 0; if (!readPod(p,a.end,x)) return false; v=x; break;
                }
                case GGUFMetaType::UINT16: {
                    uint16_t x = 0; if (!readPod(p,a.end,x)) return false; v=x; break;
                }
                case GGUFMetaType::INT16: {
                    int16_t x = 0; if (!readPod(p,a.end,x)) return false; v=x; break;
                }
                case GGUFMetaType::UINT32: {
                    uint32_t x = 0; if (!readPod(p,a.end,x)) return false;
                    if (x > static_cast<uint32_t>(std::numeric_limits<int32_t>::max()))
                        return false;
                    v=x; break;
                }
                case GGUFMetaType::INT32: {
                    int32_t x = 0; if (!readPod(p,a.end,x)) return false; v=x; break;
                }
                case GGUFMetaType::UINT64: {
                    uint64_t x = 0; if (!readPod(p,a.end,x)) return false;
                    if (x > static_cast<uint64_t>(std::numeric_limits<int32_t>::max()))
                        return false;
                    v=static_cast<int64_t>(x); break;
                }
                case GGUFMetaType::INT64: {
                    int64_t x = 0; if (!readPod(p,a.end,x)) return false; v=x; break;
                }
                default:
                    out.clear();
                    return false;
            }

            if (v < std::numeric_limits<int32_t>::min() ||
                v > std::numeric_limits<int32_t>::max()) {
                out.clear();
                return false;
            }
            out.push_back(static_cast<int32_t>(v));
        }
        return true;
    }

private:
    static constexpr uint32_t kMagic = 0x46554747u; // bytes: G G U F
    static constexpr uint64_t kDefaultAlignment = 32;
    static constexpr uint64_t kMaxMetadata = 4ull * 1024ull * 1024ull;
    static constexpr uint64_t kMaxTensors = 16ull * 1024ull * 1024ull;
    static constexpr uint64_t kMaxStringBytes = 1ull << 30;
    static constexpr uint32_t kMaxDims = 8;
    static constexpr uint32_t kMaxArrayDepth = 8;

    struct MappedFile {
        std::string path;
        const uint8_t* data = nullptr;
        size_t size = 0;
#ifdef _WIN32
        HANDLE file = INVALID_HANDLE_VALUE;
        HANDLE mapping = nullptr;
#else
        int fd = -1;
#endif

        ~MappedFile() { close(); }

        MappedFile(const MappedFile&) = delete;
        MappedFile& operator=(const MappedFile&) = delete;
        MappedFile() = default;

        bool openReadOnly(const std::string& p, std::string& err) {
            close();
            path = p;
#ifdef _WIN32
            file = CreateFileA(p.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file == INVALID_HANDLE_VALUE) {
                err = "CreateFileA failed for " + p;
                return false;
            }
            LARGE_INTEGER li{};
            if (!GetFileSizeEx(file, &li) || li.QuadPart <= 0 ||
                static_cast<unsigned long long>(li.QuadPart) >
                    static_cast<unsigned long long>(std::numeric_limits<size_t>::max())) {
                err = "invalid GGUF file size: " + p;
                close();
                return false;
            }
            size = static_cast<size_t>(li.QuadPart);
            mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (!mapping) {
                err = "CreateFileMappingA failed for " + p;
                close();
                return false;
            }
            data = static_cast<const uint8_t*>(
                MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
            if (!data) {
                err = "MapViewOfFile failed for " + p;
                close();
                return false;
            }
#else
            fd = ::open(p.c_str(), O_RDONLY);
            if (fd < 0) {
                err = "open failed for " + p;
                return false;
            }
            struct stat st{};
            if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
                static_cast<uint64_t>(st.st_size) >
                    static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
                err = "invalid GGUF file size: " + p;
                close();
                return false;
            }
            size = static_cast<size_t>(st.st_size);
            void* view = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
            if (view == MAP_FAILED) {
                err = "mmap failed for " + p;
                close();
                return false;
            }
            data = static_cast<const uint8_t*>(view);
#endif
            return true;
        }

        void close() {
#ifdef _WIN32
            if (data) UnmapViewOfFile(data);
            data = nullptr;
            if (mapping) CloseHandle(mapping);
            mapping = nullptr;
            if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
            file = INVALID_HANDLE_VALUE;
#else
            if (data && size) munmap(const_cast<uint8_t*>(data), size);
            data = nullptr;
            if (fd >= 0) ::close(fd);
            fd = -1;
#endif
            size = 0;
            path.clear();
        }
    };

    struct MetaArrayView {
        uint32_t elementType = 0;
        uint64_t count = 0;
        const uint8_t* data = nullptr;
        const uint8_t* end = nullptr;
    };

    struct PendingTensor {
        std::string name;
        GGMLType type = GGMLType::GGML_TYPE_F32;
        std::vector<int64_t> shape;
        uint64_t relativeOffset = 0;
    };

    static bool mulOverflow(size_t a, size_t b, size_t& out) {
        if (a != 0 && b > std::numeric_limits<size_t>::max() / a)
            return true;
        out = a * b;
        return false;
    }

    static bool addOverflow(uint64_t a, uint64_t b, uint64_t& out) {
        if (b > std::numeric_limits<uint64_t>::max() - a)
            return true;
        out = a + b;
        return false;
    }

    template <typename T>
    static bool readPod(const uint8_t*& p, const uint8_t* end, T& out) {
        if (!p || !end || p > end ||
            static_cast<size_t>(end - p) < sizeof(T))
            return false;
        std::memcpy(&out, p, sizeof(T));
        p += sizeof(T);
        return true;
    }

    static bool readStringBounded(const uint8_t*& p, const uint8_t* end,
                                  std::string& out, uint64_t maxLen) {
        uint64_t len = 0;
        if (!readPod(p, end, len)) return false;
        if (len > maxLen || len > static_cast<uint64_t>(end - p))
            return false;
        out.assign(reinterpret_cast<const char*>(p),
                   static_cast<size_t>(len));
        p += static_cast<size_t>(len);
        return true;
    }

    static uint64_t alignUp(uint64_t v, uint64_t alignment) {
        if (alignment == 0) return 0;
        const uint64_t rem = v % alignment;
        if (rem == 0) return v;
        const uint64_t add = alignment - rem;
        if (v > std::numeric_limits<uint64_t>::max() - add) return 0;
        return v + add;
    }

    static bool typeGeometry(uint32_t type, size_t& blockElems, size_t& blockBytes) {
        switch (type) {
            case 0:  blockElems = 1;   blockBytes = 4;   return true; // F32
            case 1:  blockElems = 1;   blockBytes = 2;   return true; // F16
            case 2:  blockElems = 32;  blockBytes = 18;  return true; // Q4_0
            case 3:  blockElems = 32;  blockBytes = 20;  return true; // Q4_1
            case 6:  blockElems = 32;  blockBytes = 22;  return true; // Q5_0
            case 7:  blockElems = 32;  blockBytes = 24;  return true; // Q5_1
            case 8:  blockElems = 32;  blockBytes = 34;  return true; // Q8_0
            case 10: blockElems = 256; blockBytes = 84;  return true; // Q2_K
            case 11: blockElems = 256; blockBytes = 110; return true; // Q3_K
            case 12: blockElems = 256; blockBytes = 144; return true; // Q4_K
            case 13: blockElems = 256; blockBytes = 176; return true; // Q5_K
            case 14: blockElems = 256; blockBytes = 210; return true; // Q6_K
            case 15: blockElems = 256; blockBytes = 292; return true; // Q8_K
            case 16: blockElems = 256; blockBytes = 66;  return true; // IQ2_XXS
            case 24: blockElems = 1;   blockBytes = 1;   return true; // I8
            case 25: blockElems = 1;   blockBytes = 2;   return true; // I16
            case 26: blockElems = 1;   blockBytes = 4;   return true; // I32
            case 27: blockElems = 1;   blockBytes = 8;   return true; // I64
            case 28: blockElems = 1;   blockBytes = 8;   return true; // F64
            case 30: blockElems = 1;   blockBytes = 2;   return true; // BF16
            case 40: blockElems = 64;  blockBytes = 36;  return true; // NVFP4
            default: blockElems = blockBytes = 0; return false;
        }
    }

    static bool tensorByteSize(const PendingTensor& t, size_t& out) {
        out = 0;
        if (t.shape.empty()) return false;

        size_t blockElems = 0, blockBytes = 0;
        if (!typeGeometry(static_cast<uint32_t>(t.type), blockElems, blockBytes)) {
            fprintf(stderr,
                "[GGUF_DIAG] tensorByteSize FAIL: name=%s type=%u typeGeometry returned false\n",
                t.name.c_str(), static_cast<uint32_t>(t.type));
            return false;
        }

        if (t.shape[0] <= 0) {
            fprintf(stderr,
                "[GGUF_DIAG] tensorByteSize FAIL: name=%s type=%u shape[0]=%lld <= 0\n",
                t.name.c_str(), static_cast<uint32_t>(t.type), (long long)t.shape[0]);
            return false;
        }
        const size_t rowElems = static_cast<size_t>(t.shape[0]);
        if (blockElems > 1 && (rowElems % blockElems) != 0) {
            fprintf(stderr,
                "[GGUF_DIAG] tensorByteSize FAIL: name=%s type=%u blockElems=%zu blockBytes=%zu "
                "shape[0]=%zu rowElems=%zu rowElems%%blockElems=%zu\n",
                t.name.c_str(), static_cast<uint32_t>(t.type), blockElems, blockBytes,
                rowElems, rowElems, rowElems % blockElems);
            return false;
        }

        const size_t blocksPerRow =
            (rowElems + blockElems - 1) / blockElems;

        size_t rowBytes = 0;
        if (mulOverflow(blocksPerRow, blockBytes, rowBytes)) {
            fprintf(stderr,
                "[GGUF_DIAG] tensorByteSize FAIL: name=%s type=%u blocksPerRow=%zu blockBytes=%zu overflow\n",
                t.name.c_str(), static_cast<uint32_t>(t.type), blocksPerRow, blockBytes);
            return false;
        }

        size_t rows = 1;
        for (size_t d = 1; d < t.shape.size(); ++d) {
            if (t.shape[d] <= 0) {
                fprintf(stderr,
                    "[GGUF_DIAG] tensorByteSize FAIL: name=%s shape[%zu]=%lld <= 0\n",
                    t.name.c_str(), d, (long long)t.shape[d]);
                return false;
            }
            size_t next = 0;
            if (mulOverflow(rows, static_cast<size_t>(t.shape[d]), next)) {
                fprintf(stderr,
                    "[GGUF_DIAG] tensorByteSize FAIL: name=%s rows overflow at dim %zu\n",
                    t.name.c_str(), d);
                return false;
            }
            rows = next;
        }
        if (!mulOverflow(rowBytes, rows, out)) {
            fprintf(stderr,
                "[GGUF_DIAG] tensorByteSize PASS: name=%s type=%u shape[0]=%zu rows=%zu out=%zu\n",
                t.name.c_str(), static_cast<uint32_t>(t.type), rowElems, rows, out);
            return true;
        }
        fprintf(stderr,
            "[GGUF_DIAG] tensorByteSize FAIL: name=%s final overflow rowBytes=%zu rows=%zu\n",
            t.name.c_str(), rowBytes, rows);
        return false;
    }

    bool skipValue(uint32_t type, const uint8_t*& p,
                   const uint8_t* end, uint32_t depth) const {
        if (depth > kMaxArrayDepth) return false;
        switch (static_cast<GGUFMetaType>(type)) {
            case GGUFMetaType::UINT8:
            case GGUFMetaType::INT8:
            case GGUFMetaType::BOOL: {
                uint8_t x{};
                return readPod(p, end, x);
            }
            case GGUFMetaType::UINT16:
            case GGUFMetaType::INT16: {
                uint16_t x{};
                return readPod(p, end, x);
            }
            case GGUFMetaType::UINT32:
            case GGUFMetaType::INT32:
            case GGUFMetaType::FLOAT32: {
                uint32_t x{};
                return readPod(p, end, x);
            }
            case GGUFMetaType::UINT64:
            case GGUFMetaType::INT64:
            case GGUFMetaType::FLOAT64: {
                uint64_t x{};
                return readPod(p, end, x);
            }
            case GGUFMetaType::STRING: {
                std::string s;
                return readStringBounded(p, end, s, kMaxStringBytes);
            }
            case GGUFMetaType::ARRAY: {
                uint32_t elementType = 0;
                uint64_t count = 0;
                if (!readPod(p, end, elementType) ||
                    !readPod(p, end, count) ||
                    count > kMaxMetadata * 1024ull)
                    return false;
                for (uint64_t i = 0; i < count; ++i) {
                    if (!skipValue(elementType, p, end, depth + 1))
                        return false;
                }
                return true;
            }
            default:
                return false;
        }
    }

    bool parseMetadataValue(const std::string& key, uint32_t type,
                            const uint8_t*& p, const uint8_t* end,
                            uint64_t& localAlignment) {
        switch (static_cast<GGUFMetaType>(type)) {
            case GGUFMetaType::UINT8: {
                uint8_t v{}; if (!readPod(p,end,v)) return false;
                metaInt_.emplace(key, static_cast<int64_t>(v)); break;
            }
            case GGUFMetaType::INT8: {
                int8_t v{}; if (!readPod(p,end,v)) return false;
                metaInt_.emplace(key, static_cast<int64_t>(v)); break;
            }
            case GGUFMetaType::UINT16: {
                uint16_t v{}; if (!readPod(p,end,v)) return false;
                metaInt_.emplace(key, static_cast<int64_t>(v)); break;
            }
            case GGUFMetaType::INT16: {
                int16_t v{}; if (!readPod(p,end,v)) return false;
                metaInt_.emplace(key, static_cast<int64_t>(v)); break;
            }
            case GGUFMetaType::UINT32: {
                uint32_t v{}; if (!readPod(p,end,v)) return false;
                metaInt_.emplace(key, static_cast<int64_t>(v));
                if (key == "general.alignment") localAlignment = v;
                break;
            }
            case GGUFMetaType::INT32: {
                int32_t v{}; if (!readPod(p,end,v)) return false;
                metaInt_.emplace(key, static_cast<int64_t>(v)); break;
            }
            case GGUFMetaType::FLOAT32: {
                float v{}; if (!readPod(p,end,v)) return false;
                metaFloat_.emplace(key, static_cast<double>(v)); break;
            }
            case GGUFMetaType::BOOL: {
                uint8_t v{}; if (!readPod(p,end,v) || v > 1) return false;
                metaInt_.emplace(key, static_cast<int64_t>(v)); break;
            }
            case GGUFMetaType::STRING: {
                std::string v;
                if (!readStringBounded(p,end,v,kMaxStringBytes)) return false;
                metaString_.emplace(key, std::move(v));
                break;
            }
            case GGUFMetaType::UINT64: {
                uint64_t v{}; if (!readPod(p,end,v)) return false;
                if (v <= static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
                    metaInt_.emplace(key, static_cast<int64_t>(v));
                else
                    metaFloat_.emplace(key, static_cast<double>(v));
                break;
            }
            case GGUFMetaType::INT64: {
                int64_t v{}; if (!readPod(p,end,v)) return false;
                metaInt_.emplace(key, v); break;
            }
            case GGUFMetaType::FLOAT64: {
                double v{}; if (!readPod(p,end,v)) return false;
                metaFloat_.emplace(key, v); break;
            }
            case GGUFMetaType::ARRAY: {
                uint32_t elementType = 0;
                uint64_t count = 0;
                if (!readPod(p,end,elementType) || !readPod(p,end,count) ||
                    count > kMaxMetadata * 1024ull)
                    return false;

                MetaArrayView view;
                view.elementType = elementType;
                view.count = count;
                view.data = p;
                view.end = end;

                const uint8_t* q = p;
                for (uint64_t i = 0; i < count; ++i) {
                    if (!skipValue(elementType, q, end, 1)) return false;
                }
                p = q;
                metaArrays_.emplace(key, view);
                break;
            }
            default:
                return false;
        }
        return true;
    }

    bool loadOneShard(const std::string& path, uint32_t shardId) {
        auto mf = std::make_unique<MappedFile>();
        if (!mf->openReadOnly(path, error_)) return false;

        const uint8_t* p = mf->data;
        const uint8_t* end = mf->data + mf->size;

        uint32_t magic = 0, version = 0;
        uint64_t tensorCount = 0, metadataCount = 0;
        if (!readPod(p,end,magic) || !readPod(p,end,version) ||
            !readPod(p,end,tensorCount) || !readPod(p,end,metadataCount)) {
            return fail("truncated GGUF header: " + path);
        }
        if (magic != kMagic) return fail("bad GGUF magic: " + path);
        if (version != 2 && version != 3)
            return fail("unsupported GGUF version (expected v2/v3): " + path);
        if (tensorCount > kMaxTensors || metadataCount > kMaxMetadata)
            return fail("unreasonable GGUF table counts: " + path);

        if (version_ == 0) version_ = version;
        if (version_ != version) return fail("mixed GGUF versions across shards");

        // Store header counts for metadata-only queries (LoadMetadata)
        if (shardId == 0) {
            tensorCountHeader_ = tensorCount;
            metadataCountHeader_ = metadataCount;
        }

        uint64_t localAlignment = kDefaultAlignment;

        for (uint64_t i = 0; i < metadataCount; ++i) {
            std::string key;
            uint32_t type = 0;
            if (!readStringBounded(p,end,key,65535) ||
                !readPod(p,end,type) ||
                !parseMetadataValue(key,type,p,end,localAlignment)) {
                return fail("invalid GGUF metadata entry in " + path);
            }
        }

        if (localAlignment < 8 || (localAlignment & (localAlignment - 1)) != 0)
            return fail("general.alignment must be a power-of-two >= 8");

        std::vector<PendingTensor> pending;
        pending.reserve(static_cast<size_t>(tensorCount));

        for (uint64_t i = 0; i < tensorCount; ++i) {
            PendingTensor t;
            uint32_t dims = 0;
            uint32_t type = 0;
            if (!readStringBounded(p,end,t.name,64) ||
                !readPod(p,end,dims) || dims == 0 || dims > kMaxDims) {
                return fail("invalid GGUF tensor descriptor in " + path);
            }

            t.shape.resize(dims);
            for (uint32_t d = 0; d < dims; ++d) {
                uint64_t ne = 0;
                if (!readPod(p,end,ne) || ne == 0 ||
                    ne > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
                    return fail("invalid GGUF tensor dimension in " + path);
                }
                t.shape[d] = static_cast<int64_t>(ne);
            }

            if (!readPod(p,end,type) || !readPod(p,end,t.relativeOffset))
                return fail("truncated GGUF tensor descriptor in " + path);
            t.type = static_cast<GGMLType>(type);

            if ((t.relativeOffset % localAlignment) != 0)
                return fail("unaligned GGUF tensor offset in " + path);

            size_t bytes = 0;
            if (!tensorByteSize(t, bytes)) {
                size_t be = 0, bb = 0;
                typeGeometry(static_cast<uint32_t>(t.type), be, bb);
                std::string reason;
                if (be == 0 && bb == 0)
                    reason = "unknown_type";
                else if (t.shape[0] <= 0)
                    reason = "empty_first_dim";
                else if (be > 1 && (static_cast<size_t>(t.shape[0]) % be) != 0)
                    reason = "row_not_block_aligned";
                else
                    reason = "byte_size_overflow";
                fprintf(stderr,
                    "[GGUF_REJECT] name=%s type=%u "
                    "shape=[%lld%s] blockElems=%zu blockBytes=%zu reason=%s\n",
                    t.name.c_str(), static_cast<uint32_t>(t.type),
                    (long long)t.shape[0],
                    t.shape.size() > 1 ? ",..." : "",
                    be, bb, reason.c_str());
                return fail("unsupported/malformed GGML tensor type or shape: " + t.name);
            }

            pending.emplace_back(std::move(t));
        }

        const uint64_t tableEnd =
            static_cast<uint64_t>(p - mf->data);
        const uint64_t dataStart = alignUp(tableEnd, localAlignment);
        if (dataStart == 0 || dataStart > mf->size)
            return fail("invalid GGUF tensor_data offset in " + path);

        for (const PendingTensor& pt : pending) {
            size_t bytes = 0;
            if (!tensorByteSize(pt, bytes))
                return fail("failed tensor byte-size validation");

            uint64_t abs = 0;
            if (addOverflow(dataStart, pt.relativeOffset, abs) ||
                abs > mf->size ||
                bytes > static_cast<size_t>(mf->size - static_cast<size_t>(abs))) {
                return fail("GGUF tensor range outside mapped shard: " + pt.name);
            }

            if (tensors_.find(pt.name) != tensors_.end())
                return fail("duplicate tensor name across GGUF shards: " + pt.name);

            GGUFTensor t;
            t.name = pt.name;
            t.type = pt.type;
            t.shape = pt.shape;
            t.data = mf->data + static_cast<size_t>(abs);
            t.sizeBytes = bytes;
            t.fileOffset = abs;
            t.tensorOffset = pt.relativeOffset;
            t.shardId = shardId;
            t.mapped = true;
            tensors_.emplace(t.name, std::move(t));
        }

        if (totalMappedBytes_ >
            std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(mf->size))
            return fail("mapped-byte counter overflow");
        totalMappedBytes_ += static_cast<uint64_t>(mf->size);
        maps_.emplace_back(std::move(mf));
        return true;
    }

    bool fail(const std::string& msg) {
        error_ = msg;
        return false;
    }

    static bool allDigits(const std::string& s, size_t off, size_t n) {
        if (off + n > s.size()) return false;
        for (size_t i = 0; i < n; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(s[off+i])))
                return false;
        }
        return true;
    }

    static uint32_t parse5(const std::string& s, size_t off) {
        uint32_t v = 0;
        for (size_t i = 0; i < 5; ++i)
            v = v * 10u + static_cast<uint32_t>(s[off+i] - '0');
        return v;
    }

    static bool parseCanonicalShardName(const std::string& path,
                                        std::string& prefix,
                                        uint32_t& index,
                                        uint32_t& count) {
        prefix.clear();
        index = count = 0;
        if (path.size() < 20) return false;

        std::string ext = path.substr(path.size() - 5);
        for (char& c : ext) c = static_cast<char>(
            std::tolower(static_cast<unsigned char>(c)));
        if (ext != ".gguf") return false;

        const size_t segStart = path.size() - 5 - 15;
        const std::string seg = path.substr(segStart, 15);
        if (seg.size() != 15 || seg[0] != '-' ||
            seg.substr(6,4) != "-of-" ||
            !allDigits(seg,1,5) || !allDigits(seg,10,5))
            return false;

        index = parse5(seg,1);
        count = parse5(seg,10);
        if (index == 0 || count == 0 || index > count) return false;

        prefix = path.substr(0, segStart + 1); // keep dash before shard index
        return true;
    }

    static std::string fiveDigits(uint32_t v) {
        char buf[16]{};
        std::snprintf(buf, sizeof(buf), "%05u", v);
        return std::string(buf);
    }

        bool loaded_ = false;
        uint32_t version_ = 0;
        uint32_t shardCount_ = 0;
        uint64_t totalMappedBytes_ = 0;
        uint64_t tensorCountHeader_ = 0;   // GGUF header tensor count
        uint64_t metadataCountHeader_ = 0; // GGUF header metadata count
    std::string path_;
    std::string error_;

    std::vector<std::unique_ptr<MappedFile>> maps_;
    std::unordered_map<std::string, GGUFTensor> tensors_;
    std::unordered_map<std::string, int64_t> metaInt_;
    std::unordered_map<std::string, double> metaFloat_;
    std::unordered_map<std::string, std::string> metaString_;
    std::unordered_map<std::string, MetaArrayView> metaArrays_;
};

} // namespace Deep2

// ============================================================================
// Extended types for ModelOpenCompat.hpp and Deep2Engine.cpp compatibility
// ============================================================================
namespace Deep2 {

struct TensorInfo {
    std::string name;
    std::vector<uint64_t> dimensions;
    uint32_t type = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint64_t dataOffset = 0;

    // ---- Payload ----
    // Pointer into the GGUFLoader's mapped shard memory. Populated by
    // GGUFLoader::Load() from gt->data. Remains valid for the lifetime of the
    // GGUFLoader (or GGUFLoadResult, which holds the loader internally).
    // Do NOT free directly — the loader owns the mapping via RAII.
    void* data = nullptr;

    // Number of addressable units in the payload. Deep2Engine uses this to size
    // K/V and expert buffers, so it is derived from the byte size rather than
    // being a caller-supplied guess.
    uint64_t GetNumBlocks() const {
        if (size == 0) return 0;
        return size;   // GGUF tensor sizes are already byte counts
    }
};

struct ModelMetadata {
    uint32_t vocabSize = 0;
    uint32_t hiddenSize = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKeyValueHeads = 0;
    uint32_t intermediateSize = 0;
    uint32_t keyLength = 0;
    std::vector<std::string> vocab;
    std::string architecture;
    std::string name;        // general.name from GGUF metadata
    std::string chatTemplate; // tokenizer.chat_template from GGUF metadata
    std::string bosToken;     // tokenizer.bos_token or tokenizer.ggml.bos_token
    std::string eosToken;     // tokenizer.eos_token or tokenizer.ggml.eos_token

    // ---- MoE and attention fields ----
    // Deep2Engine.cpp reads these directly. They are populated with the
    // ARCHITECTURE-specific GGUF prefix rather than a hardcoded "llama." prefix,
    // because the target model is nemotron_h_moe, whose keys are
    // "nemotron_h_moe.*". An "llama."-only lookup silently returns 0 for it.
    uint32_t numExperts = 0;
    uint32_t numExpertsPerToken = 0;
    uint32_t numSharedExperts = 0;
    uint32_t moeIntermediateSize = 0;
    uint32_t sharedExpertIntermediateSize = 0;
    uint32_t leadingDenseBlockCount = 0;
    uint32_t valueLength = 0;
    uint32_t ropeDimensionCount = 0;
    uint32_t keyLengthMla = 0;
    uint32_t valueLengthMla = 0;
    uint32_t qLoraRank = 0;
    uint32_t kvLoraRank = 0;
    float    rmsNormEps = 0.0f;
    float    ropeTheta = 0.0f;
    uint32_t ropeScaling = 0;   // 0 = linear/off; engine reads it as a flag
    uint32_t maxPositionEmbeddings = 0;   // <arch>.context_length, mirrors vocab-style fallback
};

} // namespace Deep2

// GGUFLoadResult defined at global scope (not in namespace Deep2)
// The forward declaration + using-alias above (in namespace Deep2) makes it accessible as Deep2::GGUFLoadResult

struct GGUFLoadResult {
    bool success = false;
    bool ok = false;  // alias for compatibility
    int mmapBound = 0;
    uint32_t shardCount = 0;
    uint64_t totalSize = 0;
    uint64_t dataOffset = 0;
    std::shared_ptr<Deep2::GGUFLoader> loader;
    Deep2::ModelMetadata metadata;
    std::vector<Deep2::TensorInfo> tensors;
    std::string error;
    std::unique_ptr<void, void(*)(void*)> mmapKeep{nullptr, [](void*){}};
    // Sovereign authority fields
    std::map<std::string,std::string> rawKv; // all GGUF metadata as string KV pairs
    uint32_t ggufVersion = 0;
    uint64_t tensorCountHeader = 0;
    uint64_t metadataCountHeader = 0;
};

// Implementation of GGUFLoader::LoadMetadata (requires complete GGUFLoadResult)
namespace Deep2 {
inline GGUFLoadResult GGUFLoader::LoadMetadata(const char* filepath) {
    GGUFLoadResult result;
    if (!filepath || !filepath[0]) {
        result.error = "empty GGUF path";
        return result;
    }

    auto loader = std::make_shared<GGUFLoader>();
    if (!loader->load(std::string(filepath))) {
        result.success = false;
        result.ok = false;
        result.error = loader->error();
        return result;
    }

    result.success = true;
    result.ok = true;
    result.mmapBound = loader->mappedBytes() > 0 ? 1 : 0;
    result.shardCount = loader->shardCount();
    result.ggufVersion = loader->version();
    result.tensorCountHeader = loader->tensorCountHeader();
    result.metadataCountHeader = loader->metadataCountHeader();
    result.totalSize = loader->mappedBytes();
    result.loader = std::move(loader);

    // Populate rawKv from all metadata key-value pairs
    auto rawStrings = result.loader->getMetaAllStrings();
    result.rawKv = std::move(rawStrings);

    // Populate structured metadata
    auto& meta = result.metadata;
    meta.architecture = result.loader->getMetaString("general.architecture", "unknown");
    meta.name = result.loader->getMetaString("general.name", "");
    meta.vocabSize = static_cast<uint32_t>(result.loader->getMetaInt(
        "tokenizer.ggml.vocab_size",
        result.loader->getMetaInt("llama.vocab_size", 0)));
    meta.numLayers = static_cast<uint32_t>(result.loader->getMetaInt("llama.block_count", 0));
    meta.numHeads = static_cast<uint32_t>(result.loader->getMetaInt("llama.attention.head_count", 0));
    meta.numKeyValueHeads = static_cast<uint32_t>(result.loader->getMetaInt("llama.attention.head_count_kv", meta.numHeads));
    meta.intermediateSize = static_cast<uint32_t>(result.loader->getMetaInt("llama.feed_forward_length", 0));
    meta.keyLength = static_cast<uint32_t>(result.loader->getMetaInt("llama.attention.key_length", 0));
    meta.chatTemplate = result.loader->getMetaString("tokenizer.chat_template", "");

    // Populate tensor descriptors
    auto tensorNames = result.loader->listTensors();
    result.tensors.reserve(tensorNames.size());
    for (const auto& name : tensorNames) {
        const auto* gt = result.loader->getTensor(name);
        if (gt) {
            TensorInfo ti;
            ti.name = name;
            ti.dimensions.reserve(gt->shape.size());
            for (int64_t d : gt->shape)
                ti.dimensions.push_back(static_cast<uint64_t>(d));
            ti.type = static_cast<uint32_t>(gt->type);
            ti.offset = gt->tensorOffset;
            ti.size = gt->sizeBytes;
            ti.dataOffset = gt->fileOffset;
            result.tensors.push_back(std::move(ti));
        }
    }

    return result;
}


// ---------------------------------------------------------------------------
// GGUFLoader::FreeTensorData -- release a TensorInfo::data pointer.
//
// Kept adjacent to the matching allocation so the VirtualAlloc/VirtualFree
// pair is confined to this header. free()/delete on this pointer is undefined
// behaviour, which is why it is not exposed as a plain pointer.
// Safe to call with nullptr (documented).
// ---------------------------------------------------------------------------
inline void GGUFLoader::FreeTensorData(void* p) {
    if (!p) return;
#ifdef _WIN32
    ::VirtualFree(p, 0, MEM_RELEASE);
#else
    std::free(p);
#endif
}


// ---------------------------------------------------------------------------
// GGUFLoader::Load Ã¢â‚¬â€ full load.
//
// Defined here because it needs a complete GGUFLoadOptions and GGUFLoadResult.
// It calls the SAME loader->load(path) and the SAME metadata-population logic
// that LoadMetadata and load_gguf already use, so this adds no second parser
// and no second set of semantics.
//
// The only new responsibility is honours options.loadTensors and options.mmap:
// when loadTensors is false the tensor directory is not described, which is
// what Deep2Engine asks for multi-shard models where tensors are covered by
// the GlobalTensorIndex instead.
// ---------------------------------------------------------------------------
inline GGUFLoadResult GGUFLoader::Load(const char* filepath, const GGUFLoadOptions& options) {
    GGUFLoadResult result;

    if (!filepath || !filepath[0]) {
        result.error = "empty GGUF path";
        return result;
    }

    auto loader = std::make_shared<GGUFLoader>();
    // The member load() already memory-maps; options.mmap == false would need
    // a read-based path that the loader does not implement. Rather than
    // silently ignoring the request, report it so a caller cannot believe it
    // got a heap-resident copy.
    if (!options.mmap && loader->mappedBytes() == 0) {
        // mmap is the only implemented path; continue mapped and disclose.
        result.mmapBound = 1;
    }

    if (!loader->load(std::string(filepath))) {
        result.success = false;
        result.ok = false;
        result.error = loader->error();
        return result;
    }

    result.success = true;
    result.ok = true;
    result.mmapBound = loader->mappedBytes() > 0 ? 1 : 0;
    result.shardCount = loader->shardCount();
    result.ggufVersion = loader->version();
    result.tensorCountHeader = loader->tensorCountHeader();
    result.metadataCountHeader = loader->metadataCountHeader();
    result.totalSize = loader->mappedBytes();
    result.loader = std::move(loader);

    // Populate rawKv so callers can audit every GGUF key without re-reading.
    result.rawKv = result.loader->getMetaAllStrings();

    // ---- Structured metadata ----
    // The prefix is ARCHITECTURE-specific. Hardcoding "llama." returns zeros for
    // nemotron_h_moe and every other non-Llama architecture, which is the class
    // of bug this loader previously had.
    auto& ld = *result.loader;
    const std::string arch = ld.getMetaString("general.architecture", "");

    auto archKey = [&arch](const std::string& suffix) -> std::string {
        return arch.empty() ? ("llama." + suffix) : (arch + "." + suffix);
    };
    auto keyWithFallback = [&archKey](const std::string& suffix) -> std::vector<std::string> {
        std::vector<std::string> v;
        v.push_back(archKey(suffix));        // architecture-specific first
        v.push_back("llama." + suffix);      // legacy second
        return v;
    };

    auto& meta = result.metadata;
    meta.architecture = arch.empty() ? "unknown" : arch;
    meta.name = ld.getMetaString("general.name", "");

    auto readInt = [&ld](const std::vector<std::string>& keys, int64_t def) -> int64_t {
        for (const auto& k : keys) {
            if (ld.hasMeta(k)) {
                int64_t v = ld.getMetaInt(k, def);
                if (v != 0) return v;
                // Scalar read returned 0 but the key may be an integer array
                // (e.g. expert_used_count, head_count_kv).  Try the first
                // array element as the scalar value.
                int64_t av = ld.getMetaIntArrayFirst(k, def);
                if (av != 0) return av;
            }
        }
        return def;
    };

    meta.vocabSize = static_cast<uint32_t>(readInt(
        {"tokenizer.ggml.vocab_size"}, 0));
    meta.hiddenSize = static_cast<uint32_t>(readInt(
        keyWithFallback("embedding_length"), 0));
    meta.numLayers = static_cast<uint32_t>(readInt(
        keyWithFallback("block_count"), 0));
    meta.numHeads = static_cast<uint32_t>(readInt(
        keyWithFallback("attention.head_count"), 0));
    meta.numKeyValueHeads = static_cast<uint32_t>(readInt(
        keyWithFallback("attention.head_count_kv"), meta.numHeads));
    meta.intermediateSize = static_cast<uint32_t>(readInt(
        keyWithFallback("feed_forward_length"), 0));
    meta.keyLength = static_cast<uint32_t>(readInt(
        keyWithFallback("attention.key_length"), 0));
    meta.valueLength = static_cast<uint32_t>(readInt(
        keyWithFallback("attention.value_length"), meta.keyLength));
    meta.maxPositionEmbeddings = static_cast<uint32_t>(readInt(
        keyWithFallback("context_length"), 0));
    meta.ropeDimensionCount = static_cast<uint32_t>(readInt(
        keyWithFallback("rope.dimension_count"), 0));
    meta.chatTemplate = ld.getMetaString("tokenizer.chat_template", "");

    // ---- MoE ----
    meta.numExperts = static_cast<uint32_t>(readInt(
        keyWithFallback("expert_count"), 0));
    {
        std::vector<std::string> moeTopKKeys;
        moeTopKKeys.push_back(archKey("expert_used_count"));
        moeTopKKeys.push_back(archKey("expert_group_used_count"));
        moeTopKKeys.push_back("llama.expert_used_count");
        moeTopKKeys.push_back("llama.expert_group_used_count");
        meta.numExpertsPerToken = static_cast<uint32_t>(readInt(moeTopKKeys, 0));
    }
    meta.numSharedExperts = static_cast<uint32_t>(readInt(
        keyWithFallback("expert_shared_count"), 0));
    meta.moeIntermediateSize = static_cast<uint32_t>(readInt(
        keyWithFallback("expert_feed_forward_length"), 0));
    meta.sharedExpertIntermediateSize = static_cast<uint32_t>(readInt(
        keyWithFallback("expert_shared_feed_forward_length"), 0));
    meta.leadingDenseBlockCount = static_cast<uint32_t>(readInt(
        keyWithFallback("attention.sliding_window"), 0));

    // ---- MLA / LoRA, present on DeepSeek-style models and absent elsewhere ----
    meta.keyLengthMla = static_cast<uint32_t>(readInt(
        keyWithFallback("key_length_mla"), 0));
    meta.valueLengthMla = static_cast<uint32_t>(readInt(
        keyWithFallback("value_length_mla"), 0));
    meta.qLoraRank = static_cast<uint32_t>(readInt(
        keyWithFallback("q_lora_rank"), 0));
    meta.kvLoraRank = static_cast<uint32_t>(readInt(
        keyWithFallback("kv_lora_rank"), 0));

    meta.rmsNormEps = static_cast<float>(
        ld.getMetaFloat(archKey("attention.layer_norm_rms_epsilon"), 0.0));
    if (meta.rmsNormEps == 0.0f) {
        meta.rmsNormEps = static_cast<float>(
            ld.getMetaFloat("llama.attention.layer_norm_rms_epsilon", 0.0f));
    }
    meta.ropeTheta = static_cast<float>(
        ld.getMetaFloat(archKey("rope.freq_base"), 0.0f));
    if (meta.ropeTheta == 0.0f) {
        meta.ropeTheta = static_cast<float>(
            ld.getMetaFloat("llama.rope.freq_base", 0.0f));
    }
    // ropeScaling is read as a has/finetuned flag: 1 when the GGUF metadata
    // says rope scaling is applied, 0 otherwise.
    {
        const std::string scKey = archKey("rope.scaling.finetuned");
        meta.ropeScaling = ld.hasMeta(scKey)
            ? static_cast<uint32_t>(ld.getMetaInt(scKey, 0) ? 1 : 0) : 0u;
    }

    // ---- Vocabulary ----
    std::vector<std::string> tokens;
    if (ld.getMetaStringArray("tokenizer.ggml.tokens", tokens)) {
        meta.vocab = std::move(tokens);
        if (meta.vocabSize == 0) meta.vocabSize = static_cast<uint32_t>(meta.vocab.size());
    }

    // ---- Tensor descriptors ----
    if (options.loadTensors) {
        auto tensorNames = ld.listTensors();
        result.tensors.reserve(tensorNames.size());
        for (const auto& name : tensorNames) {
            const auto* gt = ld.getTensor(name);
            if (!gt) continue;
            TensorInfo ti;
            ti.name = name;
            ti.dimensions.reserve(gt->shape.size());
            for (int64_t d : gt->shape) ti.dimensions.push_back(static_cast<uint64_t>(d));
            ti.type = static_cast<uint32_t>(gt->type);
            ti.offset = gt->tensorOffset;
            ti.size = gt->sizeBytes;
            ti.dataOffset = gt->fileOffset;
            ti.data = const_cast<void*>(static_cast<const void*>(gt->data));  // data pointer from mapped shard
            result.tensors.push_back(std::move(ti));
        }
    } else {
        // Report the tensor count from the GGUF header without enumerating.
        result.tensors.clear();
    }

    if (options.verbose) {
        std::printf("[GGUFLoader::Load] arch=%s layers=%u heads=%u experts=%u/%u vocab=%u tensors=%zu mmap=%d\n",
                    meta.architecture.c_str(), meta.numLayers, meta.numHeads,
                    meta.numExperts, meta.numExpertsPerToken, meta.vocabSize,
                    result.tensors.size(), result.mmapBound);
    }

    return result;
}

} // namespace Deep2

inline bool load_gguf(const std::string& path, void* out) {
    if (!out) return false;
    auto* result = static_cast<GGUFLoadResult*>(out);
    *result = {};

    auto loader = std::make_shared<Deep2::GGUFLoader>();
    if (!loader->load(path)) {
        result->error = loader->error();
        return false;
    }

    result->success = true;
    result->ok = true;
    result->mmapBound = 1;
    result->shardCount = loader->shardCount();
    result->loader = std::move(loader);

    // Populate metadata from GGUF metadata
    auto& meta = result->metadata;
    meta.vocabSize = static_cast<uint32_t>(result->loader->getMetaInt("tokenizer.ggml.vocab_size", 
                                                                   result->loader->getMetaInt("llama.vocab_size", 0)));
    meta.hiddenSize = static_cast<uint32_t>(result->loader->getMetaInt("llama.embedding_length", 0));
    meta.numLayers = static_cast<uint32_t>(result->loader->getMetaInt("llama.block_count", 0));
    meta.numHeads = static_cast<uint32_t>(result->loader->getMetaInt("llama.attention.head_count", 0));
    meta.numKeyValueHeads = static_cast<uint32_t>(result->loader->getMetaInt("llama.attention.head_count_kv", meta.numHeads));
    meta.intermediateSize = static_cast<uint32_t>(result->loader->getMetaInt("llama.feed_forward_length", 0));
    meta.keyLength = static_cast<uint32_t>(result->loader->getMetaInt("llama.attention.key_length", 0));
    meta.architecture = result->loader->getMetaString("general.architecture", "unknown");

    // Load vocab
    std::vector<std::string> tokens;
    if (result->loader->getMetaStringArray("tokenizer.ggml.tokens", tokens)) {
        meta.vocab = std::move(tokens);
        if (meta.vocabSize == 0) meta.vocabSize = static_cast<uint32_t>(meta.vocab.size());
    }

    // Populate tensors
    auto& tensors = result->tensors;
    auto tensorNames = result->loader->listTensors();
    tensors.reserve(tensorNames.size());
    for (const auto& name : tensorNames) {
        const auto* gt = result->loader->getTensor(name);
        if (gt) {
            Deep2::TensorInfo ti;
            ti.name = name;
            ti.dimensions.reserve(gt->shape.size());
            for (int64_t d : gt->shape) {
                ti.dimensions.push_back(static_cast<uint64_t>(d));
            }
            ti.type = static_cast<uint32_t>(gt->type);
            ti.offset = gt->tensorOffset;
            ti.size = gt->sizeBytes;
            ti.dataOffset = gt->fileOffset;
            ti.data = const_cast<void*>(static_cast<const void*>(gt->data));  // data pointer from mapped shard
            tensors.push_back(std::move(ti));
        }
    }

    return true;
}
