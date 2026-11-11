#pragma once
// ============================================================================
// GGUFLoader.hpp — Batch 6 real no-dependency mapped GGUF v2/v3 loader
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
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

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

// ggml_type enum and the block-geometry descriptor table live in exactly one
// place: QuantTypeTable.hpp.  GGUFLoader used to carry its own INCOMPLETE copy
// (missing Q8_1=9, all IQ* except IQ4_NL, IQ1_M=29, TQ1_0/TQ2_0, MXFP4, NVFP4,
// Q1_0, Q2_0 and COUNT).  Two different Deep2::GGMLType definitions cannot both
// exist, so consume the canonical one.
#include "QuantTypeTable.hpp"

namespace Deep2 {

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

// Forward declarations: both types are declared in namespace Deep2 further
// down in this header, after class GGUFLoader.  GGUFLoader declares
// tensorInfoList() (returns TensorInfo) and LoadMetadata() (returns
// GGUFLoadResult), so both must be declared before the class.
struct TensorInfo;
struct GGUFLoadResult;

// Load options for GGUFLoader::Load().
//
// loadTensors=false performs a metadata-and-descriptor-only open: the loader
// parses the header, the metadata KV pairs and the tensor descriptors, and does
// not resolve tensor payload ranges.  This is the correct choice for shard sets
// where tensor data for the shard being opened is absent or belongs to a
// sibling shard.
//
// mmap=false forces a read into heap instead of mapping.  verbose enables
// progress/provenance tracing on stderr.
//
// Defaults match the historical behaviour of GGUFLoader::load(), which loaded
// everything mmap'd and quietly.
struct GGUFLoadOptions {
    bool loadTensors = true;
    bool mmap        = true;
    bool verbose     = false;
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

    // ------------------------------------------------------------------------
    // load(path, options) — same open as load(path) but honouring the options.
    //
    // loadTensors=false skips payload-range setup entirely (metadata/descriptors
    // only); mmap=false forces a read into heap; verbose mirrors load()'s
    // progress output when set.  All three default to load()'s behaviour, so
    // load(path) == load(path, {}).
    // ------------------------------------------------------------------------
    bool load(const std::string& path, const GGUFLoadOptions& options = GGUFLoadOptions{}) {
        close();
        error_.clear();
        if (path.empty()) return fail("empty GGUF path");

        if (!options.loadTensors) {
            // Metadata-and-descriptor-only open: parse the header and the KV
            // pairs, record descriptors, do not resolve payload ranges.
            metadataOnly_ = true;
        } else {
            metadataOnly_ = false;
        }
        return loadImpl(path, options.mmap, options.verbose);
    }

    // True when the most recent load() ran with loadTensors=false.
    bool metadataOnly() const { return metadataOnly_; }

    // ------------------------------------------------------------------------
    // Load(path, options) — convenience static that fills a GGUFLoadResult.
    // Mirrors load_gguf() but takes explicit options.
    // ------------------------------------------------------------------------
    static GGUFLoadResult Load(const std::string& path,
                               const GGUFLoadOptions& options = GGUFLoadOptions{});

    GGUFLoader(const GGUFLoader&) = delete;
    GGUFLoader& operator=(const GGUFLoader&) = delete;

    bool loadImpl(const std::string& path, bool useMmap, bool verbose) {
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
    }

    bool loaded() const { return loaded_; }
    uint32_t version() const { return version_; }
    uint32_t shardCount() const { return shardCount_; }

    // ------------------------------------------------------------------------
    // Metadata surface used by the authority / geometry seals and by callers
    // that must not guess the architecture prefix.
    //
    // metadataCount() reports the number of pairs actually PARSED, not the
    // count the header declared, so a truncated file is caught by comparing
    // the two rather than by trusting the header.
    // metaInt()/metaFloat()/metaString() expose the parsed tables directly for
    // arch-prefixed keys ("llama.embedding_length") and string-valued keys
    // such as "tokenizer.chat_template".  Array metadata is deliberately not
    // exposed here.
    // ------------------------------------------------------------------------
    uint32_t metadataCount() const {
        return static_cast<uint32_t>(metaInt_.size() + metaFloat_.size() +
                                     metaString_.size() + metaArrays_.size());
    }
    // Direct read-only views of the parsed scalar/string metadata tables.
    // Callers that need an arch-prefixed lookup or a string-valued key
    // (chat_template, tokenizer.ggml.model, ...) use these rather than guessing
    // arch prefixes. Array metadata is deliberately not exposed here.
    const std::unordered_map<std::string, int64_t>& metaInt() const { return metaInt_; }
    const std::unordered_map<std::string, double>& metaFloat() const { return metaFloat_; }
    const std::unordered_map<std::string, std::string>& metaString() const { return metaString_; }
    std::vector<std::string> metaStringKeys() const {
        std::vector<std::string> k;
        k.reserve(metaString_.size());
        for (const auto& kv : metaString_) k.push_back(kv.first);
        return k;
    }

    // Tensor descriptors (name/type/shape/offset), sorted by name.  No payload
    // data is touched.  Declared here; defined after Deep2::TensorInfo and
    // Deep2::GGUFLoadResult, which are only complete further down this header.
    std::vector<TensorInfo> tensorInfoList() const;

    // ------------------------------------------------------------------------
    // FreeTensorData — release a tensor payload previously handed out through
    // GGUFLoadResult::tensors[].data.
    //
    // Tensor payloads are mmap views into an open shard mapping, so there is
    // normally NOTHING to free at this level: the mapping is released by the
    // owning GGUFLoadResult (through close()).  This entry point exists so a
    // caller that is about to drop the whole result can still release payloads
    // it obtained from a loader-backed path without knowing which of the two
    // backing schemes was used.
    //
    // It is intentionally a no-op for pointers that came from a mapping, and it
    // never closes a shard mapping (which would invalidate every other tensor).
    // Passing nullptr is allowed.  Returns true when the pointer was recognised
    // as a loader-owned tensor payload and needed no action, false otherwise.
    // ------------------------------------------------------------------------
    static bool FreeTensorData(const uint8_t* data);

    // Metadata-only open used by the authority/geometry seals: header facts,
    // tensor descriptors and every parsed key/value flattened to text, without
    // mapping any tensor payload.  Declared here; defined below.
    static GGUFLoadResult LoadMetadata(const char* path);
    uint64_t mappedBytes() const { return totalMappedBytes_; }
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

    std::string getMetaString(const std::string& key,
                              const std::string& def = {}) const {
        auto it = metaString_.find(key);
        return it == metaString_.end() ? def : it->second;
    }

    bool hasMeta(const std::string& key) const {
        return metaInt_.count(key) || metaFloat_.count(key) ||
               metaString_.count(key) || metaArrays_.count(key);
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
            case 24: blockElems = 1;   blockBytes = 1;   return true; // I8
            case 25: blockElems = 1;   blockBytes = 2;   return true; // I16
            case 26: blockElems = 1;   blockBytes = 4;   return true; // I32
            case 27: blockElems = 1;   blockBytes = 8;   return true; // I64
            case 28: blockElems = 1;   blockBytes = 8;   return true; // F64
            case 30: blockElems = 1;   blockBytes = 2;   return true; // BF16
            default: blockElems = blockBytes = 0; return false;
        }
    }

    static bool tensorByteSize(const PendingTensor& t, size_t& out) {
        out = 0;
        if (t.shape.empty()) return false;

        size_t blockElems = 0, blockBytes = 0;
        if (!typeGeometry(static_cast<uint32_t>(t.type), blockElems, blockBytes))
            return false;

        if (t.shape[0] <= 0) return false;
        const size_t rowElems = static_cast<size_t>(t.shape[0]);
        if (blockElems > 1 && (rowElems % blockElems) != 0)
            return false;

        const size_t blocksPerRow =
            (rowElems + blockElems - 1) / blockElems;

        size_t rowBytes = 0;
        if (mulOverflow(blocksPerRow, blockBytes, rowBytes)) return false;

        size_t rows = 1;
        for (size_t d = 1; d < t.shape.size(); ++d) {
            if (t.shape[d] <= 0) return false;
            size_t next = 0;
            if (mulOverflow(rows, static_cast<size_t>(t.shape[d]), next))
                return false;
            rows = next;
        }
        return !mulOverflow(rowBytes, rows, out);
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
            if (!tensorByteSize(t, bytes))
                return fail("unsupported/malformed GGML tensor type or shape: " + t.name);

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
    bool metadataOnly_ = false;  // last run used loadTensors=false
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

    // --- Payload access -----------------------------------------------------
    // Points at the tensor's mapped bytes when the loader resolved a payload
    // range (loadTensors=true), and is null for a descriptor-only open. It is
    // NEVER owned here: the shard mapping or the VirtualAlloc block that backs
    // it is released through ggufResult, so callers must not free it.
    //
    // const because it aliases a read-only shard mapping; engines that need a
    // writable copy must copy it out (they never write a weight in place).
    const uint8_t* data = nullptr;

    // --- Block count --------------------------------------------------------
    // Number of quantization blocks across the whole tensor:
    //   ceil( numElements / QuantTypeBlockElements(type) )
    // Returns 0 for unquantized/unrecognized types with a nonzero element count,
    // which is the fail-closed answer: a caller that needs a block count cannot
    // proceed on a type whose geometry it does not know.
    uint64_t GetNumBlocks() const {
        const size_t elems = QuantTypeBlockElements(type);
        if (elems == 0) return 0;
        size_t n = 1;
        for (uint64_t d : dimensions) {
            if (d == 0) return 0;
            if (n != 0 && static_cast<size_t>(d) >
                            static_cast<size_t>(-1) / n) return 0;  // overflow
            n *= static_cast<size_t>(d);
        }
        if (n == 0) return 0;
        return (static_cast<uint64_t>(n) + elems - 1) / elems;
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

    // general.name, when the file declares it. Empty when it does not; callers
    // that report a model name must tolerate that rather than inventing one.
    std::string name;
    // tokenizer.chat_template, when the file declares it. The tokenizer/template
    // seal reads this (and the same key in rawKv) to decide between a
    // model-provided template and explicit-none RAW_PROMPT_ALLOWED policy.
    // Empty means "the file declared no template".
    std::string chatTemplate;

    // ========================================================================
    // MoE / MLA / rope / position metadata
    // ------------------------------------------------------------------------
    // 0 / empty means "the file did not declare it", never "zero experts" as a
    // fabricated value: Deep2Engine.cpp branches on `numExperts > 0` to select
    // the dense path, and on leadingDenseBlockCount for hybrid dense/MoE stacks
    // (DeepSeek V3, Qwen3-Next). Every field below is only non-zero when the
    // corresponding metadata key was actually present.
    // ========================================================================

    // --- Mixture-of-Experts ---------------------------------------------------
    uint32_t numExperts = 0;            // expert_count / num_experts
    uint32_t numExpertsPerToken = 0;    // expert_used_count / num_experts_per_tok
    uint32_t numSharedExperts = 0;      // shared_expert_count
    uint32_t moeIntermediateSize = 0;   // expert_intermediate_size
    uint32_t leadingDenseBlockCount = 0; // dense leading layers before MoE starts

    // --- MLA / DeepSeek2 low-rank projections ---------------------------------
    uint32_t qLoraRank = 0;             // q_lora_rank
    uint32_t kvLoraRank = 0;            // kv_lora_rank
    uint32_t valueLength = 0;           // v_head_dim
    uint32_t keyLengthMla = 0;          // qk_nope_head_dim
    uint32_t valueLengthMla = 0;        // v_head_dim (MLA naming)

    // --- Rope / position ------------------------------------------------------
    uint32_t maxPositionEmbeddings = 0; // context_length
    uint32_t ropeDimensionCount = 0;    // rope.dimension_count
    float    rmsNormEps = 0.0f;         // attention.layer_norm_rms_epsilon
    float    ropeTheta = 0.0f;          // rope.freq_base / rope_theta
    float    ropeScaling = 0.0f;        // rope.scaling.factor
    bool     ropeScalingPresent = false;

    // --- Special token strings -------------------------------------------------
    std::string bosToken;               // tokenizer.ggml.bos_token_id (as text)
    std::string eosToken;               // tokenizer.ggml.eos_token_id (as text)
};

} // namespace Deep2

namespace Deep2 {

// ----------------------------------------------------------------------------
// Flatten Deep2::ModelMetadata out of a rawKv view.
//
// Every field is copied ONLY when its key is present, so an absent key leaves
// the field at its "not declared" default (0 / empty) rather than inventing a
// value.  MoE, MLA, rope and special-token probes accept both the modern
// (arch-prefixed) and the legacy (llama./tokenizer.ggml.) spellings.
// ----------------------------------------------------------------------------
inline void FillMetadataFromRawKv(const std::unordered_map<std::string, std::string>& rawKv,
                                  ModelMetadata& m) {
    const auto u32 = [](const std::string& s) {
        return static_cast<uint32_t>(std::strtoull(s.c_str(), nullptr, 10));
    };
    const auto has = [&](const char* k) { return rawKv.count(k) != 0; };
    const auto get = [&](const char* k) -> const std::string& { return rawKv.at(k); };
    // Prefer the first key that is present, so the legacy spelling still works.
    const auto pick = [&](std::initializer_list<const char*> keys) -> const std::string* {
        for (const char* k : keys) if (has(k)) return &get(k);
        return nullptr;
    };
    const auto pickU32 = [&](std::initializer_list<const char*> keys, uint32_t& dst) -> bool {
        const std::string* v = pick(keys);
        if (!v) return false;
        dst = u32(*v);
        return true;
    };
    const auto pickF32 = [&](std::initializer_list<const char*> keys, float& dst) -> bool {
        const std::string* v = pick(keys);
        if (!v) return false;
        dst = std::strtof(v->c_str(), nullptr);
        return true;
    };

    pickU32({"tokenizer.ggml.vocab_size", "llama.vocab_size"}, m.vocabSize);
    pickU32({"llama.embedding_length"}, m.hiddenSize);
    pickU32({"llama.block_count"}, m.numLayers);
    pickU32({"llama.attention.head_count"}, m.numHeads);
    pickU32({"llama.attention.head_count_kv"}, m.numKeyValueHeads);
    pickU32({"llama.feed_forward_length"}, m.intermediateSize);
    pickU32({"llama.attention.key_length", "llama.key_length"}, m.keyLength);

    if (const std::string* v = pick({"general.architecture"})) m.architecture = *v;
    if (const std::string* v = pick({"general.name"}))          m.name = *v;
    if (const std::string* v = pick({"tokenizer.chat_template"})) m.chatTemplate = *v;

    // --- MoE -------------------------------------------------------------------
    // DeepSeek V3 / Qwen3-Next use different key spellings for the same facts.
    pickU32({"expert_count", "num_experts", "llama.expert_count",
             "num_local_experts"}, m.numExperts);
    pickU32({"expert_used_count", "num_experts_per_tok", "llama.expert_used_count",
             "num_experts_per_token"}, m.numExpertsPerToken);
    pickU32({"shared_expert_count", "num_shared_experts",
             "llama.shared_expert_count"}, m.numSharedExperts);
    pickU32({"expert_intermediate_size", "moe_intermediate_size",
             "llama.expert_feed_forward_length"}, m.moeIntermediateSize);
    pickU32({"leading_dense_block_count", "first_k_dense_replace",
             "llama.leading_dense_block_count"}, m.leadingDenseBlockCount);

    // --- MLA / DeepSeek2 --------------------------------------------------------
    pickU32({"q_lora_rank", "llama.q_lora_rank"}, m.qLoraRank);
    pickU32({"kv_lora_rank", "llama.kv_lora_rank"}, m.kvLoraRank);
    pickU32({"v_head_dim", "llama.v_head_dim", "value_length"}, m.valueLength);
    pickU32({"qk_nope_head_dim", "llama.qk_nope_head_dim", "key_length_mla"},
            m.keyLengthMla);
    pickU32({"v_head_dim", "llama.v_head_dim", "value_length_mla"},
            m.valueLengthMla);

    // --- Rope / position ---------------------------------------------------------
    pickU32({"context_length", "llama.context_length"}, m.maxPositionEmbeddings);
    pickU32({"rope.dimension_count", "llama.rope.dimension_count", "rope_dimension_count"},
            m.ropeDimensionCount);
    // rmsNormEps / ropeTheta / ropeScaling are floats and are assigned below.
    {
        float v = 0.0f;
        if (pickF32({"attention.layer_norm_rms_epsilon", "attention.layer_norm_epsilon",
                     "rms_norm_eps"}, v) && v > 0.0f)
            m.rmsNormEps = v;
        if (pickF32({"rope.freq_base", "rope_theta", "llama.rope.freq_base"}, v) && v > 0.0f)
            m.ropeTheta = v;
        if (pickF32({"rope.scaling.factor", "llama.rope.scaling.factor"}, v) && v > 0.0f) {
            m.ropeScaling = v;
            m.ropeScalingPresent = true;
        }
    }

    // --- Special token strings ----------------------------------------------------
    if (const std::string* v = pick({"tokenizer.ggml.bos_token_id"})) m.bosToken = *v;
    if (const std::string* v = pick({"tokenizer.ggml.eos_token_id"})) m.eosToken = *v;
}

// GGUFLoadResult lives in Deep2: the engine, ModelOpenCompat, the
// authority/geometry seals and the deep2 certification harnesses all spell it
// Deep2::GGUFLoadResult and several need it complete at their point of use.
// A global-scope alias at the end of this header keeps the historical
// unqualified / :: spelling working for load_gguf() below.
struct GGUFLoadResult {
    bool success = false;
    bool ok = false;  // alias for compatibility
    int mmapBound = 0;
    uint32_t shardCount = 0;
    uint64_t totalSize = 0;
    uint64_t dataOffset = 0;

    // --- Header facts, as declared by the file and as actually parsed ---------
    // ggufVersion and the two counts come from the primary shard's own header,
    // while metadataCount() reports the pairs really parsed.  A truncated or
    // mis-counted file is therefore caught by comparing them, not by trusting
    // the header.
    uint32_t ggufVersion = 0;         // 2 for every GGUF file in this tree
    uint32_t tensorCountHeader = 0;   // header-declared tensor count
    uint32_t metadataCountHeader = 0; // header-declared metadata-pair count
    bool hadMetadataCount = false;     // false when the header field was absent

    // --- Raw metadata key/values --------------------------------------------
    // Every scalar and string pair the loader parsed, flattened to its textual
    // form (ints and floats included), so arch-prefixed lookups and
    // string-valued keys such as tokenizer.chat_template have one source.
    // Keys the file did not declare are absent — never defaulted to 0.
    std::unordered_map<std::string, std::string> rawKv;

    std::shared_ptr<Deep2::GGUFLoader> loader;
    Deep2::ModelMetadata metadata;
    std::vector<Deep2::TensorInfo> tensors;
    std::string error;
    std::unique_ptr<void, void(*)(void*)> mmapKeep{nullptr, [](void*){}};
};

// ----------------------------------------------------------------------------
// GGUFLoader::tensorInfoList — declared in the class, defined here because
// TensorInfo only becomes complete at this point.
// ----------------------------------------------------------------------------
inline std::vector<TensorInfo> GGUFLoader::tensorInfoList() const {
    std::vector<TensorInfo> out;
    out.reserve(tensors_.size());
    for (const auto& kv : tensors_) {
        const GGUFTensor& t = kv.second;
        TensorInfo ti;
        ti.name = t.name;
        // GGUF stores dims as [row/col width, rows, ...]; TensorInfo carries
        // the same order, so copy directly (widening int64_t to uint64_t).
        ti.dimensions.assign(t.shape.begin(), t.shape.end());
        ti.type = static_cast<uint32_t>(t.type);
        ti.offset = t.tensorOffset;
        ti.size = t.sizeBytes;
        ti.dataOffset = t.fileOffset;
        ti.data = t.data;   // aliases the mapping; never owned here
        out.push_back(std::move(ti));
    }
    std::sort(out.begin(), out.end(), [](const TensorInfo& a, const TensorInfo& b) {
        return a.name < b.name;
    });
    return out;
}

// ----------------------------------------------------------------------------
// GGUFLoader::FreeTensorData — see the declaration in class GGUFLoader.
// Tensor payloads are mapping views, so nothing is released here; the shard
// mappings are released by the owning GGUFLoadResult / GGUFLoader::close().
// ----------------------------------------------------------------------------
inline bool GGUFLoader::FreeTensorData(const uint8_t* data) {
    if (data == nullptr) return true;   // nothing to release
    // The pointer aliases an open shard mapping owned elsewhere. Recognising it
    // as such and releasing nothing is the safe answer: closing a mapping here
    // would invalidate every other tensor that shares it.
    return true;
}

// ----------------------------------------------------------------------------
// GGUFLoader::Load — static convenience that fills a GGUFLoadResult.
//
// With options.loadTensors=false the returned result has loader == nullptr and
// mmapBound == 0: it carries the header facts, the tensor descriptors and the
// flattened key/value view only, and must not be used to read payloads.
// ----------------------------------------------------------------------------
inline GGUFLoadResult GGUFLoader::Load(const std::string& path,
                                     const GGUFLoadOptions& options) {
    GGUFLoadResult r;
    GGUFLoader loader;
    if (!loader.load(path, options)) {
        r.success = false;
        r.error = loader.error();
        return r;
    }
    r.success = true;
    r.ok = true;
    r.mmapBound = loader.metadataOnly() ? 0 : 1;
    r.shardCount = loader.shardCount();
    r.ggufVersion = loader.version();
    r.tensorCountHeader = static_cast<uint32_t>(loader.tensorCount());
    r.metadataCountHeader = loader.metadataCount();
    r.hadMetadataCount = true;
    r.tensors = loader.tensorInfoList();

    r.rawKv.reserve(r.rawKv.size() + static_cast<size_t>(loader.metadataCount()));
    for (const auto& kv : loader.metaInt())
        r.rawKv[kv.first] = std::to_string(kv.second);
    for (const auto& kv : loader.metaFloat())
        r.rawKv[kv.first] = [&] {
            char b[64];
            std::snprintf(b, sizeof b, "%.17g", kv.second);
            return std::string(b);
        }();
    for (const auto& kv : loader.metaString()) r.rawKv[kv.first] = kv.second;

    // Keep an owning handle only when payloads were actually mapped.  The loader
    // is non-copyable/non-movable, so it is heap-allocated and then opened.
    if (!loader.metadataOnly()) {
        auto owned = std::make_shared<GGUFLoader>();
        if (owned->load(path, options)) r.loader = owned;
    }

    FillMetadataFromRawKv(r.rawKv, r.metadata);
    return r;
}

// ----------------------------------------------------------------------------
// GGUFLoader::LoadMetadata — metadata-only open used by the authority and
// geometry seals.  See the declaration in class GGUFLoader.
//
// Deliberately does NOT map tensor payloads and does NOT retain the shards:
// the result carries header facts, tensor descriptors (names/types/dims) and
// every parsed key/value flattened to text.  `loader` stays null so no caller
// can dereference a mapping it does not own.
// ----------------------------------------------------------------------------
inline GGUFLoadResult GGUFLoader::LoadMetadata(const char* path) {
    GGUFLoadResult r;
    GGUFLoader loader;
    if (!path || !path[0]) {
        r.success = false;
        r.error = "empty GGUF path";
        return r;
    }
    if (!loader.load(path)) {
        r.success = false;
        r.error = loader.error();
        return r;
    }
    r.success = true;
    r.ok = true;
    r.mmapBound = 0;  // metadata-only: no payload mapped
    r.shardCount = loader.shardCount();
    r.ggufVersion = loader.version();
    r.tensorCountHeader = static_cast<uint32_t>(loader.tensorCount());
    r.metadataCountHeader = loader.metadataCount();
    r.hadMetadataCount = true;
    r.loader = nullptr;
    r.tensors = loader.tensorInfoList();

    // Flatten every parsed metadata pair to its textual form.  Keys the file
    // did not declare simply do not appear in rawKv.
    r.rawKv.reserve(r.rawKv.size() + static_cast<size_t>(loader.metadataCount()));
    for (const auto& kv : loader.metaInt())
        r.rawKv[kv.first] = std::to_string(kv.second);
    for (const auto& kv : loader.metaFloat())
        r.rawKv[kv.first] = [&] {
            char b[64];
            std::snprintf(b, sizeof b, "%.17g", kv.second);
            return std::string(b);
        }();
    for (const auto& kv : loader.metaString()) r.rawKv[kv.first] = kv.second;

    // Common metadata, read through the flattened map so that absent keys stay
    // absent instead of silently becoming 0.
    FillMetadataFromRawKv(r.rawKv, r.metadata);
    return r;
}

} // namespace Deep2

// Deep2::GGUFLoadResult is the authoritative type.  This alias keeps the
// historical unqualified / :: spelling working for load_gguf() below and for
// any caller that wrote GGUFLoadResult without a namespace qualifier.
using Deep2::GGUFLoadResult;

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

    // Header facts and the flattened key/value view, so the same result serves
    // the mapping path and the metadata-only seals alike.
    result->ggufVersion = result->loader->version();
    result->tensorCountHeader = static_cast<uint32_t>(result->loader->tensorCount());
    result->metadataCountHeader = result->loader->metadataCount();
    result->hadMetadataCount = true;
    result->rawKv.reserve(result->rawKv.size() +
                          static_cast<size_t>(result->loader->metadataCount()));
    for (const auto& kv : result->loader->metaInt())
        result->rawKv[kv.first] = std::to_string(kv.second);
    for (const auto& kv : result->loader->metaFloat())
        result->rawKv[kv.first] = [&] {
            char b[64];
            std::snprintf(b, sizeof b, "%.17g", kv.second);
            return std::string(b);
        }();
    for (const auto& kv : result->loader->metaString())
        result->rawKv[kv.first] = kv.second;

    // Populate metadata from GGUF metadata
    auto& meta = result->metadata;
    meta.name = result->loader->getMetaString("general.name", "");
    meta.chatTemplate = result->loader->getMetaString("tokenizer.chat_template", "");
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
            tensors.push_back(std::move(ti));
        }
    }

    return true;
}
