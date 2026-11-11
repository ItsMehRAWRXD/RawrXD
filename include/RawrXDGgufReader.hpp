#pragma once
// RawrXDGgufReader.hpp
// RAWRXD_GGUF_UNIVERSAL_READER_001
//
// Dependency-free generic GGUF reader. Any file whose first four bytes are
// "GGUF" can be opened, regardless of which architecture produced it.
//
// The reader deliberately knows nothing about any specific model. It parses
// the header, the metadata key/value block and the tensor directory, and
// resolves a tensor's role from its name. Architecture-specific build plans
// are the caller's job; this exists so that no architecture has to special
// case the file format.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace rawrxd {

enum class GgufType : int32_t {
    U8 = 0, I8 = 1, U16 = 2, I16 = 3, U32 = 4, I32 = 5, F32 = 6, BOOL = 7,
    STRING = 8, ARRAY = 9, U64 = 10, I64 = 11, F64 = 12
};

// ggml type ids as they appear in GGUF. Ids not in the specification are
// reported as UNKNOWN so a novel dtype is surfaced rather than mis-read.
enum class GgmlType : int32_t {
    F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3, Q5_0 = 6, Q5_1 = 7, Q8_0 = 8,
    Q8_1 = 9, Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13, Q6_K = 14,
    Q8_K = 15, IQ2_XXS = 16, IQ2_XS = 17, IQ3_XXS = 18, IQ1_S = 19,
    IQ4_NL = 20, IQ3_S = 21, IQ2_S = 22, IQ4_XS = 23, I8 = 24, I16 = 25,
    I32 = 26, I64 = 27, F64 = 28, BF16 = 30, MXFP4 = 39
};

const char* GgmlTypeName(int32_t t);
size_t      GgmlTypeSize(int32_t t);          // 0 for unknown/block-quantised

struct GgufTensor {
    std::string          name;
    std::vector<int64_t> dims;      // ggml order: ne[0] is the fastest axis
    int32_t              type = -1; // raw ggml type id
    uint64_t             offset = 0;
    uint64_t             abs_offset = 0;   // absolute file offset
    uint64_t             nbytes = 0;

    int64_t ne0() const { return dims.empty() ? 0 : dims[0]; }
    int64_t ne1() const { return dims.size() > 1 ? dims[1] : 1; }
    int64_t ne2() const { return dims.size() > 2 ? dims[2] : 1; }
    int64_t ne3() const { return dims.size() > 3 ? dims[3] : 1; }
    int64_t nelements() const {
        int64_t n = 1;
        for (int64_t d : dims) n *= d;
        return n;
    }
};

// A tensor's job in a transformer. The mapping is name-based and independent
// of any architecture, so an unknown tensor still reports UNKNOWN rather than
// being silently dropped.
enum class Role {
    NONE, TOKEN_EMB, OUTPUT_NORM, OUTPUT, Q_CUR, K_CUR, V_CUR, QKV_CUR,
    FFN_GATE, FFN_UP, FFN_DOWN, MOE_ROUTER, MOE_GATE_INP, MOE_EXPERT_GWUP,
    MOE_EXPERT_DOWN, MOE_SHARED_GWUP, MOE_SHARED_DOWN, MOE_EXP_PROBS,
    ATTN_NORM, FFN_NORM, SSM_CONV1D, SSM_IN, SSM_OUT, SSM_A, SSM_D, SSM_DT_BIAS,
    SSM_NORM, MLA_WQ_A, MLA_WQ_B, MLA_WKV_A, MLA_WKV_B, MLA_WO,
    ROPE_CACHE, OUTPUT_BIAS, UNKNOWN
};

const char* RoleName(Role r);

class GgufReader {
public:
    GgufReader() = default;
    ~GgufReader();

    GgufReader(const GgufReader&) = delete;
    GgufReader& operator=(const GgufReader&) = delete;

    // Opens and parses. Returns false and leaves why() populated on failure.
    bool Open(const char* path);
    void Close();

    const std::string& why() const { return why_; }

    uint32_t version() const { return version_; }
    uint64_t tensorCount() const { return tensors_.size(); }
    uint64_t dataStart() const { return data_start_; }
    uint64_t fileSize() const { return file_size_; }

    // Metadata access by exact key.
    bool        hasKey(const char* key) const;
    bool        getU64(const char* key, uint64_t& out) const;
    bool        getF32(const char* key, float& out) const;
    bool        getBool(const char* key, bool& out) const;
    bool        getString(const char* key, std::string& out) const;
    // Typed accessor that also resolves the architecture prefix: for the
    // architecture in the file, "<arch>.block_count" resolves as "block_count".
    bool        getArchU64(const char* leaf, uint64_t& out) const;
    bool        getArchF32(const char* leaf, float& out) const;
    std::string architecture() const;

    const std::map<std::string, GgufTensor>& tensors() const { return tensors_; }
    const GgufTensor* find(const char* name) const;

    // Every tensor whose name matches blk.<N>.* (suffix without the prefix).
    void layerTensors(int blockIndex, std::vector<const GgufTensor*>& out,
                      const char* suffix) const;

    // Distinct block indices present in the tensor directory.
    void blockIndices(std::vector<int>& out) const;

    // True if the file contains SSM (Mamba2) tensors, attention tensors and
    // MoE tensors. Used by a caller to pick a block plan without hardcoding.
    bool hasSsm() const;
    bool hasAttention() const;
    bool hasMoe() const;

    // Reads a tensor's raw bytes into dst. dstBytes must be at least
    // nbytes(). Returns false with why() set on any failure.
    bool readRaw(const GgufTensor& t, void* dst, size_t dstBytes);

    // Convenience: F32 read of a tensor with every element converted from its
    // stored dtype where the type is known. Unsupported quantised types are
    // left as zeros and why() is set, rather than mis-interpreted.
    bool readF32(const GgufTensor& t, std::vector<float>& out);

private:
    bool        readExact(void* p, size_t n);
    bool        parseValue(int32_t type, std::string& key);
    static std::string normalizeName(const std::string& n);

    FILE*       fp_ = nullptr;
    std::string why_;
    std::string path_;
    uint32_t    version_ = 0;
    uint64_t    data_start_ = 0;
    uint64_t    file_size_ = 0;
    std::string arch_;

    struct Value {
        int32_t               type = 0;
        uint64_t              u = 0;
        double                f = 0;
        bool                  b = false;
        std::string           s;
    };
    std::map<std::string, Value> meta_;
    std::map<std::string, GgufTensor> tensors_;
};

} // namespace rawrxd
