// ============================================================================
// GGUFLoader.hpp - Zero-Dependency GGUF Parser for Deep2
// Reads GGUF format directly into Deep2 WeightTensor structures
// No external dependencies - pure C++ implementation
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <algorithm>

namespace Deep2 {

// GGUF Magic number: "GGUF" in little-endian
constexpr uint32_t GGUF_MAGIC = 0x46554747;
constexpr uint32_t GGUF_VERSION = 3;
constexpr int GGUF_MAX_DIMS = 4;  // Maximum tensor dimensions supported

// GGUF Value types
enum class GGUFValueType : uint32_t {
    UINT8   = 0, INT8 = 1, UINT16 = 2, INT16 = 3,
    UINT32  = 4, INT32 = 5, FLOAT32 = 6, BOOL = 7,
    STRING  = 8, ARRAY = 9, UINT64 = 10, INT64 = 11, FLOAT64 = 12
};

// GGML Quantization types
enum class GGMLType : uint32_t {
    GGML_TYPE_F32 = 0, GGML_TYPE_F16 = 1,
    GGML_TYPE_Q4_0 = 2, GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6, GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8, GGML_TYPE_Q8_K = 9,
    GGML_TYPE_Q2_K = 10, GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12, GGML_TYPE_Q5_K = 13, GGML_TYPE_Q6_K = 14,
    GGML_TYPE_IQ2_XXS = 17, GGML_TYPE_IQ2_XS = 18,
    GGML_TYPE_IQ3_XXS = 19, GGML_TYPE_IQ1_S = 20,
    GGML_TYPE_IQ4_NL = 21, GGML_TYPE_IQ3_S = 22,
    GGML_TYPE_IQ2_S = 23, GGML_TYPE_IQ4_XS = 24,
    GGML_TYPE_I8 = 25, GGML_TYPE_I16 = 26,
    GGML_TYPE_I32 = 27, GGML_TYPE_I64 = 28, GGML_TYPE_F64 = 29,
    GGML_TYPE_COUNT
};

// Quantization block structures
#pragma pack(push, 1)
struct block_q4_0 { uint16_t d; uint8_t qs[16]; }; // 18 bytes, 32 elements
struct block_q4_1 { uint16_t d; uint16_t m; uint8_t qs[16]; }; // 20 bytes
struct block_q5_0 { uint16_t d; uint8_t qh[4]; uint8_t qs[16]; }; // 22 bytes
struct block_q5_1 { uint16_t d; uint16_t m; uint8_t qh[4]; uint8_t qs[16]; }; // 24 bytes
struct block_q8_0 { uint16_t d; int8_t qs[32]; }; // 34 bytes
struct block_q8_1 { uint16_t d; uint16_t s; int8_t qs[32]; }; // 36 bytes
struct block_q2_K { uint8_t scales[16]; uint8_t qs[64]; uint16_t d; uint16_t dmin; }; // 84 bytes
struct block_q3_K { uint8_t hmask[32]; uint8_t qs[64]; uint16_t d; }; // 98 bytes
struct block_q4_K { uint16_t d; uint16_t dmin; uint8_t scales[12]; uint8_t qs[128]; }; // 144 bytes, 256 elements
struct block_q5_K { uint16_t d; uint8_t qh[32]; uint8_t qs[128]; }; // 162 bytes
struct block_q6_K { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; }; // 210 bytes
struct block_q8_K { float d; float s; int8_t qs[256]; }; // 264 bytes
#pragma pack(pop)
struct block_iq2_xxs { uint16_t d; uint8_t qs[64]; }; // 66 bytes, 256 elements
struct block_iq2_xs  { uint16_t d; uint16_t scales[2]; uint8_t qs[68]; }; // 74 bytes, 256 elements
struct block_iq2_s   { uint16_t d; uint8_t scales[8]; uint8_t qs[72]; }; // 82 bytes, 256 elements
struct block_iq3_xxs { uint16_t d; uint8_t qs[96]; }; // 98 bytes, 256 elements
struct block_iq3_s   { uint16_t d; uint8_t scales[8]; uint8_t qs[100]; }; // 110 bytes, 256 elements
struct block_iq4_nl  { uint16_t d; uint16_t dmin; uint8_t qs[128]; }; // 132 bytes, 256 elements
struct block_iq4_xs  { uint16_t d; uint8_t scales[6]; uint8_t qs[128]; }; // 136 bytes, 256 elements
struct block_iq1_s   { uint8_t qs[32]; uint16_t d; }; // 184 bytes

// Block sizes (elements per block)
constexpr size_t QK4_0 = 32;
constexpr size_t QK4_1 = 32;
constexpr size_t QK5_0 = 32;
constexpr size_t QK5_1 = 32;
constexpr size_t QK8_0 = 32;
constexpr size_t QK8_1 = 32;
constexpr size_t QK_K  = 256;
constexpr size_t QK4_NL = 32;

// Q4_K_M block (alias for q4_K)
struct alignas(32) Q4_K_M_Block {
    uint16_t scales[32];
    uint16_t mins[32];
    uint8_t  weights[128];
};

// Tensor info from GGUF
struct TensorInfo {
    std::string name;
    GGMLType type = GGMLType::GGML_TYPE_F32;
    std::vector<uint64_t> dimensions;
    uint64_t offset = 0;
    uint64_t size = 0;
    void* data = nullptr;

    size_t GetNumElements() const {
        if (dimensions.empty()) return 0;
        size_t n = 1;
        for (auto d : dimensions) n *= d;
        return n;
    }

    size_t GetNumBlocks() const {
        size_t blockSize = GetBlockSize();
        size_t elemsPerBlock = GetElemsPerBlock();
        if (elemsPerBlock == 0) return 0;
        return (GetNumElements() + elemsPerBlock - 1) / elemsPerBlock;
    }

    bool IsQuantized() const {
        return type != GGMLType::GGML_TYPE_F32 &&
               type != GGMLType::GGML_TYPE_F16 &&
               type != GGMLType::GGML_TYPE_I8 &&
               type != GGMLType::GGML_TYPE_I16 &&
               type != GGMLType::GGML_TYPE_I32 &&
               type != GGMLType::GGML_TYPE_I64 &&
               type != GGMLType::GGML_TYPE_F64;
    }

    size_t GetBlockSize() const {
        switch (type) {
            case GGMLType::GGML_TYPE_F32: return 4;
            case GGMLType::GGML_TYPE_F16: return 2;
            case GGMLType::GGML_TYPE_Q4_0: return sizeof(block_q4_0);
            case GGMLType::GGML_TYPE_Q4_1: return sizeof(block_q4_1);
            case GGMLType::GGML_TYPE_Q5_0: return sizeof(block_q5_0);
            case GGMLType::GGML_TYPE_Q5_1: return sizeof(block_q5_1);
            case GGMLType::GGML_TYPE_Q8_0: return sizeof(block_q8_0);
            case GGMLType::GGML_TYPE_Q8_K: return sizeof(block_q8_K);
            case GGMLType::GGML_TYPE_Q2_K: return sizeof(block_q2_K);
            case GGMLType::GGML_TYPE_Q3_K: return sizeof(block_q3_K);
            case GGMLType::GGML_TYPE_Q4_K: return sizeof(block_q4_K);
            case GGMLType::GGML_TYPE_Q5_K: return sizeof(block_q5_K);
            case GGMLType::GGML_TYPE_Q6_K: return sizeof(block_q6_K);
            default: return 4;
        }
    }

    size_t GetElemsPerBlock() const {
        switch (type) {
            case GGMLType::GGML_TYPE_F32:
            case GGMLType::GGML_TYPE_F16:
            case GGMLType::GGML_TYPE_I8:
            case GGMLType::GGML_TYPE_I16:
            case GGMLType::GGML_TYPE_I32:
            case GGMLType::GGML_TYPE_I64:
            case GGMLType::GGML_TYPE_F64:
                return 1;
            case GGMLType::GGML_TYPE_Q4_0: return QK4_0;
            case GGMLType::GGML_TYPE_Q4_1: return QK4_1;
            case GGMLType::GGML_TYPE_Q5_0: return QK5_0;
            case GGMLType::GGML_TYPE_Q5_1: return QK5_1;
            case GGMLType::GGML_TYPE_Q8_0: return QK8_0;
            case GGMLType::GGML_TYPE_Q8_K: return QK_K;
            case GGMLType::GGML_TYPE_Q2_K: return QK_K;
            case GGMLType::GGML_TYPE_Q3_K: return QK_K;
            case GGMLType::GGML_TYPE_Q4_K: return QK_K;
            case GGMLType::GGML_TYPE_Q5_K: return QK_K;
            case GGMLType::GGML_TYPE_Q6_K: return QK_K;
            default: return 1;
        }
    }
};

// Model metadata from GGUF
struct ModelMetadata {
    std::string architecture;
    uint32_t vocabSize = 0;
    uint32_t hiddenSize = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKeyValueHeads = 0;
    uint32_t intermediateSize = 0;
    float rmsNormEps = 1e-6f;
    uint32_t maxPositionEmbeddings = 0;
    float ropeTheta = 10000.0f;
    
    // MoE metadata (real, parsed from GGUF)
    uint32_t numExperts = 0;
    uint32_t numExpertsPerToken = 0;  // top-k
    uint32_t numSharedExperts = 0;
    uint32_t moeIntermediateSize = 0;
    float ropeScaling = 1.0f;

    void Print() const {
        printf("[GGUF] Architecture: %s\n", architecture.c_str());
        printf("[GGUF] Vocab: %u, Hidden: %u, Layers: %u, Heads: %u\n",
               vocabSize, hiddenSize, numLayers, numHeads);
        printf("[GGUF] KV Heads: %u, Intermediate: %u\n",
               numKeyValueHeads, intermediateSize);
        if (numExperts > 0) {
            printf("[GGUF] MoE: experts=%u topK=%u shared=%u moeInter=%u\n",
                   numExperts, numExpertsPerToken, numSharedExperts,
                   moeIntermediateSize);
        }
    }
};

// Loading options
struct GGUFLoadOptions {
    bool mmap = true;
    bool verifyChecksum = false;
    size_t maxMemoryMB = 0;
    bool loadTensors = true;
    bool verbose = false;
};

// Loading result
struct GGUFLoadResult {
    bool success = false;
    char error[256] = {0};
    ModelMetadata metadata;
    std::vector<TensorInfo> tensors;
    size_t totalSize = 0;
    double loadTimeMs = 0.0;

    const TensorInfo* GetTensor(const char* name) const {
        for (const auto& t : tensors) {
            if (t.name == name) return &t;
        }
        return nullptr;
    }

    TensorInfo* GetTensor(const char* name) {
        for (auto& t : tensors) {
            if (t.name == name) return &t;
        }
        return nullptr;
    }

    int GetTensorIndex(const char* name) const {
        for (size_t i = 0; i < tensors.size(); ++i) {
            if (tensors[i].name == name) return (int)i;
        }
        return -1;
    }
};

// ============================================================================
// GGUFLoader - Zero-dependency GGUF parser
// ============================================================================
class GGUFLoader {
public:
    static GGUFLoadResult Load(const char* filepath, const GGUFLoadOptions& options);
    static GGUFLoadResult LoadMetadata(const char* filepath);
    static int ConvertType(GGMLType ggmlType);
    static const char* GetTypeName(GGMLType type);
    static size_t CalculateTensorSize(const TensorInfo& tensor);
    static bool ValidateFile(const char* filepath, char* error = nullptr);
    
    // Hardened version with page fault fixes
    static GGUFLoadResult LoadHardened(const char* filepath, const GGUFLoadOptions& options);

private:
    static bool ParseHeader(FILE* fp, uint64_t& tensorCount, uint64_t& kvCount);
    static bool ParseMetadataKV(FILE* fp, uint64_t kvCount, ModelMetadata& metadata,
                                std::unordered_map<std::string, std::string>& rawMeta);
    static bool ParseTensors(FILE* fp, uint64_t tensorCount,
                             std::vector<TensorInfo>& tensors,
                             uint64_t& dataOffset, bool verbose);
    static bool LoadTensorData(FILE* fp, std::vector<TensorInfo>& tensors,
                               uint64_t dataOffset, uint64_t fileSize);

    // Validation
    static bool ValidateFile(const char* filepath, uint64_t& outFileSize, uint64_t& outDataOffset);

    // Memory management
    static void FreeTensorData(void* data);

    static std::string ReadString(FILE* fp);
    static uint64_t ReadUint64(FILE* fp);
    static uint32_t ReadUint32(FILE* fp);
    static int32_t ReadInt32(FILE* fp);
    static float ReadFloat32(FILE* fp);
    static uint16_t ReadUint16(FILE* fp);
    static int16_t ReadInt16(FILE* fp);
    static uint8_t ReadUint8(FILE* fp);
    static int8_t ReadInt8(FILE* fp);
    static double ReadFloat64(FILE* fp);
    static bool ReadBool(FILE* fp);
};

// Forward declaration
class Deep2Engine;

// Integration helpers
int LoadGGUFIntoEngine(const char* filepath, Deep2Engine& engine, bool verbose = false);
int LoadGGUFTensor(const char* filepath, const char* tensorName, Deep2Engine& engine);

} // namespace Deep2
