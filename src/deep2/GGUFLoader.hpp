// ============================================================================
// GGUFLoader.hpp - Zero-Dependency GGUF Parser for Deep2
// Reads GGUF format directly into Deep2 WeightTensor structures
// No external dependencies - pure C++ implementation
// ============================================================================

#pragma once

#include "UniversalTensorDescriptor.hpp"
#include "QuantTypeTable.hpp"
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

// GGMLType + QuantTypeDescriptor live in QuantTypeTable.hpp (canonical IDs).

// Quantization block structures — layouts MUST match ggml-common.h sizes.
#pragma pack(push, 1)
struct block_q4_0 { uint16_t d; uint8_t qs[16]; }; // 18 bytes, 32 elements
struct block_q4_1 { uint16_t d; uint16_t m; uint8_t qs[16]; }; // 20 bytes
struct block_q5_0 { uint16_t d; uint8_t qh[4]; uint8_t qs[16]; }; // 22 bytes
struct block_q5_1 { uint16_t d; uint16_t m; uint8_t qh[4]; uint8_t qs[16]; }; // 24 bytes
struct block_q8_0 { uint16_t d; int8_t qs[32]; }; // 34 bytes
struct block_q8_1 { uint16_t d; uint16_t s; int8_t qs[32]; }; // 36 bytes
struct block_q2_K { uint16_t d; uint16_t dmin; uint8_t scales[16]; uint8_t qs[64]; }; // 84 bytes
struct block_q3_K { uint8_t hmask[32]; uint8_t qs[64]; uint8_t scales[12]; uint16_t d; }; // 110 bytes
struct block_q4_K { uint16_t d; uint16_t dmin; uint8_t scales[12]; uint8_t qs[128]; }; // 144 bytes, 256 elements
struct block_q5_K { uint16_t d; uint16_t dmin; uint8_t scales[12]; uint8_t qh[32]; uint8_t qs[128]; }; // 176 bytes
struct block_q6_K { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; }; // 210 bytes
struct block_q8_K { float d; int8_t qs[256]; int16_t bsums[16]; }; // 292 bytes
// IQ / modern formats (canonical ggml sizes)
struct block_iq2_xxs { uint16_t d; uint8_t qs[64]; }; // 66 bytes (== ggml uint16 qs[32])
struct block_iq2_xs  { uint16_t d; uint8_t qs[64]; uint8_t scales[8]; }; // 74 bytes
struct block_iq2_s   { uint16_t d; uint8_t qs[64]; uint8_t qh[8]; uint8_t scales[8]; }; // 82 bytes
struct block_iq3_xxs { uint16_t d; uint8_t qs[96]; }; // 98 bytes
struct block_iq3_s   { uint16_t d; uint8_t qs[64]; uint8_t qh[8]; uint8_t signs[32]; uint8_t scales[4]; }; // 110
struct block_iq1_s   { uint16_t d; uint8_t qs[32]; uint16_t qh[8]; }; // 50 bytes, 256 elems
struct block_iq1_m   { uint8_t qs[32]; uint8_t qh[16]; uint8_t scales[8]; }; // 56 bytes
struct block_iq4_nl  { uint16_t d; uint8_t qs[16]; }; // 18 bytes, 32 elems (NOT 132/256)
struct block_iq4_xs  {
    uint16_t d;
    union {
        struct { uint16_t scales_h; uint8_t scales_l[4]; };
        uint8_t scales[6]; // legacy kernel access (same 6 bytes)
    };
    uint8_t qs[128];
}; // 136 bytes
struct block_tq1_0   { uint8_t qs[48]; uint8_t qh[4]; uint16_t d; }; // 54 bytes
struct block_tq2_0   { uint8_t qs[64]; uint16_t d; }; // 66 bytes
struct block_mxfp4   { uint8_t e; uint8_t qs[16]; }; // 17 bytes, 32 elems
struct block_nvfp4   { uint8_t d[4]; uint8_t qs[32]; }; // 36 bytes, 64 elems
struct block_q1_0    { uint16_t d; uint8_t qs[16]; }; // 18 bytes, 128 elems
struct block_bf16    { uint16_t bits; }; // 2 bytes, 1 elem
#pragma pack(pop)

static_assert(sizeof(block_q4_0) == 18, "q4_0");
static_assert(sizeof(block_q4_1) == 20, "q4_1");
static_assert(sizeof(block_q5_0) == 22, "q5_0");
static_assert(sizeof(block_q5_1) == 24, "q5_1");
static_assert(sizeof(block_q8_0) == 34, "q8_0");
static_assert(sizeof(block_q8_1) == 36, "q8_1");
static_assert(sizeof(block_q2_K) == 84, "q2_K");
static_assert(sizeof(block_q3_K) == 110, "q3_K");
static_assert(sizeof(block_q4_K) == 144, "q4_K");
static_assert(sizeof(block_q5_K) == 176, "q5_K");
static_assert(sizeof(block_q6_K) == 210, "q6_K");
static_assert(sizeof(block_q8_K) == 292, "q8_K MUST be 292 not 29");
static_assert(sizeof(block_iq2_xxs) == 66, "iq2_xxs");
static_assert(sizeof(block_iq2_xs) == 74, "iq2_xs");
static_assert(sizeof(block_iq2_s) == 82, "iq2_s");
static_assert(sizeof(block_iq3_xxs) == 98, "iq3_xxs");
static_assert(sizeof(block_iq3_s) == 110, "iq3_s");
static_assert(sizeof(block_iq1_s) == 50, "iq1_s MUST be 50 not 34");
static_assert(sizeof(block_iq1_m) == 56, "iq1_m");
static_assert(sizeof(block_iq4_nl) == 18, "iq4_nl MUST be 18 not 132");
static_assert(sizeof(block_iq4_xs) == 136, "iq4_xs");
static_assert(sizeof(block_tq1_0) == 54, "tq1_0");
static_assert(sizeof(block_tq2_0) == 66, "tq2_0");
static_assert(sizeof(block_mxfp4) == 17, "mxfp4");
static_assert(sizeof(block_nvfp4) == 36, "nvfp4");
static_assert(sizeof(block_q1_0) == 18, "q1_0");

// Block sizes (elements per block) — prefer QuantTypeTable; kept for call sites.
constexpr size_t QK4_0 = 32;
constexpr size_t QK4_1 = 32;
constexpr size_t QK5_0 = 32;
constexpr size_t QK5_1 = 32;
constexpr size_t QK8_0 = 32;
constexpr size_t QK8_1 = 32;
constexpr size_t QK_K  = 256;
constexpr size_t QK4_NL = 32;

// Q4_K_M block (DEPRECATED — use block_q4_K from GGUF spec, 144 bytes)
// Kept for backward compatibility with legacy test code only.
// New code should use block_q4_K directly.
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
        size_t elemsPerBlock = GetElemsPerBlock();
        if (elemsPerBlock == 0) return 0;
        return (GetNumElements() + elemsPerBlock - 1) / elemsPerBlock;
    }

    bool IsQuantized() const {
        return QuantTypeIsQuantized(static_cast<uint32_t>(type));
    }

    // Authoritative: QuantTypeTable. Returns 0 for unknown → fail-closed (no silent {4,1}).
    size_t GetBlockSize() const {
        return QuantTypeBlockBytes(static_cast<uint32_t>(type));
    }

    size_t GetElemsPerBlock() const {
        return QuantTypeBlockElements(static_cast<uint32_t>(type));
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

    // MLA / DeepSeek2 metadata (real, parsed from GGUF)
    uint32_t leadingDenseBlockCount = 0;
    uint32_t qLoraRank = 0;
    uint32_t kvLoraRank = 0;
    uint32_t keyLength = 0;
    uint32_t valueLength = 0;
    uint32_t keyLengthMla = 0;
    uint32_t valueLengthMla = 0;
    uint32_t ropeDimensionCount = 0;

    // Tokenizer vocabulary (extracted from tokenizer.ggml.tokens)
    std::vector<std::string> vocab;
    
    // Chat template for instruction-tuned models (e.g. Llama-3, Qwen, etc.)
    std::string chatTemplate;
    std::string bosToken = "<s>";
    std::string eosToken = "</s>";
    std::string unkToken = "<unk>";

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
        if (qLoraRank > 0 || kvLoraRank > 0) {
            printf("[GGUF] MLA: qLoraRank=%u kvLoraRank=%u keyLength=%u valueLength=%u\n",
                   qLoraRank, kvLoraRank, keyLength, valueLength);
            printf("[GGUF] MLA: keyLengthMla=%u valueLengthMla=%u ropeDim=%u\n",
                   keyLengthMla, valueLengthMla, ropeDimensionCount);
        }
        if (leadingDenseBlockCount > 0) {
            printf("[GGUF] Leading dense blocks: %u\n", leadingDenseBlockCount);
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
    uint64_t dataOffset = 0;  // Absolute byte offset to tensor data section in file

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
    static RawrXD::QuantType ConvertGGMLType(GGMLType ggmlType);
    static size_t CalculateTensorSize(const TensorInfo& tensor);
    static bool ValidateFile(const char* filepath, char* error = nullptr);

    // Hardened version with page fault fixes
    static GGUFLoadResult LoadHardened(const char* filepath, const GGUFLoadOptions& options);

    // Public parsing entry points for IOCP-based streaming loaders
    static bool ParseHeader(FILE* fp, uint64_t& tensorCount, uint64_t& kvCount);
    static bool ParseMetadataKV(FILE* fp, uint64_t kvCount, ModelMetadata& metadata,
                                std::unordered_map<std::string, std::string>& rawMeta);
    static bool ParseTensors(FILE* fp, uint64_t tensorCount,
                             std::vector<TensorInfo>& tensors,
                             uint64_t& dataOffset, bool verbose);

    // Release VirtualAlloc / aligned tensor buffers owned by GGUFLoadResult.
    static void FreeTensorData(void* data);

private:
    static bool LoadTensorData(FILE* fp, std::vector<TensorInfo>& tensors,
                               uint64_t dataOffset, uint64_t fileSize);

    // Extended validation returning file size and data offset (for diagnostics)
    static bool ValidateFile(const char* filepath, uint64_t& outFileSize, uint64_t& outDataOffset);

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
