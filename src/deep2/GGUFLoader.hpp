// ============================================================================
// GGUFLoader.hpp - Zero-Dependency GGUF Parser for Deep2
// Reads GGUF format directly into Deep2 WeightTensor structures
// No external dependencies - pure C++ implementation
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <string>

namespace Deep2 {

// GGUF Magic number: "GGUF" in little-endian
constexpr uint32_t GGUF_MAGIC = 0x46554747;  // "GGUF"
constexpr uint32_t GGUF_VERSION = 3;         // Current version

// GGUF Value types
enum class GGUFValueType : uint32_t {
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
    FLOAT64 = 12
};

// GGML Quantization types (matching ggml.h)
enum class GGMLType : uint32_t {
    GGML_TYPE_F32  = 0,
    GGML_TYPE_F16  = 1,
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q4_1 = 3,
    GGML_TYPE_Q5_0 = 6,
    GGML_TYPE_Q5_1 = 7,
    GGML_TYPE_Q8_0 = 8,
    GGML_TYPE_Q8_K = 9,
    GGML_TYPE_Q2_K = 10,
    GGML_TYPE_Q3_K = 11,
    GGML_TYPE_Q4_K = 12,  // Q4_K_M
    GGML_TYPE_Q5_K = 13,
    GGML_TYPE_Q6_K = 14,
    GGML_TYPE_Q4_K_S = 15,  // Q4_K_S variant
    GGML_TYPE_Q8_K_R8 = 16,
    GGML_TYPE_IQ2_XXS = 17,
    GGML_TYPE_IQ2_XS  = 18,
    GGML_TYPE_IQ3_XXS = 19,
    GGML_TYPE_IQ1_S   = 20,
    GGML_TYPE_IQ4_NL  = 21,
    GGML_TYPE_IQ3_S   = 22,
    GGML_TYPE_IQ2_S   = 23,
    GGML_TYPE_IQ4_XS  = 24,
    GGML_TYPE_I8      = 25,
    GGML_TYPE_I16     = 26,
    GGML_TYPE_I32     = 27,
    GGML_TYPE_I64     = 28,
    GGML_TYPE_F64     = 29,
    GGML_TYPE_IQ1_M   = 30,
    GGML_TYPE_COUNT
};

// Q4_K_M block structure (256 weights per block)
struct alignas(32) Q4_K_M_Block {
    uint16_t scales[32];      // FP16 scales (64 bytes)
    uint16_t mins[32];        // FP16 mins (64 bytes)
    uint8_t  weights[128];    // 256 x 4-bit packed (128 bytes)
    // Total: 256 bytes for 256 weights = 4x compression vs FP32
};

// Tensor info from GGUF
struct TensorInfo {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> dimensions;
    uint64_t offset;          // Offset in file to tensor data
    uint64_t size;            // Size in bytes
    void* data = nullptr;     // Mapped/loaded data pointer
    
    // Convenience accessors
    size_t GetNumElements() const;
    size_t GetNumBlocks() const;  // For quantized types
    bool IsQuantized() const;
    size_t GetBlockSize() const;  // Bytes per block
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
    
    void Print() const;
};

// Loading options
struct GGUFLoadOptions {
    bool mmap = true;              // Use memory mapping (if available)
    bool verifyChecksum = false;   // Verify tensor checksums
    size_t maxMemoryMB = 0;        // 0 = unlimited
    bool loadTensors = true;       // Load tensor data (not just metadata)
    bool verbose = false;          // Print debug info
};

// Loading result
struct GGUFLoadResult {
    bool success = false;
    char error[256] = {0};
    ModelMetadata metadata;
    std::vector<TensorInfo> tensors;
    size_t totalSize = 0;
    double loadTimeMs = 0.0;
    
    // Get tensor by name
    const TensorInfo* GetTensor(const char* name) const;
    TensorInfo* GetTensor(const char* name);
    
    // Get tensor index by name
    int GetTensorIndex(const char* name) const;
};

// ============================================================================
// GGUFLoader - Zero-dependency GGUF parser
// ============================================================================
class GGUFLoader {
public:
    // Load GGUF file and parse metadata + tensor info
    // If loadTensors=true, also loads tensor data into memory
    static GGUFLoadResult Load(const char* filepath, const GGUFLoadOptions& options);
    
    // Load only metadata (fast, minimal memory)
    static GGUFLoadResult LoadMetadata(const char* filepath);
    
    // Convert GGML type to Deep2 WeightType
    static int ConvertType(GGMLType ggmlType);
    
    // Get type name
    static const char* GetTypeName(GGMLType type);
    
    // Calculate tensor size in bytes
    static size_t CalculateTensorSize(const TensorInfo& tensor);
    
    // Validate GGUF file (check magic, version)
    static bool ValidateFile(const char* filepath, char* error = nullptr);

private:
    // Internal parsing functions
    static bool ParseHeader(FILE* fp, uint64_t& tensorCount, uint64_t& kvCount);
    static bool ParseMetadata(FILE* fp, uint64_t kvCount, ModelMetadata& metadata);
    static bool ParseTensors(FILE* fp, uint64_t tensorCount, std::vector<TensorInfo>& tensors, 
                            uint64_t& dataOffset, bool verbose);
    static bool LoadTensorData(FILE* fp, std::vector<TensorInfo>& tensors, uint64_t dataOffset);
    
    // Value reading helpers
    static std::string ReadString(FILE* fp);
    static uint64_t ReadUint64(FILE* fp);
    static uint32_t ReadUint32(FILE* fp);
    static int32_t ReadInt32(FILE* fp);
    static float ReadFloat32(FILE* fp);
};

// ============================================================================
// Integration helpers for Deep2Engine
// ============================================================================

// Load GGUF and register all tensors with Deep2Engine
// Returns number of tensors registered, or -1 on error
int LoadGGUFIntoEngine(const char* filepath, Deep2Engine& engine, bool verbose = false);

// Load specific tensor by name pattern (e.g., "token_embd", "output_norm")
// Returns weight index in engine, or -1 on error
int LoadGGUFTensor(const char* filepath, const char* tensorName, Deep2Engine& engine);

} // namespace Deep2
