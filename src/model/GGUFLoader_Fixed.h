// ============================================================================
// GGUFLoader_Fixed.h - Production-Ready GGUF Parser Header
// ============================================================================
// Fixes alignment issues, adds validation, provides C API for integration
// ============================================================================

#pragma once

#include <cstdint.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <fstream>

namespace RawrXD {
namespace Model {

// GGUF type enumeration
enum class GGUFType : uint32_t {
    UINT8 = 0,
    INT8 = 1,
    UINT16 = 2,
    INT16 = 3,
    UINT32 = 4,
    INT32 = 5,
    FLOAT32 = 6,
    UINT64 = 7,
    INT64 = 8,
    FLOAT64 = 9,
    BOOL = 10,
    STRING = 11,
    ARRAY = 12,
    UINT128 = 13,
    INT128 = 14,
    // Quantized types
    Q4_0 = 32,
    Q4_1 = 33,
    Q5_0 = 34,
    Q5_1 = 35,
    Q8_0 = 36,
    Q8_1 = 37,
    Q2_K = 38,
    Q3_K = 39,
    Q4_K = 40,
    Q5_K = 41,
    Q6_K = 42,
    Q8_K = 43,
    IQ2_XXS = 44,
    IQ2_XS = 45,
    IQ3_XXS = 46,
    IQ3_S = 47,
    IQ4_XS = 48,
    IQ4_NL = 49,
    IQ5_K = 50,
    IQ6_K = 51,
    IQ8_K = 52,
    // Count
    COUNT = 53
};

// GGUF file header
#pragma pack(push, 1)
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t kv_count;
};
#pragma pack(pop)

// Maximum dimensions for a tensor
static constexpr uint32_t GGUF_MAX_DIMS = 4;
static constexpr uint64_t GGUF_MAX_STRING_LENGTH = 65536;

// Forward declarations
struct MetadataValue;

// Array value structure
struct ArrayValue {
    GGUFType type;
    std::vector<MetadataValue> values;
};

// Metadata value union
struct MetadataValue {
    GGUFType type;
    
    union {
        uint8_t u8;
        int8_t i8;
        uint16_t u16;
        int16_t i16;
        uint32_t u32;
        int32_t i32;
        float f32;
        uint64_t u64;
        int64_t i64;
        double f64;
        bool b;
    };
    
    std::string str;
    ArrayValue arr;
    
    MetadataValue() : type(GGUFType::UINT8), u8(0) {}
    ~MetadataValue() = default;
    
    // Move constructor and assignment
    MetadataValue(MetadataValue&& other) noexcept;
    MetadataValue& operator=(MetadataValue&& other) noexcept;
    
    // Disable copy
    MetadataValue(const MetadataValue&) = delete;
    MetadataValue& operator=(const MetadataValue&) = delete;
};

// Tensor info from GGUF header
struct TensorInfo {
    std::string name;
    std::vector<uint64_t> dims;
    GGUFType type;
    uint64_t offset;
    
    size_t CalculateSize() const;
    size_t GetTypeSize() const;
};

// Loaded tensor with data
struct Tensor {
    std::string name;
    GGUFType type;
    std::vector<uint64_t> dims;
    void* data;
    size_t size;
    size_t offset;
    
    Tensor() : type(GGUFType::UINT8), data(nullptr), size(0), offset(0) {}
    ~Tensor() = default;
    
    // Disable copy, enable move
    Tensor(const Tensor&) = delete;
    Tensor& operator=(const Tensor&) = delete;
    Tensor(Tensor&&) noexcept = default;
    Tensor& operator=(Tensor&&) noexcept = default;
};

// Complete GGUF model
struct GGUFModel {
    std::string name;
    std::string architecture;
    uint32_t contextSize = 0;
    uint32_t embeddingDim = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t vocabSize = 0;
    size_t totalSize = 0;
    
    std::unordered_map<std::string, MetadataValue> metadata;
    std::vector<TensorInfo> tensors;
};

// Production-ready GGUF loader
class GGUFLoader {
public:
    GGUFLoader();
    ~GGUFLoader();
    
    // Load a GGUF file
    bool Load(const std::string& path, GGUFModel& model);
    
    // Unload and free memory
    void Unload();
    
    // Check if loaded
    bool IsLoaded() const;
    
    // Get tensor by name
    const Tensor* GetTensor(const std::string& name) const;
    
    // Get all tensor names
    std::vector<std::string> GetTensorNames() const;
    
    // Get loaded model info
    const GGUFModel& GetModelInfo() const { return loadedModel_; }

private:
    GGUFModel loadedModel_;
    std::vector<Tensor> loadedTensors_;
    std::unordered_map<std::string, size_t> tensorMap_;
    
    // Reading helpers
    bool ReadStruct(std::ifstream& file, GGUFHeader& header);
    bool ReadMetadata(std::ifstream& file, uint64_t count, 
                      std::unordered_map<std::string, MetadataValue>& metadata);
    bool ReadTensorInfo(std::ifstream& file, uint64_t count, 
                        std::vector<TensorInfo>& tensors);
    bool ReadTensorData(std::ifstream& file, size_t tensorDataOffset, 
                        GGUFModel& model);
    
    std::string ReadString(std::ifstream& file);
    
    template<typename T>
    bool ReadValue(std::ifstream& file, T& value);
    
    bool ReadValueByType(std::ifstream& file, GGUFType type, MetadataValue& value);
    
    size_t CalculateTensorDataOffset(std::streampos currentPos);
    size_t AlignOffset(size_t offset, size_t alignment);
    
    void ExtractModelInfo(GGUFModel& model);
    std::string ValueToString(const MetadataValue& value);
};

// C API for integration
extern "C" {
    void* GGUFLoader_Create();
    void GGUFLoader_Destroy(void* loader);
    int GGUFLoader_Load(void* loader, const char* path);
    void GGUFLoader_Unload(void* loader);
    int GGUFLoader_IsLoaded(void* loader);
    const char* GGUFLoader_GetArchitecture(void* loader);
}

} // namespace Model
} // namespace RawrXD
