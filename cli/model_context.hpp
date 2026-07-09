#pragma once
// ============================================================================
// ModelContext — Immutable model state with GGUF tensor registry
// ============================================================================
// Owns: GGUF metadata, tensor descriptors, tokenizer vocabulary
// Does NOT own: execution state, KV cache, temporary tensors
// ============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <cstdint>
#include <string>

// Forward declaration for TensorView
namespace RawrXD {
namespace CLI {
struct TensorView;
}
}

namespace RawrXD {
namespace CLI {

// Tensor data type enumeration
enum class TensorType {
    F32,    // 32-bit float
    F16,    // 16-bit float  
    Q4_0,   // 4-bit quantized (32 elements per block)
    Q4_1,   // 4-bit quantized with bias
    Q5_0,   // 5-bit quantized
    Q5_1,   // 5-bit quantized with bias
    Q8_0,   // 8-bit quantized (32 elements per block)
    Q8_1,   // 8-bit quantized with bias
    Q2_K,   // 2-bit K-quant
    Q3_K,   // 3-bit K-quant
    Q4_K,   // 4-bit K-quant
    Q5_K,   // 5-bit K-quant
    Q6_K,   // 6-bit K-quant
    Q8_K,   // 8-bit K-quant
    I8,     // 8-bit integer
    I16,    // 16-bit integer
    I32,    // 32-bit integer
    COUNT
};

// Tensor shape/dimensions
struct TensorShape {
    std::vector<uint64_t> dimensions;
    
    uint64_t NumElements() const {
        uint64_t n = 1;
        for (auto dim : dimensions) n *= dim;
        return n;
    }
    
    uint64_t operator[](size_t idx) const {
        return idx < dimensions.size() ? dimensions[idx] : 1;
    }
};

// Tensor entry in registry (metadata only, not the actual data)
struct TensorEntry {
    std::string name;
    TensorType type;
    TensorShape shape;
    uint64_t offset;        // Offset in GGUF file
    uint64_t size;          // Size in bytes
    
    bool IsValid() const { return !name.empty() && size > 0; }
    
    // Calculate element size based on type
    size_t ElementSize() const;
    
    // Total number of elements
    uint64_t NumElements() const { return shape.NumElements(); }
};

// GGUF metadata value (variant type)
struct MetadataValue {
    enum class Type {
        UINT32,
        INT32,
        FLOAT32,
        STRING,
        ARRAY,
        UINT64,
        INT64,
        FLOAT64,
        BOOL
    };
    
    Type type;
    union {
        uint32_t u32;
        int32_t i32;
        float f32;
        uint64_t u64;
        int64_t i64;
        double f64;
        bool b;
    } value;
    std::string str;  // For STRING type
    std::vector<MetadataValue> array;  // For ARRAY type
    
    MetadataValue() : type(Type::UINT32), value{0} {}
};

// Model architecture parameters (extracted from GGUF metadata)
struct ModelArchitecture {
    std::string name;           // e.g., "phi3-mini"
    std::string architecture;   // e.g., "phi3", "llama"
    uint32_t vocabSize = 32000;
    uint32_t hiddenSize = 4096;
    uint32_t numLayers = 32;
    uint32_t numHeads = 32;
    uint32_t numKVHeads = 32;   // For GQA
    uint32_t contextLength = 4096;
    uint32_t intermediateSize = 11008;  // FFN dimension
    float rmsNormEps = 1e-6f;
    float ropeTheta = 10000.0f;
    uint32_t ropeScaling = 1;
    
    // Validation
    bool IsValid() const { return hiddenSize > 0 && numLayers > 0; }
};

// ModelContext — Immutable model state
class ModelContext {
public:
    ModelContext();
    ~ModelContext();
    
    // Load from GGUF file
    bool LoadFromGGUF(const std::string& path);
    
    // Check if model is loaded
    bool IsLoaded() const { return m_loaded; }
    
    // Get model path
    const std::string& GetPath() const { return m_modelPath; }
    
    // Get architecture parameters
    const ModelArchitecture& GetArchitecture() const { return m_arch; }
    
    // Metadata access
    bool HasMetadata(const std::string& key) const;
    const MetadataValue* GetMetadata(const std::string& key) const;
    
    // Convenience accessors for common metadata
    std::string GetMetadataString(const std::string& key, const std::string& defaultVal = "") const;
    int32_t GetMetadataInt(const std::string& key, int32_t defaultVal = 0) const;
    float GetMetadataFloat(const std::string& key, float defaultVal = 0.0f) const;
    
    // Tensor registry access
    bool HasTensor(const std::string& name) const;
    const TensorEntry* GetTensor(const std::string& name) const;
    const TensorEntry* GetTensorByPattern(const std::string& pattern) const;  // Partial match
    
    // Get all tensor names
    std::vector<std::string> GetTensorNames() const;
    
    // Get tensor data pointer (returns pointer into memory-mapped file)
    // Returns nullptr if tensor not found
    const void* GetTensorData(const std::string& name) const;
    
    // Get TensorView for runtime kernel access
    // Returns view with status if tensor not found or unsupported
    TensorView GetTensorView(const std::string& name) const;
    
    // Specific tensor accessors (convenience)
    const TensorEntry* GetTokenEmbeddings() const;
    const TensorEntry* GetOutputWeight() const;
    const TensorEntry* GetNormWeight() const;
    const TensorEntry* GetLayerNormWeight(uint32_t layer) const;
    const TensorEntry* GetAttentionQWeight(uint32_t layer) const;
    const TensorEntry* GetAttentionKWeight(uint32_t layer) const;
    const TensorEntry* GetAttentionVWeight(uint32_t layer) const;
    const TensorEntry* GetAttentionOutputWeight(uint32_t layer) const;
    const TensorEntry* GetFFNUpWeight(uint32_t layer) const;
    const TensorEntry* GetFFNGateWeight(uint32_t layer) const;
    const TensorEntry* GetFFNDownWeight(uint32_t layer) const;
    
    // File data access (for tensor data pointers)
    const std::vector<uint8_t>& GetFileData() const { return m_fileData; }
    
    // Validation gates
    bool ValidateGate1_Metadata() const;      // Check required metadata present
    bool ValidateGate2_TensorLookup() const; // Check required tensors present
    bool ValidateGate3_SingleToken() const;  // Check can do single token forward
    
    // Get validation report
    std::string GetValidationReport() const;

private:
    bool m_loaded = false;
    std::string m_modelPath;
    
    // Architecture parameters (extracted from metadata)
    ModelArchitecture m_arch;
    
    // Metadata storage
    std::unordered_map<std::string, MetadataValue> m_metadata;
    
    // Tensor registry (name -> entry)
    std::unordered_map<std::string, TensorEntry> m_tensors;
    
    // File data (keeps GGUF file in memory)
    std::vector<uint8_t> m_fileData;
    
    // Parse GGUF file from memory
    bool ParseGGUF(const uint8_t* data, size_t size);
    
    // Extract architecture from metadata
    void ExtractArchitecture();
};

} // namespace CLI
} // namespace RawrXD
