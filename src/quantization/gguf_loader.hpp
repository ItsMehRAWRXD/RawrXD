// ============================================================================
// GGUF Loader for Quantized Models
// ============================================================================
// Loads ministral3 and similar models from GGUF format
// ============================================================================

#pragma once

#include "quantized_inference.hpp"
#include "quantized_transformer_layer.hpp"
#include <string>
#include <vector>
#include <memory>
#include <fstream>

namespace rawrxd {
namespace quantization {

// ============================================================================
// GGUF Format Structures
// ============================================================================

#pragma pack(push, 1)

struct GGUFHeader {
    uint32_t magic;              // 0x46554747 = "GGUF"
    uint32_t version;            // Currently 3
    uint64_t tensor_count;       // Number of tensors
    uint64_t metadata_kv_count;  // Number of metadata key-value pairs
};

struct GGUFMetadataKV {
    std::string key;
    uint32_t type;
    // Value follows based on type
};

enum class GGUFType : uint32_t {
    UINT8 = 0,
    INT8 = 1,
    UINT16 = 2,
    INT16 = 3,
    UINT32 = 4,
    INT32 = 5,
    FLOAT32 = 6,
    BOOL = 7,
    STRING = 8,
    ARRAY = 9,
    UINT64 = 10,
    INT64 = 11,
    FLOAT64 = 12
};

enum class GGMLType : uint32_t {
    F32 = 0,
    F16 = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    IQ2_XXS = 16,
    IQ2_XS = 17,
    IQ3_XXS = 18,
    IQ1_S = 19,
    IQ4_NL = 20,
    IQ3_S = 21,
    IQ2_S = 22,
    IQ4_XS = 23,
    I8 = 24,
    I16 = 25,
    I32 = 26,
    I64 = 27,
    F64 = 28,
    IQ1_M = 29
};

#pragma pack(pop)

// ============================================================================
// Model Configuration
// ============================================================================

struct ModelConfig {
    // Architecture
    std::string architecture;
    uint32_t block_count = 0;        // num_layers
    uint32_t context_length = 0;
    uint32_t embedding_length = 0;   // hidden_size
    uint32_t feed_forward_length = 0; // intermediate_size
    uint32_t head_count = 0;         // num_heads
    uint32_t head_count_kv = 0;      // num_kv_heads (for GQA)
    
    // Tokenizer
    uint32_t vocab_size = 0;
    std::string tokenizer_model;
    
    // Quantization
    GGMLType weight_type = GGMLType::F32;
    
    // Helper to get head dimension
    uint32_t head_dim() const { 
        return head_count > 0 ? embedding_length / head_count : 0; 
    }
    
    // Check if using GQA
    bool use_gqa() const { return head_count_kv > 0 && head_count_kv < head_count; }
};

// ============================================================================
// Tensor Info
// ============================================================================

struct TensorInfo {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> dimensions;
    uint64_t offset;  // Offset in file where tensor data begins
    uint64_t size;    // Size in bytes
    
    // Get number of elements
    uint64_t num_elements() const {
        uint64_t n = 1;
        for (auto d : dimensions) n *= d;
        return n;
    }
};

// ============================================================================
// GGUF Model Loader
// ============================================================================

class GGUFModelLoader {
public:
    GGUFModelLoader();
    ~GGUFModelLoader();
    
    // Load model from file
    bool Load(const std::string& path);
    
    // Get model configuration
    const ModelConfig& GetConfig() const { return config_; }
    
    // Get tensor info
    const std::vector<TensorInfo>& GetTensors() const { return tensors_; }
    
    // Load specific tensor as quantized
    bool LoadQuantizedTensor(const std::string& name, QuantizedTensor& tensor, 
                              QuantType target_type);
    
    // Load embedding weights (F32)
    bool LoadEmbeddingWeights(std::vector<float>& embeddings);
    
    // Load output norm weights (F32)
    bool LoadOutputNorm(std::vector<float>& norm);
    
    // Load layer weights
    bool LoadLayerWeights(int layer_idx, QuantizedLayerWeightsExtended& weights);
    
    // Check if file is valid GGUF
    static bool IsValidGGUF(const std::string& path);
    
    // Get metadata value
    template<typename T>
    bool GetMetadata(const std::string& key, T& value) const;
    
private:
    std::string path_;
    std::ifstream file_;
    GGUFHeader header_;
    ModelConfig config_;
    std::vector<TensorInfo> tensors_;
    uint64_t data_offset_ = 0;  // Where tensor data begins
    
    // Internal helpers
    bool ParseMetadata();
    bool ParseTensors();
    bool ParseConfigFromMetadata();
    void InferVocabSizeFromEmbeddings();  // Infer vocab_size from token_embd.weight
    
    std::string ReadString();
    uint32_t ReadU32();
    uint64_t ReadU64();
    float ReadF32();
    
    // Get tensor size in bytes based on type
    uint64_t GetTensorSizeBytes(const TensorInfo& info) const;
    
    // Convert GGML type to our QuantType
    QuantType ConvertGGMLType(GGMLType type) const;
};

} // namespace quantization
} // namespace rawrxd
