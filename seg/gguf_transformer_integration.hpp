// ============================================================================
// GGUF Transformer Integration
// Tight coupling between GGUF loader and Transformer Runtime
// ============================================================================

#pragma once

#include "transformer_layer_runtime.hpp"
#include <string>
#include <unordered_map>

// Include GGUF adapter bridge
#include "../../rawrxd/sovereign/gguf_adapter_bridge_v2.hpp"

namespace transformer {

// ============================================================================
// GGUF to Transformer Runtime Bridge
// ============================================================================
class GGUFTransformerLoader {
public:
    GGUFTransformerLoader();
    ~GGUFTransformerLoader();
    
    // Load model from GGUF file
    bool LoadFromFile(const std::string& path, TransformerConfig& config);
    
    // Get layer weights for a specific layer
    bool GetLayerWeights(uint32_t layer_idx, LayerWeights& weights);
    
    // Get embedding weights
    bool GetEmbeddingWeights(std::vector<float>& embeddings);
    bool GetOutputWeights(std::vector<float>& weights);
    bool GetOutputNorm(std::vector<float>& norm);
    
    // Get tokenizer vocab (if present in GGUF)
    bool GetTokenizerVocab(std::vector<std::string>& vocab);
    
    // Model info
    uint32_t GetNumLayers() const { return num_layers_; }
    uint32_t GetHiddenSize() const { return hidden_size_; }
    uint32_t GetNumHeads() const { return num_heads_; }
    uint32_t GetNumKVHeads() const { return num_kv_heads_; }
    uint32_t GetVocabSize() const { return vocab_size_; }
    uint32_t GetContextLength() const { return context_length_; }
    
    // Check if file is open
    bool IsOpen() const { return loader_ && loader_->isOpen(); }
    
    // Get raw loader for advanced usage
    sovereign::StreamingGGUFLoader* GetLoader() { return loader_.get(); }

private:
    std::unique_ptr<sovereign::StreamingGGUFLoader> loader_;
    
    // Cached model dimensions from GGUF metadata
    uint32_t num_layers_ = 0;
    uint32_t hidden_size_ = 0;
    uint32_t num_heads_ = 0;
    uint32_t num_kv_heads_ = 0;
    uint32_t vocab_size_ = 0;
    uint32_t context_length_ = 0;
    uint32_t intermediate_size_ = 0;
    uint32_t head_dim_ = 0;
    
    // Tensor name mapping (architecture-specific)
    std::string model_arch_ = "llama"; // llama, qwen2, etc.
    
    // Helper functions
    bool ParseModelConfig();
    std::string GetTensorName(const std::string& pattern, uint32_t layer);
    bool LoadTensorData(const std::string& name, std::vector<float>& data);
    bool ConvertToFloat32(const sovereign::TensorView& view, std::vector<float>& data);
    
    // Architecture-specific tensor name patterns
    struct TensorPatterns {
        std::string input_norm;
        std::string post_attn_norm;
        std::string q_proj;
        std::string k_proj;
        std::string v_proj;
        std::string o_proj;
        std::string gate_proj;
        std::string up_proj;
        std::string down_proj;
    };
    TensorPatterns patterns_;
    
    void SetupPatterns();
};

// ============================================================================
// Complete Model Loader
// ============================================================================
struct CompleteModel {
    TransformerConfig config;
    std::vector<LayerWeights> layer_weights;
    std::vector<float> token_embeddings;
    std::vector<float> output_norm;
    std::vector<float> lm_head;
    std::vector<std::string> vocab;
    
    bool Validate() const;
    void PrintInfo() const;
};

// Load complete model from GGUF
CompleteModel LoadModelFromGGUF(const std::string& path);

// ============================================================================
// Integration with TransformerRuntime
// ============================================================================
class GGUFTransformerRuntime : public TransformerRuntime {
public:
    GGUFTransformerRuntime();
    ~GGUFTransformerRuntime();
    
    // Initialize from GGUF file
    bool InitializeFromGGUF(const std::string& path);
    
    // Get model info
    const CompleteModel& GetModel() const { return model_; }

private:
    CompleteModel model_;
};

// ============================================================================
// Quantized Weight Support
// ============================================================================
struct QuantizedTensor {
    sovereign::GGMLType type;
    std::vector<uint8_t> data;
    std::vector<float> scales;
    std::vector<float> biases;
    std::vector<uint64_t> shape;
    
    // Dequantize to float32
    std::vector<float> Dequantize() const;
};

// Load quantized tensor from GGUF
QuantizedTensor LoadQuantizedTensor(sovereign::StreamingGGUFLoader& loader, 
                                     const std::string& name);

// ============================================================================
// Utility Functions
// ============================================================================

// Map GGML type to size per element
size_t GetGGMLTypeSize(sovereign::GGMLType type);

// Check if type is supported
bool IsTypeSupported(sovereign::GGMLType type);

// Get model architecture from GGUF
std::string DetectModelArchitecture(sovereign::StreamingGGUFLoader& loader);

} // namespace transformer
