// ============================================================================
// Quantized Transformer Layer Extended
// ============================================================================
// Extended transformer layer implementation with Q4_0/Q8_0 quantized weights
// ============================================================================

#pragma once

#include "quantized_inference.hpp"
#include <vector>
#include <memory>

namespace rawrxd {
namespace quantization {

// ============================================================================
// Quantized Layer Weights Extended
// ============================================================================
// Extended version with direct tensor storage (not unique_ptr)

struct QuantizedLayerWeightsExtended {
    // Attention weights
    QuantizedTensor q_proj;  // Query projection
    QuantizedTensor k_proj;  // Key projection
    QuantizedTensor v_proj;  // Value projection
    QuantizedTensor o_proj;  // Output projection
    
    // FFN weights
    QuantizedTensor gate_proj;  // Gate projection (for Gated Linear Units)
    QuantizedTensor up_proj;    // Up projection
    QuantizedTensor down_proj;  // Down projection
    
    // Normalization parameters (kept in F32 for precision)
    std::vector<float> input_layernorm;
    std::vector<float> post_attention_layernorm;
    
    // Dimensions
    size_t hidden_size;
    size_t intermediate_size;
    size_t num_heads;
    size_t head_dim;
    
    QuantizedLayerWeightsExtended() : hidden_size(0), intermediate_size(0), num_heads(0), head_dim(0) {}
};

// ============================================================================
// Quantized Transformer Layer Extended
// ============================================================================
// Extended transformer layer with direct tensor storage

class QuantizedTransformerLayerExtended {
public:
    QuantizedTransformerLayerExtended();
    ~QuantizedTransformerLayerExtended();
    
    // Initialize with layer weights
    bool Initialize(const QuantizedLayerWeightsExtended& weights);
    
    // Forward pass
    // input: [batch_size, seq_len, hidden_size]
    // output: [batch_size, seq_len, hidden_size]
    bool Forward(const float* input, float* output,
                 size_t batch_size, size_t seq_len,
                 float* kv_cache_k, float* kv_cache_v,
                 size_t kv_cache_len);
    
    // Getters
    size_t GetHiddenSize() const { return weights_.hidden_size; }
    size_t GetIntermediateSize() const { return weights_.intermediate_size; }
    
private:
    QuantizedLayerWeightsExtended weights_;
    
    // Working buffers
    std::vector<float> q_buf_;
    std::vector<float> k_buf_;
    std::vector<float> v_buf_;
    std::vector<float> attn_out_buf_;
    std::vector<float> ffn_gate_buf_;
    std::vector<float> ffn_up_buf_;
    std::vector<float> ffn_out_buf_;
    
    // Helper functions
    void ApplyRMSNorm(const float* input, float* output, 
                      const std::vector<float>& gamma,
                      size_t num_elements, float eps = 1e-5f);
    void ApplySilu(const float* input, float* output, size_t num_elements);
    void ApplySoftmax(float* data, size_t seq_len, size_t num_heads, size_t head_dim);
    void RotaryEmbed(float* q, float* k, size_t seq_len, size_t num_heads, 
                     size_t head_dim, size_t offset);
};

// ============================================================================
// Quantized Model
// ============================================================================
// Full transformer model with quantized weights

class QuantizedTransformerModel {
public:
    QuantizedTransformerModel();
    ~QuantizedTransformerModel();
    
    // Initialize from GGUF file
    bool LoadFromGGUF(const std::string& path);
    
    // Forward pass for inference
    bool Forward(const int* input_ids, float* logits,
                 size_t batch_size, size_t seq_len);
    
    // Generate tokens autoregressively
    std::vector<int> Generate(const std::vector<int>& prompt,
                              size_t max_new_tokens,
                              float temperature = 0.8f,
                              int top_k = 40);
    
    // Getters
    size_t GetNumLayers() const { return layers_.size(); }
    size_t GetVocabSize() const { return vocab_size_; }
    size_t GetHiddenSize() const { return hidden_size_; }
    
private:
    std::vector<std::unique_ptr<QuantizedTransformerLayer>> layers_;
    
    // Model config
    size_t vocab_size_;
    size_t hidden_size_;
    size_t num_layers_;
    size_t num_heads_;
    size_t num_kv_heads_;  // For GQA
    size_t intermediate_size_;
    
    // Embeddings (kept in F32)
    std::vector<float> token_embeddings_;
    std::vector<float> output_norm_;
    QuantizedTensor lm_head_;  // Can be quantized
    
    // KV cache
    std::vector<float> kv_cache_k_;
    std::vector<float> kv_cache_v_;
    size_t max_seq_len_;
    
    // Sampling
    int Sample(const float* logits, size_t vocab_size, 
               float temperature, int top_k);
};

// ============================================================================
// Quantized Attention
// ============================================================================
// Optimized attention with quantized weights

class QuantizedAttention {
public:
    QuantizedAttention();
    ~QuantizedAttention();
    
    bool Initialize(const QuantizedTensor& q_proj,
                    const QuantizedTensor& k_proj,
                    const QuantizedTensor& v_proj,
                    const QuantizedTensor& o_proj,
                    size_t num_heads,
                    size_t head_dim);
    
    // Forward pass with KV cache
    bool Forward(const float* hidden_states,
                 float* output,
                 size_t batch_size,
                 size_t seq_len,
                 float* kv_cache_k,
                 float* kv_cache_v,
                 size_t kv_cache_len);
    
private:
    QuantizedTensor q_proj_;
    QuantizedTensor k_proj_;
    QuantizedTensor v_proj_;
    QuantizedTensor o_proj_;
    
    size_t num_heads_;
    size_t head_dim_;
    size_t hidden_size_;
};

// ============================================================================
// Quantized FFN
// ============================================================================
// Feed-forward network with quantized weights

class QuantizedFFN {
public:
    QuantizedFFN();
    ~QuantizedFFN();
    
    bool Initialize(const QuantizedTensor& gate_proj,
                    const QuantizedTensor& up_proj,
                    const QuantizedTensor& down_proj);
    
    // Forward pass
    bool Forward(const float* input, float* output,
                 size_t batch_size, size_t seq_len);
    
private:
    QuantizedTensor gate_proj_;
    QuantizedTensor up_proj_;
    QuantizedTensor down_proj_;
    
    size_t hidden_size_;
    size_t intermediate_size_;
};

} // namespace quantization
} // namespace rawrxd
