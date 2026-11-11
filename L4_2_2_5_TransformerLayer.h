// L4_2_2_5_TransformerLayer.h
// L4.2.2.5 Complete Transformer Layer
// First end-to-end transformer layer using validated primitives

#pragma once

#include "L4_2_2_TransformerPrimitives.h"
#include <cstdint>
#include <vector>
#include <memory>
#include <string>
#include <random>

namespace RawrXD {
namespace L4 {

// ============================================================================
// Transformer Layer Configuration
// ============================================================================

struct TransformerLayerConfig {
    // Architecture dimensions
    uint32_t hidden_dim = 4096;
    uint32_t intermediate_dim = 14336;  // 3.5x for Llama-3
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 8;  // GQA: fewer KV heads
    uint32_t head_dim = 128;
    
    // Normalization
    float rms_epsilon = 1e-6f;
    
    // Derived properties
    uint32_t num_key_value_heads() const { return num_kv_heads; }
    uint32_t num_query_heads() const { return num_heads; }
    uint32_t num_key_value_groups() const { return num_heads / num_kv_heads; }
};

// ============================================================================
// KV Cache Contract
// ============================================================================
// KV cache belongs to the runtime, not the attention kernel
// Pre-allocated for max sequence length

struct KVCache {
    // Dimensions: [num_kv_heads, max_seq_len, head_dim]
    std::vector<float> key_cache;
    std::vector<float> value_cache;
    
    // Current state
    uint32_t sequence_length = 0;
    uint32_t max_capacity = 0;
    
    // Configuration
    uint32_t num_kv_heads = 0;
    uint32_t head_dim = 0;
    
    // Initialize cache with capacity
    void Initialize(uint32_t kv_heads, uint32_t h_dim, uint32_t max_seq);
    
    // Get pointer to key/value for a specific position
    float* GetKey(uint32_t head, uint32_t pos);
    float* GetValue(uint32_t head, uint32_t pos);
    const float* GetKey(uint32_t head, uint32_t pos) const;
    const float* GetValue(uint32_t head, uint32_t pos) const;
    
    // Append new key/value at current sequence length
    void AppendKey(uint32_t head, const float* key_data);
    void AppendValue(uint32_t head, const float* value_data);
    
    // Increment sequence length after appending
    void IncrementSequenceLength();
    
    // Reset for new sequence
    void Reset();
    
    // Check if cache is full
    bool IsFull() const;
};

// ============================================================================
// Layer Weights
// ============================================================================
// All weights for a single transformer layer

struct TransformerLayerWeights {
    // Input normalization
    std::vector<float> input_layernorm_weight;  // [hidden_dim]
    
    // Attention projections
    std::vector<float> q_proj_weight;  // [num_heads * head_dim, hidden_dim]
    std::vector<float> k_proj_weight;  // [num_kv_heads * head_dim, hidden_dim]
    std::vector<float> v_proj_weight;  // [num_kv_heads * head_dim, hidden_dim]
    std::vector<float> o_proj_weight;  // [hidden_dim, num_heads * head_dim]
    
    // Post-attention normalization
    std::vector<float> post_attention_layernorm_weight;  // [hidden_dim]
    
    // FFN weights (SwiGLU)
    std::vector<float> gate_proj_weight;  // [intermediate_dim, hidden_dim]
    std::vector<float> up_proj_weight;   // [intermediate_dim, hidden_dim]
    std::vector<float> down_proj_weight;  // [hidden_dim, intermediate_dim]
    
    // Load from GGUF (placeholder for future)
    bool LoadFromGGUF(const std::string& gguf_path, uint32_t layer_idx);
    
    // Initialize with random values for testing
    void InitializeRandom(uint32_t layer_idx, uint32_t seed);
};

// ============================================================================
// Forward Result
// ============================================================================

struct ForwardResult {
    bool success;
    std::string error_message;
    
    // Optional: timing breakdown
    float rms_norm_time_ms;
    float qkv_proj_time_ms;
    float rope_time_ms;
    float attention_time_ms;
    float output_proj_time_ms;
    float ffn_time_ms;
    float total_time_ms;
};

// ============================================================================
// Transformer Layer Execution
// ============================================================================

class TransformerLayer {
public:
    TransformerLayer() = default;
    ~TransformerLayer() = default;
    
    // Initialize with configuration and weights
    bool Initialize(
        const TransformerLayerConfig& config,
        const TransformerLayerWeights& weights
    );
    
    // Execute single token forward pass
    // Input: hidden state [hidden_dim]
    // Output: next hidden state [hidden_dim] (modified in place)
    // KV cache is updated with new key/value for this position
    ForwardResult Execute(
        float* hidden,           // [hidden_dim] - modified in place
        uint32_t position,       // Current token position
        KVCache& kv_cache        // Updated with K,V for this position
    );
    
    // Get configuration
    const TransformerLayerConfig& GetConfig() const { return config_; }

private:
    TransformerLayerConfig config_;
    TransformerLayerWeights weights_;
    
    // Pre-allocated buffers
    std::vector<float> norm_buffer_;      // [hidden_dim]
    std::vector<float> q_buffer_;        // [num_heads * head_dim]
    std::vector<float> k_buffer_;        // [num_kv_heads * head_dim]
    std::vector<float> v_buffer_;        // [num_kv_heads * head_dim]
    std::vector<float> attn_output_;     // [num_heads * head_dim]
    std::vector<float> ffn_gate_;        // [intermediate_dim]
    std::vector<float> ffn_up_;          // [intermediate_dim]
    std::vector<float> ffn_down_;       // [hidden_dim]
    
    // RoPE tables (precomputed)
    RoPETables rope_tables_;
    
    // Internal methods
    void ProjectQKV(const float* input, float* q, float* k, float* v);
    void ProjectOutput(const float* attn_out, float* output);
    void ProjectFFN(const float* input, float* output);
};

// ============================================================================
// Validation
// ============================================================================

// Validate a complete transformer layer against reference
bool ValidateTransformerLayer(
    const TransformerLayer& layer,
    const TransformerLayerConfig& config,
    uint32_t num_test_tokens = 10
);

// Compare layer output against llama.cpp reference (future)
struct LayerValidationResult {
    bool passed;
    float max_error;
    float mean_error;
    float cosine_similarity;
};

LayerValidationResult CompareAgainstReference(
    const TransformerLayer& layer,
    const std::string& reference_output_path
);

} // namespace L4
} // namespace RawrXD
