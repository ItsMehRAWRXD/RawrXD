// ============================================================================
// Optimized Transformer Layer Header
// ============================================================================
// High-performance transformer with OptimizedKVCache and multi-threading
// ============================================================================

#pragma once

#include <cstdint>
#include <vector>
#include "kv_cache_optimized.hpp"

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Configuration
// ============================================================================

struct TransformerConfig {
    uint32_t num_layers = 24;
    uint32_t num_heads = 32;
    uint32_t head_dim = 64;
    uint32_t hidden_size = 2048;      // num_heads * head_dim
    uint32_t intermediate_size = 5504; // ~2.7 * hidden_size
    uint32_t vocab_size = 32000;
    uint32_t max_seq_len = 2048;
    uint32_t batch_size = 1;
};

// ============================================================================
// Optimized Transformer Layer
// ============================================================================

class OptimizedTransformerLayer {
public:
    OptimizedTransformerLayer();
    ~OptimizedTransformerLayer();
    
    // Move-only (KV cache is not copyable)
    OptimizedTransformerLayer(OptimizedTransformerLayer&&) = default;
    OptimizedTransformerLayer& operator=(OptimizedTransformerLayer&&) = default;
    OptimizedTransformerLayer(const OptimizedTransformerLayer&) = delete;
    OptimizedTransformerLayer& operator=(const OptimizedTransformerLayer&) = delete;

    // Initialize with configuration
    bool Initialize(const TransformerConfig& config);

    // Reset KV cache
    void Reset();

    // Forward pass with multi-threaded attention
    // All weights are expected to be 64-byte aligned
    bool Forward(
        const float* input,              // [seq_len, hidden_size]
        const float* q_weights,        // [hidden_size, hidden_size]
        const float* k_weights,        // [hidden_size, hidden_size]
        const float* v_weights,        // [hidden_size, hidden_size]
        const float* o_weights,        // [hidden_size, hidden_size]
        const float* ffn_gate_weights, // [hidden_size, intermediate_size]
        const float* ffn_up_weights,   // [hidden_size, intermediate_size]
        const float* ffn_down_weights, // [intermediate_size, hidden_size]
        float* output,                 // [seq_len, hidden_size]
        uint32_t seq_len);

    // Get current sequence length
    uint32_t GetCurrentSeqLen() const { return current_seq_len_; }

    // Get memory usage
    size_t GetMemoryUsage() const { return kv_cache_.GetMemoryUsage(); }

private:
    TransformerConfig config_;
    OptimizedKVCache kv_cache_;
    uint32_t current_seq_len_ = 0;
    bool initialized_ = false;

    // Aligned buffers
    std::vector<float> q_buf_, k_buf_, v_buf_;
    std::vector<float> attn_out_;
    std::vector<float> ffn_gate_, ffn_up_, ffn_out_;

    // Aligned pointers
    float* q_aligned_ = nullptr;
    float* k_aligned_ = nullptr;
    float* v_aligned_ = nullptr;
    float* attn_out_aligned_ = nullptr;
    float* ffn_gate_aligned_ = nullptr;
    float* ffn_up_aligned_ = nullptr;
    float* ffn_out_aligned_ = nullptr;
};

// ============================================================================
// Optimized Transformer Model (Multi-Layer)
// ============================================================================

class OptimizedTransformerModel {
public:
    OptimizedTransformerModel();
    ~OptimizedTransformerModel();

    // Initialize with configuration
    bool Initialize(const TransformerConfig& config);

    // Reset all layers
    void Reset();

    // Full forward pass through all layers
    bool Forward(
        const int32_t* input_tokens,   // [seq_len]
        const float* embedding_weights, // [vocab_size, hidden_size]
        const float* output_weights,     // [hidden_size, vocab_size]
        const float* layer_weights,      // Array of all layer weights
        float* logits,                   // [vocab_size]
        uint32_t seq_len);

    // Get current sequence length
    uint32_t GetCurrentSeqLen() const { return current_seq_len_; }

    // Get total memory usage
    size_t GetMemoryUsage() const;

private:
    TransformerConfig config_;
    std::vector<OptimizedTransformerLayer> layers_;
    uint32_t current_seq_len_ = 0;
    bool initialized_ = false;

    // Aligned buffers
    std::vector<float> embedding_buf_;
    std::vector<float> output_buf_;
    std::vector<float> logits_buf_;

    // Aligned pointers
    float* embedding_aligned_ = nullptr;
    float* output_aligned_ = nullptr;
    float* logits_aligned_ = nullptr;
};

} // namespace Runtime
} // namespace RawrXD
