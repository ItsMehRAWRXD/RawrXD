// ============================================================================
// Optimized Transformer Layer - SREM + AVX2 Implementation
// High-performance attention and FFN with cache-aware tiling
// ============================================================================

#pragma once

#include "avx2_gemm.hpp"
#include "../quantization/quantized_tensor.hpp"
#include <vector>
#include <memory>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Optimized Transformer Configuration
// ============================================================================
struct OptimizedTransformerConfig {
    size_t hidden_size = 1024;
    size_t num_heads = 16;
    size_t num_kv_heads = 16;  // GQA support
    size_t head_dim = 64;      // hidden_size / num_heads
    size_t intermediate_size = 8192;
    size_t max_seq_len = 32768;
    
    // Performance tuning
    bool use_avx2 = true;
    bool use_flash_attention = false;  // TODO: Implement FlashAttention
    size_t tile_size = 64;
};

// ============================================================================
// Optimized Layer Weights (memory-aligned for AVX2)
// ============================================================================
struct alignas(32) OptimizedLayerWeights {
    // Attention weights (quantized)
    std::vector<float> q_proj;      // [hidden_size, hidden_size]
    std::vector<float> k_proj;      // [hidden_size, head_dim * num_kv_heads]
    std::vector<float> v_proj;      // [hidden_size, head_dim * num_kv_heads]
    std::vector<float> o_proj;      // [hidden_size, hidden_size]
    
    // FFN weights (quantized)
    std::vector<float> gate_proj;   // [hidden_size, intermediate_size]
    std::vector<float> up_proj;     // [hidden_size, intermediate_size]
    std::vector<float> down_proj;   // [intermediate_size, hidden_size]
    
    // Normalization
    std::vector<float> input_layernorm;
    std::vector<float> post_attention_layernorm;
    
    // Dimensions
    size_t hidden_size = 0;
    size_t intermediate_size = 0;
    size_t num_heads = 0;
    size_t head_dim = 0;
};

// ============================================================================
// KV Cache with SREM layout
// ============================================================================
class SREMKVCache {
public:
    SREMKVCache() = default;
    
    bool Initialize(size_t max_batch, size_t max_seq, 
                    size_t num_kv_heads, size_t head_dim);
    
    // Get pointers for writing new KV values
    float* GetKWritePtr(size_t batch_idx, size_t seq_idx);
    float* GetVWritePtr(size_t batch_idx, size_t seq_idx);
    
    // Get pointers for reading cached KV values
    const float* GetKReadPtr(size_t batch_idx, size_t start_seq) const;
    const float* GetVReadPtr(size_t batch_idx, size_t start_seq) const;
    
    void Clear();
    size_t GetCurrentLength() const { return current_length_; }
    void Advance(size_t tokens) { current_length_ += tokens; }
    
private:
    std::vector<float> k_cache_;  // [batch, seq, num_kv_heads, head_dim]
    std::vector<float> v_cache_;  // [batch, seq, num_kv_heads, head_dim]
    
    size_t max_batch_ = 0;
    size_t max_seq_ = 0;
    size_t num_kv_heads_ = 0;
    size_t head_dim_ = 0;
    size_t current_length_ = 0;
    size_t kv_stride_ = 0;
};

// ============================================================================
// Optimized Transformer Layer
// ============================================================================
class OptimizedTransformerLayer {
public:
    OptimizedTransformerLayer();
    ~OptimizedTransformerLayer();
    
    bool Initialize(const OptimizedLayerWeights& weights,
                   const OptimizedTransformerConfig& config);
    
    // Forward pass with AVX2 acceleration
    bool Forward(const float* input,
                float* output,
                size_t batch_size,
                size_t seq_len,
                SREMKVCache* kv_cache,
                size_t kv_cache_len);
    
    // Performance metrics
    double GetLastForwardTimeMs() const { return last_forward_time_ms_; }
    double GetAttentionTimeMs() const { return attention_time_ms_; }
    double GetFfnTimeMs() const { return ffn_time_ms_; }
    
private:
    // Attention components
    bool ComputeAttention(const float* q, const float* k, const float* v,
                         float* output,
                         size_t batch_size, size_t seq_len, size_t total_len);
    
    bool ApplyRotaryEmbeddings(float* q, float* k,
                               size_t seq_len, size_t offset);
    
    // FFN components
    bool ComputeFFN(const float* input, float* output,
                   size_t batch_size, size_t seq_len);
    
    // Working buffers (pre-allocated)
    std::vector<float> q_buf_;
    std::vector<float> k_buf_;
    std::vector<float> v_buf_;
    std::vector<float> attn_out_buf_;
    std::vector<float> ffn_gate_buf_;
    std::vector<float> ffn_up_buf_;
    std::vector<float> ffn_out_buf_;
    std::vector<float> normed_buf_;
    
    // Attention scores buffer
    std::vector<float> attn_scores_;
    
    // Configuration
    OptimizedLayerWeights weights_;
    OptimizedTransformerConfig config_;
    
    // Performance tracking
    double last_forward_time_ms_ = 0.0;
    double attention_time_ms_ = 0.0;
    double ffn_time_ms_ = 0.0;
    bool initialized_ = false;
};

// ============================================================================
// Optimized Model (full stack)
// ============================================================================
class OptimizedModel {
public:
    OptimizedModel();
    ~OptimizedModel();
    
    bool Initialize(const OptimizedTransformerConfig& config);
    bool LoadWeights(const std::string& gguf_path);
    
    // Fast inference
    bool Forward(const std::vector<int32_t>& tokens,
                std::vector<float>& logits,
                size_t batch_size = 1);
    
    // Token generation
    int32_t GenerateNextToken(const std::vector<int32_t>& context,
                             float temperature = 1.0f,
                             int32_t top_k = 50);
    
    // Performance
    double GetTokensPerSecond() const;
    double GetLastLatencyMs() const { return last_latency_ms_; }
    
private:
    std::vector<std::unique_ptr<OptimizedTransformerLayer>> layers_;
    std::unique_ptr<SREMKVCache> kv_cache_;
    
    // Embeddings and head
    std::vector<float> token_embeddings_;  // [vocab_size, hidden_size]
    std::vector<float> output_norm_;
    std::vector<float> lm_head_;             // [vocab_size, hidden_size]
    
    // Config
    OptimizedTransformerConfig config_;
    size_t vocab_size_ = 0;
    
    // Performance
    double last_latency_ms_ = 0.0;
    size_t total_tokens_generated_ = 0;
};

} // namespace kernels
} // namespace rawrxd
