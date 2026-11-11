// ============================================================================
// Transformer Layer Inference - Full Forward Pass
// ============================================================================
// Complete transformer layer with attention and FFN
// ============================================================================

#pragma once

#include <vector>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <cstdint>
#include <memory>
#include "int8_gemm.hpp"
#include "parallel_gemm.hpp"

namespace RawrXD {
namespace Inference {

// Transformer configuration
struct TransformerConfig {
    uint32_t hidden_size = 4096;
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 8;  // GQA
    uint32_t head_dim = 128;    // hidden_size / num_heads
    uint32_t intermediate_size = 14336;
    uint32_t num_layers = 34;   // Number of transformer layers
    float rms_norm_eps = 1e-5f;
};

// Weight tensors for one layer
struct LayerWeights {
    // Attention (FP32 fallback)
    std::vector<float> q_weight;  // [hidden_size, hidden_size]
    std::vector<float> k_weight;  // [hidden_size, kv_hidden_size]
    std::vector<float> v_weight;  // [hidden_size, kv_hidden_size]
    std::vector<float> o_weight;  // [hidden_size, hidden_size]
    std::vector<float> attn_norm; // [hidden_size]
    
    // FFN (FP32 fallback)
    std::vector<float> ffn_gate;  // [hidden_size, intermediate_size]
    std::vector<float> ffn_up;    // [hidden_size, intermediate_size]
    std::vector<float> ffn_down;  // [intermediate_size, hidden_size]
    std::vector<float> ffn_norm;  // [hidden_size]
    
    // INT8 quantized weights for speed
    SEG::Q8Matrix q_weight_q8;    // [hidden_size, hidden_size]
    SEG::Q8Matrix k_weight_q8;    // [hidden_size, kv_hidden_size]
    SEG::Q8Matrix v_weight_q8;    // [hidden_size, kv_hidden_size]
    SEG::Q8Matrix o_weight_q8;    // [hidden_size, hidden_size]
    SEG::Q8Matrix ffn_gate_q8;    // [intermediate, hidden_size]
    SEG::Q8Matrix ffn_up_q8;      // [intermediate, hidden_size]
    SEG::Q8Matrix ffn_down_q8;    // [hidden_size, intermediate]
    bool use_int8 = false;
};

// KV cache entry
struct KVCache {
    std::vector<float> k_cache;  // [max_seq_len, kv_hidden_size]
    std::vector<float> v_cache;  // [max_seq_len, kv_hidden_size]
    uint32_t cache_len = 0;
};

// Transformer layer inference
class TransformerLayer {
public:
    TransformerLayer(const TransformerConfig& config);
    
    // Load weights from dequantized tensors
    bool LoadWeights(const float* q_w, const float* k_w, 
                     const float* v_w, const float* o_w,
                     const float* attn_n,
                     const float* ffn_g, const float* ffn_u,
                     const float* ffn_d, const float* ffn_n);
    
    // Forward pass for one token
    // input: [hidden_size]
    // output: [hidden_size]
    bool Forward(const float* input, float* output, 
                 KVCache& kv_cache, uint32_t position);
    
    // Fused forward pass with kernel fusion
    // Reduces memory round-trips for better performance
    bool ForwardFused(const float* input, float* output,
                      KVCache& kv_cache, uint32_t position);

protected:
    TransformerConfig config_;
    LayerWeights weights_;
    
    // Working buffers
    std::vector<float> normed_;      // RMSNorm output
    std::vector<float> q_proj_;      // Q projection
    std::vector<float> k_proj_;      // K projection
    std::vector<float> v_proj_;      // V projection
    std::vector<float> attn_out_;    // Attention output
    std::vector<float> ffn_gate_;   // FFN gate projection
    std::vector<float> ffn_up_;      // FFN up projection
    std::vector<float> ffn_act_;     // FFN activation
    
    // Thread pool for parallel operations
    std::unique_ptr<SEG::ThreadPool> thread_pool_;
    bool use_parallel_ = false;
    
    // Helper functions - protected for derived classes
    void RMSNorm(const float* input, const float* weight, float* output, uint32_t size);
    void Softmax(float* data, uint32_t seq_len);
    void SiLU(float* data, uint32_t size);
    void MatMul(const float* A, const float* B, float* C, 
                uint32_t M, uint32_t K, uint32_t N);
    void AttentionForward(const float* Q, const float* K, const float* V,
                          float* output, KVCache& kv_cache, uint32_t position);
    
    // Parallel FFN helper - splits work across threads
    void FFNForwardChunk(const float* input, float* output, 
                         uint32_t start_chunk, uint32_t end_chunk);
};

} // namespace Inference
} // namespace RawrXD
