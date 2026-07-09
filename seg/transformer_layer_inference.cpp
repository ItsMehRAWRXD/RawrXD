// ============================================================================
// Transformer Layer Inference Implementation
// ============================================================================
// Integrated with AVX-512 kernels for performance
// ============================================================================

#include "transformer_layer_inference.hpp"
#include "avx512_kernels.hpp"
#include "flash_attention_avx512.hpp"
#include <iostream>

namespace RawrXD {
namespace Inference {

TransformerLayer::TransformerLayer(const TransformerConfig& config)
    : config_(config) {
    // Allocate working buffers
    normed_.resize(config.hidden_size);
    q_proj_.resize(config.hidden_size);
    k_proj_.resize(config.num_kv_heads * config.head_dim);
    v_proj_.resize(config.num_kv_heads * config.head_dim);
    attn_out_.resize(config.hidden_size);
    ffn_gate_.resize(config.intermediate_size);
    ffn_up_.resize(config.intermediate_size);
    ffn_act_.resize(config.intermediate_size);
}

bool TransformerLayer::LoadWeights(const float* q_w, const float* k_w,
                                   const float* v_w, const float* o_w,
                                   const float* attn_n,
                                   const float* ffn_g, const float* ffn_u,
                                   const float* ffn_d, const float* ffn_n) {
    uint32_t hidden = config_.hidden_size;
    uint32_t kv_hidden = config_.num_kv_heads * config_.head_dim;
    uint32_t intermediate = config_.intermediate_size;
    
    // Copy attention weights
    weights_.q_weight.assign(q_w, q_w + hidden * hidden);
    weights_.k_weight.assign(k_w, k_w + hidden * kv_hidden);
    weights_.v_weight.assign(v_w, v_w + hidden * kv_hidden);
    weights_.o_weight.assign(o_w, o_w + hidden * hidden);
    weights_.attn_norm.assign(attn_n, attn_n + hidden);
    
    // Copy FFN weights
    weights_.ffn_gate.assign(ffn_g, ffn_g + hidden * intermediate);
    weights_.ffn_up.assign(ffn_u, ffn_u + hidden * intermediate);
    weights_.ffn_down.assign(ffn_d, ffn_d + intermediate * hidden);
    weights_.ffn_norm.assign(ffn_n, ffn_n + hidden);
    
    return true;
}

void TransformerLayer::RMSNorm(const float* input, const float* weight,
                               float* output, uint32_t size) {
    // Use AVX-512 optimized RMSNorm via dispatch layer
    SEG::KernelDispatch::RMSNormF32(input, weight, config_.rms_norm_eps, output, size);
}

void TransformerLayer::Softmax(float* data, uint32_t seq_len) {
    // Find max for numerical stability
    float max_val = data[0];
    for (uint32_t i = 1; i < seq_len; i++) {
        if (data[i] > max_val) max_val = data[i];
    }
    
    // Compute exp and sum
    float sum = 0.0f;
    for (uint32_t i = 0; i < seq_len; i++) {
        data[i] = std::exp(data[i] - max_val);
        sum += data[i];
    }
    
    // Normalize
    for (uint32_t i = 0; i < seq_len; i++) {
        data[i] /= sum;
    }
}

void TransformerLayer::SiLU(float* data, uint32_t size) {
    // Use AVX-512 optimized SiLU via dispatch layer
    // Note: Currently uses scalar fallback, can be optimized further
    SEG::KernelDispatch::SiLUF32(data, data, size);
}

void TransformerLayer::MatMul(const float* A, const float* B, float* C,
                              uint32_t M, uint32_t K, uint32_t N) {
    // Use AVX-512 optimized MatMul via dispatch layer
    // Automatically falls back to scalar on non-AVX-512 CPUs
    SEG::KernelDispatch::MatMulF32(A, B, C, M, N, K);
}

void TransformerLayer::AttentionForward(const float* Q, const float* K, const float* V,
                                        float* output, KVCache& kv_cache, uint32_t position) {
    uint32_t num_heads = config_.num_heads;
    uint32_t num_kv_heads = config_.num_kv_heads;
    uint32_t head_dim = config_.head_dim;
    uint32_t kv_hidden = num_kv_heads * head_dim;
    
    // Store K and V in cache
    for (uint32_t i = 0; i < kv_hidden; i++) {
        kv_cache.k_cache[position * kv_hidden + i] = K[i];
        kv_cache.v_cache[position * kv_hidden + i] = V[i];
    }
    kv_cache.cache_len = position + 1;
    
    // For each head, compute attention using Flash Attention
    for (uint32_t h = 0; h < num_heads; h++) {
        uint32_t kv_h = h / (num_heads / num_kv_heads);  // GQA mapping
        
        // Q for this head
        const float* q_head = Q + h * head_dim;
        float* out_head = output + h * head_dim;
        
        // Use Flash Attention for cached attention computation
        // The KV cache is stored as [cache_len, kv_hidden] with heads interleaved
        // We need to access the correct KV head's data
        SEG::FlashAttentionCachedF32(
            q_head,
            kv_cache.k_cache.data(),  // Full K cache
            kv_cache.v_cache.data(),  // Full V cache
            out_head,
            kv_cache.cache_len,
            head_dim
        );
    }
}

bool TransformerLayer::Forward(const float* input, float* output,
                               KVCache& kv_cache, uint32_t position) {
    uint32_t hidden = config_.hidden_size;
    uint32_t kv_hidden = config_.num_kv_heads * config_.head_dim;
    uint32_t intermediate = config_.intermediate_size;
    
    // === Attention Block ===
    // 1. RMSNorm
    RMSNorm(input, weights_.attn_norm.data(), normed_.data(), hidden);
    
    // 2. QKV projections
    MatMul(normed_.data(), weights_.q_weight.data(), q_proj_.data(), 1, hidden, hidden);
    MatMul(normed_.data(), weights_.k_weight.data(), k_proj_.data(), 1, hidden, kv_hidden);
    MatMul(normed_.data(), weights_.v_weight.data(), v_proj_.data(), 1, hidden, kv_hidden);
    
    // 3. Attention
    AttentionForward(q_proj_.data(), k_proj_.data(), v_proj_.data(),
                     attn_out_.data(), kv_cache, position);
    
    // 4. Output projection
    MatMul(attn_out_.data(), weights_.o_weight.data(), normed_.data(), 1, hidden, hidden);
    
    // 5. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        normed_[i] = input[i] + normed_[i];
    }
    
    // === FFN Block ===
    // 6. RMSNorm
    RMSNorm(normed_.data(), weights_.ffn_norm.data(), ffn_gate_.data(), hidden);
    
    // 7. FFN projections
    MatMul(ffn_gate_.data(), weights_.ffn_gate.data(), ffn_gate_.data(), 1, hidden, intermediate);
    MatMul(normed_.data(), weights_.ffn_up.data(), ffn_up_.data(), 1, hidden, intermediate);
    
    // 8. SiLU activation on gate
    SiLU(ffn_gate_.data(), intermediate);
    
    // 9. Element-wise multiply
    for (uint32_t i = 0; i < intermediate; i++) {
        ffn_act_[i] = ffn_gate_[i] * ffn_up_[i];
    }
    
    // 10. Down projection
    MatMul(ffn_act_.data(), weights_.ffn_down.data(), output, 1, intermediate, hidden);
    
    // 11. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        output[i] = normed_[i] + output[i];
    }
    
    return true;
}

} // namespace Inference
} // namespace RawrXD
