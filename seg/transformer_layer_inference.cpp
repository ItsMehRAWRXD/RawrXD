// ============================================================================
// Transformer Layer Inference Implementation
// ============================================================================
// Integrated with AVX-512 kernels for performance
// ============================================================================

#include "transformer_layer_inference.hpp"
#include "avx512_kernels.hpp"
#include "flash_attention_avx512.hpp"
#include "quantized_matmul_fast.hpp"
#include "fused_kernels.hpp"
#include <iostream>
#include <immintrin.h>
#include <cstring>

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
    
    // Initialize thread pool for parallel projections
    size_t num_threads = SEG::GetOptimalThreadCount();
    if (num_threads > 1) {
        thread_pool_ = std::make_unique<SEG::ThreadPool>(num_threads);
        use_parallel_ = true;
    }
}

bool TransformerLayer::LoadWeights(const float* q_w, const float* k_w,
                                   const float* v_w, const float* o_w,
                                   const float* attn_n,
                                   const float* ffn_g, const float* ffn_u,
                                   const float* ffn_d, const float* ffn_n) {
    uint32_t hidden = config_.hidden_size;
    uint32_t kv_hidden = config_.num_kv_heads * config_.head_dim;
    uint32_t intermediate = config_.intermediate_size;
    
    // Copy attention weights (keep FP32 for accuracy)
    weights_.q_weight.assign(q_w, q_w + hidden * hidden);
    weights_.k_weight.assign(k_w, k_w + hidden * kv_hidden);
    weights_.v_weight.assign(v_w, v_w + hidden * kv_hidden);
    weights_.o_weight.assign(o_w, o_w + hidden * hidden);
    weights_.attn_norm.assign(attn_n, attn_n + hidden);
    
    // Copy FFN weights (FP32 fallback)
    weights_.ffn_gate.assign(ffn_g, ffn_g + hidden * intermediate);
    weights_.ffn_up.assign(ffn_u, ffn_u + hidden * intermediate);
    weights_.ffn_down.assign(ffn_d, ffn_d + intermediate * hidden);
    weights_.ffn_norm.assign(ffn_n, ffn_n + hidden);
    
    // Quantize all projection weights to INT8 for speed
    // Attention projections
    weights_.q_weight_q8 = SEG::ConvertWeightsToQ8(q_w, hidden, hidden);
    weights_.k_weight_q8 = SEG::ConvertWeightsToQ8(k_w, kv_hidden, hidden);
    weights_.v_weight_q8 = SEG::ConvertWeightsToQ8(v_w, kv_hidden, hidden);
    weights_.o_weight_q8 = SEG::ConvertWeightsToQ8(o_w, hidden, hidden);
    
    // FFN projections
    // Note: FFN weights are stored as [N, K] where N=output dim, K=input dim
    weights_.ffn_gate_q8 = SEG::ConvertWeightsToQ8(ffn_g, intermediate, hidden);
    weights_.ffn_up_q8 = SEG::ConvertWeightsToQ8(ffn_u, intermediate, hidden);
    weights_.ffn_down_q8 = SEG::ConvertWeightsToQ8(ffn_d, hidden, intermediate);
    weights_.use_int8 = true;
    
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
        // Pass kv_h * head_dim as offset to access correct KV head
        SEG::FlashAttentionCachedF32(
            q_head,
            kv_cache.k_cache.data() + kv_h * head_dim,  // K cache for this KV head
            kv_cache.v_cache.data() + kv_h * head_dim,  // V cache for this KV head
            out_head,
            kv_cache.cache_len,
            head_dim,
            kv_hidden  // Stride between consecutive KV entries
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
    
    // 2. QKV projections - use INT8 quantized for speed
    if (weights_.use_int8) {
        SEG::Int8VecMatMul(normed_.data(), weights_.q_weight_q8, q_proj_.data());
        SEG::Int8VecMatMul(normed_.data(), weights_.k_weight_q8, k_proj_.data());
        SEG::Int8VecMatMul(normed_.data(), weights_.v_weight_q8, v_proj_.data());
    } else {
        SEG::FastVecMatMul(normed_.data(), weights_.q_weight.data(), q_proj_.data(), hidden, hidden);
        SEG::FastVecMatMul(normed_.data(), weights_.k_weight.data(), k_proj_.data(), kv_hidden, hidden);
        SEG::FastVecMatMul(normed_.data(), weights_.v_weight.data(), v_proj_.data(), kv_hidden, hidden);
    }
    
    // 3. Attention
    AttentionForward(q_proj_.data(), k_proj_.data(), v_proj_.data(),
                     attn_out_.data(), kv_cache, position);
    
    // 4. Output projection - use INT8 quantized for speed
    if (weights_.use_int8) {
        SEG::Int8VecMatMul(attn_out_.data(), weights_.o_weight_q8, normed_.data());
    } else {
        SEG::FastVecMatMul(attn_out_.data(), weights_.o_weight.data(), normed_.data(), hidden, hidden);
    }
    
    // 5. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        normed_[i] = input[i] + normed_[i];
    }
    
    // === FFN Block ===
    // 6. RMSNorm
    RMSNorm(normed_.data(), weights_.ffn_norm.data(), ffn_gate_.data(), hidden);
    
    // 7. FFN projections - use INT8 quantized with optional parallelization
    if (weights_.use_int8) {
        // INT8 path: ~1.87x faster for large matrices
        // Use parallel version for large FFN projections
        if (use_parallel_ && intermediate >= 8192) {
            SEG::ParallelInt8VecMatMul(ffn_gate_.data(), weights_.ffn_gate_q8, ffn_gate_.data(), *thread_pool_);
            SEG::ParallelInt8VecMatMul(ffn_gate_.data(), weights_.ffn_up_q8, ffn_up_.data(), *thread_pool_);
        } else {
            SEG::Int8VecMatMul(ffn_gate_.data(), weights_.ffn_gate_q8, ffn_gate_.data());
            SEG::Int8VecMatMul(ffn_gate_.data(), weights_.ffn_up_q8, ffn_up_.data());
        }
    } else {
        // FP32 fallback
        SEG::FastVecMatMul(ffn_gate_.data(), weights_.ffn_gate.data(), 
                           ffn_gate_.data(), intermediate, hidden);
        SEG::FastVecMatMul(ffn_gate_.data(), weights_.ffn_up.data(), 
                           ffn_up_.data(), intermediate, hidden);
    }
    
    // 8. SiLU activation on gate
    SiLU(ffn_gate_.data(), intermediate);
    
    // 9. Element-wise multiply
    for (uint32_t i = 0; i < intermediate; i++) {
        ffn_act_[i] = ffn_gate_[i] * ffn_up_[i];
    }
    
    // 10. Down projection - use INT8 if available
    if (weights_.use_int8) {
        SEG::Int8VecMatMul(ffn_act_.data(), weights_.ffn_down_q8, output);
    } else {
        SEG::FastVecMatMul(ffn_act_.data(), weights_.ffn_down.data(), output, hidden, intermediate);
    }
    
    // 11. Residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        output[i] = normed_[i] + output[i];
    }
    
    return true;
}

// Fused forward pass with kernel fusion
// Reduces memory round-trips for better performance
bool TransformerLayer::ForwardFused(const float* input, float* output,
                                      KVCache& kv_cache, uint32_t position) {
    uint32_t hidden = config_.hidden_size;
    uint32_t kv_hidden = config_.num_kv_heads * config_.head_dim;
    uint32_t intermediate = config_.intermediate_size;
    
    // === Attention Block (Fused) ===
    // 1. RMSNorm + QKV projections fused
    // First compute RMSNorm scale, then use it during QKV projections
    float rms_scale = 0.0f;
    {
        __m512 sum_sq_vec = _mm512_setzero_ps();
        size_t i = 0;
        for (; i + 16 <= hidden; i += 16) {
            __m512 val = _mm512_loadu_ps(&input[i]);
            sum_sq_vec = _mm512_fmadd_ps(val, val, sum_sq_vec);
        }
        float sum_sq = _mm512_reduce_add_ps(sum_sq_vec);
        for (; i < hidden; i++) {
            sum_sq += input[i] * input[i];
        }
        rms_scale = 1.0f / std::sqrt(sum_sq / hidden + config_.rms_norm_eps);
    }
    
    // Apply RMSNorm to working buffer
    for (uint32_t i = 0; i < hidden; i++) {
        normed_[i] = input[i] * rms_scale * weights_.attn_norm[i];
    }
    
    // 2. Fused QKV projections - all three with cached normalized input
    SEG::FusedQKVProjection(normed_.data(),
                             weights_.q_weight.data(),
                             weights_.k_weight.data(),
                             weights_.v_weight.data(),
                             q_proj_.data(), k_proj_.data(), v_proj_.data(),
                             hidden, kv_hidden);
    
    // 3. Attention (Flash Attention)
    AttentionForward(q_proj_.data(), k_proj_.data(), v_proj_.data(),
                     attn_out_.data(), kv_cache, position);
    
    // 4. Output projection
    SEG::FastVecMatMul(attn_out_.data(), weights_.o_weight.data(), normed_.data(), hidden, hidden);
    
    // 5. Fused Residual + RMSNorm for FFN input
    // Compute residual and RMSNorm in one pass
    float ffn_rms_scale = 0.0f;
    {
        __m512 sum_sq_vec = _mm512_setzero_ps();
        size_t i = 0;
        for (; i + 16 <= hidden; i += 16) {
            __m512 val = _mm512_loadu_ps(&input[i]);
            __m512 norm_val = _mm512_loadu_ps(&normed_[i]);
            __m512 sum = _mm512_add_ps(val, norm_val);
            sum_sq_vec = _mm512_fmadd_ps(sum, sum, sum_sq_vec);
        }
        float sum_sq = _mm512_reduce_add_ps(sum_sq_vec);
        for (; i < hidden; i++) {
            float sum = input[i] + normed_[i];
            sum_sq += sum * sum;
        }
        ffn_rms_scale = 1.0f / std::sqrt(sum_sq / hidden + config_.rms_norm_eps);
    }
    
    // Apply FFN RMSNorm
    for (uint32_t i = 0; i < hidden; i++) {
        float sum = input[i] + normed_[i];
        ffn_gate_[i] = sum * ffn_rms_scale * weights_.ffn_norm[i];
    }
    
    // === FFN Block (Fused) ===
    // 6. FFN Gate and Up projections
    // Reuse normed_ buffer for FFN input
    std::memcpy(normed_.data(), ffn_gate_.data(), hidden * sizeof(float));
    
    SEG::FastVecMatMul(normed_.data(), weights_.ffn_gate.data(),
                       ffn_gate_.data(), intermediate, hidden);
    SEG::FastVecMatMul(normed_.data(), weights_.ffn_up.data(),
                       ffn_up_.data(), intermediate, hidden);
    
    // 7. SiLU on gate (using existing optimized implementation)
    SiLU(ffn_gate_.data(), intermediate);
    
    // 8. Fused Multiply + Down projection
    // This fuses the element-wise multiply with the down projection
    SEG::FusedMultiplyMatMul(ffn_gate_.data(), ffn_up_.data(),
                             weights_.ffn_down.data(), output,
                             hidden, intermediate);
    
    // 9. Final residual connection
    for (uint32_t i = 0; i < hidden; i++) {
        output[i] = normed_[i] + output[i];
    }
    
    return true;
}

} // namespace Inference
} // namespace RawrXD
