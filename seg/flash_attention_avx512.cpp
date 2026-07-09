// ============================================================================
// Flash Attention Implementation for AVX-512
// ============================================================================
// Memory-efficient attention using online softmax and tiling
// ============================================================================

#include "flash_attention_avx512.hpp"
#include <immintrin.h>
#include <cmath>
#include <algorithm>

namespace SEG {

// Tile size for Flash Attention - chosen to fit in L1 cache
static constexpr size_t BLOCK_SIZE = 64;

// Online softmax update
// Given current max and sum, update with new values
static inline void OnlineSoftmaxUpdate(float& max_val, float& sum_exp, 
                                        float new_max, float new_sum) {
    float max_prev = max_val;
    max_val = std::max(max_val, new_max);
    sum_exp = sum_exp * std::exp(max_prev - max_val) + new_sum * std::exp(new_max - max_val);
}

void FlashAttentionCachedF32(const float* q,
                                const float* k_cache, const float* v_cache,
                                float* output,
                                size_t cache_len, size_t head_dim) {
    // Initialize output and running statistics
    float max_score = -INFINITY;
    float sum_exp = 0.0f;
    
    // Clear output
    for (size_t d = 0; d < head_dim; d++) {
        output[d] = 0.0f;
    }
    
    // Process KV cache in blocks for cache efficiency
    for (size_t block_start = 0; block_start < cache_len; block_start += BLOCK_SIZE) {
        size_t block_end = std::min(block_start + BLOCK_SIZE, cache_len);
        size_t block_len = block_end - block_start;
        
        // Compute attention scores for this block: Q @ K^T
        float block_scores[BLOCK_SIZE];
        float block_max = -INFINITY;
        
        for (size_t pos = 0; pos < block_len; pos++) {
            const float* k_vec = k_cache + (block_start + pos) * head_dim;
            
            // Compute dot product Q @ K^T
            float dot = 0.0f;
            size_t d = 0;
            
            // AVX-512 dot product
            __m512 sum_vec = _mm512_setzero_ps();
            for (; d + 16 <= head_dim; d += 16) {
                __m512 q_vec = _mm512_loadu_ps(&q[d]);
                __m512 k_vec_avx = _mm512_loadu_ps(&k_vec[d]);
                sum_vec = _mm512_fmadd_ps(q_vec, k_vec_avx, sum_vec);
            }
            dot = _mm512_reduce_add_ps(sum_vec);
            
            // Scalar remainder
            for (; d < head_dim; d++) {
                dot += q[d] * k_vec[d];
            }
            
            // Scale by sqrt(head_dim)
            float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
            block_scores[pos] = dot * scale;
            block_max = std::max(block_max, block_scores[pos]);
        }
        
        // Compute softmax for this block
        float block_sum = 0.0f;
        for (size_t pos = 0; pos < block_len; pos++) {
            block_scores[pos] = std::exp(block_scores[pos] - block_max);
            block_sum += block_scores[pos];
        }
        
        // Update online softmax statistics
        float max_prev = max_score;
        max_score = std::max(max_score, block_max);
        float exp_scale = std::exp(max_prev - max_score);
        sum_exp = sum_exp * exp_scale + block_sum * std::exp(block_max - max_score);
        
        // Accumulate weighted values
        for (size_t pos = 0; pos < block_len; pos++) {
            const float* v_vec = v_cache + (block_start + pos) * head_dim;
            float weight = block_scores[pos];
            
            size_t d = 0;
            // AVX-512 accumulation
            for (; d + 16 <= head_dim; d += 16) {
                __m512 out_vec = _mm512_loadu_ps(&output[d]);
                __m512 v_vec_avx = _mm512_loadu_ps(&v_vec[d]);
                __m512 weight_vec = _mm512_set1_ps(weight);
                out_vec = _mm512_fmadd_ps(weight_vec, v_vec_avx, out_vec);
                _mm512_storeu_ps(&output[d], out_vec);
            }
            
            // Scalar remainder
            for (; d < head_dim; d++) {
                output[d] += weight * v_vec[d];
            }
        }
    }
    
    // Normalize by softmax sum
    float norm_scale = 1.0f / sum_exp;
    size_t d = 0;
    
    // AVX-512 normalization
    __m512 scale_vec = _mm512_set1_ps(norm_scale);
    for (; d + 16 <= head_dim; d += 16) {
        __m512 out_vec = _mm512_loadu_ps(&output[d]);
        out_vec = _mm512_mul_ps(out_vec, scale_vec);
        _mm512_storeu_ps(&output[d], out_vec);
    }
    
    // Scalar remainder
    for (; d < head_dim; d++) {
        output[d] *= norm_scale;
    }
}

void FlashAttentionForwardF32(const float* Q, const float* K, const float* V,
                                 float* output,
                                 size_t seq_len, size_t head_dim) {
    // For each query position
    for (size_t q_pos = 0; q_pos < seq_len; q_pos++) {
        const float* q_vec = Q + q_pos * head_dim;
        float* out_vec = output + q_pos * head_dim;
        
        // Use cached version with full KV cache up to q_pos
        FlashAttentionCachedF32(q_vec, K, V, out_vec, q_pos + 1, head_dim);
    }
}

} // namespace SEG
