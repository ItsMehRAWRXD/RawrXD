//=============================================================================
// Sliding Window Attention Implementation - AVX-512 Optimized
// O(n·w) complexity vs O(n²) for full attention
//=============================================================================

#include "sliding_window_attention.hpp"
#include <cstring>  // For memset

namespace RawrXD {
namespace Kernels {

//=============================================================================
// Main Sliding Window Attention Kernel
//=============================================================================

extern "C" void sliding_window_attention_avx512(
    const float* __restrict Q,
    const float* __restrict K_cache,
    const float* __restrict V_cache,
    float* __restrict output,
    int batch_size,
    int seq_len,
    int num_heads,
    int head_dim,
    size_t kv_cache_head
) {
    const float scale = 1.0f / sqrtf(static_cast<float>(head_dim));
    
    // Temporary buffer for attention scores (max window size)
    alignas(64) float scores[kSlidingWindowSize];
    
    for (int b = 0; b < batch_size; b++) {
        for (int h = 0; h < num_heads; h++) {
            // Calculate offsets for this head
            int head_offset = (b * num_heads + h) * seq_len * head_dim;
            const float* q_head = Q + head_offset;
            const float* k_head = K_cache + (h * kSlidingWindowSize * head_dim);
            const float* v_head = V_cache + (h * kSlidingWindowSize * head_dim);
            float* out_head = output + head_offset;
            
            // Process each query position
            for (int i = 0; i < seq_len; i++) {
                const float* q_vec = q_head + (i * head_dim);
                float* out_vec = out_head + (i * head_dim);
                
                // Determine window bounds for this query
                size_t window_start = (i > kSlidingWindowSize) ? (i - kSlidingWindowSize) : 0;
                size_t window_end = i + 1;  // Include current position (causal)
                size_t window_size = window_end - window_start;
                
                // Step 1: Compute attention scores (Q · K^T)
                ComputeWindowedAttentionScores(
                    q_vec, k_head, scores,
                    head_dim, window_start, window_end, scale
                );
                
                // Step 2: Softmax over window
                WindowedSoftmax(scores, window_size);
                
                // Step 3: Weighted sum of values
                ComputeWeightedSum(
                    v_head, scores, out_vec,
                    head_dim, window_start, window_size
                );
            }
        }
    }
}

//=============================================================================
// Optimized version for fixed-size heads (common case: 64, 128 dims)
//=============================================================================

template <int HeadDim>
void sliding_window_attention_fixed_impl(
    const float* __restrict Q,
    const float* __restrict K_cache,
    const float* __restrict V_cache,
    float* __restrict output,
    int batch_size,
    int seq_len,
    int num_heads
) {
    constexpr int simd_width = 16;  // AVX-512
    constexpr int num_simd_iters = HeadDim / simd_width;
    constexpr int tail_size = HeadDim % simd_width;
    
    // Validate alignment at compile time
    static_assert(HeadDim >= simd_width, "HeadDim must be at least 16");
    
    const float scale = 1.0f / sqrtf(static_cast<float>(HeadDim));
    alignas(64) float scores[kSlidingWindowSize];
    
    for (int b = 0; b < batch_size; b++) {
        for (int h = 0; h < num_heads; h++) {
            int head_offset = (b * num_heads + h) * seq_len * HeadDim;
            const float* q_head = Q + head_offset;
            const float* k_head = K_cache + (h * kSlidingWindowSize * HeadDim);
            const float* v_head = V_cache + (h * kSlidingWindowSize * HeadDim);
            float* out_head = output + head_offset;
            
            for (int i = 0; i < seq_len; i++) {
                const float* q_vec = q_head + (i * HeadDim);
                float* out_vec = out_head + (i * HeadDim);
                
                size_t window_start = (i > kSlidingWindowSize) ? (i - kSlidingWindowSize) : 0;
                size_t window_end = i + 1;
                size_t window_size = window_end - window_start;
                
                // Compute scores with SIMD + tail handling
                for (size_t j = window_start; j < window_end; j++) {
                    const float* k_vec = k_head + ((j & KVCacheRingBuffer<float, 4096>::kMask) * HeadDim);
                    
                    __m512 sum_vec = _mm512_setzero_ps();
                    
                    // Main SIMD loop (16 floats at a time)
                    #pragma unroll
                    for (int d = 0; d < num_simd_iters; d++) {
                        __m512 q = _mm512_load_ps(q_vec + d * simd_width);
                        __m512 k = _mm512_load_ps(k_vec + d * simd_width);
                        sum_vec = _mm512_fmadd_ps(q, k, sum_vec);
                    }
                    
                    // Tail handling (remaining elements)
                    float tail_sum = 0.0f;
                    if constexpr (tail_size > 0) {
                        for (int d = num_simd_iters * simd_width; d < HeadDim; d++) {
                            tail_sum += q_vec[d] * k_vec[d];
                        }
                    }
                    
                    scores[j - window_start] = (_mm512_reduce_add_ps(sum_vec) + tail_sum) * scale;
                }
                
                // Softmax
                WindowedSoftmax(scores, window_size);
                
                // Weighted sum with SIMD + tail handling
                __m512 out_acc[num_simd_iters];
                float tail_acc[tail_size > 0 ? tail_size : 1] = {};
                
                #pragma unroll
                for (int d = 0; d < num_simd_iters; d++) {
                    out_acc[d] = _mm512_setzero_ps();
                }
                
                // Accumulate weighted values
                for (size_t j = 0; j < window_size; j++) {
                    size_t cache_idx = window_start + j;
                    const float* v_vec = v_head + ((cache_idx & KVCacheRingBuffer<float, 4096>::kMask) * HeadDim);
                    __m512 score_vec = _mm512_set1_ps(scores[j]);
                    
                    #pragma unroll
                    for (int d = 0; d < num_simd_iters; d++) {
                        __m512 v = _mm512_load_ps(v_vec + d * simd_width);
                        out_acc[d] = _mm512_fmadd_ps(score_vec, v, out_acc[d]);
                    }
                    
                    // Tail handling
                    if constexpr (tail_size > 0) {
                        for (int d = 0; d < tail_size; d++) {
                            tail_acc[d] += scores[j] * v_vec[num_simd_iters * simd_width + d];
                        }
                    }
                }
                
                // Store SIMD results
                #pragma unroll
                for (int d = 0; d < num_simd_iters; d++) {
                    _mm512_store_ps(out_vec + d * simd_width, out_acc[d]);
                }
                
                // Store tail results
                if constexpr (tail_size > 0) {
                    for (int d = 0; d < tail_size; d++) {
                        out_vec[num_simd_iters * simd_width + d] = tail_acc[d];
                    }
                }
            }
        }
    }
}

// Explicit instantiations for common head sizes
void sliding_window_attention_64(
    const float* Q, const float* K_cache, const float* V_cache,
    float* output, int batch_size, int seq_len, int num_heads
) {
    sliding_window_attention_fixed_impl<64>(Q, K_cache, V_cache, output, batch_size, seq_len, num_heads);
}

void sliding_window_attention_128(
    const float* Q, const float* K_cache, const float* V_cache,
    float* output, int batch_size, int seq_len, int num_heads
) {
    sliding_window_attention_fixed_impl<128>(Q, K_cache, V_cache, output, batch_size, seq_len, num_heads);
}

//=============================================================================
// Performance Comparison Helper
//=============================================================================

// Returns theoretical speedup of sliding window vs full attention
double CalculateSlidingWindowSpeedup(int seq_len, int window_size) {
    if (seq_len <= window_size) {
        return 1.0;  // No benefit for short sequences
    }
    
    // Full attention: O(n²) operations
    double full_ops = static_cast<double>(seq_len) * seq_len;
    
    // Sliding window: O(n·w) operations
    double window_ops = static_cast<double>(seq_len) * window_size;
    
    return full_ops / window_ops;
}

// Expected TPS improvement
void PrintPerformanceProjection(int current_tps, int seq_len) {
    double speedup = CalculateSlidingWindowSpeedup(seq_len, kSlidingWindowSize);
    int projected_tps = static_cast<int>(current_tps * speedup);
    
    printf("Sliding Window Attention Performance Projection:\n");
    printf("  Sequence Length: %d\n", seq_len);
    printf("  Window Size: %d\n", kSlidingWindowSize);
    printf("  Complexity Reduction: O(n²) → O(n·w) = %.1fx\n", speedup);
    printf("  Current TPS: %d\n", current_tps);
    printf("  Projected TPS: %d\n", projected_tps);
    printf("  Target TPS: 875\n");
    printf("  Status: %s\n", (projected_tps >= 875) ? "✅ TARGET ACHIEVED" : "⚠️  ADDITIONAL OPTIMIZATIONS NEEDED");
}

} // namespace Kernels
} // namespace RawrXD
