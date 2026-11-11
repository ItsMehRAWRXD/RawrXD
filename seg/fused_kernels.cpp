// ============================================================================
// Fused Kernels Implementation
// ============================================================================
// Combines multiple operations to reduce memory round-trips
// ============================================================================

#include "fused_kernels.hpp"
#include <immintrin.h>
#include <cmath>

namespace SEG {

// Fast sigmoid approximation using polynomial
// sigmoid(x) ≈ 0.5 + 0.5 * tanh(x/2) ≈ 0.5 + 0.25*x for small x, clamped
inline __m512 FastSigmoid(__m512 x) {
    // Clamp to avoid overflow
    __m512 min_val = _mm512_set1_ps(-10.0f);
    __m512 max_val = _mm512_set1_ps(10.0f);
    x = _mm512_max_ps(x, min_val);
    x = _mm512_min_ps(x, max_val);
    
    // Polynomial approximation: sigmoid(x) ≈ 0.5 + 0.25*x - 0.02*x^3
    __m512 half = _mm512_set1_ps(0.5f);
    __m512 quarter = _mm512_set1_ps(0.25f);
    __m512 coeff3 = _mm512_set1_ps(-0.02f);
    
    __m512 x2 = _mm512_mul_ps(x, x);
    __m512 x3 = _mm512_mul_ps(x2, x);
    
    return _mm512_add_ps(half, _mm512_add_ps(_mm512_mul_ps(quarter, x), _mm512_mul_ps(coeff3, x3)));
}

// Fused RMSNorm + MatMul
// Reduces memory traffic by computing RMSNorm on-the-fly during MatMul
void FusedRMSNormMatMul(const float* input, const float* weight_norm,
                        const float* weights, float* output,
                        size_t N, size_t K, float eps) {
    // First compute RMSNorm scale factor
    __m512 sum_sq_vec = _mm512_setzero_ps();
    size_t i = 0;
    for (; i + 16 <= K; i += 16) {
        __m512 val = _mm512_loadu_ps(&input[i]);
        sum_sq_vec = _mm512_fmadd_ps(val, val, sum_sq_vec);
    }
    float sum_sq = _mm512_reduce_add_ps(sum_sq_vec);
    for (; i < K; i++) {
        sum_sq += input[i] * input[i];
    }
    float scale = 1.0f / std::sqrt(sum_sq / K + eps);
    
    // Now perform MatMul with on-the-fly RMSNorm
    for (size_t n = 0; n < N; n++) {
        __m512 sum_vec0 = _mm512_setzero_ps();
        __m512 sum_vec1 = _mm512_setzero_ps();
        __m512 sum_vec2 = _mm512_setzero_ps();
        __m512 sum_vec3 = _mm512_setzero_ps();
        const float* weight_row = weights + n * K;
        
        size_t k = 0;
        // 4x unrolled with prefetching
        for (; k + 64 <= K; k += 64) {
            _mm_prefetch(reinterpret_cast<const char*>(&input[k + 64]), _MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(&weight_row[k + 64]), _MM_HINT_T0);
            
            // Load and normalize input on-the-fly
            __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
            __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
            __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
            __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
            __m512 norm_vec0 = _mm512_loadu_ps(&weight_norm[k]);
            __m512 norm_vec1 = _mm512_loadu_ps(&weight_norm[k + 16]);
            __m512 norm_vec2 = _mm512_loadu_ps(&weight_norm[k + 32]);
            __m512 norm_vec3 = _mm512_loadu_ps(&weight_norm[k + 48]);
            
            // Apply RMSNorm: input * scale * weight_norm
            __m512 scale_vec = _mm512_set1_ps(scale);
            input_vec0 = _mm512_mul_ps(_mm512_mul_ps(input_vec0, scale_vec), norm_vec0);
            input_vec1 = _mm512_mul_ps(_mm512_mul_ps(input_vec1, scale_vec), norm_vec1);
            input_vec2 = _mm512_mul_ps(_mm512_mul_ps(input_vec2, scale_vec), norm_vec2);
            input_vec3 = _mm512_mul_ps(_mm512_mul_ps(input_vec3, scale_vec), norm_vec3);
            
            __m512 weight_vec0 = _mm512_loadu_ps(&weight_row[k]);
            __m512 weight_vec1 = _mm512_loadu_ps(&weight_row[k + 16]);
            __m512 weight_vec2 = _mm512_loadu_ps(&weight_row[k + 32]);
            __m512 weight_vec3 = _mm512_loadu_ps(&weight_row[k + 48]);
            
            sum_vec0 = _mm512_fmadd_ps(input_vec0, weight_vec0, sum_vec0);
            sum_vec1 = _mm512_fmadd_ps(input_vec1, weight_vec1, sum_vec1);
            sum_vec2 = _mm512_fmadd_ps(input_vec2, weight_vec2, sum_vec2);
            sum_vec3 = _mm512_fmadd_ps(input_vec3, weight_vec3, sum_vec3);
        }
        
        // Combine partial sums
        __m512 sum_vec = _mm512_add_ps(_mm512_add_ps(sum_vec0, sum_vec1),
                                       _mm512_add_ps(sum_vec2, sum_vec3));
        
        // Process remaining elements
        for (; k + 16 <= K; k += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input[k]);
            __m512 norm_vec = _mm512_loadu_ps(&weight_norm[k]);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
            input_vec = _mm512_mul_ps(_mm512_mul_ps(input_vec, _mm512_set1_ps(scale)), norm_vec);
            sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        
        // Scalar remainder
        for (; k < K; k++) {
            float normalized = input[k] * scale * weight_norm[k];
            sum += normalized * weight_row[k];
        }
        
        output[n] = sum;
    }
}

// Fused Multiply + MatMul for FFN
// Computes: output = MatMul(activated * up, down_weights)
// where activated is already SiLU(gate)
// This fuses the element-wise multiply with the down projection
void FusedMultiplyMatMul(const float* activated, const float* up,
                          const float* down_weights, float* output,
                          size_t hidden, size_t intermediate) {
    // Process each output element
    for (size_t h = 0; h < hidden; h++) {
        __m512 sum_vec0 = _mm512_setzero_ps();
        __m512 sum_vec1 = _mm512_setzero_ps();
        __m512 sum_vec2 = _mm512_setzero_ps();
        __m512 sum_vec3 = _mm512_setzero_ps();
        const float* weight_row = down_weights + h * intermediate;
        
        size_t i = 0;
        // 4x unrolled with on-the-fly multiply
        for (; i + 64 <= intermediate; i += 64) {
            _mm_prefetch(reinterpret_cast<const char*>(&activated[i + 64]), _MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(&up[i + 64]), _MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(&weight_row[i + 64]), _MM_HINT_T0);
            
            // Load activated and up, multiply on-the-fly
            __m512 act_vec0 = _mm512_loadu_ps(&activated[i]);
            __m512 act_vec1 = _mm512_loadu_ps(&activated[i + 16]);
            __m512 act_vec2 = _mm512_loadu_ps(&activated[i + 32]);
            __m512 act_vec3 = _mm512_loadu_ps(&activated[i + 48]);
            __m512 up_vec0 = _mm512_loadu_ps(&up[i]);
            __m512 up_vec1 = _mm512_loadu_ps(&up[i + 16]);
            __m512 up_vec2 = _mm512_loadu_ps(&up[i + 32]);
            __m512 up_vec3 = _mm512_loadu_ps(&up[i + 48]);
            
            // Element-wise multiply: activated * up
            __m512 prod_vec0 = _mm512_mul_ps(act_vec0, up_vec0);
            __m512 prod_vec1 = _mm512_mul_ps(act_vec1, up_vec1);
            __m512 prod_vec2 = _mm512_mul_ps(act_vec2, up_vec2);
            __m512 prod_vec3 = _mm512_mul_ps(act_vec3, up_vec3);
            
            // Load weights and accumulate
            __m512 weight_vec0 = _mm512_loadu_ps(&weight_row[i]);
            __m512 weight_vec1 = _mm512_loadu_ps(&weight_row[i + 16]);
            __m512 weight_vec2 = _mm512_loadu_ps(&weight_row[i + 32]);
            __m512 weight_vec3 = _mm512_loadu_ps(&weight_row[i + 48]);
            
            sum_vec0 = _mm512_fmadd_ps(prod_vec0, weight_vec0, sum_vec0);
            sum_vec1 = _mm512_fmadd_ps(prod_vec1, weight_vec1, sum_vec1);
            sum_vec2 = _mm512_fmadd_ps(prod_vec2, weight_vec2, sum_vec2);
            sum_vec3 = _mm512_fmadd_ps(prod_vec3, weight_vec3, sum_vec3);
        }
        
        // Combine partial sums
        __m512 sum_vec = _mm512_add_ps(_mm512_add_ps(sum_vec0, sum_vec1),
                                       _mm512_add_ps(sum_vec2, sum_vec3));
        
        // Process remaining elements
        for (; i + 16 <= intermediate; i += 16) {
            __m512 act_vec = _mm512_loadu_ps(&activated[i]);
            __m512 up_vec = _mm512_loadu_ps(&up[i]);
            __m512 prod_vec = _mm512_mul_ps(act_vec, up_vec);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[i]);
            sum_vec = _mm512_fmadd_ps(prod_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        
        // Scalar remainder
        for (; i < intermediate; i++) {
            float prod = activated[i] * up[i];
            sum += prod * weight_row[i];
        }
        
        output[h] = sum;
    }
}

// Fused Residual + RMSNorm
void FusedResidualRMSNorm(const float* input, const float* residual,
                          const float* weight, float* output,
                          size_t size, float eps) {
    // Compute sum of squares on-the-fly during addition
    __m512 sum_sq_vec = _mm512_setzero_ps();
    
    // First pass: compute residual + input and sum of squares
    // We'll do this in a single pass where possible
    size_t i = 0;
    for (; i + 16 <= size; i += 16) {
        __m512 input_vec = _mm512_loadu_ps(&input[i]);
        __m512 residual_vec = _mm512_loadu_ps(&residual[i]);
        __m512 sum_vec = _mm512_add_ps(input_vec, residual_vec);
        sum_sq_vec = _mm512_fmadd_ps(sum_vec, sum_vec, sum_sq_vec);
    }
    
    float sum_sq = _mm512_reduce_add_ps(sum_sq_vec);
    for (; i < size; i++) {
        float sum = input[i] + residual[i];
        sum_sq += sum * sum;
    }
    
    float scale = 1.0f / std::sqrt(sum_sq / size + eps);
    
    // Second pass: normalize and apply weight
    i = 0;
    for (; i + 16 <= size; i += 16) {
        __m512 input_vec = _mm512_loadu_ps(&input[i]);
        __m512 residual_vec = _mm512_loadu_ps(&residual[i]);
        __m512 sum_vec = _mm512_add_ps(input_vec, residual_vec);
        __m512 weight_vec = _mm512_loadu_ps(&weight[i]);
        __m512 scale_vec = _mm512_set1_ps(scale);
        __m512 result_vec = _mm512_mul_ps(_mm512_mul_ps(sum_vec, scale_vec), weight_vec);
        _mm512_storeu_ps(&output[i], result_vec);
    }
    
    for (; i < size; i++) {
        float sum = input[i] + residual[i];
        output[i] = sum * scale * weight[i];
    }
}

// Fused QKV projection
void FusedQKVProjection(const float* input_normed,
                         const float* q_weights, const float* k_weights,
                         const float* v_weights,
                         float* q_out, float* k_out, float* v_out,
                         size_t hidden, size_t kv_hidden) {
    // Process all three projections with shared input
    // This keeps the normalized input in cache
    
    // Q projection: [hidden]
    for (size_t n = 0; n < hidden; n++) {
        __m512 sum_vec = _mm512_setzero_ps();
        const float* weight_row = q_weights + n * hidden;
        
        size_t k = 0;
        for (; k + 16 <= hidden; k += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input_normed[k]);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
            sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        for (; k < hidden; k++) {
            sum += input_normed[k] * weight_row[k];
        }
        q_out[n] = sum;
    }
    
    // K projection: [kv_hidden]
    for (size_t n = 0; n < kv_hidden; n++) {
        __m512 sum_vec = _mm512_setzero_ps();
        const float* weight_row = k_weights + n * hidden;
        
        size_t k = 0;
        for (; k + 16 <= hidden; k += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input_normed[k]);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
            sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        for (; k < hidden; k++) {
            sum += input_normed[k] * weight_row[k];
        }
        k_out[n] = sum;
    }
    
    // V projection: [kv_hidden]
    for (size_t n = 0; n < kv_hidden; n++) {
        __m512 sum_vec = _mm512_setzero_ps();
        const float* weight_row = v_weights + n * hidden;
        
        size_t k = 0;
        for (; k + 16 <= hidden; k += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input_normed[k]);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
            sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        for (; k < hidden; k++) {
            sum += input_normed[k] * weight_row[k];
        }
        v_out[n] = sum;
    }
}

} // namespace SEG
