// ============================================================================
// Fused FFN Kernels Implementation
// ============================================================================
// Combines multiple operations to reduce memory round-trips
// ============================================================================

#include "fused_ffn_kernels.hpp"
#include <immintrin.h>
#include <cmath>

namespace SEG {

// Fused SiLU + Multiply + Down Projection
// Computes: output = (silu(gate) * up) @ down_weights
void FusedSiLUMulDownProj(const float* gate, const float* up,
                          const float* down_weights,
                          float* output,
                          size_t hidden, size_t intermediate) {
    // Process output elements with fused computation
    for (size_t h = 0; h < hidden; h++) {
        __m512 sum_vec = _mm512_setzero_ps();
        const float* weight_row = down_weights + h * intermediate;
        
        size_t i = 0;
        // Process 16 elements at a time with fused SiLU+multiply
        for (; i + 16 <= intermediate; i += 16) {
            // Load gate and up
            __m512 gate_vec = _mm512_loadu_ps(&gate[i]);
            __m512 up_vec = _mm512_loadu_ps(&up[i]);
            
            // Compute SiLU: x * sigmoid(x)
            // Approximate sigmoid with fast formula
            __m512 neg_gate = _mm512_sub_ps(_mm512_set1_ps(0.0f), gate_vec);
            __m512 exp_neg = _mm512_exp_ps(neg_gate); // Note: exp is expensive, consider approximation
            __m512 sigmoid = _mm512_div_ps(_mm512_set1_ps(1.0f), 
                                           _mm512_add_ps(_mm512_set1_ps(1.0f), exp_neg));
            __m512 silu_vec = _mm512_mul_ps(gate_vec, sigmoid);
            
            // Multiply with up
            __m512 mul_vec = _mm512_mul_ps(silu_vec, up_vec);
            
            // Load weights and accumulate
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[i]);
            sum_vec = _mm512_fmadd_ps(mul_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        
        // Scalar remainder
        for (; i < intermediate; i++) {
            float x = gate[i];
            float sigmoid = 1.0f / (1.0f + std::exp(-x));
            float silu = x * sigmoid;
            sum += silu * up[i] * weight_row[i];
        }
        
        output[h] = sum;
    }
}

// Simpler fused kernel: SiLU + Multiply only (no down proj)
// This is more practical as down proj is a separate MatMul
void FusedSiLUMultiply(const float* gate, const float* up,
                       float* output, size_t n) {
    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= n; i += 16) {
        __m512 gate_vec = _mm512_loadu_ps(&gate[i]);
        __m512 up_vec = _mm512_loadu_ps(&up[i]);
        
        // SiLU: x * sigmoid(x)
        // Use fast approximation: sigmoid(x) ≈ 1 / (1 + exp(-x))
        __m512 neg_gate = _mm512_sub_ps(_mm512_set1_ps(0.0f), gate_vec);
        // For performance, use scalar exp in loop or approximate
        // Here we'll do scalar for simplicity
        _mm512_storeu_ps(&output[i], _mm512_setzero_ps());
    }
    
    // Scalar version for the actual computation
    for (i = 0; i < n; i++) {
        float x = gate[i];
        float sigmoid = 1.0f / (1.0f + std::exp(-x));
        output[i] = x * sigmoid * up[i];
    }
}

// Optimized version using precomputed SiLU
void FastSiLUMultiply(const float* gate, const float* up,
                      float* output, size_t n) {
    size_t i = 0;
    
    // AVX-512 version
    for (; i + 16 <= n; i += 16) {
        __m512 gate_vec = _mm512_loadu_ps(&gate[i]);
        __m512 up_vec = _mm512_loadu_ps(&up[i]);
        
        // Compute SiLU element-wise
        // sigmoid(x) = 1 / (1 + exp(-x))
        // We'll compute this more efficiently
        float gate_vals[16];
        float up_vals[16];
        _mm512_storeu_ps(gate_vals, gate_vec);
        _mm512_storeu_ps(up_vals, up_vec);
        
        float result[16];
        for (int j = 0; j < 16; j++) {
            float x = gate_vals[j];
            float sigmoid = 1.0f / (1.0f + std::exp(-x));
            result[j] = x * sigmoid * up_vals[j];
        }
        _mm512_storeu_ps(&output[i], _mm512_loadu_ps(result));
    }
    
    // Scalar remainder
    for (; i < n; i++) {
        float x = gate[i];
        float sigmoid = 1.0f / (1.0f + std::exp(-x));
        output[i] = x * sigmoid * up[i];
    }
}

void FusedRMSNormMatMul(const float* input, const float* norm_weights,
                        const float* matmul_weights,
                        float* output,
                        size_t hidden, size_t output_dim,
                        float eps) {
    // Compute RMSNorm first
    float sum_sq = 0.0f;
    for (size_t i = 0; i < hidden; i++) {
        sum_sq += input[i] * input[i];
    }
    float scale = 1.0f / std::sqrt(sum_sq / hidden + eps);
    
    // Then MatMul
    for (size_t o = 0; o < output_dim; o++) {
        float sum = 0.0f;
        const float* weight_row = matmul_weights + o * hidden;
        
        size_t i = 0;
        // AVX-512 accumulation
        __m512 sum_vec = _mm512_setzero_ps();
        __m512 scale_vec = _mm512_set1_ps(scale);
        
        for (; i + 16 <= hidden; i += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input[i]);
            __m512 norm_vec = _mm512_mul_ps(input_vec, scale_vec);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[i]);
            sum_vec = _mm512_fmadd_ps(norm_vec, weight_vec, sum_vec);
        }
        
        sum = _mm512_reduce_add_ps(sum_vec);
        
        // Scalar remainder
        for (; i < hidden; i++) {
            float norm_val = input[i] * scale * norm_weights[i];
            sum += norm_val * weight_row[i];
        }
        
        output[o] = sum;
    }
}

} // namespace SEG
