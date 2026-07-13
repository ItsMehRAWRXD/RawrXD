// ============================================================================
// Quantized Matrix Multiplication Implementation
// ============================================================================
// On-the-fly dequantization for reduced memory bandwidth
// ============================================================================

#include "quantized_matmul.hpp"
#include "avx512_kernels.hpp"
#include <immintrin.h>
#include <cstring>

namespace SEG {

// Simple Q8_K structure for testing
struct BlockQ8_K_Simple {
    float d;              // scale
    int8_t qs[256];       // quantized values
};

// Quantized vector-matrix multiplication with on-the-fly dequantization
// This reduces memory bandwidth by 4x compared to float32
void QuantizedVecMatMulQ8_K(const float* input, const void* weights_q8_k,
                            float* output,
                            size_t N, size_t K) {
    const BlockQ8_K_Simple* blocks = static_cast<const BlockQ8_K_Simple*>(weights_q8_k);
    const size_t num_blocks = K / 256;
    
    // Clear output
    std::memset(output, 0, N * sizeof(float));
    
    // Process each output column
    for (size_t n = 0; n < N; n++) {
        float sum = 0.0f;
        
        // Process K dimension in blocks of 256
        for (size_t block_idx = 0; block_idx < num_blocks; block_idx++) {
            const BlockQ8_K_Simple& block = blocks[block_idx * N + n];
            const float* input_block = input + block_idx * 256;
            
            // AVX-512 accumulation with on-the-fly dequantization
            __m512 sum_vec = _mm512_setzero_ps();
            __m512 scale_vec = _mm512_set1_ps(block.d);
            
            size_t k = 0;
            for (; k + 16 <= 256; k += 16) {
                // Load input
                __m512 input_vec = _mm512_loadu_ps(&input_block[k]);
                
                // Load and dequantize weights
                // Convert int8 to float and scale
                __m512i weight_i8 = _mm512_cvtepi8_epi32(
                    _mm_loadu_si128(reinterpret_cast<const __m128i*>(&block.qs[k]))
                );
                __m512 weight_vec = _mm512_cvtepi32_ps(weight_i8);
                weight_vec = _mm512_mul_ps(weight_vec, scale_vec);
                
                // Multiply-accumulate
                sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
            }
            
            // Horizontal sum
            sum += _mm512_reduce_add_ps(sum_vec);
            
            // Scalar remainder (shouldn't happen with 256-block size)
            for (; k < 256; k++) {
                sum += input_block[k] * (block.qs[k] * block.d);
            }
        }
        
        output[n] = sum;
    }
}

// Standard float MatMul for comparison
void StandardVecMatMul(const float* input, const float* weights,
                        float* output,
                        size_t N, size_t K) {
    std::memset(output, 0, N * sizeof(float));
    
    for (size_t n = 0; n < N; n++) {
        float sum = 0.0f;
        for (size_t k = 0; k < K; k++) {
            sum += input[k] * weights[n * K + k];
        }
        output[n] = sum;
    }
}

} // namespace SEG
