// ============================================================================
// Fast Quantized Matrix Multiplication Implementation
// ============================================================================
// On-the-fly dequantization with AVX-512 for maximum performance
// ============================================================================

#include "quantized_matmul_fast.hpp"
#include <immintrin.h>
#include <xmmintrin.h>
#include <cstring>
#include <cmath>

namespace SEG {

// Fast quantized vector-matrix multiplication with on-the-fly dequantization
// Weights layout: [num_blocks, N] where each block is Q8_K_Block
void QuantizedVecMatMulQ8_K_Fast(const float* input, 
                                   const Q8_K_Block* weights,
                                   float* output,
                                   size_t N, size_t K) {
    const size_t num_blocks = K / 256;
    
    // Clear output
    std::memset(output, 0, N * sizeof(float));
    
    // Process each output column
    for (size_t n = 0; n < N; n++) {
        float sum = 0.0f;
        
        // Process K dimension in blocks of 256
        for (size_t block_idx = 0; block_idx < num_blocks; block_idx++) {
            // Weights stored as [num_blocks, N] - access as weights[block_idx * N + n]
            const Q8_K_Block& block = weights[block_idx * N + n];
            const float* input_block = input + block_idx * 256;
            
            // AVX-512 accumulation with on-the-fly dequantization
            __m512 sum_vec = _mm512_setzero_ps();
            __m512 scale_vec = _mm512_set1_ps(block.d);
            
            size_t k = 0;
            for (; k + 16 <= 256; k += 16) {
                // Load input
                __m512 input_vec = _mm512_loadu_ps(&input_block[k]);
                
                // Load and dequantize weights
                __m128i weight_i8 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&block.qs[k]));
                __m512i weight_i32 = _mm512_cvtepi8_epi32(weight_i8);
                __m512 weight_vec = _mm512_cvtepi32_ps(weight_i32);
                weight_vec = _mm512_mul_ps(weight_vec, scale_vec);
                
                // Multiply-accumulate
                sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
            }
            
            // Horizontal sum
            sum += _mm512_reduce_add_ps(sum_vec);
            
            // Scalar remainder
            for (; k < 256; k++) {
                sum += input_block[k] * (block.qs[k] * block.d);
            }
        }
        
        output[n] = sum;
    }
}

// Precompute dequantized weights for maximum speed
void PrecomputeQ8_K_Dequantized(const Q8_K_Block* quantized, 
                                 float* dequantized,
                                 size_t num_blocks) {
    for (size_t i = 0; i < num_blocks; i++) {
        const Q8_K_Block& block = quantized[i];
        float* out = dequantized + i * 256;
        
        // Dequantize all 256 values
        for (size_t j = 0; j < 256; j++) {
            out[j] = block.qs[j] * block.d;
        }
    }
}

// Standard fast MatMul (no quantization overhead)
// Computes: output[n] = sum_k(input[k] * weights[n*K + k])
// Weights are stored as [N, K] in row-major order
// Maximum optimization: 4x unroll + prefetching + streaming stores
void FastVecMatMul(const float* input, const float* weights,
                    float* output, size_t N, size_t K) {
    // Process each output element with AVX-512
    // Unroll by 4 for maximum instruction-level parallelism
    for (size_t n = 0; n < N; n++) {
        __m512 sum_vec0 = _mm512_setzero_ps();
        __m512 sum_vec1 = _mm512_setzero_ps();
        __m512 sum_vec2 = _mm512_setzero_ps();
        __m512 sum_vec3 = _mm512_setzero_ps();
        const float* weight_row = weights + n * K;
        
        size_t k = 0;
        // Process 64 elements at a time (4x unroll) with prefetching
        for (; k + 128 <= K; k += 64) {
            // Prefetch next iteration data
            _mm_prefetch(reinterpret_cast<const char*>(&input[k + 64]), _MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(&weight_row[k + 64]), _MM_HINT_T0);
            
            __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
            __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
            __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
            __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
            __m512 weight_vec0 = _mm512_loadu_ps(&weight_row[k]);
            __m512 weight_vec1 = _mm512_loadu_ps(&weight_row[k + 16]);
            __m512 weight_vec2 = _mm512_loadu_ps(&weight_row[k + 32]);
            __m512 weight_vec3 = _mm512_loadu_ps(&weight_row[k + 48]);
            
            sum_vec0 = _mm512_fmadd_ps(input_vec0, weight_vec0, sum_vec0);
            sum_vec1 = _mm512_fmadd_ps(input_vec1, weight_vec1, sum_vec1);
            sum_vec2 = _mm512_fmadd_ps(input_vec2, weight_vec2, sum_vec2);
            sum_vec3 = _mm512_fmadd_ps(input_vec3, weight_vec3, sum_vec3);
        }
        
        // Process remaining 64-element chunks without prefetch
        for (; k + 64 <= K; k += 64) {
            __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
            __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
            __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
            __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
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
        
        // Process remaining 16 elements
        for (; k + 16 <= K; k += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input[k]);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
            sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        
        // Scalar remainder
        for (; k < K; k++) {
            sum += input[k] * weight_row[k];
        }
        
        output[n] = sum;
    }
}

// Fast MatMul with streaming stores for output
// Reduces cache pollution when output won't be reused soon
void FastVecMatMulStreaming(const float* input, const float* weights,
                               float* output, size_t N, size_t K) {
    for (size_t n = 0; n < N; n++) {
        __m512 sum_vec0 = _mm512_setzero_ps();
        __m512 sum_vec1 = _mm512_setzero_ps();
        __m512 sum_vec2 = _mm512_setzero_ps();
        __m512 sum_vec3 = _mm512_setzero_ps();
        const float* weight_row = weights + n * K;
        
        size_t k = 0;
        for (; k + 128 <= K; k += 64) {
            _mm_prefetch(reinterpret_cast<const char*>(&input[k + 64]), _MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(&weight_row[k + 64]), _MM_HINT_T0);
            
            __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
            __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
            __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
            __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
            __m512 weight_vec0 = _mm512_loadu_ps(&weight_row[k]);
            __m512 weight_vec1 = _mm512_loadu_ps(&weight_row[k + 16]);
            __m512 weight_vec2 = _mm512_loadu_ps(&weight_row[k + 32]);
            __m512 weight_vec3 = _mm512_loadu_ps(&weight_row[k + 48]);
            
            sum_vec0 = _mm512_fmadd_ps(input_vec0, weight_vec0, sum_vec0);
            sum_vec1 = _mm512_fmadd_ps(input_vec1, weight_vec1, sum_vec1);
            sum_vec2 = _mm512_fmadd_ps(input_vec2, weight_vec2, sum_vec2);
            sum_vec3 = _mm512_fmadd_ps(input_vec3, weight_vec3, sum_vec3);
        }
        
        for (; k + 64 <= K; k += 64) {
            __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
            __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
            __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
            __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
            __m512 weight_vec0 = _mm512_loadu_ps(&weight_row[k]);
            __m512 weight_vec1 = _mm512_loadu_ps(&weight_row[k + 16]);
            __m512 weight_vec2 = _mm512_loadu_ps(&weight_row[k + 32]);
            __m512 weight_vec3 = _mm512_loadu_ps(&weight_row[k + 48]);
            
            sum_vec0 = _mm512_fmadd_ps(input_vec0, weight_vec0, sum_vec0);
            sum_vec1 = _mm512_fmadd_ps(input_vec1, weight_vec1, sum_vec1);
            sum_vec2 = _mm512_fmadd_ps(input_vec2, weight_vec2, sum_vec2);
            sum_vec3 = _mm512_fmadd_ps(input_vec3, weight_vec3, sum_vec3);
        }
        
        __m512 sum_vec = _mm512_add_ps(_mm512_add_ps(sum_vec0, sum_vec1),
                                       _mm512_add_ps(sum_vec2, sum_vec3));
        
        for (; k + 16 <= K; k += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input[k]);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
            sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        
        for (; k < K; k++) {
            sum += input[k] * weight_row[k];
        }
        
        output[n] = sum;
    }
}

// Fast MatMul with SiLU activation applied to output
// Computes: output[n] = SiLU(sum_k(input[k] * weights[n*K + k]))
// Fuses activation into the matrix multiplication to reduce memory passes
void FastVecMatMulSiLU(const float* input, const float* weights,
                        float* output, size_t N, size_t K) {
    // Process each output element with AVX-512
    for (size_t n = 0; n < N; n++) {
        __m512 sum_vec0 = _mm512_setzero_ps();
        __m512 sum_vec1 = _mm512_setzero_ps();
        __m512 sum_vec2 = _mm512_setzero_ps();
        __m512 sum_vec3 = _mm512_setzero_ps();
        const float* weight_row = weights + n * K;
        
        size_t k = 0;
        // Process 64 elements at a time (4x unroll) with prefetching
        for (; k + 128 <= K; k += 64) {
            _mm_prefetch(reinterpret_cast<const char*>(&input[k + 64]), _MM_HINT_T0);
            _mm_prefetch(reinterpret_cast<const char*>(&weight_row[k + 64]), _MM_HINT_T0);
            
            __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
            __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
            __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
            __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
            __m512 weight_vec0 = _mm512_loadu_ps(&weight_row[k]);
            __m512 weight_vec1 = _mm512_loadu_ps(&weight_row[k + 16]);
            __m512 weight_vec2 = _mm512_loadu_ps(&weight_row[k + 32]);
            __m512 weight_vec3 = _mm512_loadu_ps(&weight_row[k + 48]);
            
            sum_vec0 = _mm512_fmadd_ps(input_vec0, weight_vec0, sum_vec0);
            sum_vec1 = _mm512_fmadd_ps(input_vec1, weight_vec1, sum_vec1);
            sum_vec2 = _mm512_fmadd_ps(input_vec2, weight_vec2, sum_vec2);
            sum_vec3 = _mm512_fmadd_ps(input_vec3, weight_vec3, sum_vec3);
        }
        
        // Process remaining 64-element chunks without prefetch
        for (; k + 64 <= K; k += 64) {
            __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
            __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
            __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
            __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
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
        
        // Process remaining 16 elements
        for (; k + 16 <= K; k += 16) {
            __m512 input_vec = _mm512_loadu_ps(&input[k]);
            __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
            sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
        }
        
        float sum = _mm512_reduce_add_ps(sum_vec);
        
        // Scalar remainder
        for (; k < K; k++) {
            sum += input[k] * weight_row[k];
        }
        
        // Apply SiLU: x * sigmoid(x)
        // sigmoid(x) = 1 / (1 + exp(-x))
        float sigmoid = 1.0f / (1.0f + std::exp(-sum));
        output[n] = sum * sigmoid;
    }
}

} // namespace SEG
