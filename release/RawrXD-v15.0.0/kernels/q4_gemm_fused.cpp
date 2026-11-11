/**
 * @file q4_gemm_fused.cpp
 * @brief Fused Q4 dequantization + GEMM kernel implementations
 *
 * @copyright RawrXD 2026
 */

#include "q4_gemm_fused.h"
#include <immintrin.h>
#include <thread>
#include <vector>
#include <cstring>
#include <cmath>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Q4_0 Decompression
// ============================================================================

void decompress_q4_block(const Q4_0_Block* block, float* output) {
    // GGML Q4_0 format: scale (FP16) + 32 nibbles (16 bytes)
    // Dequantize: (nibble - 8) * scale
    float scale = block->scale;
    const uint8_t* nibbles = block->nibbles;
    
    for (int i = 0; i < 32; i++) {
        // Extract nibble (4 bits)
        uint8_t byte = nibbles[i / 2];
        uint8_t nibble = (i % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
        
        // Dequantize: (nibble - 8) * scale
        output[i] = (static_cast<float>(nibble) - 8.0f) * scale;
    }
}

void decompress_q4_block_avx2(const Q4_0_Block* block, float* output) {
    // For now, use scalar version - AVX2 version needs careful shuffle index handling
    decompress_q4_block(block, output);
}

// ============================================================================
// Fused Q4 GEMV
// ============================================================================

void gemv_q4_fused(const Q4_0_Block* weights, const float* input,
                   float* output, int rows, int cols) {
    int blocks_per_row = cols / 32;
    
    for (int i = 0; i < rows; i++) {
        float sum = 0.0f;
        const Q4_0_Block* row_blocks = &weights[i * blocks_per_row];
        
        for (int b = 0; b < blocks_per_row; b++) {
            // Decompress block on-the-fly
            float decompressed[32];
            decompress_q4_block(&row_blocks[b], decompressed);
            
            // Dot product with input slice
            const float* input_slice = &input[b * 32];
            for (int j = 0; j < 32; j++) {
                sum += decompressed[j] * input_slice[j];
            }
        }
        
        output[i] = sum;
    }
}

void gemv_q4_fused_avx2(const Q4_0_Block* weights, const float* input,
                        float* output, int rows, int cols) {
    int blocks_per_row = cols / 32;
    
    for (int i = 0; i < rows; i++) {
        __m256 sum_vec = _mm256_setzero_ps();
        const Q4_0_Block* row_blocks = &weights[i * blocks_per_row];
        
        for (int b = 0; b < blocks_per_row; b++) {
            // Decompress block using AVX2
            float decompressed[32];
            decompress_q4_block_avx2(&row_blocks[b], decompressed);
            
            // Vectorized dot product
            const float* input_slice = &input[b * 32];
            for (int j = 0; j < 32; j += 8) {
                __m256 w = _mm256_loadu_ps(&decompressed[j]);
                __m256 x = _mm256_loadu_ps(&input_slice[j]);
                __m256 prod = _mm256_mul_ps(w, x);
                sum_vec = _mm256_add_ps(sum_vec, prod);
            }
        }
        
        // Horizontal sum
        float sum_array[8];
        _mm256_storeu_ps(sum_array, sum_vec);
        float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                    sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];
        output[i] = sum;
    }
}

// ============================================================================
// Multi-threaded Fused Q4 GEMV
// ============================================================================

static void gemv_q4_fused_worker(const Q4_0_Block* weights, const float* input,
                                  float* output, int cols, int blocks_per_row,
                                  int start_row, int end_row) {
    for (int i = start_row; i < end_row; i++) {
        __m256 sum_vec = _mm256_setzero_ps();
        const Q4_0_Block* row_blocks = &weights[i * blocks_per_row];
        
        for (int b = 0; b < blocks_per_row; b++) {
            // Decompress block
            float decompressed[32];
            decompress_q4_block_avx2(&row_blocks[b], decompressed);
            
            // Vectorized dot product
            const float* input_slice = &input[b * 32];
            for (int j = 0; j < 32; j += 8) {
                __m256 w = _mm256_loadu_ps(&decompressed[j]);
                __m256 x = _mm256_loadu_ps(&input_slice[j]);
                __m256 prod = _mm256_mul_ps(w, x);
                sum_vec = _mm256_add_ps(sum_vec, prod);
            }
        }
        
        // Horizontal sum
        float sum_array[8];
        _mm256_storeu_ps(sum_array, sum_vec);
        float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                    sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];
        output[i] = sum;
    }
}

void gemv_q4_fused_avx2_mt(const Q4_0_Block* weights, const float* input,
                           float* output, int rows, int cols, int num_threads) {
    int blocks_per_row = cols / 32;
    
    std::vector<std::thread> threads;
    int chunk_size = rows / num_threads;
    
    for (int t = 0; t < num_threads; t++) {
        int start_row = t * chunk_size;
        int end_row = (t == num_threads - 1) ? rows : (t + 1) * chunk_size;
        threads.emplace_back(gemv_q4_fused_worker, weights, input, output,
                              cols, blocks_per_row, start_row, end_row);
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

// ============================================================================
// Fused Q4 FFN SwiGLU
// ============================================================================

static inline float silu(float x) {
    return x / (1.0f + std::exp(-x));
}

void ffn_swiglu_q4_fused_mt(const float* input,
                            const Q4_0_Block* w_gate,
                            const Q4_0_Block* w_up,
                            const Q4_0_Block* w_down,
                            float* output,
                            int hidden_dim, int ffn_dim, int num_threads) {
    // Temporary buffers
    std::vector<float> gate(ffn_dim);
    std::vector<float> up(ffn_dim);
    std::vector<float> fused(ffn_dim);
    
    // Step 1: Gate projection (Q4 fused)
    gemv_q4_fused_avx2_mt(w_gate, input, gate.data(), ffn_dim, hidden_dim, num_threads);
    
    // Apply SiLU
    for (int i = 0; i < ffn_dim; i++) {
        gate[i] = silu(gate[i]);
    }
    
    // Step 2: Up projection (Q4 fused)
    gemv_q4_fused_avx2_mt(w_up, input, up.data(), ffn_dim, hidden_dim, num_threads);
    
    // Step 3: Element-wise multiply (AVX2)
    int i = 0;
    for (; i <= ffn_dim - 8; i += 8) {
        __m256 g = _mm256_loadu_ps(&gate[i]);
        __m256 u = _mm256_loadu_ps(&up[i]);
        __m256 f = _mm256_mul_ps(g, u);
        _mm256_storeu_ps(&fused[i], f);
    }
    for (; i < ffn_dim; i++) {
        fused[i] = gate[i] * up[i];
    }
    
    // Step 4: Down projection (Q4 fused)
    gemv_q4_fused_avx2_mt(w_down, fused.data(), output, hidden_dim, ffn_dim, num_threads);
}

} // namespace kernels
} // namespace rawrxd
