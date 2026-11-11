/**
 * @file gemm_avx2.cpp
 * @brief AVX2-optimized GEMM kernel implementations
 *
 * @copyright RawrXD 2026
 */

#include "gemm_avx2.h"
#include <immintrin.h>
#include <thread>
#include <vector>
#include <cmath>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Internal worker functions
// ============================================================================

static void gemv_avx2_worker(const float* weights, const float* input, float* output,
                              int cols, int start_row, int end_row) {
    const int SIMD_WIDTH = 8;

    for (int i = start_row; i < end_row; i++) {
        __m256 sum_vec = _mm256_setzero_ps();

        int j = 0;
        // Main SIMD loop
        for (; j <= cols - SIMD_WIDTH; j += SIMD_WIDTH) {
            __m256 w_vec = _mm256_loadu_ps(&weights[i * cols + j]);
            __m256 x_vec = _mm256_loadu_ps(&input[j]);
            __m256 prod = _mm256_mul_ps(w_vec, x_vec);
            sum_vec = _mm256_add_ps(sum_vec, prod);
        }

        // Horizontal sum
        float sum_array[8];
        _mm256_storeu_ps(sum_array, sum_vec);
        float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                    sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];

        // Remainder
        for (; j < cols; j++) {
            sum += weights[i * cols + j] * input[j];
        }

        output[i] = sum;
    }
}

static inline float silu(float x) {
    return x / (1.0f + std::exp(-x));
}

// ============================================================================
// Public API implementations
// ============================================================================

void gemv_avx2(const float* weights, const float* input, float* output,
               int rows, int cols) {
    gemv_avx2_worker(weights, input, output, cols, 0, rows);
}

void gemv_avx2_mt(const float* weights, const float* input, float* output,
                  int rows, int cols, int num_threads) {
    std::vector<std::thread> threads;
    int chunk_size = rows / num_threads;

    for (int t = 0; t < num_threads; t++) {
        int start_row = t * chunk_size;
        int end_row = (t == num_threads - 1) ? rows : (t + 1) * chunk_size;
        threads.emplace_back(gemv_avx2_worker, weights, input, output,
                            cols, start_row, end_row);
    }

    for (auto& t : threads) {
        t.join();
    }
}

void ffn_swiglu_avx2_mt(const float* input,
                        const float* w_gate, const float* w_up, const float* w_down,
                        float* output,
                        int hidden_dim, int ffn_dim, int num_threads) {
    // Temporary buffers
    std::vector<float> gate(ffn_dim);
    std::vector<float> up(ffn_dim);
    std::vector<float> fused(ffn_dim);

    // Step 1: Gate projection (MT + AVX2)
    gemv_avx2_mt(w_gate, input, gate.data(), ffn_dim, hidden_dim, num_threads);

    // Apply SiLU to gate
    for (int i = 0; i < ffn_dim; i++) {
        gate[i] = silu(gate[i]);
    }

    // Step 2: Up projection (MT + AVX2)
    gemv_avx2_mt(w_up, input, up.data(), ffn_dim, hidden_dim, num_threads);

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

    // Step 4: Down projection (MT + AVX2)
    gemv_avx2_mt(w_down, fused.data(), output, hidden_dim, ffn_dim, num_threads);
}

void qkv_projection_avx2_mt(const float* input, const float* weights,
                            float* qkv_output,
                            int hidden_dim, int qkv_dim, int num_threads) {
    gemv_avx2_mt(weights, input, qkv_output, qkv_dim, hidden_dim, num_threads);
}

void output_projection_avx2_mt(const float* hidden, const float* weights,
                               float* logits,
                               int embed_dim, int vocab_size, int num_threads) {
    gemv_avx2_mt(weights, hidden, logits, vocab_size, embed_dim, num_threads);
}

} // namespace kernels
} // namespace rawrxd
