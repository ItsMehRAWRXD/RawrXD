/**
 * @file attention_avx2.cpp
 * @brief AVX2-optimized attention kernel implementations
 *
 * @copyright RawrXD 2026
 */

#include "attention_avx2.h"
#include <immintrin.h>
#include <thread>
#include <vector>
#include <cmath>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Internal utility functions
// ============================================================================

float dot_product_avx2(const float* a, const float* b, int n) {
    const int SIMD_WIDTH = 8;
    __m256 sum_vec = _mm256_setzero_ps();

    int i = 0;
    for (; i <= n - SIMD_WIDTH; i += SIMD_WIDTH) {
        __m256 a_vec = _mm256_loadu_ps(&a[i]);
        __m256 b_vec = _mm256_loadu_ps(&b[i]);
        __m256 prod = _mm256_mul_ps(a_vec, b_vec);
        sum_vec = _mm256_add_ps(sum_vec, prod);
    }

    // Horizontal sum
    float sum_array[8];
    _mm256_storeu_ps(sum_array, sum_vec);
    float sum = sum_array[0] + sum_array[1] + sum_array[2] + sum_array[3] +
                sum_array[4] + sum_array[5] + sum_array[6] + sum_array[7];

    // Remainder
    for (; i < n; i++) {
        sum += a[i] * b[i];
    }

    return sum;
}

void softmax_avx2(float* scores, int n) {
    // Find max for numerical stability
    float max_score = scores[0];
    for (int i = 1; i < n; i++) {
        if (scores[i] > max_score) max_score = scores[i];
    }

    // Compute exp and sum
    float sum_exp = 0.0f;
    for (int i = 0; i < n; i++) {
        scores[i] = std::exp(scores[i] - max_score);
        sum_exp += scores[i];
    }

    // Normalize
    for (int i = 0; i < n; i++) {
        scores[i] /= sum_exp;
    }
}

// ============================================================================
// Attention head worker
// ============================================================================

static void attention_head_worker(const float* q, const float* k_cache, const float* v_cache,
                                  float* output, int head_dim, int seq_len, int hidden_dim,
                                  int start_head, int end_head) {
    const float scale = 1.0f / std::sqrt((float)head_dim);

    std::vector<float> scores(seq_len);

    for (int h = start_head; h < end_head; h++) {
        const float* q_head = &q[h * head_dim];
        float* out_head = &output[h * head_dim];

        // Step 1: Compute attention scores
        for (int pos = 0; pos < seq_len; pos++) {
            const float* k_head = &k_cache[pos * hidden_dim + h * head_dim];
            scores[pos] = dot_product_avx2(q_head, k_head, head_dim) * scale;
        }

        // Step 2: Softmax
        softmax_avx2(scores.data(), seq_len);

        // Step 3: Weighted sum of values
        for (int d = 0; d < head_dim; d++) {
            out_head[d] = 0.0f;
        }

        for (int pos = 0; pos < seq_len; pos++) {
            const float* v_head = &v_cache[pos * hidden_dim + h * head_dim];
            float weight = scores[pos];

            int d = 0;
            __m256 w_vec = _mm256_set1_ps(weight);
            for (; d <= head_dim - 8; d += 8) {
                __m256 out_vec = _mm256_loadu_ps(&out_head[d]);
                __m256 v_vec = _mm256_loadu_ps(&v_head[d]);
                __m256 prod = _mm256_mul_ps(w_vec, v_vec);
                out_vec = _mm256_add_ps(out_vec, prod);
                _mm256_storeu_ps(&out_head[d], out_vec);
            }
            for (; d < head_dim; d++) {
                out_head[d] += weight * v_head[d];
            }
        }
    }
}

// ============================================================================
// Public API implementations
// ============================================================================

void attention_avx2_mt(const float* q, const float* k_cache, const float* v_cache,
                       float* output, int num_heads, int head_dim, int seq_len,
                       int num_threads) {
    int hidden_dim = num_heads * head_dim;

    std::vector<std::thread> threads;
    int chunk_size = num_heads / num_threads;

    for (int t = 0; t < num_threads; t++) {
        int start_head = t * chunk_size;
        int end_head = (t == num_threads - 1) ? num_heads : (t + 1) * chunk_size;
        threads.emplace_back(attention_head_worker, q, k_cache, v_cache, output,
                            head_dim, seq_len, hidden_dim, start_head, end_head);
    }

    for (auto& t : threads) {
        t.join();
    }
}

} // namespace kernels
} // namespace rawrxd
