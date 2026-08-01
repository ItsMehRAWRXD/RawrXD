/**
 * @file attention_avx2.h
 * @brief AVX2-optimized attention kernels for RawrXD
 *
 * @copyright RawrXD 2026
 */

#ifndef ATTENTION_AVX2_H
#define ATTENTION_AVX2_H

#include <cstddef>

namespace rawrxd {
namespace kernels {

/**
 * @brief AVX2-optimized multi-head attention (decode mode)
 *
 * Computes scaled dot-product attention for a single query token
 * against the key/value cache.
 *
 * @param q Query vector (num_heads × head_dim elements)
 * @param k_cache Key cache (seq_len × num_heads × head_dim elements)
 * @param v_cache Value cache (seq_len × num_heads × head_dim elements)
 * @param output Output vector (num_heads × head_dim elements)
 * @param num_heads Number of attention heads
 * @param head_dim Dimension per head
 * @param seq_len Current sequence length
 * @param num_threads Number of threads to use
 */
void attention_avx2_mt(const float* q, const float* k_cache, const float* v_cache,
                       float* output, int num_heads, int head_dim, int seq_len,
                       int num_threads);

/**
 * @brief Compute dot product with AVX2
 *
 * @param a First vector
 * @param b Second vector
 * @param n Vector length
 * @return Dot product result
 */
float dot_product_avx2(const float* a, const float* b, int n);

/**
 * @brief Apply softmax to scores
 *
 * @param scores Input/output scores (modified in-place)
 * @param n Number of scores
 */
void softmax_avx2(float* scores, int n);

} // namespace kernels
} // namespace rawrxd

#endif // ATTENTION_AVX2_H
