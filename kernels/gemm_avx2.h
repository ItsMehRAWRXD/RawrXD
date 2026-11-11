/**
 * @file gemm_avx2.h
 * @brief AVX2-optimized GEMM kernels for RawrXD
 *
 * Provides optimized matrix-vector multiplication for:
 *   - Output projection (vocab_size × embed_dim)
 *   - FFN gate/up/down projections
 *   - QKV projection
 *
 * @copyright RawrXD 2026
 */

#ifndef GEMM_AVX2_H
#define GEMM_AVX2_H

#include <cstddef>

namespace rawrxd {
namespace kernels {

/**
 * @brief AVX2-optimized matrix-vector multiplication
 *
 * Computes: output = weights × input
 * Where: weights[rows][cols], input[cols], output[rows]
 *
 * @param weights Weight matrix (row-major, rows × cols)
 * @param input Input vector (cols elements)
 * @param output Output vector (rows elements)
 * @param rows Number of output rows
 * @param cols Number of input columns
 */
void gemv_avx2(const float* weights, const float* input, float* output,
               int rows, int cols);

/**
 * @brief Multithreaded AVX2 matrix-vector multiplication
 *
 * Same as gemv_avx2 but parallelized across output rows
 *
 * @param weights Weight matrix (row-major, rows × cols)
 * @param input Input vector (cols elements)
 * @param output Output vector (rows elements)
 * @param rows Number of output rows
 * @param cols Number of input columns
 * @param num_threads Number of threads to use
 */
void gemv_avx2_mt(const float* weights, const float* input, float* output,
                  int rows, int cols, int num_threads);

/**
 * @brief FFN SwiGLU forward pass
 *
 * Computes:
 *   gate = SiLU(W_gate × input)
 *   up = W_up × input
 *   output = W_down × (gate ⊙ up)
 *
 * @param input Input hidden state (hidden_dim elements)
 * @param w_gate Gate projection weights (ffn_dim × hidden_dim)
 * @param w_up Up projection weights (ffn_dim × hidden_dim)
 * @param w_down Down projection weights (hidden_dim × ffn_dim)
 * @param output Output hidden state (hidden_dim elements)
 * @param hidden_dim Hidden dimension size
 * @param ffn_dim FFN intermediate dimension size
 * @param num_threads Number of threads to use
 */
void ffn_swiglu_avx2_mt(const float* input,
                        const float* w_gate, const float* w_up, const float* w_down,
                        float* output,
                        int hidden_dim, int ffn_dim, int num_threads);

/**
 * @brief QKV projection
 *
 * Computes: qkv = W_qkv × input
 * Where qkv is concatenated [Q, K, V]
 *
 * @param input Input hidden state (hidden_dim elements)
 * @param weights QKV projection weights (qkv_dim × hidden_dim)
 * @param qkv_output Output [Q, K, V] (qkv_dim elements)
 * @param hidden_dim Hidden dimension size
 * @param qkv_dim QKV dimension size (3 × hidden_dim)
 * @param num_threads Number of threads to use
 */
void qkv_projection_avx2_mt(const float* input, const float* weights,
                            float* qkv_output,
                            int hidden_dim, int qkv_dim, int num_threads);

/**
 * @brief Output projection (logits generation)
 *
 * Computes: logits = W_out × hidden
 *
 * @param hidden Final hidden state (embed_dim elements)
 * @param weights Output projection weights (vocab_size × embed_dim)
 * @param logits Output logits (vocab_size elements)
 * @param embed_dim Embedding dimension size
 * @param vocab_size Vocabulary size
 * @param num_threads Number of threads to use
 */
void output_projection_avx2_mt(const float* hidden, const float* weights,
                               float* logits,
                               int embed_dim, int vocab_size, int num_threads);

} // namespace kernels
} // namespace rawrxd

#endif // GEMM_AVX2_H
