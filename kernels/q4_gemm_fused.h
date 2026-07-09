/**
 * @file q4_gemm_fused.h
 * @brief Fused Q4 dequantization + GEMM kernels for RawrXD
 *
 * Fuses Q4_0 weight dequantization with GEMM computation
 * to eliminate FP32 intermediate buffer and reduce memory bandwidth.
 *
 * @copyright RawrXD 2026
 */

#ifndef Q4_GEMM_FUSED_H
#define Q4_GEMM_FUSED_H

#include <cstddef>
#include <cstdint>

namespace rawrxd {
namespace kernels {

/**
 * @brief Q4_0 quantization block
 *
 * 32 weights packed as 4-bit nibbles with shared scale
 */
struct Q4_0_Block {
    float scale;           // Dequantization scale
    uint8_t nibbles[16];     // 32 weights packed as nibbles (4 bits each)
};

/**
 * @brief Decompress Q4_0 block to FP32
 *
 * @param block Input Q4_0 block
 * @param output Output buffer (32 floats)
 */
void decompress_q4_block(const Q4_0_Block* block, float* output);

/**
 * @brief AVX2-optimized Q4_0 block decompression
 *
 * @param block Input Q4_0 block
 * @param output Output buffer (32 floats, 32-byte aligned)
 */
void decompress_q4_block_avx2(const Q4_0_Block* block, float* output);

/**
 * @brief Fused Q4 GEMV (single-threaded)
 *
 * Computes: output = weights × input
 * Where weights are Q4_0 quantized
 *
 * @param weights Q4_0 weight blocks (rows × (cols/32) blocks)
 * @param input Input vector (cols elements)
 * @param output Output vector (rows elements)
 * @param rows Number of output rows
 * @param cols Number of input columns (must be multiple of 32)
 */
void gemv_q4_fused(const Q4_0_Block* weights, const float* input,
                   float* output, int rows, int cols);

/**
 * @brief Fused Q4 GEMV with AVX2 (single-threaded)
 *
 * @param weights Q4_0 weight blocks
 * @param input Input vector
 * @param output Output vector
 * @param rows Number of output rows
 * @param cols Number of input columns (must be multiple of 32)
 */
void gemv_q4_fused_avx2(const Q4_0_Block* weights, const float* input,
                        float* output, int rows, int cols);

/**
 * @brief Fused Q4 GEMV with AVX2 (multi-threaded)
 *
 * @param weights Q4_0 weight blocks
 * @param input Input vector
 * @param output Output vector
 * @param rows Number of output rows
 * @param cols Number of input columns (must be multiple of 32)
 * @param num_threads Number of threads to use
 */
void gemv_q4_fused_avx2_mt(const Q4_0_Block* weights, const float* input,
                           float* output, int rows, int cols, int num_threads);

/**
 * @brief Fused Q4 FFN SwiGLU
 *
 * Computes SwiGLU with Q4_0 quantized weights:
 *   gate = SiLU(W_gate × input)
 *   up = W_up × input
 *   output = W_down × (gate ⊙ up)
 *
 * @param input Input hidden state
 * @param w_gate Q4_0 gate weights
 * @param w_up Q4_0 up weights
 * @param w_down Q4_0 down weights
 * @param output Output hidden state
 * @param hidden_dim Hidden dimension
 * @param ffn_dim FFN intermediate dimension
 * @param num_threads Number of threads
 */
void ffn_swiglu_q4_fused_mt(const float* input,
                            const Q4_0_Block* w_gate,
                            const Q4_0_Block* w_up,
                            const Q4_0_Block* w_down,
                            float* output,
                            int hidden_dim, int ffn_dim, int num_threads);

} // namespace kernels
} // namespace rawrxd

#endif // Q4_GEMM_FUSED_H
