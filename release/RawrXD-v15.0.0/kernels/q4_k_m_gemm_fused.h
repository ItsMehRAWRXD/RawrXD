/**
 * @file q4_k_m_gemm_fused.h
 * @brief Q4_K_M (K-quant) mixed-precision fused GEMM kernels
 *
 * Q4_K_M uses 6-bit for important weights, 4-bit for others.
 * Higher compression than Q4_0 with better precision retention.
 *
 * @copyright RawrXD 2026
 */

#ifndef RAWRXD_Q4_K_M_GEMM_FUSED_H
#define RAWRXD_Q4_K_M_GEMM_FUSED_H

#include <cstdint>
#include <cstddef>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Q4_K_M Block Structure (GGML K-quant variant)
// ============================================================================
// Super-block: 256 weights
// - 8 sub-blocks of 32 weights each
// - Mixed 6-bit/4-bit quantization

struct Q4_K_M_SubBlock {
    uint8_t quants[24];  // 6-bit packed: 32 weights × 6 bits = 192 bits = 24 bytes
    // OR 4-bit: 32 weights × 4 bits = 128 bits = 16 bytes (with padding)
};

struct Q4_K_M_Block {
    float scale;                    // FP32 super-block scale
    float min;                      // FP32 super-block min (for zero-point)
    uint8_t scales[8];            // Per-sub-block 6-bit scales (packed)
    uint8_t quants[256];            // 256 weights at 4-bit = 128 bytes
    // Total: 4 + 4 + 8 + 256 = 272 bytes for 256 weights
    // Effective: 8.5 bits/weight = 3.76:1 vs FP32 (but with better precision)
};

// Alternative: True Q4_K_M from llama.cpp
// Block size: 256 elements
// - scales: Q6 (6-bit) for important weights
// - quants: Q4 (4-bit) for all weights
// - 4.5-6.5 bits/weight effective

struct Q4_K_M_Block_v2 {
    uint8_t scales[12];     // 6-bit scales for 8 sub-blocks (packed)
    uint8_t quants[128];    // 4-bit weights: 256 weights = 128 bytes
    uint8_t mins[12];       // 6-bit mins for zero-points
    // Total: ~152 bytes for 256 weights = 4.75 bits/weight
};

// ============================================================================
// Q4_K_M Decompression
// ============================================================================

/**
 * @brief Decompress a Q4_K_M sub-block to FP32
 *
 * Uses mixed 6-bit/4-bit dequantization with per-block scales.
 *
 * @param block Pointer to Q4_K_M block
 * @param sub_block_idx Which sub-block (0-7)
 * @param output Output buffer (32 floats)
 */
void decompress_q4_k_m_subblock(const Q4_K_M_Block* block, int sub_block_idx,
                                 float* output);

/**
 * @brief AVX2-optimized Q4_K_M decompression
 */
void decompress_q4_k_m_subblock_avx2(const Q4_K_M_Block* block, int sub_block_idx,
                                      float* output);

// ============================================================================
// Fused Q4_K_M GEMV
// ============================================================================

/**
 * @brief Fused Q4_K_M GEMV (single-threaded)
 *
 * @param weights Q4_K_M weight blocks
 * @param input Input vector (cols elements)
 * @param output Output vector (rows elements)
 * @param rows Number of output rows
 * @param cols Number of input columns (must be multiple of 256)
 */
void gemv_q4_k_m_fused(const Q4_K_M_Block* weights, const float* input,
                       float* output, int rows, int cols);

/**
 * @brief AVX2-optimized fused Q4_K_M GEMV (single-threaded)
 */
void gemv_q4_k_m_fused_avx2(const Q4_K_M_Block* weights, const float* input,
                            float* output, int rows, int cols);

/**
 * @brief Multi-threaded AVX2 fused Q4_K_M GEMV
 *
 * @param num_threads Number of worker threads
 */
void gemv_q4_k_m_fused_avx2_mt(const Q4_K_M_Block* weights, const float* input,
                               float* output, int rows, int cols, int num_threads);

// ============================================================================
// Fused Q4_K_M FFN SwiGLU
// ============================================================================

/**
 * @brief Fused Q4_K_M FFN SwiGLU with multi-threading
 */
void ffn_swiglu_q4_k_m_fused_mt(const float* input,
                                const Q4_K_M_Block* w_gate,
                                const Q4_K_M_Block* w_up,
                                const Q4_K_M_Block* w_down,
                                float* output,
                                int hidden_dim, int ffn_dim, int num_threads);

// ============================================================================
// Compression Ratio Constants
// ============================================================================

constexpr float Q4_K_M_COMPRESSION_RATIO = 6.7f;  // 32 bits / 4.75 bits
constexpr size_t Q4_K_M_BLOCK_SIZE = 256;         // Weights per block
constexpr size_t Q4_K_M_BYTES_PER_BLOCK = 152;    // Bytes per block

} // namespace kernels
} // namespace rawrxd

#endif // RAWRXD_Q4_K_M_GEMM_FUSED_H
