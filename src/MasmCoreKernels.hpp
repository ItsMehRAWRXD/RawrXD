#pragma once
#include <stdint.h>

extern "C" {
    /**
     * @brief High-performance AVX2 Q2_K Block Dequantization Kernel.
     * @param src_payload Pointer to the raw, packed low-bit blocks in the GGUF memory map.
     * @param dst_fp32 Pointer to the pre-allocated, 32-byte aligned destination buffer.
     * @param num_blocks Total number of discrete quantization blocks to unpack.
     */
    void dequantize_q2_k_avx512(
        const uint8_t* __restrict src_payload,
        float* __restrict dst_fp32,
        uint64_t num_blocks
    );

    /**
     * @brief AVX2 Fused Multiply-Accumulate Vector Dot-Product Engine.
     * @param vec_a 32-byte aligned float array (typically weights or inputs).
     * @param vec_b 32-byte aligned float array.
     * @param num_elements Length of vector arrays (must be a multiple of 8 for YMM execution).
     */
    float vec_dot_prod_fp32_avx512(
        const float* __restrict vec_a,
        const float* __restrict vec_b,
        uint64_t num_elements
    );
}
