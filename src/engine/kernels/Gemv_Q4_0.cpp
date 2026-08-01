// src/engine/kernels/Gemv_Q4_0.cpp
// Cache-Aligned Matrix-Vector Multiplier — Q4_0 quantized weights × FP32 input
//
// Processes tensor weights dynamically on the fly, streaming memory pages directly
// through L1/L2 hardware caches without allocating large intermediate buffers.
// Dequantizes and multiplies in a fused loop for maximum cache efficiency.

#include "SovereignMathCore.hpp"
#include <cstring>
#include <cstdint>

// ---------------------------------------------------------------------------
// Fused dequantize + GEMV for Q4_0 blocks
// Processes one row at a time: dequantize block → dot product → accumulate
// No large intermediate buffer needed — results stream directly to output.
// ---------------------------------------------------------------------------
void SovereignMathCore::Gemv_Q4_0_Matrix(
    size_t m, size_t n,
    const void* __restrict weights,
    const float* __restrict input,
    float* __restrict output
) {
    const uint8_t* byteBase = static_cast<const uint8_t*>(weights);
    size_t bytesPerBlock = sizeof(Block_Q4_0);
    size_t blocksPerRow = n / 32;
    size_t rowStrideBytes = blocksPerRow * bytesPerBlock;

    // Process each row: fused dequantize + dot product
    for (size_t r = 0; r < m; ++r) {
        const Block_Q4_0* rowBlocks = reinterpret_cast<const Block_Q4_0*>(byteBase + r * rowStrideBytes);
        float sum = 0.0f;

        // Process each block in the row
        for (size_t b = 0; b < blocksPerRow; ++b) {
            float scale = SovereignMathCore::FP16_To_FP32(rowBlocks[b].deltaHalf);
            const uint8_t* nibbles = rowBlocks[b].packedNibbles;

            // Manual unrolled dot product for 32 elements
            for (int j = 0; j < 16; ++j) {
                uint8_t packed = nibbles[j];
                int8_t low = (packed & 0x0F) - 8;
                int8_t high = (packed >> 4) - 8;
                size_t idx = b * 32 + j * 2;
                sum += (low * scale) * input[idx];
                sum += (high * scale) * input[idx + 1];
            }
        }
        output[r] = sum;
    }
}

// ---------------------------------------------------------------------------
// FP32 GEMV — Fallback for non-quantized weights
// ---------------------------------------------------------------------------
void SovereignMathCore::Gemv_F32_Matrix(
    size_t m, size_t n,
    const float* __restrict weights,
    const float* __restrict input,
    float* __restrict output
) {
    for (size_t r = 0; r < m; ++r) {
        float sum = 0.0f;
        const float* row = weights + r * n;
        for (size_t c = 0; c < n; ++c) {
            sum += row[c] * input[c];
        }
        output[r] = sum;
    }
}
