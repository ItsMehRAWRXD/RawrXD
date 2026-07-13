// ============================================================================
// INT8 GEMM with AVX-512 VNNI
// ============================================================================
// Maximum performance integer matrix multiplication
// Requires AVX-512 VNNI (Vector Neural Network Instructions)
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace SEG {

// INT8 weight block with 128-element granularity
// Optimized for AVX-512 VNNI (32 int8 * 32 int8 -> 32 int32 per instruction)
struct alignas(64) Q8_128_Block {
    float d;              // scale factor (dequantization)
    int8_t qs[128];       // quantized values
};

// INT8 quantized matrix for FFN layers
// Weights stored as [N, K/128] blocks in row-major
struct Q8Matrix {
    Q8_128_Block* blocks;  // [N, num_blocks] where num_blocks = K/128
    size_t N;              // output dimension
    size_t K;              // input dimension
    size_t num_blocks;     // K / 128
    
    // Get block at (n, block_idx)
    Q8_128_Block* GetBlock(size_t n, size_t block_idx) {
        return &blocks[n * num_blocks + block_idx];
    }
    const Q8_128_Block* GetBlock(size_t n, size_t block_idx) const {
        return &blocks[n * num_blocks + block_idx];
    }
};

// Quantize float weights to INT8
// Returns scale factor for dequantization
void QuantizeFloatToQ8(const float* input, Q8_128_Block* output,
                       size_t N, size_t K);

// Dequantize INT8 weights back to float
void DequantizeQ8ToFloat(const Q8_128_Block* input, float* output,
                         size_t N, size_t K);

// Fast INT8 GEMM with AVX-512 VNNI
// Computes: output[n] = sum_k(input[k] * dequantized(weights[n,k]))
// Uses VNNI for 4x throughput vs FP32
void Int8VecMatMul(const float* input, const Q8Matrix& weights,
                   float* output);

// Convert existing float weights to Q8 format
// Returns newly allocated Q8Matrix (caller must free)
Q8Matrix ConvertWeightsToQ8(const float* weights, size_t N, size_t K);

// Free Q8Matrix memory
void FreeQ8Matrix(Q8Matrix& matrix);

} // namespace SEG
