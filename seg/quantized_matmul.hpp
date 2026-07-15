// ============================================================================
// Quantized Matrix Multiplication
// ============================================================================
// Performs MatMul with on-the-fly dequantization for memory bandwidth reduction
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace SEG {

// Quantized matrix multiplication with Q8_K weights
// Input: float[M, K]
// Weight: Q8_K[K/256, 256] packed (K must be multiple of 256)
// Output: float[M, N]
// N is the number of output features (columns)
void QuantizedMatMulQ8_K(const float* input, const void* weights_q8_k,
                         float* output,
                         size_t M, size_t N, size_t K);

// Quantized matrix multiplication with Q4_K weights
// 4-bit weights reduce memory bandwidth by 4x
void QuantizedMatMulQ4_K(const float* input, const void* weights_q4_k,
                         float* output,
                         size_t M, size_t N, size_t K);

// Quantized vector-matrix multiplication (M=1 case)
// Optimized for single-token inference
void QuantizedVecMatMulQ8_K(const float* input, const void* weights_q8_k,
                            float* output,
                            size_t N, size_t K);

} // namespace SEG
