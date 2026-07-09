// ============================================================================
// Fast Quantized Matrix Multiplication
// ============================================================================
// On-the-fly dequantization with AVX-512 for maximum performance
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace SEG {

// Q8_K block structure for fast access
struct alignas(64) Q8_K_Block {
    float d;              // scale
    int8_t qs[256];       // quantized values
    
    // Precomputed for fast dequantization
    float dequantized[256]; // cached dequantized values (optional)
};

// Fast quantized vector-matrix multiplication
// Input: float[K]
// Weights: Q8_K[K/256, N] blocks
// Output: float[N]
// This reduces memory bandwidth by 4x compared to float32
void QuantizedVecMatMulQ8_K_Fast(const float* input, 
                                   const Q8_K_Block* weights,
                                   float* output,
                                   size_t N, size_t K);

// Precompute dequantized weights for maximum speed
// Call once after loading weights
void PrecomputeQ8_K_Dequantized(const Q8_K_Block* quantized, 
                                 float* dequantized,
                                 size_t num_blocks);

// MatMul with pre-dequantized weights (fastest)
void FastVecMatMul(const float* input, const float* weights,
                    float* output, size_t N, size_t K);

} // namespace SEG
