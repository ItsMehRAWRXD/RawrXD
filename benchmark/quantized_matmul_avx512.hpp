// ============================================================================
// C5c: AVX-512 Quantized Matrix Multiplication
// 2× speedup over scalar Q4_0 implementation
// ============================================================================

#pragma once

#include "quantized_matmul.hpp"
#include <immintrin.h>

namespace benchmark {

// ============================================================================
// AVX-512 Q4_0 Dequantization
// Process 16 weights at once (512-bit vectors)
// ============================================================================

// Dequantize 32 Q4_0 weights (1 block) to 32 FP32 values using AVX-512
inline void DequantizeQ4_0Block_AVX512(const Q4_0Block* block, float* output) {
    // Load scale
    float scale = F16ToF32(block->scale_f16);
    __m512 scale_vec = _mm512_set1_ps(scale);
    
    // Load 16 bytes of quantized data
    __m128i quants = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block->quants));
    
    // Extract low and high nibbles
    __m128i low_mask = _mm_set1_epi8(0x0F);
    __m128i low_nibbles = _mm_and_si128(quants, low_mask);
    __m128i high_nibbles = _mm_srli_epi16(quants, 4);
    high_nibbles = _mm_and_si128(high_nibbles, low_mask);
    
    // Convert to 32-bit integers and subtract 8 (signed range: -8 to +7)
    __m512i low_i32 = _mm512_cvtepu8_epi32(low_nibbles);
    __m512i high_i32 = _mm512_cvtepu8_epi32(high_nibbles);
    
    low_i32 = _mm512_sub_epi32(low_i32, _mm512_set1_epi32(8));
    high_i32 = _mm512_sub_epi32(high_i32, _mm512_set1_epi32(8));
    
    // Convert to float and scale
    __m512 low_f32 = _mm512_cvtepi32_ps(low_i32);
    __m512 high_f32 = _mm512_cvtepi32_ps(high_i32);
    
    low_f32 = _mm512_mul_ps(low_f32, scale_vec);
    high_f32 = _mm512_mul_ps(high_f32, scale_vec);
    
    // Store results
    _mm512_storeu_ps(output, low_f32);
    _mm512_storeu_ps(output + 16, high_f32);
}

// ============================================================================
// AVX-512 Matrix Multiplication
// ============================================================================

void MatMulQ4_0_AVX512_Impl(const uint8_t* weights, const float* input,
                            float* output, size_t batch_size,
                            size_t input_dim, size_t output_dim);

// ============================================================================
// Performance Monitoring
// ============================================================================

struct AVX512PerformanceMetrics {
    float gflops;
    float memory_bandwidth_gb_s;
    float dequantization_time_ms;
    float matmul_time_ms;
    float total_time_ms;
    size_t bytes_transferred;
};

AVX512PerformanceMetrics BenchmarkAVX512MatMul(
    size_t batch_size, size_t input_dim, size_t output_dim,
    int iterations = 100
);

// ============================================================================
// Validation
// ============================================================================

bool ValidateAVX512Correctness(size_t input_dim, size_t output_dim);

} // namespace benchmark
