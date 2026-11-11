// ============================================================================
// C5a: Q4_0 Quantized Matrix Multiplication
// 8:1 compression with on-the-fly dequantization
// ============================================================================

#pragma once

#include <immintrin.h>
#include <cstdint>
#include <vector>
#include <cstring>
#include <cmath>

namespace benchmark {

// Q4_0 Block: 32 weights → 18 bytes
// 8:1 compression vs FP32
struct alignas(32) Q4_0Block {
    uint16_t scale_f16;    // Scale factor (F16)
    uint8_t quants[16];    // 32 nibbles packed (4 bits each)
    
    static constexpr size_t WEIGHTS_PER_BLOCK = 32;
    static constexpr size_t BYTES_PER_BLOCK = 18;
};

// ============================================================================
// F16/F32 Conversion
// ============================================================================

inline float F16ToF32(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return (sign ? -1.0f : 1.0f) * val * std::pow(2.0f, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    float val = 1.0f + mant / 1024.0f;
    int32_t exp32 = exp - 15 + 127;
    uint32_t f32 = (sign << 31) | (exp32 << 23) | (mant << 13);
    float result;
    std::memcpy(&result, &f32, sizeof(result));
    return result;
}

inline uint16_t F32ToF16(float f32) {
    uint32_t f32_bits;
    std::memcpy(&f32_bits, &f32, sizeof(f32));
    
    uint32_t sign = (f32_bits >> 31) & 0x1;
    uint32_t exp = (f32_bits >> 23) & 0xFF;
    uint32_t mant = f32_bits & 0x7FFFFF;
    
    if (exp == 0) return sign << 15;  // Zero
    if (exp == 255) return (sign << 15) | 0x7C00;  // Inf
    
    int32_t exp16 = exp - 127 + 15;
    if (exp16 >= 31) return (sign << 15) | 0x7C00;  // Overflow
    if (exp16 <= 0) return (sign << 15);  // Underflow
    
    uint32_t mant16 = mant >> 13;
    return static_cast<uint16_t>((sign << 15) | (exp16 << 10) | mant16);
}

// ============================================================================
// Quantization
// ============================================================================

// Quantize FP32 weights to Q4_0
void QuantizeF32ToQ4_0(const float* input, size_t num_weights, 
                       std::vector<uint8_t>& output);

// Dequantize Q4_0 to FP32
void DequantizeQ4_0ToF32(const uint8_t* input, size_t num_weights,
                         float* output);

// ============================================================================
// Quantized Matrix Multiplication
// ============================================================================

// Scalar fallback
void MatMulQ4_0_Scalar(const uint8_t* weights, const float* input,
                       float* output, size_t batch_size, 
                       size_t input_dim, size_t output_dim);

// AVX2 implementation (256-bit)
void MatMulQ4_0_AVX2(const uint8_t* weights, const float* input,
                     float* output, size_t batch_size,
                     size_t input_dim, size_t output_dim);

// AVX-512 implementation (512-bit)
void MatMulQ4_0_AVX512(const uint8_t* weights, const float* input,
                       float* output, size_t batch_dim,
                       size_t input_dim, size_t output_dim);

// Auto-dispatch based on CPU features
void MatMulQ4_0(const uint8_t* weights, const float* input,
                float* output, size_t batch_size,
                size_t input_dim, size_t output_dim);

// ============================================================================
// Benchmark
// ============================================================================

struct QuantizedMatMulResult {
    float gflops;
    float memory_gb_s;
    float time_ms;
    size_t bytes_transferred;
};

QuantizedMatMulResult BenchmarkQuantizedMatMul(
    size_t batch_size, size_t input_dim, size_t output_dim,
    int iterations = 100
);

// ============================================================================
// Validation
// ============================================================================

// Compare quantized vs FP32
float ComputeQuantizationError(const float* reference, 
                               const float* quantized,
                               size_t num_elements);

// Verify correctness
bool ValidateQuantizedMatMul(size_t input_dim, size_t output_dim);

} // namespace benchmark
