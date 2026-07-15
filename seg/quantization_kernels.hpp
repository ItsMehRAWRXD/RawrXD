// ============================================================================
// Quantization Kernels - Q4_K, Q6_K, Q8_K with AVX-512 Support
// ============================================================================
// Implements K-quant dequantization (Q4_K, Q6_K) with AVX-512 acceleration
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <cmath>
#include <limits>

// QK_K = 256 (super-block size)
#define QK_K 256
#define K_SCALE_SIZE 12

namespace RawrXD {
namespace Quantization {

// ============================================================================
// Block Structures (from GGML)
// ============================================================================

// Q4_K: 4-bit K-quantization
// 8 blocks of 32 elements each
// weight is represented as x = a * q + b
// Effectively 4.5 bits per weight
struct BlockQ4_K {
    union {
        struct {
            uint16_t d;    // super-block scale for quantized scales (f16)
            uint16_t dmin; // super-block scale for quantized mins (f16)
        };
        uint32_t dm;
    };
    uint8_t scales[K_SCALE_SIZE]; // scales and mins, quantized with 6 bits
    uint8_t qs[QK_K/2];           // 4-bit quants (128 bytes)
};

// Q6_K: 6-bit K-quantization
// 16 blocks of 16 elements each
// weight is represented as x = a * q
// Effectively 6.5625 bits per weight
struct BlockQ6_K {
    uint8_t ql[QK_K/2];      // quants, lower 4 bits (128 bytes)
    uint8_t qh[QK_K/4];      // quants, upper 2 bits (64 bytes)
    int8_t  scales[QK_K/16]; // scales, quantized with 8 bits (16 bytes)
    uint16_t d;              // super-block scale (f16)
};

// Q8_K: 8-bit K-quantization (intermediate)
struct BlockQ8_K {
    float   d;              // delta
    int8_t  qs[QK_K];       // quants (256 bytes)
    int16_t bsums[QK_K/16]; // sum of quants in groups of 16
};

// ============================================================================
// Scalar Dequantization Functions
// ============================================================================

// Dequantize Q4_K to float
// Returns number of elements dequantized
size_t DequantizeQ4_K_Scalar(const void* quantized, float* output, size_t num_elements);

// Dequantize Q6_K to float
size_t DequantizeQ6_K_Scalar(const void* quantized, float* output, size_t num_elements);

// Dequantize Q8_K to float
size_t DequantizeQ8_K_Scalar(const void* quantized, float* output, size_t num_elements);

// ============================================================================
// AVX-512 Optimized Dequantization
// ============================================================================

#ifdef __AVX512F__
// AVX-512 dequantize Q4_K - processes 16 elements at a time
size_t DequantizeQ4_K_AVX512(const void* quantized, float* output, size_t num_elements);

// AVX-512 dequantize Q6_K - processes 16 elements at a time
size_t DequantizeQ6_K_AVX512(const void* quantized, float* output, size_t num_elements);

// AVX-512 dequantize Q8_K - processes 16 elements at a time
size_t DequantizeQ8_K_AVX512(const void* quantized, float* output, size_t num_elements);
#endif

// ============================================================================
// Dispatch Layer - Auto-selects best implementation
// ============================================================================

class QuantizationKernels {
public:
    // Initialize and detect CPU features
    static void Initialize();
    
    // Check if AVX-512 is available
    static bool HasAVX512();
    
    // Dequantize Q4_K (auto-dispatch)
    static size_t DequantizeQ4_K(const void* quantized, float* output, size_t num_elements);
    
    // Dequantize Q6_K (auto-dispatch)
    static size_t DequantizeQ6_K(const void* quantized, float* output, size_t num_elements);
    
    // Dequantize Q8_K (auto-dispatch)
    static size_t DequantizeQ8_K(const void* quantized, float* output, size_t num_elements);
    
private:
    static bool initialized_;
    static bool has_avx512_;
    static bool has_avx2_;
    static bool has_fma_;
};

// ============================================================================
// Utility Functions
// ============================================================================

// Convert half-precision float to single-precision
inline float HalfToFloat(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        // Denormal
        float val = mant / 1024.0f;
        return (sign ? -1.0f : 1.0f) * val * std::pow(2.0f, -14);
    }
    if (exp == 31) {
        if (mant == 0) {
            return sign ? -std::numeric_limits<float>::infinity() 
                        : std::numeric_limits<float>::infinity();
        }
        return std::numeric_limits<float>::quiet_NaN();
    }
    
    float f = std::pow(2.0f, static_cast<float>(exp - 15)) * (1.0f + mant / 1024.0f);
    return sign ? -f : f;
}

} // namespace Quantization
} // namespace RawrXD
