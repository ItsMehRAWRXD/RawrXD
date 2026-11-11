// Production implementation for dequantize_q4_0.cpp
// Q4_0 dequantization: 4-bit quantized weights with block-wise scaling
// Format: Each block has 32 weights (16 bytes) + 2-byte scale (FP16)
// Total block size: 18 bytes for 32 weights
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include <cstdint>
#include <cstring>
#include <cmath>
#include <immintrin.h>

namespace RawrXD { namespace Core {

// Q4_0 block structure:
// - 2 bytes: scale (FP16)
// - 16 bytes: 32 x 4-bit weights (packed, 2 weights per byte)
struct Q4_0_Block {
    uint16_t scale;      // FP16 scale
    uint8_t weights[16]; // 32 x 4-bit weights
};

// Convert FP16 to FP32
static inline float FP16ToFP32(uint16_t fp16) {
    // Simple FP16 to FP32 conversion
    // FP16: 1 sign bit, 5 exponent bits, 10 mantissa bits
    uint32_t sign = (fp16 >> 15) & 0x1;
    uint32_t exponent = (fp16 >> 10) & 0x1F;
    uint32_t mantissa = fp16 & 0x3FF;
    
    if (exponent == 0) {
        // Zero or denormal
        if (mantissa == 0) {
            return sign ? -0.0f : 0.0f;
        }
        // Denormal
        float value = (mantissa / 1024.0f) * 0.00006103515625f; // 2^-14
        return sign ? -value : value;
    }
    
    if (exponent == 0x1F) {
        // Infinity or NaN
        return (mantissa == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
    }
    
    // Normal number
    int32_t exp = static_cast<int32_t>(exponent) - 15 + 127; // Adjust bias
    uint32_t result = (sign << 31) | (static_cast<uint32_t>(exp) << 23) | (mantissa << 13);
    
    float f;
    std::memcpy(&f, &result, sizeof(f));
    return f;
}

void DequantizeQ4_0(const void* input, float* output, int n) {
    if (!input || !output || n <= 0) return;
    
    const uint8_t* src = static_cast<const uint8_t*>(input);
    int blocks = (n + 31) / 32; // Round up to full blocks
    
    for (int b = 0; b < blocks; ++b) {
        const Q4_0_Block* block = reinterpret_cast<const Q4_0_Block*>(src + b * sizeof(Q4_0_Block));
        
        // Extract scale
        float scale = FP16ToFP32(block->scale);
        
        // Dequantize 32 weights
        for (int i = 0; i < 16 && (b * 32 + i * 2) < n; ++i) {
            uint8_t packed = block->weights[i];
            
            // First weight (low nibble)
            int8_t w0 = static_cast<int8_t>(packed & 0x0F) - 8; // Convert to signed [-8, 7]
            output[b * 32 + i * 2] = w0 * scale;
            
            // Second weight (high nibble)
            if ((b * 32 + i * 2 + 1) < n) {
                int8_t w1 = static_cast<int8_t>((packed >> 4) & 0x0F) - 8;
                output[b * 32 + i * 2 + 1] = w1 * scale;
            }
        }
    }
}

// AVX2-optimized version for large arrays
void DequantizeQ4_0_AVX2(const void* input, float* output, int n) {
    if (!input || !output || n <= 0) return;
    
#if defined(__AVX2__) || defined(_MSC_VER)
    const uint8_t* src = static_cast<const uint8_t*>(input);
    int blocks = n / 32; // Full blocks only for AVX2
    
    for (int b = 0; b < blocks; ++b) {
        const Q4_0_Block* block = reinterpret_cast<const Q4_0_Block*>(src + b * sizeof(Q4_0_Block));
        
        // Load scale
        float scale = FP16ToFP32(block->scale);
        __m256 vscale = _mm256_set1_ps(scale);
        
        // Load packed weights
        __m128i packed = _mm_loadu_si128(reinterpret_cast<const __m128i*>(block->weights));
        
        // Unpack low and high nibbles
        __m128i low_mask = _mm_set1_epi8(0x0F);
        __m128i low_nibbles = _mm_and_si128(packed, low_mask);
        __m128i high_nibbles = _mm_srli_epi16(packed, 4);
        high_nibbles = _mm_and_si128(high_nibbles, low_mask);
        
        // Convert to 16-bit integers
        __m256i low_16 = _mm256_cvtepu8_epi16(low_nibbles);
        __m256i high_16 = _mm256_cvtepu8_epi16(high_nibbles);
        
        // Subtract 8 to get signed values
        __m256i offset = _mm256_set1_epi16(8);
        low_16 = _mm256_sub_epi16(low_16, offset);
        high_16 = _mm256_sub_epi16(high_16, offset);
        
        // Convert to 32-bit integers and then to float
        __m256i low_32_lo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(low_16));
        __m256i low_32_hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(low_16, 1));
        __m256i high_32_lo = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(high_16));
        __m256i high_32_hi = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(high_16, 1));
        
        __m256 low_f_lo = _mm256_cvtepi32_ps(low_32_lo);
        __m256 low_f_hi = _mm256_cvtepi32_ps(low_32_hi);
        __m256 high_f_lo = _mm256_cvtepi32_ps(high_32_lo);
        __m256 high_f_hi = _mm256_cvtepi32_ps(high_32_hi);
        
        // Multiply by scale
        low_f_lo = _mm256_mul_ps(low_f_lo, vscale);
        low_f_hi = _mm256_mul_ps(low_f_hi, vscale);
        high_f_lo = _mm256_mul_ps(high_f_lo, vscale);
        high_f_hi = _mm256_mul_ps(high_f_hi, vscale);
        
        // Store results
        _mm256_storeu_ps(output + b * 32, low_f_lo);
        _mm256_storeu_ps(output + b * 32 + 8, low_f_hi);
        _mm256_storeu_ps(output + b * 32 + 16, high_f_lo);
        _mm256_storeu_ps(output + b * 32 + 24, high_f_hi);
    }
    
    // Handle remaining elements
    int processed = blocks * 32;
    if (processed < n) {
        DequantizeQ4_0(src + blocks * sizeof(Q4_0_Block), output + processed, n - processed);
    }
#else
    // Fallback to scalar implementation
    DequantizeQ4_0(input, output, n);
#endif
}

}} // namespace RawrXD::Core
