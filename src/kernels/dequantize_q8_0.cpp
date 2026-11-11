// Production implementation for dequantize_q8_0.cpp
// Q8_0 dequantization: 8-bit quantized weights with block-wise scaling
// Format: Each block has 32 weights (32 bytes) + 2-byte scale (FP16)
// Total block size: 34 bytes for 32 weights
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include <cstdint>
#include <cstring>
#include <cmath>
#include <immintrin.h>

namespace RawrXD { namespace Core {

// Q8_0 block structure:
// - 2 bytes: scale (FP16)
// - 32 bytes: 32 x 8-bit weights (signed)
struct Q8_0_Block {
    uint16_t scale;      // FP16 scale
    int8_t weights[32];  // 32 x 8-bit signed weights
};

// Convert FP16 to FP32
static inline float FP16ToFP32(uint16_t fp16) {
    uint32_t sign = (fp16 >> 15) & 0x1;
    uint32_t exponent = (fp16 >> 10) & 0x1F;
    uint32_t mantissa = fp16 & 0x3FF;
    
    if (exponent == 0) {
        if (mantissa == 0) {
            return sign ? -0.0f : 0.0f;
        }
        float value = (mantissa / 1024.0f) * 0.00006103515625f;
        return sign ? -value : value;
    }
    
    if (exponent == 0x1F) {
        return (mantissa == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
    }
    
    int32_t exp = static_cast<int32_t>(exponent) - 15 + 127;
    uint32_t result = (sign << 31) | (static_cast<uint32_t>(exp) << 23) | (mantissa << 13);
    
    float f;
    std::memcpy(&f, &result, sizeof(f));
    return f;
}

void DequantizeQ8_0(const void* input, float* output, int n) {
    if (!input || !output || n <= 0) return;
    
    const uint8_t* src = static_cast<const uint8_t*>(input);
    int blocks = (n + 31) / 32; // Round up to full blocks
    
    for (int b = 0; b < blocks; ++b) {
        const Q8_0_Block* block = reinterpret_cast<const Q8_0_Block*>(src + b * sizeof(Q8_0_Block));
        
        // Extract scale
        float scale = FP16ToFP32(block->scale);
        
        // Dequantize 32 weights
        for (int i = 0; i < 32 && (b * 32 + i) < n; ++i) {
            output[b * 32 + i] = block->weights[i] * scale;
        }
    }
}

// AVX2-optimized version for large arrays
void DequantizeQ8_0_AVX2(const void* input, float* output, int n) {
    if (!input || !output || n <= 0) return;
    
#if defined(__AVX2__) || defined(_MSC_VER)
    const uint8_t* src = static_cast<const uint8_t*>(input);
    int blocks = n / 32; // Full blocks only for AVX2
    
    for (int b = 0; b < blocks; ++b) {
        const Q8_0_Block* block = reinterpret_cast<const Q8_0_Block*>(src + b * sizeof(Q8_0_Block));
        
        // Load scale
        float scale = FP16ToFP32(block->scale);
        __m256 vscale = _mm256_set1_ps(scale);
        
        // Load 32 signed 8-bit weights
        __m256i weights = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(block->weights));
        
        // Convert to 16-bit integers
        __m256i weights_16_lo = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(weights));
        __m256i weights_16_hi = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(weights, 1));
        
        // Convert to 32-bit integers and then to float
        __m256i w32_0 = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(weights_16_lo));
        __m256i w32_1 = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(weights_16_lo, 1));
        __m256i w32_2 = _mm256_cvtepi16_epi32(_mm256_castsi256_si128(weights_16_hi));
        __m256i w32_3 = _mm256_cvtepi16_epi32(_mm256_extracti128_si256(weights_16_hi, 1));
        
        __m256 wf_0 = _mm256_cvtepi32_ps(w32_0);
        __m256 wf_1 = _mm256_cvtepi32_ps(w32_1);
        __m256 wf_2 = _mm256_cvtepi32_ps(w32_2);
        __m256 wf_3 = _mm256_cvtepi32_ps(w32_3);
        
        // Multiply by scale
        wf_0 = _mm256_mul_ps(wf_0, vscale);
        wf_1 = _mm256_mul_ps(wf_1, vscale);
        wf_2 = _mm256_mul_ps(wf_2, vscale);
        wf_3 = _mm256_mul_ps(wf_3, vscale);
        
        // Store results
        _mm256_storeu_ps(output + b * 32, wf_0);
        _mm256_storeu_ps(output + b * 32 + 8, wf_1);
        _mm256_storeu_ps(output + b * 32 + 16, wf_2);
        _mm256_storeu_ps(output + b * 32 + 24, wf_3);
    }
    
    // Handle remaining elements
    int processed = blocks * 32;
    if (processed < n) {
        DequantizeQ8_0(src + blocks * sizeof(Q8_0_Block), output + processed, n - processed);
    }
#else
    // Fallback to scalar implementation
    DequantizeQ8_0(input, output, n);
#endif
}

}} // namespace RawrXD::Core
