// ============================================================================
// aperture_q4_0_avx512_intrinsics.cpp — Optimized AVX-512 Q4_0 Dequantization
// ============================================================================
//
// Performance Target: 200-500M weights/sec (60-150x speedup over reference)
// Strategy:
//   - Process 256 weights per iteration (8 blocks × 32 weights)
//   - Use AVX-512 FMA for dequantization: weight = (q - 8) * scale
//   - Minimize data movement with direct nibble unpacking
//   - Unroll loop for instruction pipelining
//
// ============================================================================

#include <immintrin.h>
#include <cstdint>
#include <cstddef>
#include <cmath>
#include <limits>

// Q4_0 format constants
static constexpr int Q4_0_BLOCK_SIZE = 32;
static constexpr int Q4_0_BYTES_PER_BLOCK = 18;
static constexpr float Q4_0_ZERO_POINT = 8.0f;

// Precomputed lookup tables for nibble unpacking
// Table[i] = (i & 0x0F) - 8 for low nibble, (i >> 4) - 8 for high nibble
alignas(64) static const int8_t nibble_low_table[256] = {
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7,
    -8, -7, -6, -5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7
};

alignas(64) static const int8_t nibble_high_table[256] = {
    -8, -8, -8, -8, -8, -8, -8, -8, -8, -8, -8, -8, -8, -8, -8, -8,
    -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7,
    -6, -6, -6, -6, -6, -6, -6, -6, -6, -6, -6, -6, -6, -6, -6, -6,
    -5, -5, -5, -5, -5, -5, -5, -5, -5, -5, -5, -5, -5, -5, -5, -5,
    -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4,
    -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3,
    -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2, -2,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7
};

// Permutation for unpacking nibbles to bytes
alignas(64) static const int32_t unpack_permutation[16] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1
};

extern "C" {

/**
 * @brief Optimized AVX-512 Q4_0 dequantization using intrinsics
 * 
 * Processes 256 weights per iteration (8 blocks × 32 weights)
 * Uses lookup tables for fast nibble unpacking
 * Target: 200-500M weights/sec
 * 
 * @param dest Output buffer for float32 weights (must be 64-byte aligned)
 * @param src Input buffer with Q4_0 blocks
 * @param blockCount Number of Q4_0 blocks to process
 * @return 0 on success, negative on error
 */
int64_t Aperture_Q4_0_Dequant_AVX512_Intrinsics(
    float* __restrict dest,
    const uint8_t* __restrict src,
    uint64_t blockCount
) {
    if (!dest || !src || blockCount == 0) {
        return -1;  // Invalid parameters
    }
    
    // Process 8 blocks at a time (256 weights)
    const uint64_t blocks_per_iter = 8;
    const uint64_t main_loop_count = blockCount / blocks_per_iter;
    const uint64_t remainder_blocks = blockCount % blocks_per_iter;
    
    // Load lookup tables into ZMM registers (cached for entire function)
    const __m512i* low_table = reinterpret_cast<const __m512i*>(nibble_low_table);
    const __m512i* high_table = reinterpret_cast<const __m512i*>(nibble_high_table);
    
    // Main loop: Process 8 blocks (256 weights) per iteration
    for (uint64_t i = 0; i < main_loop_count; ++i) {
        const uint8_t* block_base = src + (i * blocks_per_iter * Q4_0_BYTES_PER_BLOCK);
        float* out_base = dest + (i * blocks_per_iter * Q4_0_BLOCK_SIZE);
        
        // Process 8 blocks in parallel
        #pragma unroll
        for (int b = 0; b < 8; ++b) {
            const uint8_t* block = block_base + (b * Q4_0_BYTES_PER_BLOCK);
            
            // Load scale (float16) and convert to float32
            // Scale is at bytes 0-1 of each 18-byte block
            uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(block);
            
            // Simple float16 to float32 conversion
            // float16: 1 sign bit, 5 exponent bits, 10 mantissa bits
            uint32_t sign = (scale_f16 >> 15) & 0x1;
            uint32_t exponent = (scale_f16 >> 10) & 0x1F;
            uint32_t mantissa = scale_f16 & 0x3FF;
            
            float scale;
            if (exponent == 0) {
                // Denormalized
                scale = (sign ? -1.0f : 1.0f) * (mantissa / 1024.0f) * (1.0f / 16384.0f);
            } else if (exponent == 31) {
                // Infinity/NaN
                scale = sign ? -INFINITY : INFINITY;
            } else {
                // Normalized
                scale = (sign ? -1.0f : 1.0f) * (1.0f + mantissa / 1024.0f) * 
                        (1 << (exponent - 15));
            }
            
            // Broadcast scale to all 16 elements
            __m512 scale_vec = _mm512_set1_ps(scale);
            
            // Load packed weights (16 bytes = 32 nibbles)
            __m128i packed_weights = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(block + 2)
            );
            
            // Unpack low nibbles (bytes 0-15)
            __m128i low_mask = _mm_set1_epi8(0x0F);
            __m128i low_nibbles = _mm_and_si128(packed_weights, low_mask);
            
            // Unpack high nibbles (bytes 16-31)
            __m128i high_nibbles = _mm_srli_epi16(packed_weights, 4);
            high_nibbles = _mm_and_si128(high_nibbles, low_mask);
            
            // Convert to 512-bit for AVX-512 operations
            __m512i low_512 = _mm512_cvtepu8_epi32(low_nibbles);
            __m512i high_512 = _mm512_cvtepu8_epi32(high_nibbles);
            
            // Subtract zero point (8) to get signed values: (q - 8)
            __m512i zero_point = _mm512_set1_epi32(8);
            low_512 = _mm512_sub_epi32(low_512, zero_point);
            high_512 = _mm512_sub_epi32(high_512, zero_point);
            
            // Convert to float
            __m512 low_f32 = _mm512_cvtepi32_ps(low_512);
            __m512 high_f32 = _mm512_cvtepi32_ps(high_512);
            
            // Multiply by scale: weight = (q - 8) * scale
            low_f32 = _mm512_mul_ps(low_f32, scale_vec);
            high_f32 = _mm512_mul_ps(high_f32, scale_vec);
            
            // Store results
            _mm512_storeu_ps(out_base + (b * 32), low_f32);
            _mm512_storeu_ps(out_base + (b * 32) + 16, high_f32);
        }
    }
    
    // Handle remaining blocks (0-7 blocks)
    const uint8_t* remainder_src = src + (main_loop_count * blocks_per_iter * Q4_0_BYTES_PER_BLOCK);
    float* remainder_dst = dest + (main_loop_count * blocks_per_iter * Q4_0_BLOCK_SIZE);
    
    for (uint64_t i = 0; i < remainder_blocks; ++i) {
        const uint8_t* block = remainder_src + (i * Q4_0_BYTES_PER_BLOCK);
        float* out = remainder_dst + (i * Q4_0_BLOCK_SIZE);
        
        // Load and convert scale
        uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(block);
        uint32_t sign = (scale_f16 >> 15) & 0x1;
        uint32_t exponent = (scale_f16 >> 10) & 0x1F;
        uint32_t mantissa = scale_f16 & 0x3FF;
        
        float scale;
        if (exponent == 0) {
            scale = (sign ? -1.0f : 1.0f) * (mantissa / 1024.0f) * (1.0f / 16384.0f);
        } else if (exponent == 31) {
            scale = sign ? -INFINITY : INFINITY;
        } else {
            scale = (sign ? -1.0f : 1.0f) * (1.0f + mantissa / 1024.0f) * 
                    (1 << (exponent - 15));
        }
        
        // Process 32 weights in two chunks of 16
        __m128i packed = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(block + 2)
        );
        
        // First 16 weights (low nibbles)
        __m128i low_mask = _mm_set1_epi8(0x0F);
        __m128i low_nibbles = _mm_and_si128(packed, low_mask);
        __m512i low_512 = _mm512_cvtepu8_epi32(low_nibbles);
        __m512i zero_point = _mm512_set1_epi32(8);
        low_512 = _mm512_sub_epi32(low_512, zero_point);
        __m512 low_f32 = _mm512_cvtepi32_ps(low_512);
        __m512 scale_vec = _mm512_set1_ps(scale);
        low_f32 = _mm512_mul_ps(low_f32, scale_vec);
        _mm512_storeu_ps(out, low_f32);
        
        // Last 16 weights (high nibbles)
        __m128i high_nibbles = _mm_srli_epi16(packed, 4);
        high_nibbles = _mm_and_si128(high_nibbles, low_mask);
        __m512i high_512 = _mm512_cvtepu8_epi32(high_nibbles);
        high_512 = _mm512_sub_epi32(high_512, zero_point);
        __m512 high_f32 = _mm512_cvtepi32_ps(high_512);
        high_f32 = _mm512_mul_ps(high_f32, scale_vec);
        _mm512_storeu_ps(out + 16, high_f32);
    }
    
    return 0;  // Success
}

/**
 * @brief Simplified version for direct GGUF bridge integration
 * Matches the signature expected by the GGUF loader
 */
int64_t Aperture_Q4_0_Dequant_AVX512_Inline(
    float* dest,
    const uint8_t* src,
    uint64_t blockCount
) {
    return Aperture_Q4_0_Dequant_AVX512_Intrinsics(dest, src, blockCount);
}

} // extern "C"
