// ============================================================================
// aperture_q8_0_avx512_intrinsics.cpp — Optimized AVX-512 Q8_0 Dequantization
// ============================================================================
//
// Q8_0 Format:
//   - 32 weights per block
//   - 34 bytes per block:
//     - Bytes 0-1: scale (float16)
//     - Bytes 2-33: 32 x int8 weights
//   - Dequantization: weight = int8_weight * scale
//
// Performance Target: 200-400M weights/sec
// Strategy:
//   - Process 256 weights per iteration (8 blocks × 32 weights)
//   - Direct int8 to float conversion via AVX-512
//   - No nibble unpacking (simpler than Q4_0)
//
// ============================================================================

#include <immintrin.h>
#include <cmath>
#include <limits>
#include <cstdint>
#include <cstddef>

// Q8_0 format constants
static constexpr int Q8_0_BLOCK_SIZE = 32;
static constexpr int Q8_0_BYTES_PER_BLOCK = 34;

extern "C" {

/**
 * @brief Optimized AVX-512 Q8_0 dequantization using intrinsics
 * 
 * Q8_0 is simpler than Q4_0 because:
 *   - Each weight is a full int8 (no nibble packing)
 *   - Direct conversion: _mm512_cvtepi8_epi32 → _mm512_cvtepi32_ps
 * 
 * Processes 256 weights per iteration (8 blocks × 32 weights)
 * Target: 200-400M weights/sec
 * 
 * @param dest Output buffer for float32 weights
 * @param src Input buffer with Q8_0 blocks
 * @param blockCount Number of Q8_0 blocks to process
 * @return 0 on success, negative on error
 */
int64_t Aperture_Q8_0_Dequant_AVX512_Intrinsics(
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
    
    // Main loop: Process 8 blocks (256 weights) per iteration
    for (uint64_t i = 0; i < main_loop_count; ++i) {
        const uint8_t* block_base = src + (i * blocks_per_iter * Q8_0_BYTES_PER_BLOCK);
        float* out_base = dest + (i * blocks_per_iter * Q8_0_BLOCK_SIZE);
        
        // Process 8 blocks in parallel
        #pragma unroll
        for (int b = 0; b < 8; ++b) {
            const uint8_t* block = block_base + (b * Q8_0_BYTES_PER_BLOCK);
            
            // Load scale (float16) and convert to float32
            uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(block);
            
            // Float16 to float32 conversion
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
            
            // Load 32 int8 weights (2 × 16 bytes)
            // First 16 weights
            __m128i weights_low = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(block + 2)
            );
            
            // Last 16 weights
            __m128i weights_high = _mm_loadu_si128(
                reinterpret_cast<const __m128i*>(block + 18)
            );
            
            // Convert int8 to int32 (sign-extended)
            __m512i weights_low_512 = _mm512_cvtepi8_epi32(weights_low);
            __m512i weights_high_512 = _mm512_cvtepi8_epi32(weights_high);
            
            // Convert int32 to float32
            __m512 weights_low_f32 = _mm512_cvtepi32_ps(weights_low_512);
            __m512 weights_high_f32 = _mm512_cvtepi32_ps(weights_high_512);
            
            // Multiply by scale: weight = int8_weight * scale
            weights_low_f32 = _mm512_mul_ps(weights_low_f32, scale_vec);
            weights_high_f32 = _mm512_mul_ps(weights_high_f32, scale_vec);
            
            // Store results
            _mm512_storeu_ps(out_base + (b * 32), weights_low_f32);
            _mm512_storeu_ps(out_base + (b * 32) + 16, weights_high_f32);
        }
    }
    
    // Handle remaining blocks (0-7 blocks)
    const uint8_t* remainder_src = src + (main_loop_count * blocks_per_iter * Q8_0_BYTES_PER_BLOCK);
    float* remainder_dst = dest + (main_loop_count * blocks_per_iter * Q8_0_BLOCK_SIZE);
    
    for (uint64_t i = 0; i < remainder_blocks; ++i) {
        const uint8_t* block = remainder_src + (i * Q8_0_BYTES_PER_BLOCK);
        float* out = remainder_dst + (i * Q8_0_BLOCK_SIZE);
        
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
        __m512 scale_vec = _mm512_set1_ps(scale);
        
        // First 16 weights
        __m128i weights_low = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(block + 2)
        );
        __m512i weights_low_512 = _mm512_cvtepi8_epi32(weights_low);
        __m512 weights_low_f32 = _mm512_cvtepi32_ps(weights_low_512);
        weights_low_f32 = _mm512_mul_ps(weights_low_f32, scale_vec);
        _mm512_storeu_ps(out, weights_low_f32);
        
        // Last 16 weights
        __m128i weights_high = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(block + 18)
        );
        __m512i weights_high_512 = _mm512_cvtepi8_epi32(weights_high);
        __m512 weights_high_f32 = _mm512_cvtepi32_ps(weights_high_512);
        weights_high_f32 = _mm512_mul_ps(weights_high_f32, scale_vec);
        _mm512_storeu_ps(out + 16, weights_high_f32);
    }
    
    return 0;  // Success
}

/**
 * @brief Simplified version for direct GGUF bridge integration
 * Matches the signature expected by the GGUF loader
 */
int64_t Aperture_Q8_0_Dequant_AVX512_Inline(
    float* dest,
    const uint8_t* src,
    uint64_t blockCount
) {
    return Aperture_Q8_0_Dequant_AVX512_Intrinsics(dest, src, blockCount);
}

} // extern "C"
