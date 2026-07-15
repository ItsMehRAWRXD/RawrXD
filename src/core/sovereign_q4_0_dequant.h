// =============================================================================
// sovereign_q4_0_dequant.h
// Q4_0 Dequantization for Sovereign Engine
// =============================================================================

#ifndef SOVEREIGN_Q4_0_DEQUANT_H
#define SOVEREIGN_Q4_0_DEQUANT_H

#include <cstdint>
#include <cstddef>
#include <cmath>
#include <limits>

namespace Sovereign {

// Q4_0 Format Constants
static constexpr size_t Q4_0_BLOCK_SIZE = 32;      // Weights per block
static constexpr size_t Q4_0_BLOCK_BYTES = 18;     // Bytes per block (2 scale + 16 weights)
static constexpr size_t Q4_0_SCALE_BYTES = 2;    // Scale is float16

/**
 * @brief Convert float16 to float32
 * @param h Float16 value as uint16_t
 * @return Float32 value
 */
inline float float16_to_float32(uint16_t h) {
    // Extract components
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exponent = (h >> 10) & 0x1F;
    uint32_t mantissa = h & 0x3FF;
    
    // Handle special cases
    if (exponent == 0) {
        if (mantissa == 0) {
            return sign ? -0.0f : 0.0f;
        }
        // Denormal
        float value = static_cast<float>(mantissa) / 1024.0f;
        return sign ? -value * 0.00006103515625f : value * 0.00006103515625f;
    } else if (exponent == 31) {
        if (mantissa == 0) {
            return sign ? -std::numeric_limits<float>::infinity() : std::numeric_limits<float>::infinity();
        }
        return std::numeric_limits<float>::quiet_NaN();
    }
    
    // Normal number
    uint32_t f32_sign = sign << 31;
    uint32_t f32_exponent = (exponent + 112) << 23;
    uint32_t f32_mantissa = mantissa << 13;
    
    union {
        uint32_t u;
        float f;
    } converter;
    converter.u = f32_sign | f32_exponent | f32_mantissa;
    return converter.f;
}

/**
 * @brief Dequantize a single Q4_0 block
 * @param src Source block (18 bytes: 2 bytes FP16 scale + 16 bytes packed weights)
 * @param dst Destination buffer (32 floats)
 */
inline void dequantize_q4_0_block(const uint8_t* __restrict src, float* __restrict dst) {
    // Read FP16 scale
    uint16_t scale_fp16 = *reinterpret_cast<const uint16_t*>(src);
    float scale = float16_to_float32(scale_fp16);
    
    // Unpack 32 weights from 16 bytes (2 weights per byte)
    for (size_t i = 0; i < 16; ++i) {
        uint8_t packed = src[2 + i];
        uint8_t high_nibble = (packed >> 4) & 0x0F;
        uint8_t low_nibble = packed & 0x0F;
        
        // Dequantize: w = (q - 8) * scale
        dst[i * 2] = (static_cast<float>(high_nibble) - 8.0f) * scale;
        dst[i * 2 + 1] = (static_cast<float>(low_nibble) - 8.0f) * scale;
    }
}

/**
 * @brief Dequantize Q4_0 tensor to float32
 * @param src Source tensor (Q4_0 quantized)
 * @param dst Destination buffer (float32)
 * @param num_blocks Number of Q4_0 blocks to dequantize
 * @return 0 on success, -1 on error
 */
inline int DequantizeQ4_0(const uint8_t* __restrict src,
                          float* __restrict dst,
                          size_t num_blocks) {
    if (!src || !dst || num_blocks == 0) {
        return -1;
    }
    
    for (size_t block = 0; block < num_blocks; ++block) {
        const uint8_t* block_src = src + block * Q4_0_BLOCK_BYTES;
        float* block_dst = dst + block * Q4_0_BLOCK_SIZE;
        dequantize_q4_0_block(block_src, block_dst);
    }
    
    return 0;
}

/**
 * @brief Calculate number of elements in a Q4_0 tensor
 * @param tensor_size_bytes Size of the Q4_0 tensor in bytes
 * @return Number of elements (float32 values after dequantization)
 */
inline size_t GetElementCount_Q4_0(size_t tensor_size_bytes) {
    return (tensor_size_bytes / Q4_0_BLOCK_BYTES) * Q4_0_BLOCK_SIZE;
}

} // namespace Sovereign

#endif // SOVEREIGN_Q4_0_DEQUANT_H
