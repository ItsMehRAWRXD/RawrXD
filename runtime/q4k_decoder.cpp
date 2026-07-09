#include "q4k_decoder.hpp"
#include <cstring>
#include <cmath>

namespace rawrxd {

// F16 to F32 conversion (IEEE 754 half-precision)
float Q4KDecoder::F16ToF32(uint16_t f16) {
    // Extract components
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    uint32_t f32;
    if (exp == 0) {
        // Zero or denormal
        if (mant == 0) {
            f32 = sign << 31;
        } else {
            // Denormal
            exp = 1;
            while ((mant & 0x400) == 0) {
                mant <<= 1;
                exp--;
            }
            mant &= 0x3FF;
            f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        // Infinity or NaN
        f32 = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        // Normal
        f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    }
    
    float result;
    std::memcpy(&result, &f32, sizeof(result));
    return result;
}

void Q4KDecoder::GetBlockScaleMin(const BlockQ4_K* block, float& scale, float& min) {
    scale = F16ToF32(block->d);
    min = F16ToF32(block->dmin);
}

void Q4KDecoder::DecodeBlock(const BlockQ4_K* block, float* output) {
    float d = F16ToF32(block->d);
    float dmin = F16ToF32(block->dmin);
    
    // Q4_K uses a more complex scaling scheme than Q2_K
    // The 256 values are divided into 8 groups of 32
    // Each group has its own scale and min derived from the packed scales
    
    // Unpack the 12 scale bytes into 8 scales and 8 mins
    // Each scale/min is 6 bits, packed into the 12 bytes
    float scales[8];
    float mins[8];
    
    // Unpack scales (llama.cpp style)
    // scales are stored as 6-bit values in the 12 bytes
    // This is the Q6_K-style packing adapted for Q4_K
    for (int i = 0; i < 8; i++) {
        int scale_idx = i;
        int min_idx = i + 8;
        
        // Extract 6-bit scale and min from packed bytes
        // Each value spans parts of multiple bytes
        int byte_offset = (i * 6) / 8;
        int bit_offset = (i * 6) % 8;
        
        // Read 6 bits for scale
        uint16_t scale_bits = (block->scales[byte_offset] >> bit_offset);
        if (bit_offset + 6 > 8) {
            scale_bits |= (block->scales[byte_offset + 1] << (8 - bit_offset));
        }
        scale_bits &= 0x3F; // 6 bits
        
        // Read 6 bits for min
        uint16_t min_bits = (block->scales[byte_offset + 6] >> bit_offset);
        if (bit_offset + 6 > 8) {
            min_bits |= (block->scales[byte_offset + 7] << (8 - bit_offset));
        }
        min_bits &= 0x3F;
        
        scales[i] = d * scale_bits;
        mins[i] = dmin * min_bits;
    }
    
    // Dequantize the 256 values
    // qs contains 128 bytes = 256 4-bit values
    for (int group = 0; group < 8; group++) {
        float group_scale = scales[group];
        float group_min = mins[group];
        
        for (int j = 0; j < 32; j++) {
            int idx = group * 32 + j;
            uint8_t q = GetQ4(block->qs, idx);
            output[idx] = group_scale * q + group_min;
        }
    }
}

void Q4KDecoder::DecodeRow(const uint8_t* row_data, size_t num_elements, float* output) {
    const BlockQ4_K* blocks = reinterpret_cast<const BlockQ4_K*>(row_data);
    size_t num_blocks = (num_elements + 255) / 256; // Round up
    
    size_t elements_decoded = 0;
    for (size_t b = 0; b < num_blocks && elements_decoded < num_elements; b++) {
        float block_output[256];
        DecodeBlock(&blocks[b], block_output);
        
        size_t to_copy = std::min(size_t(256), num_elements - elements_decoded);
        std::memcpy(output + elements_decoded, block_output, to_copy * sizeof(float));
        elements_decoded += to_copy;
    }
}

} // namespace rawrxd
