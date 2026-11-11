#include "q4_0_decoder.hpp"
#include <cstring>
#include <cmath>

namespace RawrXD {
namespace Runtime {

// F16 to F32 conversion table (simplified - uses bit manipulation)
float Q4_0Decoder::F16ToF32(uint16_t f16) {
    // Extract components
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    // Handle special cases
    if (exp == 0) {
        if (mant == 0) {
            // Zero
            return sign ? -0.0f : 0.0f;
        }
        // Subnormal
        float val = mant / 1024.0f * std::pow(2.0f, -14);
        return sign ? -val : val;
    }
    if (exp == 31) {
        if (mant == 0) {
            // Infinity
            return sign ? -std::numeric_limits<float>::infinity() : std::numeric_limits<float>::infinity();
        }
        // NaN
        return std::numeric_limits<float>::quiet_NaN();
    }
    
    // Normal number
    float val = (1.0f + mant / 1024.0f) * std::pow(2.0f, exp - 15);
    return sign ? -val : val;
}

bool Q4_0Decoder::Dequantize(const uint8_t* input, size_t num_elements,
                             float* output, size_t output_size) {
    if (!input || !output) {
        return false;
    }
    
    size_t expected_output = GetDequantizedSize(num_elements);
    if (output_size < expected_output) {
        return false;
    }
    
    const size_t num_blocks = GetNumBlocks(num_elements);
    const Q4_0Block* blocks = reinterpret_cast<const Q4_0Block*>(input);
    
    size_t out_idx = 0;
    for (size_t b = 0; b < num_blocks; ++b) {
        float scale = F16ToF32(blocks[b].scale);
        
        // Dequantize 32 weights per block
        for (int i = 0; i < 32 && out_idx < num_elements; ++i) {
            int8_t q = GetQ4_0Weight(blocks[b].qs, i);
            // Q4_0: values 0-15, centered at 8
            output[out_idx++] = (q - 8) * scale;
        }
    }
    
    return true;
}

size_t Q4_0Decoder::GetDequantizedSize(size_t num_elements) {
    return num_elements * sizeof(float);
}

size_t Q4_0Decoder::GetNumBlocks(size_t num_elements) {
    return (num_elements + 31) / 32;  // Round up to nearest 32
}

size_t Q4_0Decoder::GetQuantizedSize(size_t num_elements) {
    return GetNumBlocks(num_elements) * sizeof(Q4_0Block);  // 18 bytes per block
}

} // namespace Runtime
} // namespace RawrXD
