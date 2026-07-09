#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace rawrxd {

// Q4_K block structure (llama.cpp compatible)
// 256 weights per block, 144 bytes
struct BlockQ4_K {
    uint8_t scales[12];           // 12 bytes of packed 6-bit scales (actually Q6_K style)
    uint8_t qs[128];            // 128 bytes of 4-bit weights (256 values)
    uint16_t d;                 // F16 super-scale
    uint16_t dmin;              // F16 super-min
};

static_assert(sizeof(BlockQ4_K) == 144, "BlockQ4_K must be 144 bytes");

// Q8_K block structure (llama.cpp compatible)
// 256 weights per block, 276 bytes
// Note: llama.cpp uses float d, not F16
struct BlockQ8_K {
    float d;              // delta (float, not F16)
    int8_t qs[256];       // 256 int8 weights
    int16_t bsums[16];    // sum of quants in groups of 16
};
static_assert(sizeof(BlockQ8_K) == 4 + 256 + 32, "BlockQ8_K must be 292 bytes");

class Q4KDecoder {
public:
    // Dequantize a single block to 256 floats
    static void DecodeBlock(const BlockQ4_K* block, float* output);
    
    // Dequantize a row of Q4_K data
    // row_data: pointer to Q4_K blocks
    // num_elements: number of elements (must be multiple of 256, or handle remainder)
    // output: float buffer (must hold num_elements)
    static void DecodeRow(const uint8_t* row_data, size_t num_elements, float* output);
    
    // Get the scale and min for a block (for debugging)
    static void GetBlockScaleMin(const BlockQ4_K* block, float& scale, float& min);
    
private:
    // Helper: convert F16 to F32
    static float F16ToF32(uint16_t f16);
    
    // Helper: unpack 4-bit values from qs
    static inline uint8_t GetQ4(const uint8_t* qs, int idx) {
        return (idx & 1) ? (qs[idx >> 1] >> 4) : (qs[idx >> 1] & 0xF);
    }
};

} // namespace rawrxd
