#pragma once
// ============================================================================
// Q4_0 Decoder - Dequantize Q4_0 tensors to F32
// ============================================================================
// Q4_0 format: 32 4-bit weights + 1 F16 scale per block (18 bytes per 32 weights)
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <vector>

namespace RawrXD {
namespace Runtime {

// Q4_0 block structure
struct Q4_0Block {
    uint16_t scale;  // F16 scale
    uint8_t qs[16];  // 32 4-bit weights packed (16 bytes)
};

class Q4_0Decoder {
public:
    // Dequantize Q4_0 tensor to F32
    // Input: raw Q4_0 data, number of elements
    // Output: F32 vector (must be pre-allocated)
    static bool Dequantize(const uint8_t* input, size_t num_elements,
                           float* output, size_t output_size);
    
    // Get the size of dequantized data
    static size_t GetDequantizedSize(size_t num_elements);
    
    // Calculate number of Q4_0 blocks needed
    static size_t GetNumBlocks(size_t num_elements);
    
    // Calculate raw Q4_0 size in bytes
    static size_t GetQuantizedSize(size_t num_elements);

private:
    // Convert F16 to F32
    static float F16ToF32(uint16_t f16);
    
    // Extract 4-bit weight from packed bytes
    static inline int8_t GetQ4_0Weight(const uint8_t* qs, int idx) {
        return (qs[idx / 2] >> (4 * (idx % 2))) & 0x0F;
    }
};

} // namespace Runtime
} // namespace RawrXD
