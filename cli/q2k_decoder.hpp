#pragma once
// ============================================================================
// Q2_K Block Decoder — GGML Q2_K dequantization for TensorView
// ============================================================================
// Q2_K layout (per 256-element block):
//   - 1 byte: scale (shared across block)
//   - 1 byte: min (shared across block)
//   - 32 bytes: 256 x 2-bit weights (packed 4 per byte)
// Total: 34 bytes per 256 elements
// ============================================================================

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace CLI {

// Q2_K block structure (matches GGML layout)
struct Q2_KBlock {
    uint8_t scale;  // Shared scale factor
    uint8_t min;    // Shared minimum value
    uint8_t qs[32]; // 256 x 2-bit quantized values (packed)
    
    static constexpr size_t BLOCK_SIZE = 256;  // Elements per block
    static constexpr size_t BYTES_PER_BLOCK = 34;  // Bytes per block
    
    // Decode single element from block
    // idx: 0-255 within block
    float Decode(size_t idx) const;
    
    // Decode full block to float array
    // dst must have space for BLOCK_SIZE floats
    void DecodeBlock(float* dst) const;
};

// Q2_K row decoder
class Q2_KDecoder {
public:
    // Decode a row of Q2_K data
    // src: pointer to Q2_K packed data
    // dst: output float buffer (must have space for numElements)
    // numElements: number of elements to decode
    // Returns true on success
    static bool DecodeRow(const uint8_t* src, float* dst, size_t numElements);
    
    // Calculate number of blocks needed for given element count
    static size_t NumBlocks(size_t numElements) {
        return (numElements + Q2_KBlock::BLOCK_SIZE - 1) / Q2_KBlock::BLOCK_SIZE;
    }
    
    // Calculate bytes needed for given element count
    static size_t ByteSize(size_t numElements) {
        return NumBlocks(numElements) * Q2_KBlock::BYTES_PER_BLOCK;
    }
};

} // namespace CLI
} // namespace RawrXD
