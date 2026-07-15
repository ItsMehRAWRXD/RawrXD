#pragma once
// ============================================================================
// Quantization Decoder — GGML format dequantization for TensorView
// ============================================================================
// Purpose: Convert quantized GGML blocks to float arrays
// Supports: Q2_K, Q4_K, Q6_K (starting with Q2_K for Phi3-mini)
// ============================================================================

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace CLI {

// Q2_K block structure (from GGML/llama.cpp)
// 256 elements per block
// Layout: scales (6 bytes) + mins (6 bytes) + qs (128 bytes) + d (2 bytes) + dmin (2 bytes)
// Total: 144 bytes per block
struct Q2_KBlock {
    uint8_t scales[6];      // 6 scale values (packed)
    uint8_t mins[6];        // 6 min values (packed)
    uint8_t qs[128];        // 128 bytes of 4-bit quantized values
    uint16_t d;             // 16-bit float scale
    uint16_t dmin;          // 16-bit float min

    // Decode 256 floats from this block
    // dst must have space for 256 floats
    void Decode(float* dst) const;

    // Get scale as float
    float Scale() const;

    // Get min as float
    float Min() const;
};

// Q2_K decoder
class Q2_KDecoder {
public:
    // Decode a single element at given index within a block
    // index must be 0-255
    static float DecodeElement(const Q2_KBlock* block, size_t index);

    // Decode entire block to float array
    // dst must have space for 256 floats
    static void DecodeBlock(const Q2_KBlock* block, float* dst);

    // Decode a row of Q2_K data
    // rowData: pointer to start of row (may span multiple blocks)
    // rowSize: number of elements in row
    // dst: output buffer (must be sized for rowSize floats)
    static bool DecodeRow(const uint8_t* rowData, size_t rowSize, float* dst);

    // Get number of blocks needed for given element count
    static size_t NumBlocks(size_t numElements) {
        return (numElements + 255) / 256;  // Round up
    }

    // Get block size in bytes
    static constexpr size_t BlockSize() { return sizeof(Q2_KBlock); }

    // Get elements per block
    static constexpr size_t ElementsPerBlock() { return 256; }
};

// F16 to F32 conversion helper
float F16ToF32(uint16_t h);

} // namespace CLI
} // namespace RawrXD
