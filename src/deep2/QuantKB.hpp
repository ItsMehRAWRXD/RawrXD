#pragma once
#include <cstdint>
#include <cstddef>

// ============================================================================
// RawrXD QuantKB Engine -- C++ Interface
// 2-Bit Non-Uniform Bucket-Mapped Block Quantizer
// ============================================================================

// 24-byte packed block: 64 FP32 elements compressed to 8-byte FP16 header +
// 16-byte packed 2-bit indices.
struct alignas(8) QuantKB2Bit {
    uint16_t centroids[4];   // 4 x FP16 centroid values (8 bytes)
    uint64_t packed_bits[2]; // 64 x 2-bit bucket indices (16 bytes)
};

static_assert(sizeof(QuantKB2Bit) == 24, "QuantKB2Bit must be exactly 24 bytes");
static_assert(alignof(QuantKB2Bit) == 8, "QuantKB2Bit must be 8-byte aligned");

extern "C" {

// Compress 64 FP32 floats (256 bytes) into a 24-byte QuantKB2Bit block.
//   src: pointer to 64 contiguous floats
//   dst: pointer to QuantKB2Bit output block
void CompressBlock64_MASM(const float* src, QuantKB2Bit* dst);

// Decompress a 24-byte QuantKB2Bit block back into 64 FP32 floats.
//   src: pointer to QuantKB2Bit input block
//   dst: pointer to 64-float output buffer
void DecompressBlock64_MASM(const QuantKB2Bit* src, float* dst);

}

// ============================================================================
// Convenience C++ wrappers (optional)
// ============================================================================

inline void QuantKB_CompressBlock(const float* src, QuantKB2Bit* dst) {
    CompressBlock64_MASM(src, dst);
}

inline void QuantKB_DecompressBlock(const QuantKB2Bit* src, float* dst) {
    DecompressBlock64_MASM(src, dst);
}
