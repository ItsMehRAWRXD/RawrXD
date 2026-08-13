#pragma once
#include <cstdint>
#include <cmath>
#include <cstring>

// ============================================================================
// RawrXD Braid-0 Base-Plane Kernel — C++ Reference Implementation
// ============================================================================
// Braid-0 consumes ONLY the base plane (1-bit per weight).
// No residual processing. No sparse decode. No bounce logic.
//
// Algorithm per tile:
//   for each weight in tile:
//     w = ((base_plane[bit_index] >> bit_offset) & 1) ? scale : -scale
//     accum += w * activation[activation_index]
//   output = BF16(accum)
// ============================================================================

namespace Braid0 {

// ============================================================================
// BF16 conversion (software implementation, no ISA dependency)
// ============================================================================
inline uint16_t FloatToBF16(float value) {
    union { float f; uint32_t u; } converter;
    converter.f = value;
    uint32_t u = converter.u;

    // Round to nearest even: add 0x7FFF + (bit 16 of mantissa) to round
    uint32_t rounding = (u >> 16) & 1;
    u += (0x7FFF + rounding);

    // Truncate to upper 16 bits
    return static_cast<uint16_t>(u >> 16);
}

inline float BF16ToFloat(uint16_t bf16) {
    union { float f; uint32_t u; } converter;
    converter.u = static_cast<uint32_t>(bf16) << 16;
    return converter.f;
}

// ============================================================================
// Scalar reference: 1-bit unpack + GEMM + BF16 accumulation
// ============================================================================
// Parameters:
//   base_plane    — packed 1-bit weights (ceil(tile_size/8) bytes)
//   activations   — FP32 input vector (tile_size elements)
//   tile_size     — number of weights in this tile (1..64, may be partial)
//   scale         — quantization scale factor
//   out_bf16      — output BF16 accumulator (single value)
//
// Returns true on success, false on invalid parameters
// ============================================================================
inline bool ScalarBasePlaneGEMM(
    const uint8_t* base_plane,
    const float* activations,
    int tile_size,
    float scale,
    uint16_t* out_bf16)
{
    if (!base_plane || !activations || !out_bf16 || tile_size <= 0) {
        return false;
    }

    float accum = 0.0f;

    for (int i = 0; i < tile_size; ++i) {
        // Extract 1-bit weight
        int byte_idx = i >> 3;
        int bit_idx = i & 7;
        uint8_t bit = (base_plane[byte_idx] >> bit_idx) & 1;

        // Unpack to signed FP32: bit=1 → +scale, bit=0 → -scale
        float weight = bit ? scale : -scale;

        // FMA
        accum += weight * activations[i];
    }

    // Convert accumulator to BF16
    *out_bf16 = FloatToBF16(accum);
    return true;
}

// ============================================================================
// Tile-local batch GEMM: multiple tiles in one call
// ============================================================================
inline bool ScalarBasePlaneGEMMBatch(
    const uint8_t* base_planes,      // Concatenated base planes for all tiles
    const float* activations,        // Concatenated activations for all tiles
    int tile_size,                   // Elements per tile (typically 64)
    int num_tiles,                   // Number of tiles
    float scale,                     // Global quantization scale
    uint16_t* out_bf16)              // Output array (num_tiles elements)
{
    if (!base_planes || !activations || !out_bf16 || tile_size <= 0 || num_tiles <= 0) {
        return false;
    }

    const int bytes_per_tile = (tile_size + 7) >> 3;

    for (int t = 0; t < num_tiles; ++t) {
        const uint8_t* tile_base = base_planes + t * bytes_per_tile;
        const float* tile_act = activations + t * tile_size;
        uint16_t* tile_out = out_bf16 + t;

        if (!ScalarBasePlaneGEMM(tile_base, tile_act, tile_size, scale, tile_out)) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// Verification helpers
// ============================================================================
inline bool BF16Equivalence(float a, float b, float tolerance = 1e-3f) {
    // BF16 has ~3 decimal digits of precision
    float diff = std::fabs(a - b);
    float max_val = std::max(std::fabs(a), std::fabs(b));
    if (max_val < 1e-6f) return diff < tolerance;
    return (diff / max_val) < tolerance;
}

} // namespace Braid0
