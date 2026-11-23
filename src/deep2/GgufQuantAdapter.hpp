#ifndef RAWRXD_GGUF_QUANT_ADAPTER_HPP
#define RAWRXD_GGUF_QUANT_ADAPTER_HPP
// ============================================================================
// GgufQuantAdapter.hpp -- native GGUF quantization handling (Stage 6G).
// ----------------------------------------------------------------------------
// Correctly reads and dequantizes GGUF packed quantization formats so the INT4
// GPU path can consume them WITHOUT dequantize-then-requantize:
//
//   Q4_0 (type 2):  32 values/block, {fp16 d, uint8 qs[16]}, w = d*(q-8)
//                   -- maps to symmetric INT4 (q-8 is signed -8..7, scale d)
//   Q4_K (type 12): 256 values/superblock, 8 sub-blocks each {fp16 scale, fp16
//                   min}, w = d*scale[j]*q - dmin*min[j]
//                   -- NOT symmetric INT4; requires the superblock transform
//   F32 (type 0):   4 bytes/elem; F16 (type 1): 2 bytes/elem
//
// This is the foundation for native consumption: the GPU shader can read Q4_0
// directly (it is symmetric INT4 with a 32-value block), while Q4_K needs its
// own superblock-aware kernel. The adapter provides correct dequant references
// so the GPU output can be validated against the GGUF specification.
//
// Header-only, C++17, no deps.
// ============================================================================
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace rawrxd::gguf {

enum class QuantType : uint32_t {
    F32 = 0, F16 = 1, Q4_0 = 2, Q4_1 = 3, Q5_0 = 6, Q5_1 = 7,
    Q8_0 = 8, Q8_1 = 9, Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13,
    Q6_K = 14, Q8_K = 15, Unknown = 0xFFFFFFFFu
};

inline float HalfToFloat(uint16_t h) {
    uint32_t sign = (h & 0x8000u) << 16;
    uint32_t exp = (h >> 10) & 0x1f;
    uint32_t man = h & 0x3ffu;
    uint32_t out;
    if (exp == 0) {
        if (man == 0) out = sign;
        else { exp = 127 - 15 + 1; while (!(man & 0x400)) { man <<= 1; exp--; } man &= 0x3ff; out = sign | (exp << 23) | (man << 13); }
    } else if (exp == 31) out = sign | 0x7f800000u | (man << 13);
    else out = sign | ((exp - 15 + 127) << 23) | (man << 13);
    float f; std::memcpy(&f, &out, 4); return f;
}

inline uint16_t ReadF16(const uint8_t* p) {
    uint16_t h; std::memcpy(&h, p, 2); return h;
}

// Q4_0: 32 values, 18 bytes: {fp16 d, uint8 qs[16]}. w = d*(q-8).
inline void DequantizeQ4_0(const uint8_t* blocks, size_t n_blocks, std::vector<float>& out) {
    out.resize(n_blocks * 32);
    for (size_t b = 0; b < n_blocks; ++b) {
        const uint8_t* blk = blocks + b * 18;
        const float d = HalfToFloat(ReadF16(blk));
        const uint8_t* qs = blk + 2;
        for (int j = 0; j < 16; ++j) {
            uint8_t byte = qs[j];
            int q0 = byte & 0x0f;
            int q1 = byte >> 4;
            out[b * 32 + j * 2]     = d * (float)(q0 - 8);
            out[b * 32 + j * 2 + 1] = d * (float)(q1 - 8);
        }
    }
}

// Q4_K: 256 values, 144 bytes. Layout (ggml block_q4_K):
//   ggml_half d;       // super-block scale (fp16)
//   ggml_half dmin;    // super-block min (fp16)
//   uint8_t scales[12];// 6-bit packed sub-block scales + mins (8 sub-blocks)
//   uint8_t qs[128];   // 4-bit packed values
// Dequant: w = d * scale[j] * q - dmin * min[j], j = sub-block (0..7).
inline void DequantizeQ4_K(const uint8_t* blocks, size_t n_super, std::vector<float>& out) {
    out.resize(n_super * 256);
    for (size_t b = 0; b < n_super; ++b) {
        const uint8_t* blk = blocks + b * 144;
        const float d = HalfToFloat(ReadF16(blk));
        const float dmin = HalfToFloat(ReadF16(blk + 2));
        const uint8_t* scales = blk + 4;   // 12 bytes
        const uint8_t* qs = blk + 16;      // 128 bytes
        // Unpack 8 sub-block scales (6-bit) and mins (6-bit) from scales[12].
        // ggml packs: scales[0..5] = 8 6-bit scales, scales[6..11] = 8 6-bit mins.
        int subScale[8], subMin[8];
        for (int j = 0; j < 8; ++j) {
            // 6-bit extraction from the 12-byte packed stream.
            int bitPos = j * 6;
            int byteIdx = bitPos / 8;
            int bitOff = bitPos % 8;
            uint32_t v = scales[byteIdx];
            if (bitOff + 6 > 8 && byteIdx + 1 < 12) v |= (uint32_t)scales[byteIdx + 1] << 8;
            subScale[j] = (v >> bitOff) & 0x3f;
        }
        for (int j = 0; j < 8; ++j) {
            int bitPos = j * 6;
            int byteIdx = bitPos / 8 + 6; // mins start at scales[6]
            int bitOff = bitPos % 8;
            uint32_t v = scales[byteIdx];
            if (bitOff + 6 > 8 && byteIdx + 1 < 12) v |= (uint32_t)scales[byteIdx + 1] << 8;
            subMin[j] = (v >> bitOff) & 0x3f;
        }
        // 128 bytes = 256 4-bit values, grouped 32 per sub-block.
        for (int j = 0; j < 8; ++j) {
            float sc = d * (float)subScale[j];
            float mn = dmin * (float)subMin[j];
            const uint8_t* q = qs + j * 32; // 32 bytes = 64 values per sub-block? No: 16 bytes per sub-block
            // Each sub-block has 32 values = 16 bytes of 4-bit.
            for (int k = 0; k < 16; ++k) {
                uint8_t byte = qs[j * 16 + k];
                int q0 = byte & 0x0f;
                int q1 = byte >> 4;
                out[b * 256 + j * 32 + k * 2]     = sc * (float)q0 - mn;
                out[b * 256 + j * 32 + k * 2 + 1] = sc * (float)q1 - mn;
            }
        }
    }
}

// F32 / F16 direct.
inline void DequantizeF32(const uint8_t* data, size_t n, std::vector<float>& out) {
    out.resize(n);
    std::memcpy(out.data(), data, n * sizeof(float));
}
inline void DequantizeF16(const uint8_t* data, size_t n, std::vector<float>& out) {
    out.resize(n);
    for (size_t i = 0; i < n; ++i) out[i] = HalfToFloat(ReadF16(data + i * 2));
}

} // namespace rawrxd::gguf

#endif // RAWRXD_GGUF_QUANT_ADAPTER_HPP