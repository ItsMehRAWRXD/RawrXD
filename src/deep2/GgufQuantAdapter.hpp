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
// Layout is BLOCK-INTERLEAVED: y[j] = (qs[j]&0xF - 8)*d for j=0..15, then
// y[j+16] = (qs[j]>>4 - 8)*d. (Matches ggml dequantize_row_q4_0.)
inline void DequantizeQ4_0(const uint8_t* blocks, size_t n_blocks, std::vector<float>& out) {
    out.resize(n_blocks * 32);
    for (size_t b = 0; b < n_blocks; ++b) {
        const uint8_t* blk = blocks + b * 18;
        const float d = HalfToFloat(ReadF16(blk));
        const uint8_t* qs = blk + 2;
        float* y = out.data() + b * 32;
        for (int j = 0; j < 16; ++j) {
            const int x0 = (int)(qs[j] & 0x0F) - 8;
            const int x1 = (int)(qs[j] >> 4) - 8;
            y[j]      = (float)x0 * d;   // first half (low nibbles)
            y[j + 16] = (float)x1 * d;   // second half (high nibbles)
        }
    }
}

// get_scale_min_k4: exact ggml packed 6-bit scale/min extraction.
static inline void GetScaleMinK4(int j, const uint8_t* q, int* d, int* m) {
    if (j < 4) {
        *d = q[j] & 63;
        *m = q[j + 4] & 63;
    } else {
        *d = (q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4);
        *m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4);
    }
}

// Q4_K: 256 values, 144 bytes. Layout (ggml block_q4_K):
//   fp16 d; fp16 dmin; uint8 scales[12]; uint8 qs[128].
// Dequant: 4 groups of 64 values, each using TWO 6-bit scales:
//   y[..] = d*sc(is)*(q&0xF) - min*m(is)   (32 low nibbles)
//   y[..] = d*sc(is+1)*(q>>4) - min*m(is+1) (32 high nibbles)
// (Matches ggml dequantize_row_q4_K exactly.)
inline void DequantizeQ4_K(const uint8_t* blocks, size_t n_super, std::vector<float>& out) {
    out.resize(n_super * 256);
    for (size_t b = 0; b < n_super; ++b) {
        const uint8_t* blk = blocks + b * 144;
        const float d = HalfToFloat(ReadF16(blk));
        const float mn = HalfToFloat(ReadF16(blk + 2));
        const uint8_t* scales = blk + 4;
        const uint8_t* q = blk + 16;
        float* y = out.data() + b * 256;
        int is = 0;
        size_t qi = 0; // byte cursor into qs
        for (int j = 0; j < 256; j += 64) {
            int sc, m;
            GetScaleMinK4(is + 0, scales, &sc, &m);
            const float d1 = d * (float)sc; const float m1 = mn * (float)m;
            GetScaleMinK4(is + 1, scales, &sc, &m);
            const float d2 = d * (float)sc; const float m2 = mn * (float)m;
            for (int l = 0; l < 32; ++l) y[j + l]      = d1 * (float)(q[qi + l] & 0x0F) - m1;
            for (int l = 0; l < 32; ++l) y[j + 32 + l] = d2 * (float)(q[qi + l] >> 4) - m2;
            qi += 32;
            is += 2;
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