#pragma once
// Canonical, dependency-free GGML Q5_K block decoder shared by Deep2 runtime
// and the standalone reference-layout test.
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace Deep2 {
inline float NativeQ5KHalfToFloat(uint16_t h) {
    const uint32_t sign = uint32_t(h & 0x8000u) << 16;
    uint32_t mantissa = h & 0x03ffu;
    const uint32_t exponent = (h >> 10) & 0x1fu;
    uint32_t bits = 0;
    if (exponent == 0) {
        if (mantissa == 0) bits = sign;
        else {
            int e = -14;
            while ((mantissa & 0x0400u) == 0) { mantissa <<= 1; --e; }
            bits = sign | (uint32_t(e + 127) << 23) | ((mantissa & 0x03ffu) << 13);
        }
    } else if (exponent == 31) {
        bits = sign | 0x7f800000u | (mantissa << 13);
    } else {
        bits = sign | ((exponent + 112u) << 23) | (mantissa << 13);
    }
    float value;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

inline void NativeQ5KDequantize(const uint8_t* src, float* dst, size_t n) {
    if (!src || !dst) return;
    const size_t blocks = (n + 255) / 256;
    for (size_t b = 0; b < blocks; ++b) {
        const uint8_t* block = src + b * 176;
        const float d = NativeQ5KHalfToFloat(uint16_t(block[0]) |
                                             (uint16_t(block[1]) << 8));
        const float dmin = NativeQ5KHalfToFloat(uint16_t(block[2]) |
                                                (uint16_t(block[3]) << 8));
        const uint8_t* scales = block + 4;
        const uint8_t* qh = block + 16;
        const uint8_t* ql = block + 48;
        uint8_t u1 = 1, u2 = 2;
        int is = 0;
        float* y = dst + b * 256;
        for (int j = 0; j < 256; j += 64) {
            const int s0 = is < 4 ? (scales[is] & 63)
                : ((scales[is + 4] & 15) | ((scales[is - 4] >> 6) << 4));
            const int m0 = is < 4 ? (scales[is + 4] & 63)
                : ((scales[is + 4] >> 4) | ((scales[is] >> 6) << 4));
            const int s1i = is + 1;
            const int s1 = s1i < 4 ? (scales[s1i] & 63)
                : ((scales[s1i + 4] & 15) | ((scales[s1i - 4] >> 6) << 4));
            const int m1 = s1i < 4 ? (scales[s1i + 4] & 63)
                : ((scales[s1i + 4] >> 4) | ((scales[s1i] >> 6) << 4));
            const float d0 = d * float(s0), min0 = dmin * float(m0);
            const float d1 = d * float(s1), min1 = dmin * float(m1);
            for (int l = 0; l < 32; ++l) {
                const uint8_t q0 = uint8_t((ql[l] & 15u) | ((qh[l] & u1) ? 16u : 0u));
                const uint8_t q1 = uint8_t((ql[l] >> 4) | ((qh[l] & u2) ? 16u : 0u));
                const size_t i0 = size_t(j + l), i1 = size_t(j + 32 + l);
                if (b * 256 + i0 < n) y[i0] = d0 * float(q0) - min0;
                if (b * 256 + i1 < n) y[i1] = d1 * float(q1) - min1;
            }
            ql += 32;
            is += 2;
            u1 = uint8_t(u1 << 2);
            u2 = uint8_t(u2 << 2);
        }
    }
}
} // namespace Deep2
