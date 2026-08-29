#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <algorithm>

namespace RawrXD::Deep2 {

static constexpr int QK_K = 256;

struct block_q4_K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};

struct block_q6_K {
    uint8_t  ql[128];
    uint8_t  qh[64];
    int8_t   scales[16];
    uint16_t d;
};

static_assert(sizeof(block_q4_K) == 144, "Q4_K layout mismatch");
static_assert(sizeof(block_q6_K) == 210, "Q6_K layout mismatch");

inline float fp16_to_fp32(uint16_t h)
{
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t mant = h & 0x3FFu;

    uint32_t out;

    if (exp == 0) {
        if (mant == 0) {
            out = sign;
        } else {
            uint32_t m = mant;
            int e = -1;

            while ((m & 0x400u) == 0) {
                m <<= 1;
                --e;
            }

            m &= 0x3FFu;
            out = sign |
                  (uint32_t)(127 - 15 + e + 1) << 23 |
                  (m << 13);
        }
    }
    else if (exp == 31) {
        out = sign | 0x7F800000u | (mant << 13);
    }
    else {
        out = sign |
              ((exp + (127 - 15)) << 23) |
              (mant << 13);
    }

    float f;
    std::memcpy(&f, &out, sizeof(f));
    return f;
}

/*
 * Exact scalar Q4_K reference decoder.
 *
 * Layout:
 *   d
 *   dmin
 *   scales[12]
 *   qs[128]
 *
 * 256 weights, grouped into 8 groups of 32.
 */
inline void dequant_q4_k(
    const block_q4_K& b,
    float* dst)
{
    const float d    = fp16_to_fp32(b.d);
    const float dmin = fp16_to_fp32(b.dmin);

    int sc[8];
    int mn[8];

    for (int j = 0; j < 4; ++j) {
        sc[j] =
            b.scales[j] & 63;

        mn[j] =
            b.scales[j + 4] & 63;

        sc[j + 4] =
            (b.scales[j + 8] & 0x0Fu) |
            ((b.scales[j] >> 6) << 4);

        mn[j + 4] =
            (b.scales[j + 8] >> 4) |
            ((b.scales[j + 4] >> 6) << 4);
    }

    // ggml dequantize_row_q4_K: paired groups share one 32-byte qs window
    const uint8_t* q = b.qs;
    float* y = dst;
    for (int is = 0; is < 8; is += 2) {
        const float d1 = d * (float)sc[is];
        const float m1 = dmin * (float)mn[is];
        const float d2 = d * (float)sc[is + 1];
        const float m2 = dmin * (float)mn[is + 1];
        for (int l = 0; l < 32; ++l) *y++ = d1 * (float)(q[l] & 0x0F) - m1;
        for (int l = 0; l < 32; ++l) *y++ = d2 * (float)(q[l] >> 4) - m2;
        q += 32;
    }
}

/*
 * Exact scalar Q6_K reference decoder.
 */
inline void dequant_q6_k(
    const block_q6_K& b,
    float* dst)
{
    const float d = fp16_to_fp32(b.d);

    int idx = 0;

    for (int n = 0; n < QK_K; n += 128) {
        for (int l = 0; l < 32; ++l) {
            const uint8_t q1 =
                (b.ql[l] >> 0) & 0x0F;

            const uint8_t q2 =
                (b.ql[l + 32] >> 0) & 0x0F;

            const uint8_t qh1 =
                (b.qh[l] >> 0) & 0x03;

            const uint8_t qh2 =
                (b.qh[l] >> 2) & 0x03;

            const int qv1 =
                (int)(q1 | (qh1 << 4)) - 32;

            const int qv2 =
                (int)(q2 | (qh2 << 4)) - 32;

            const int sc0 =
                b.scales[l / 16];

            const int sc1 =
                b.scales[8 + l / 16];

            dst[idx++] =
                d * (float)sc0 * (float)qv1;

            dst[idx++] =
                d * (float)sc1 * (float)qv2;
        }

        /*
         * The upper two-bit planes.
         */
        for (int l = 0; l < 32; ++l) {
            const uint8_t q1 =
                (b.ql[64 + l] >> 0) & 0x0F;

            const uint8_t q2 =
                (b.ql[96 + l] >> 0) & 0x0F;

            const uint8_t qh1 =
                (b.qh[l] >> 4) & 0x03;

            const uint8_t qh2 =
                (b.qh[l] >> 6) & 0x03;

            const int qv1 =
                (int)(q1 | (qh1 << 4)) - 32;

            const int qv2 =
                (int)(q2 | (qh2 << 4)) - 32;

            const int sc0 =
                b.scales[4 + l / 16];

            const int sc1 =
                b.scales[12 + l / 16];

            dst[idx++] =
                d * (float)sc0 * (float)qv1;

            dst[idx++] =
                d * (float)sc1 * (float)qv2;
        }
    }
}

/*
 * Reference dot products.
 */
inline float dot_q4_k(
    const block_q4_K* blocks,
    const float* x,
    size_t n)
{
    float sum = 0.0f;

    size_t pos = 0;

    while (pos < n) {
        float tmp[QK_K];

        dequant_q4_k(blocks[pos / QK_K], tmp);

        const size_t count =
            std::min<size_t>(QK_K, n - pos);

        for (size_t i = 0; i < count; ++i)
            sum += tmp[i] * x[pos + i];

        pos += count;
    }

    return sum;
}

inline float dot_q6_k(
    const block_q6_K* blocks,
    const float* x,
    size_t n)
{
    float sum = 0.0f;

    size_t pos = 0;

    while (pos < n) {
        float tmp[QK_K];

        dequant_q6_k(blocks[pos / QK_K], tmp);

        const size_t count =
            std::min<size_t>(QK_K, n - pos);

        for (size_t i = 0; i < count; ++i)
            sum += tmp[i] * x[pos + i];

        pos += count;
    }

    return sum;
}

}
