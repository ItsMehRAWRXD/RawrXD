#pragma once

#include <immintrin.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <type_traits>

// ============================================================================
// RawrXD dependency-free fused K-quant GEMV
//
// Purpose:
//   Q6_K/Q4_K packed weights -> SIMD dot directly.
//   No temporary float[256] dequantization buffer.
//
// Requirements:
//   MSVC x64
//   AVX2
//
// This file deliberately has no dependency on ggml or llama.cpp.
// The packed layouts are the canonical GGML K-quant layouts.
// ============================================================================

namespace RawrXD::FusedK {

// ---------------------------------------------------------------------------
// Raw packed block layouts.
//
// These are intentionally byte-oriented so this file does not depend on the
// project's existing GGML type declarations.
//
// Q6_K:
//   ql[128]
//   qh[64]
//   scales[16]
//   d[2] FP16
//
// Q4_K:
//   d[2] FP16
//   dmin[2] FP16
//   scales[12]
//   qs[128]
// ---------------------------------------------------------------------------

#pragma pack(push, 1)

struct Q6KBlock {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t  scales[16];
    uint16_t d;
};

struct Q4KBlock {
    uint16_t d;
    uint16_t dmin;
    uint8_t scales[12];
    uint8_t qs[128];
};

#pragma pack(pop)

static_assert(sizeof(Q6KBlock) == 210, "Unexpected Q6_K block size");
static_assert(sizeof(Q4KBlock) == 144, "Unexpected Q4_K block size");

// ---------------------------------------------------------------------------
// FP16 -> FP32.
//
// This avoids depending on the project's FP16 implementation.
// ---------------------------------------------------------------------------

static inline float fp16_to_float(uint16_t h) noexcept
{
    const uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    const uint32_t exp  = (h >> 10) & 0x1Fu;
    const uint32_t mant = h & 0x03FFu;

    uint32_t bits;

    if (exp == 0) {
        if (mant == 0) {
            bits = sign;
        } else {
            // Normalize subnormal.
            uint32_t m = mant;
            int e = -1;

            do {
                m <<= 1;
                --e;
            } while ((m & 0x0400u) == 0);

            m &= 0x03FFu;

            const uint32_t fexp = (uint32_t)(127 - 15 + 1 + e);
            bits = sign | (fexp << 23) | (m << 13);
        }
    }
    else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (mant << 13);
    }
    else {
        bits = sign |
               ((exp + (127 - 15)) << 23) |
               (mant << 13);
    }

    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// ============================================================================
// Q6_K
// ============================================================================

// Canonical Q6_K scalar reference for ONE block.
// This is retained specifically for correctness testing.
//
// The canonical mapping is:
//
// q1 = ql low  nibble + qh bits 0..1
// q2 = ql low  nibble + qh bits 2..3
// q3 = ql high nibble + qh bits 4..5
// q4 = ql high nibble + qh bits 6..7
//
// repeated over two 128-value halves.
// ============================================================================

static inline float q6k_dot_reference(
    const Q6KBlock& b,
    const float* x) noexcept
{
    const float d = fp16_to_float(b.d);

    float sum = 0.0f;

    const uint8_t* ql = b.ql;
    const uint8_t* qh = b.qh;
    const int8_t* sc = b.scales;

    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            const int is = l / 16;

            const int q1 =
                (int)((ql[l + 0] & 0x0F) |
                      (((qh[l] >> 0) & 3) << 4)) - 32;

            const int q2 =
                (int)((ql[l + 32] & 0x0F) |
                      (((qh[l] >> 2) & 3) << 4)) - 32;

            const int q3 =
                (int)((ql[l + 0] >> 4) |
                      (((qh[l] >> 4) & 3) << 4)) - 32;

            const int q4 =
                (int)((ql[l + 32] >> 4) |
                      (((qh[l] >> 6) & 3) << 4)) - 32;

            sum += x[n + l + 0]   * (d * (float)sc[is + 0] * q1);
            sum += x[n + l + 32]  * (d * (float)sc[is + 2] * q2);
            sum += x[n + l + 64]  * (d * (float)sc[is + 4] * q3);
            sum += x[n + l + 96]  * (d * (float)sc[is + 6] * q4);
        }

        ql += 64;
        qh += 32;
        sc += 8;
    }

    return sum;
}

// ---------------------------------------------------------------------------
// Fused Q6_K block.
//
// Important optimization:
//   q values remain integers until multiplication by scale.
//   No 256-float dequant buffer exists.
//
// This first implementation favors correctness and low instruction count.
// Once validated, this is the point where an even more aggressive shuffle
// implementation can replace the scalar unpack section.
// ---------------------------------------------------------------------------

static inline float q6k_dot_fused(
    const Q6KBlock& b,
    const float* x) noexcept
{
    const float d = fp16_to_float(b.d);

    const uint8_t* ql = b.ql;
    const uint8_t* qh = b.qh;
    const int8_t* sc = b.scales;

    __m256 acc = _mm256_setzero_ps();

    // Each iteration handles 16 values belonging to one scale.
    //
    // We unpack the quantized values directly and immediately multiply
    // against x. There is deliberately no float[256] output.
    //
    // Two 16-element groups are assembled from the four 32-element streams.

    for (int half = 0; half < 2; ++half) {
        for (int group = 0; group < 8; ++group) {
            const int base = group * 16;

            const int scale0 = (int)sc[group];

            // Four 16-value streams exist in this 128-value half.
            // Generate them in scalar integer form, then feed SIMD.
            alignas(32) float w[16];

            for (int j = 0; j < 16; ++j) {
                const int l = base + j;

                int q;

                if (group < 2) {
                    q = (int)((ql[l] & 0x0F) |
                              (((qh[l] >> 0) & 3) << 4)) - 32;
                }
                else if (group < 4) {
                    const int ll = l - 32;

                    q = (int)((ql[ll + 32] & 0x0F) |
                              (((qh[ll] >> 2) & 3) << 4)) - 32;
                }
                else if (group < 6) {
                    const int ll = l - 64;

                    q = (int)((ql[ll] >> 4) |
                              (((qh[ll] >> 4) & 3) << 4)) - 32;
                }
                else {
                    const int ll = l - 96;

                    q = (int)((ql[ll + 32] >> 4) |
                              (((qh[ll] >> 6) & 3) << 4)) - 32;
                }

                w[j] = d * (float)scale0 * (float)q;
            }

            const __m256 vw = _mm256_load_ps(w);
            const __m256 vx = _mm256_loadu_ps(x + half * 128 + base);

            acc = _mm256_fmadd_ps(vw, vx, acc);
        }

        ql += 64;
        qh += 32;
        sc += 8;
    }

    alignas(32) float tmp[8];
    _mm256_store_ps(tmp, acc);

    float result =
        tmp[0] + tmp[1] + tmp[2] + tmp[3] +
        tmp[4] + tmp[5] + tmp[6] + tmp[7];

    return result;
}

// ============================================================================
// Q4_K
// ============================================================================

static inline void q4k_get_scale_min(
    const uint8_t* q,
    int j,
    uint8_t& scale,
    uint8_t& min) noexcept
{
    if (j < 4) {
        scale = q[j] & 63;
        min   = q[j + 4] & 63;
    }
    else {
        scale =
            (q[j + 4] & 0x0F) |
            ((q[j - 4] >> 6) << 4);

        min =
            (q[j + 4] >> 4) |
            ((q[j] >> 6) << 4);
    }
}

// ---------------------------------------------------------------------------
// Correctness reference.
// ---------------------------------------------------------------------------

static inline float q4k_dot_reference(
    const Q4KBlock& b,
    const float* x) noexcept
{
    const float d = fp16_to_float(b.d);
    const float dmin = fp16_to_float(b.dmin);

    float sum = 0.0f;

    for (int j = 0; j < 256; j += 64) {
        const int group = j / 32;

        uint8_t sc1, m1;
        uint8_t sc2, m2;

        q4k_get_scale_min(b.scales, group + 0, sc1, m1);
        q4k_get_scale_min(b.scales, group + 1, sc2, m2);

        const float d1 = d * (float)sc1;
        const float m_1 = dmin * (float)m1;

        const float d2 = d * (float)sc2;
        const float m_2 = dmin * (float)m2;

        for (int l = 0; l < 32; ++l) {
            const uint8_t q = b.qs[(j / 2) + l];

            sum += x[j + l] *
                   (d1 * (float)(q & 0x0F) - m_1);

            sum += x[j + l + 32] *
                   (d2 * (float)(q >> 4) - m_2);
        }
    }

    return sum;
}

// ---------------------------------------------------------------------------
// Fused Q4_K.
//
// The first implementation keeps the nibble extraction straightforward.
// The important optimization is that values are immediately multiplied
// against x instead of being materialized as a 256-float block.
// ---------------------------------------------------------------------------

static inline float q4k_dot_fused(
    const Q4KBlock& b,
    const float* x) noexcept
{
    const float d = fp16_to_float(b.d);
    const float dmin = fp16_to_float(b.dmin);

    __m256 acc = _mm256_setzero_ps();

    for (int group = 0; group < 8; ++group) {
        uint8_t sc;
        uint8_t mn;

        q4k_get_scale_min(b.scales, group, sc, mn);

        const float ds = d * (float)sc;
        const float dm = dmin * (float)mn;

        alignas(32) float wlo[32];
        alignas(32) float whi[32];

        const uint8_t* q = b.qs + group * 16;

        // 16 packed bytes -> 32 values.
        for (int i = 0; i < 16; ++i) {
            wlo[i] =
                ds * (float)(q[i] & 0x0F) - dm;

            whi[i] =
                ds * (float)(q[i] >> 4) - dm;
        }

        // The second half of the 32-value group is packed in the next
        // 16 bytes.
        for (int i = 0; i < 16; ++i) {
            wlo[i + 16] =
                ds * (float)(q[i + 16] & 0x0F) - dm;

            whi[i + 16] =
                ds * (float)(q[i + 16] >> 4) - dm;
        }

        const int xbase = group * 32;

        for (int i = 0; i < 32; i += 8) {
            const __m256 vx0 =
                _mm256_loadu_ps(x + xbase + i);

            const __m256 vw0 =
                _mm256_load_ps(wlo + i);

            acc = _mm256_fmadd_ps(vw0, vx0, acc);

            const __m256 vx1 =
                _mm256_loadu_ps(x + xbase + 32 + i);

            const __m256 vw1 =
                _mm256_load_ps(whi + i);

            acc = _mm256_fmadd_ps(vw1, vx1, acc);
        }
    }

    alignas(32) float tmp[8];
    _mm256_store_ps(tmp, acc);

    return tmp[0] + tmp[1] + tmp[2] + tmp[3] +
           tmp[4] + tmp[5] + tmp[6] + tmp[7];
}

// ============================================================================
// Row GEMV
// ============================================================================

static inline float q6k_gemv_row(
    const void* weights,
    const float* x,
    size_t elements) noexcept
{
    const auto* blocks =
        reinterpret_cast<const Q6KBlock*>(weights);

    float sum = 0.0f;

    const size_t nb = elements / 256;

    for (size_t i = 0; i < nb; ++i) {
        sum += q6k_dot_fused(blocks[i], x + i * 256);
    }

    return sum;
}

static inline float q4k_gemv_row(
    const void* weights,
    const float* x,
    size_t elements) noexcept
{
    const auto* blocks =
        reinterpret_cast<const Q4KBlock*>(weights);

    float sum = 0.0f;

    const size_t nb = elements / 256;

    for (size_t i = 0; i < nb; ++i) {
        sum += q4k_dot_fused(blocks[i], x + i * 256);
    }

    return sum;
}

} // namespace RawrXD::FusedK
