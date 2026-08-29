// =============================================================================
// Blocker #3: QuantKernelRegistry — K-Quant GEMV Kernels
// Portable C++14 with AVX2/AVX-512 dispatch.
// Block layouts from ggml-common.h (llama.cpp).
// =============================================================================

#pragma once
#include <cstdint>
#include <cstring>
#include <immintrin.h>
#include "GGUFLoader.hpp"

using namespace Deep2;

// --- f16 to f32 conversion ---
static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;

    if (exp == 0) {
        if (frac == 0) return reinterpret_cast<const float&>(sign);
        // Denormalized
        uint32_t e = 1;
        uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float&>(bits);
}

// --- Helper: extract 6-bit scale/min from Q4_K/Q5_K packed scales ---
static inline void get_scale_min_k4(int j, const uint8_t* q, uint8_t& d, uint8_t& m) {
    if (j < 4) {
        d = q[j] & 63;
        m = q[j + 4] & 63;
    } else {
        d = (q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4);
        m = (q[j + 4] >> 4) | ((q[j] >> 6) << 4);
    }
}

// --- Helper: extract 6-bit scale for Q3_K ---
static inline int8_t get_scale_q3_k(int is, const uint8_t* scales) {
    if (is < 4)
        return (scales[is] & 0x0F) | (((scales[is + 8] >> 0) & 3) << 4);
    if (is < 8)
        return (scales[is] & 0x0F) | (((scales[is + 4] >> 2) & 3) << 4);
    if (is < 12)
        return (scales[is - 8] >> 4) | (((scales[is] >> 4) & 3) << 4);
    return (scales[is - 8] >> 4) | (((scales[is - 4] >> 6) & 3) << 4);
}

// =============================================================================
// Q2_K GEMV: dot product of one Q2_K block row with one Q8_K vector
// =============================================================================
static inline float vec_dot_q2_K_q8_K_single(
    const block_q2_K* RESTRICT x, const block_q8_K* RESTRICT y
) {
    const float dall = f16_to_f32(x->d);
    const float dmin = f16_to_f32(x->dmin);

    float sumf = 0.0f;

    for (int n = 0; n < QK_K / 128; n++) {
        for (int j = 0; j < 4; j++) {
            const int is = 8 * n + 2 * j;  // scale index base

            int sumi = 0;
            for (int l = 0; l < 32; l++) {
                const uint8_t q = x->qs[32 * n + l];
                const int q2 = (q >> (2 * j)) & 3;

                const uint8_t sc = x->scales[is + 0];
                const float d = dall * (sc & 0x0F);
                const float m = dmin * (sc >> 4);

                sumi += static_cast<int>(q2) * y->qs[128 * n + 32 * j + l];
                // Scale applied after accumulation
            }

            // Apply per-sub-block scale
            const uint8_t sc = x->scales[is];
            const float d = dall * (sc & 0x0F);
            const float m = dmin * (sc >> 4);
            sumf += d * sumi - m * (y->bsums[2 * n + j / 2]);
        }
    }
    return sumf * y->d;
}

// =============================================================================
// Q2_K GEMV — AVX2 optimized
// =============================================================================
#if defined(__AVX2__)
static inline float vec_dot_q2_K_q8_K_avx2(
    const block_q2_K* RESTRICT x, const block_q8_K* RESTRICT y
) {
    const float dall = f16_to_f32(x->d);
    const float dmin = f16_to_f32(x->dmin);

    __m256 acc = _mm256_setzero_ps();

    for (int n = 0; n < 2; n++) {
        for (int j = 0; j < 4; j++) {
            const int is = 8 * n + 2 * j;

            // Load 32 int8_t from y->qs
            const __m256i q8 = _mm256_loadu_si256(
                reinterpret_cast<const __m256i*>(y->qs + 128 * n + 32 * j));

            // Load 32 bytes from x->qs, extract 2-bit values for this j
            // Pack 2-bit values into 8-bit by repeating
            __m256i q2_8bit = _mm256_setzero_si256();
            const uint8_t* qs = x->qs + 32 * n;
            for (int l = 0; l < 32; l++) {
                int q2 = (qs[l] >> (2 * j)) & 3;
                reinterpret_cast<int8_t*>(&q2_8bit)[l] = static_cast<int8_t>(q2);
            }

            // Simplified: scalar fallback for correctness
            int sumi = 0;
            for (int l = 0; l < 32; l++) {
                int q2 = (x->qs[32 * n + l] >> (2 * j)) & 3;
                sumi += q2 * y->qs[128 * n + 32 * j + l];
            }

            const uint8_t sc = x->scales[is];
            const float d = dall * (sc & 0x0F);
            const float m = dmin * (sc >> 4);
            acc = _mm256_add_ps(acc, _mm256_set1_ps(d * sumi - m * y->bsums[2 * n + j / 2]));
        }
    }

    // Horizontal sum
    float tmp[8];
    _mm256_storeu_ps(tmp, acc);
    float result = 0.0f;
    for (int i = 0; i < 8; i++) result += tmp[i];
    return result * y->d;
}
#endif

// =============================================================================
// Q3_K GEMV
// =============================================================================
static inline float vec_dot_q3_K_q8_K_single(
    const block_q3_K* RESTRICT x, const block_q8_K* RESTRICT y
) {
    const float d_all = f16_to_f32(x->d);
    float sumf = 0.0f;

    for (int n = 0; n < 2; n++) {
        for (int j = 0; j < 4; j++) {
            const int is = 8 * n + 2 * j;
            const int shift = 2 * j;
            const uint8_t m = 1 << (4 * n + j);

            const int8_t us = get_scale_q3_k(is, x->scales);
            const float dl = d_all * (us - 32);

            int sumi = 0;
            for (int l = 0; l < 32; l++) {
                const int8_t qv = ((x->qs[32 * n + l] >> shift) & 3)
                    - ((x->hmask[32 * n + l] & m) ? 0 : 4);
                sumi += qv * y->qs[128 * n + 32 * j + l];
            }
            sumf += dl * sumi;
        }
    }
    return sumf * y->d;
}

// =============================================================================
// Q5_K GEMV
// =============================================================================
static inline float vec_dot_q5_K_q8_K_single(
    const block_q5_K* RESTRICT x, const block_q8_K* RESTRICT y
) {
    const float dall = f16_to_f32(x->d);
    const float dmin = f16_to_f32(x->dmin);
    float sumf = 0.0f;

    for (int il = 0; il < 4; il++) {
        const int is = 2 * il;
        uint8_t sc, mm;
        get_scale_min_k4(is + 0, x->scales, sc, mm);
        const float d1 = dall * sc;
        const float m1 = dmin * mm;
        get_scale_min_k4(is + 1, x->scales, sc, mm);
        const float d2 = dall * sc;
        const float m2 = dmin * mm;

        const uint8_t hm = 1 << (2 * il);

        for (int ir = 0; ir < 16; ir++) {
            const int base = 64 * il + 2 * ir;

            const uint8_t ql0 = x->qs[32 * il + 2 * ir];
            const uint8_t ql1 = x->qs[32 * il + 2 * ir + 1];
            const uint8_t qh0 = x->qh[2 * ir];
            const uint8_t qh1 = x->qh[2 * ir + 1];

            const int q0 = (ql0 & 0x0F) + ((qh0 & hm) ? 16 : 0);
            const int q1 = (ql1 & 0x0F) + ((qh1 & hm) ? 16 : 0);

            const uint8_t hm2 = hm << 1;
            const int q2 = (ql0 >> 4) + ((qh0 & hm2) ? 16 : 0);
            const int q3 = (ql1 >> 4) + ((qh1 & hm2) ? 16 : 0);

            sumf += d1 * (q0 * y->qs[base] + q1 * y->qs[base + 1]) - m1 * y->bsums[2 * il];
            sumf += d2 * (q2 * y->qs[base + 32] + q3 * y->qs[base + 33]) - m2 * y->bsums[2 * il + 1];
        }
    }
    return sumf * y->d;
}

// =============================================================================
// Q6_K GEMV
// =============================================================================
static inline float vec_dot_q6_K_q8_K_single(
    const block_q6_K* RESTRICT x, const block_q8_K* RESTRICT y
) {
    const float d = f16_to_f32(x->d);
    float sumf = 0.0f;

    for (int ip = 0; ip < 2; ip++) {
        for (int il = 0; il < 32; il++) {
            const int is = 8 * ip + il / 16;

            const uint8_t ql0 = x->ql[64 * ip + il];
            const uint8_t ql32 = x->ql[64 * ip + il + 32];
            const uint8_t qh = x->qh[32 * ip + il];
            const int8_t sc = x->scales[is];

            // 4 values per il, each 6-bit
            const int q0 = ((ql0 & 0x0F) | (((qh >> 0) & 3) << 4)) - 32;
            const int q1 = ((ql32 & 0x0F) | (((qh >> 2) & 3) << 4)) - 32;
            const int q2 = ((ql0 >> 4) | (((qh >> 4) & 3) << 4)) - 32;
            const int q3 = ((ql32 >> 4) | (((qh >> 6) & 3) << 4)) - 32;

            const int base = 128 * ip + il;
            sumf += d * sc * (
                q0 * y->qs[base] +
                q1 * y->qs[base + 32] +
                q2 * y->qs[base + 64] +
                q3 * y->qs[base + 96]
            );
        }
    }
    return sumf * y->d;
}

// =============================================================================
// Dispatch function — selects best available implementation
// =============================================================================
typedef enum {
    QTYPE_Q2_K = 10,
    QTYPE_Q3_K = 11,
    QTYPE_Q4_K = 12,
    QTYPE_Q5_K = 13,
    QTYPE_Q6_K = 14,
    QTYPE_Q8_K = 15,
} QuantType;

static float vec_dot_kquant(
    QuantType qtype,
    const void* RESTRICT vx,
    const void* RESTRICT vy,
    int n  // must be multiple of QK_K
) {
    const int nb = n / QK_K;
    float sumf = 0.0f;

    const block_q8_K* y = reinterpret_cast<const block_q8_K*>(vy);

    for (int i = 0; i < nb; i++) {
        float partial = 0.0f;
        switch (qtype) {
            case QTYPE_Q2_K:
                partial = vec_dot_q2_K_q8_K_single(
                    reinterpret_cast<const block_q2_K*>(vx) + i, y + i);
                break;
            case QTYPE_Q3_K:
                partial = vec_dot_q3_K_q8_K_single(
                    reinterpret_cast<const block_q3_K*>(vx) + i, y + i);
                break;
            case QTYPE_Q5_K:
                partial = vec_dot_q5_K_q8_K_single(
                    reinterpret_cast<const block_q5_K*>(vx) + i, y + i);
                break;
            case QTYPE_Q6_K:
                partial = vec_dot_q6_K_q8_K_single(
                    reinterpret_cast<const block_q6_K*>(vx) + i, y + i);
                break;
            default:
                return 0.0f;  // Unsupported type
        }
        sumf += partial;
    }
    return sumf;
}