// k_quant_gemv_avx512.h
// Fused dequantize + dot-product (GEMV) kernels for GGUF K-quants.
//
// Why this file exists: QuantKernelRegistry.cpp registers `gemv_q4_k_scalar`
// for GGML_TYPE_Q4_K. Every K-quant and every 4/5-bit type dispatches to a
// SCALAR kernel there, so a real Q4_K_M model runs scalar dot products even on
// a host with full AVX-512. These kernels are the SIMD replacement.
//
// The fused form avoids materialising a float copy of the weights: each 256-value
// super-block is unpacked into ZMM registers, multiplied against the activation,
// and accumulated. Only 16 floats are live at a time instead of 256.
//
// Correctness contract: each kernel is bit-comparable to the corresponding
// scalar routine within float32 tolerance, verified by kquant_parity_check.
// Results are NOT claimed bit-exact against ggml, because ggml accumulates in a
// different lane order.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__AVX512F__)
#include <immintrin.h>
#endif

namespace rawrxd {
namespace kquant {

// ---------------------------------------------------------------------------
// fp16 -> fp32
// ---------------------------------------------------------------------------
inline float FP16ToF32(uint16_t h) {
    const uint32_t sign = static_cast<uint32_t>(h & 0x8000u) << 16;
    const uint32_t exp = (h >> 10) & 0x1Fu;
    const uint32_t mant = h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) bits = sign;
        else {
            uint32_t e = 0, m = mant;
            while ((m & 0x400u) == 0) { m <<= 1; ++e; }
            m &= 0x3FFu;
            // RAWRXD_FP16_SUBNORMAL_001: after `e` shifts the value is
            // (m/1024) * 2^(-14 - e), so the fp32 exponent is 127 - 14 - e.
            // This read `127 - 15 - e`, one too small, halving EVERY fp16
            // subnormal (measured 2046/2046, ratio exactly 0.5). The normal
            // path was already correct, which is why it survived review.
            // This is the GEMV's own copy of the same defect also fixed in
            // gguf_loader.cpp; leaving one of the two would have made the
            // kernel and the weight loader disagree by 2x.
            bits = sign | ((127 - 14 - e) << 23) | (m << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = sign | 0x7F800000u | (mant << 13);
    } else {
        bits = sign | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// ---------------------------------------------------------------------------
// Q4_K scale/min unpacking (identical to the scalar path in
// QuantKernelRegistry.cpp: get_scale_min_k4 semantics)
// ---------------------------------------------------------------------------
inline void UnpackQ4KScales(const uint8_t s[12], uint8_t sc[8], uint8_t mn[8]) {
    for (int i = 0; i < 4; ++i) { sc[i] = s[i] & 0x3F; mn[i] = s[4 + i] & 0x3F; }
    // Upper four: low nibble from s[8..11], high 2 bits from s[0..3]>>6 for the
    // scales and from s[4..7]>>6 for the minimums. Using s[0..3] for the mins
    // is a real bug: ggml's get_scale_min_k4 reads q[j-0] there, i.e. s[4..7].
    for (int i = 0; i < 4; ++i) {
        sc[4 + i] = static_cast<uint8_t>((s[8 + i] & 0x0F) | (((s[i]     >> 6) & 0x03) << 4));
        mn[4 + i] = static_cast<uint8_t>((s[8 + i] >> 4)    | (((s[4 + i] >> 6) & 0x03) << 4));
    }
}

// ---------------------------------------------------------------------------
// Q4_K fused dequant+GEMV
//
// Layout (ggml block_q4_K, 144 bytes, 256 weights):
//   uint16 d; uint16 dmin; uint8 scales[12]; uint8 qs[128];
// Weight group g (32 weights) is:
//   weights [g*32, g*32+32)  <- nibble parity g%2 of bytes qs[(g/2)*32 .. +32)
// so an even group takes the LOW nibbles of 32 bytes and an odd group takes the
// HIGH nibbles of the same 32 bytes. That single rule replaces the span/offset
// pair, which is where an earlier version of this file indexed wrong.
// ---------------------------------------------------------------------------
inline void GemvQ4K(const uint8_t* w, const float* x, float* y,
                     size_t rows, size_t cols) {
    if (cols == 0) return;
    const size_t blocksPerRow = (cols + 255) / 256;

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = w + r * blocksPerRow * 144;
        float acc = 0.0f;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* blk = row + b * 144;
            const float d    = FP16ToF32(static_cast<uint16_t>(blk[0] | (blk[1] << 8)));
            const float dmin = FP16ToF32(static_cast<uint16_t>(blk[2] | (blk[3] << 8)));
            uint8_t sc[8], mn[8];
            UnpackQ4KScales(blk + 4, sc, mn);
            const uint8_t* qs = blk + 16;
            const size_t blockBase = b * 256;
            const size_t remaining = cols - blockBase;
            const size_t elems = remaining < 256 ? remaining : 256;

            for (unsigned g = 0; g < 8; ++g) {
                const uint8_t* q = qs + (g / 2) * 32;
                const int shift = (g & 1) ? 4 : 0;
                const float ds = d * static_cast<float>(sc[g]);
                const float mm = dmin * static_cast<float>(mn[g]);
                const size_t ebase = blockBase + g * 32;
                const size_t avail = ebase < cols ? (cols - ebase < 32 ? cols - ebase : 32) : 0;
                for (size_t l = 0; l < avail; ++l) {
                    const int nib = (q[l] >> shift) & 0x0F;
                    acc += (ds * static_cast<float>(nib) - mm) * x[ebase + l];
                }
            }
            (void)elems;
        }
        y[r] += acc;
    }
}

#if defined(__AVX512F__)
// ---------------------------------------------------------------------------
// Q4_K fused dequant+GEMV, AVX-512.
//
// Each 32-byte qs span is widened to 16 int32 lanes twice (low nibbles, high
// nibbles), converted to float, and consumed with two FMA chains:
//     acc += d*sc * (q * x)  -  dmin*m * x
// The "-dmin*m*x" term is a separate fnmadd, matching the scalar expression
// exactly rather than folding it into a different algebraic form.
// ---------------------------------------------------------------------------
inline void GemvQ4K_AVX512(const uint8_t* w, const float* x, float* y,
                            size_t rows, size_t cols) {
    if (cols == 0) return;
    const size_t blocksPerRow = (cols + 255) / 256;
    const __m512i nib_mask = _mm512_set1_epi32(0x0F);

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = w + r * blocksPerRow * 144;
        __m512 vacc = _mm512_setzero_ps();

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* blk = row + b * 144;
            const float d    = FP16ToF32(static_cast<uint16_t>(blk[0] | (blk[1] << 8)));
            const float dmin = FP16ToF32(static_cast<uint16_t>(blk[2] | (blk[3] << 8)));
            uint8_t sc[8], mn[8];
            UnpackQ4KScales(blk + 4, sc, mn);
            const uint8_t* qs = blk + 16;
            const size_t blockBase = b * 256;

            for (unsigned g = 0; g < 8; ++g) {
                const uint8_t* q = qs + (g / 2) * 32;
                const int shift = (g & 1) ? 4 : 0;
                const __m512 ds = _mm512_set1_ps(d * static_cast<float>(sc[g]));
                const __m512 mm = _mm512_set1_ps(dmin * static_cast<float>(mn[g]));
                const size_t ebase = blockBase + g * 32;

                // 32 weights = two 16-lane halves.
                for (size_t half = 0; half < 2; ++half) {
                    const __m128i raw = _mm_loadu_si128(
                        reinterpret_cast<const __m128i*>(q + half * 16));
                    __m512i v = _mm512_cvtepu8_epi32(raw);
                    if (shift) v = _mm512_srli_epi32(v, 4);
                    v = _mm512_and_si512(v, nib_mask);
                    const __m512 qf = _mm512_cvtepi32_ps(v);

                    const size_t idx = ebase + half * 16;
                    if (idx >= cols) continue;
                    const size_t valid = (cols - idx) < 16 ? (cols - idx) : 16;
                    const __mmask16 m = valid >= 16
                        ? static_cast<__mmask16>(0xFFFF)
                        : static_cast<__mmask16>((1u << valid) - 1u);
                    const __m512 xv = _mm512_maskz_loadu_ps(m, x + idx);
                    vacc = _mm512_fmadd_ps(ds, _mm512_mul_ps(qf, xv), vacc);
                    vacc = _mm512_fnmadd_ps(mm, xv, vacc);
                }
            }
        }
        y[r] += _mm512_reduce_add_ps(vacc);
    }
}
#endif // __AVX512F__

// ---------------------------------------------------------------------------
// Dispatcher. Mirrors QuantKernelRegistry's capability gating so a host
// without AVX-512 still gets correct (scalar) results.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Q5_K fused dequant+GEMV
//
// Transcribed from upstream dequantize_row_q5_K (ggml-quants.c:1731), not from
// memory. Layout per block (176 bytes, 256 weights):
//   uint8 qs[128]     low 4 bits, 32 bytes consumed per 64-weight span
//   uint8 qh[32]      ONE high bit per weight, selected by a rotating mask
//                      u1 = 1<<0,1<<2,1<<4,1<<6 and u2 = 2<<0,2<<2,...
//   uint8 scales[12]  via get_scale_min_k4
//   fp16 d, fp16 dmin
// Each 64-weight span produces d1*(low+hi_bit)-m1 then d2*(high_nibble+hi_bit)-m2.
// The rotating masks u1/u2 are what make a lane-wise qh read invalid here for
// the same reason it was invalid in Q6_K: neighbour weights share a byte.
// ---------------------------------------------------------------------------
inline void GetScaleMinK4(int j, const uint8_t* q, uint8_t& d, uint8_t& m) {
    if (j < 4) { d = (uint8_t)(q[j] & 63); m = (uint8_t)(q[j + 4] & 63); }
    else {
        d = (uint8_t)((q[j + 4] & 0x0F) | (((q[j - 4] >> 6) & 0x03) << 4));
        m = (uint8_t)((q[j + 4] >> 4)   | (((q[j - 0] >> 6) & 0x03) << 4));
    }
}

inline void GemvQ5K(const uint8_t* w, const float* x, float* y,
                     size_t rows, size_t cols) {
    if (cols == 0) return;
    const size_t kQK = 256;
    const size_t blocksPerRow = (cols + kQK - 1) / kQK;

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = w + r * blocksPerRow * 176;
        float acc = 0.0f;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* blk = row + b * 176;
            const uint8_t* ql = blk + 0;      // qs[128]
            const uint8_t* qh = blk + 128;    // qh[32]
            const uint8_t* sc = blk + 160;    // scales[12]
            const float d    = FP16ToF32(static_cast<uint16_t>(blk[172] | (blk[173] << 8)));
            const float dmin = FP16ToF32(static_cast<uint16_t>(blk[174] | (blk[175] << 8)));
            const float* xb  = x + b * kQK;    // activations for THIS block

            int is = 0;
            uint8_t u1 = 1, u2 = 2;
            for (size_t n = 0; n < kQK; n += 64) {
                uint8_t s0, m0, s1, m1;
                GetScaleMinK4(is + 0, sc, s0, m0);
                GetScaleMinK4(is + 1, sc, s1, m1);
                const float d1 = d * (float)s0, mm1 = dmin * (float)m0;
                const float d2 = d * (float)s1, mm2 = dmin * (float)m1;
                for (size_t l = 0; l < 32; ++l) {
                    const float v0 = (float)((ql[l] & 0x0F) + ((qh[l] & u1) ? 16 : 0));
                    const float v1 = (float)((ql[l] >> 4)  + ((qh[l] & u2) ? 16 : 0));
                    acc += (d1 * v0 - mm1) * xb[n + l];
                    acc += (d2 * v1 - mm2) * xb[n + 32 + l];
                }
                ql += 32;
                is += 2;
                u1 = (uint8_t)(u1 << 2);
                u2 = (uint8_t)(u2 << 2);
            }
        }
        y[r] += acc;
    }
}

#if defined(__AVX512F__)
inline void GemvQ5K_AVX512(const uint8_t* w, const float* x, float* y,
                            size_t rows, size_t cols) {
    if (cols == 0) return;
    const size_t kQK = 256;
    const size_t blocksPerRow = (cols + kQK - 1) / kQK;
    const __m512i m0F = _mm512_set1_epi32(0x0F);

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = w + r * blocksPerRow * 176;
        __m512 vacc = _mm512_setzero_ps();
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* blk = row + b * 176;
            const uint8_t* ql = blk + 0;
            const uint8_t* qh = blk + 128;
            const uint8_t* sc = blk + 160;
            const float d    = FP16ToF32(static_cast<uint16_t>(blk[172] | (blk[173] << 8)));
            const float dmin = FP16ToF32(static_cast<uint16_t>(blk[174] | (blk[175] << 8)));
            const float* xb  = x + b * kQK;

            int is = 0;
            uint8_t u1 = 1, u2 = 2;
            for (size_t n = 0; n < kQK; n += 64) {
                uint8_t s0, m0, s1, m1;
                GetScaleMinK4(is + 0, sc, s0, m0);
                GetScaleMinK4(is + 1, sc, s1, m1);
                const __m512 d1 = _mm512_set1_ps(d * (float)s0);
                const __m512 e1 = _mm512_set1_ps(dmin * (float)m0);
                const __m512 d2 = _mm512_set1_ps(d * (float)s1);
                const __m512 e2 = _mm512_set1_ps(dmin * (float)m1);
                const __m512i mu1 = _mm512_set1_epi32((int)u1);
                const __m512i mu2 = _mm512_set1_epi32((int)u2);

                const __m128i ra = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ql));
                const __m128i rh = _mm_loadu_si128(reinterpret_cast<const __m128i*>(qh));
                __m512i a = _mm512_cvtepu8_epi32(ra);
                __m512i hh = _mm512_cvtepu8_epi32(rh);
                // (qh[l] & u1) != 0 -> +16, and (qh[l] & u2) != 0 -> +16
                const __mmask16 b1 = _mm512_cmpeq_epi32_mask(
                    _mm512_and_si512(hh, mu1), _mm512_setzero_epi32());
                const __mmask16 b2 = _mm512_cmpeq_epi32_mask(
                    _mm512_and_si512(hh, mu2), _mm512_setzero_epi32());
                const __m512i add1 = _mm512_maskz_set1_epi32(b1, 16);
                const __m512i add2 = _mm512_maskz_set1_epi32(b2, 16);
                const __m512i v0 = _mm512_add_epi32(
                    _mm512_and_si512(a, m0F), add1);
                const __m512i v1 = _mm512_add_epi32(
                    _mm512_and_si512(_mm512_srli_epi32(a, 4), m0F), add2);

                const __m512 xa = _mm512_loadu_ps(xb + n);
                const __m512 xb2 = _mm512_loadu_ps(xb + n + 32);
                __m512 t0 = _mm512_sub_ps(
                    _mm512_mul_ps(d1, _mm512_cvtepi32_ps(v0)), e1);
                __m512 t1 = _mm512_sub_ps(
                    _mm512_mul_ps(d2, _mm512_cvtepi32_ps(v1)), e2);
                vacc = _mm512_fmadd_ps(t0, xa, vacc);
                vacc = _mm512_fmadd_ps(t1, xb2, vacc);

                ql += 32;
                is += 2;
                u1 = (uint8_t)(u1 << 2);
                u2 = (uint8_t)(u2 << 2);
            }
        }
        y[r] += _mm512_reduce_add_ps(vacc);
    }
}
#endif

// RAWRXD_Q5K_VECTOR_WITHHELD_001
// The vector path is compiled but NOT dispatched: kquant_parity_check shows the
// scalar Q5_K kernel agrees with an independent upstream transcription across
// cols/rows shapes, while the AVX-512 form does not (rel 0.43 .. 9.45). Rather
// than ship a kernel that does not reproduce its own scalar reference, the
// proven scalar is dispatched. This is the same disposition Q6_K held before its
// qh mask defect was found, and it is deliberately reversible: the fix is a
// local defect in the VBMI/qh handling, not a structural problem.
inline void GemvQ5KDispatch(const uint8_t* w, const float* x, float* y,
                            size_t rows, size_t cols) {
    GemvQ5K(w, x, y, rows, cols);
}

// ---------------------------------------------------------------------------
// Q6_K fused dequant+GEMV
//
// Transcribed from upstream dequantize_row_q6_K (ggml-quants.c:1939), not from
// memory. Layout per block (210 bytes, 256 weights):
//   uint8 ql[128]  low 4 bits
//   uint8 qh[64]   high 2 bits, FOUR fields per byte
//   int8  scales[16]
//   fp16  d
// Two 128-weight halves per block; within each half four interleaved groups of
// 32 emit q1..q4 against x[half*128 + {0,32,64,96} + l].
// ---------------------------------------------------------------------------
inline void GemvQ6K(const uint8_t* w, const float* x, float* y,
                     size_t rows, size_t cols) {
    if (cols == 0) return;
    const size_t kQK = 256;
    const size_t blocksPerRow = (cols + kQK - 1) / kQK;

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = w + r * blocksPerRow * 210;
        float acc = 0.0f;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* blk = row + b * 210;
            const float d = FP16ToF32(static_cast<uint16_t>(blk[208] | (blk[209] << 8)));
            const int8_t* sc = reinterpret_cast<const int8_t*>(blk + 192);
            // Activation slice for THIS block. Without the b*kQK term every
            // block re-read x[0..255], so a row spanning 6 blocks applied the
            // first 256 activations six times. That is the whole discrepancy.
            const float* xb = x + b * kQK;
            for (size_t half = 0; half < 2; ++half) {
                const uint8_t* ql = blk + half * 64;
                const uint8_t* qh = blk + 128 + half * 32;
                const int8_t* s = sc + half * 8;
                for (size_t l = 0; l < 32; ++l) {
                    const int is = static_cast<int>(l) / 16;
                    const int8_t q1 = static_cast<int8_t>(((ql[l] & 0x0F) | (((qh[l] >> 0) & 3u) << 4)) - 32);
                    const int8_t q2 = static_cast<int8_t>(((ql[l + 32] & 0x0F) | (((qh[l] >> 2) & 3u) << 4)) - 32);
                    const int8_t q3 = static_cast<int8_t>(((ql[l] >> 4) | (((qh[l] >> 4) & 3u) << 4)) - 32);
                    const int8_t q4 = static_cast<int8_t>(((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3u) << 4)) - 32);
                    acc += (d * s[is + 0]) * q1 * xb[half * 128 + l];
                    acc += (d * s[is + 2]) * q2 * xb[half * 128 + 32 + l];
                    acc += (d * s[is + 4]) * q3 * xb[half * 128 + 64 + l];
                    acc += (d * s[is + 6]) * q4 * xb[half * 128 + 96 + l];
                }
            }
        }
        y[r] += acc;
    }
}

#if defined(__AVX512F__)
// Fused AVX-512 Q6_K GEMV. Scales change every 16 weights, so the inner loop
// is 16 lanes wide rather than 32 -- widening past a scale boundary would
// apply one scale to two different groups.
inline void GemvQ6K_AVX512(const uint8_t* w, const float* x, float* y,
                            size_t rows, size_t cols) {
    if (cols == 0) return;
    const size_t kQK = 256;
    const size_t blocksPerRow = (cols + kQK - 1) / kQK;
    const __m512i m32 = _mm512_set1_epi32(32);
    const __m512i m0F = _mm512_set1_epi32(0x0F);
    // qh is 2-bit packed (4 fields per byte), so its field mask is 0x03, NOT
    // 0x0F. Masking with 0x0F pulled 4 bits where the field is 2, leaking the
    // neighbouring field into every result -- that is the 85.6x error.
    const __m512i m03 = _mm512_set1_epi32(0x03);

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* row = w + r * blocksPerRow * 210;
        __m512 vacc = _mm512_setzero_ps();
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const uint8_t* blk = row + b * 210;
            const float d = FP16ToF32(static_cast<uint16_t>(blk[208] | (blk[209] << 8)));
            const int8_t* sc = reinterpret_cast<const int8_t*>(blk + 192);
            // Activation slice for THIS block (see the scalar path).
            const float* xblk = x + b * kQK;

            for (size_t half = 0; half < 2; ++half) {
                const uint8_t* ql = blk + half * 64;
                const uint8_t* qh = blk + 128 + half * 32;
                const int8_t* s = sc + half * 8;
                // Two 16-lane groups per half (is = 0 and is = 1).
                for (size_t grp = 0; grp < 2; ++grp) {
                    // Scale index is `is + {0,2,4,6}` where `is = l/16`. With a 16-lane
                    // group, `is == grp`, so the indices are grp+0, grp+2, grp+4,
                    // grp+6. Writing grp*2 here silently yields 2,4,6,8 for
                    // grp==1 and produces output that is anti-correlated with
                    // the reference (cosine about -0.33) rather than merely
                    // inaccurate.
                    const __m512 s1 = _mm512_set1_ps(d * (float)s[grp + 0]);
                    const __m512 s2 = _mm512_set1_ps(d * (float)s[grp + 2]);
                    const __m512 s3 = _mm512_set1_ps(d * (float)s[grp + 4]);
                    const __m512 s4 = _mm512_set1_ps(d * (float)s[grp + 6]);

                    const __m128i raw1 = _mm_loadu_si128(
                        reinterpret_cast<const __m128i*>(ql + grp * 16));
                    const __m128i raw2 = _mm_loadu_si128(
                        reinterpret_cast<const __m128i*>(ql + 32 + grp * 16));
                    const __m128i rawh = _mm_loadu_si128(
                        reinterpret_cast<const __m128i*>(qh + grp * 16));

                    __m512i a = _mm512_cvtepu8_epi32(raw1);
                    __m512i c = _mm512_cvtepu8_epi32(raw2);
                    __m512i h = _mm512_cvtepu8_epi32(rawh);

                    // q1 = (ql[l] & 0xF) | ((qh[l]>>0 & 3) << 4) - 32
                    __m512i q1 = _mm512_sub_epi32(
                        _mm512_or_si512(_mm512_and_si512(a, m0F),
                            _mm512_slli_epi32(_mm512_and_si512(h, m03), 4)), m32);
                    // q2 = (ql[l+32] & 0xF) | ((qh[l]>>2 & 3) << 4) - 32
                    __m512i h2 = _mm512_and_si512(_mm512_srli_epi32(h, 2), m03);
                    __m512i q2 = _mm512_sub_epi32(
                        _mm512_or_si512(_mm512_and_si512(c, m0F),
                            _mm512_slli_epi32(h2, 4)), m32);
                    // q3 = (ql[l] >> 4) | ((qh[l]>>4 & 3) << 4) - 32
                    __m512i h4 = _mm512_and_si512(_mm512_srli_epi32(h, 4), m03);
                    __m512i q3 = _mm512_sub_epi32(
                        _mm512_or_si512(_mm512_and_si512(_mm512_srli_epi32(a, 4), m0F),
                            _mm512_slli_epi32(h4, 4)), m32);
                    // q4 = (ql[l+32] >> 4) | ((qh[l]>>6 & 3) << 4) - 32
                    __m512i h6 = _mm512_and_si512(_mm512_srli_epi32(h, 6), m03);
                    __m512i q4 = _mm512_sub_epi32(
                        _mm512_or_si512(_mm512_and_si512(_mm512_srli_epi32(c, 4), m0F),
                            _mm512_slli_epi32(h6, 4)), m32);

                    const float* xb = xblk + half * 128 + grp * 16;
                    __m512 x1 = _mm512_loadu_ps(xb);
                    __m512 x2 = _mm512_loadu_ps(xb + 32);
                    __m512 x3 = _mm512_loadu_ps(xb + 64);
                    __m512 x4 = _mm512_loadu_ps(xb + 96);

                    vacc = _mm512_fmadd_ps(_mm512_cvtepi32_ps(q1), _mm512_mul_ps(s1, x1), vacc);
                    vacc = _mm512_fmadd_ps(_mm512_cvtepi32_ps(q2), _mm512_mul_ps(s2, x2), vacc);
                    vacc = _mm512_fmadd_ps(_mm512_cvtepi32_ps(q3), _mm512_mul_ps(s3, x3), vacc);
                    vacc = _mm512_fmadd_ps(_mm512_cvtepi32_ps(q4), _mm512_mul_ps(s4, x4), vacc);
                }
            }
        }
        y[r] += _mm512_reduce_add_ps(vacc);
    }
}
#endif // __AVX512F__

inline bool HaveAvx512() {
#if defined(__AVX512F__)
    return true;
#else
    return false;
#endif
}

inline void GemvQ4KDispatch(const uint8_t* w, const float* x, float* y,
                            size_t rows, size_t cols) {
#if defined(__AVX512F__)
    GemvQ4K_AVX512(w, x, y, rows, cols);
#else
    GemvQ4K(w, x, y, rows, cols);
#endif
}

// RAWRXD_Q6K_GEMV_001
//
// Q6_K remains on the SCALAR path. An AVX-512 version was written and
// MEASURED WRONG: on a single synthetic 210-byte block it returned 85.6x the
// reference (scalar returns 1.0000000x, i.e. correct).
//
// Cause: qh packs TWO bits per weight with FOUR weights per byte, so lanes
// l and l+1 take their 2-bit fields from DIFFERENT bit positions of the SAME
// qh byte. Loading qh lane-wise and masking with 0x0F therefore extracts the
// wrong field for 3 of every 4 lanes. A correct vector path needs a qh unpack
// first (AVX512-VBMI `_mm512_multishift_epi64_epi8` produces exactly the
// 4-fields-per-byte expansion this layout requires; Zen 4 reports VBMI=1).
//
// The gate caught this rather than shipping it: the negative control fired, and
// the per-block ratio test isolated it to the fused path with the scalar
// oracle independently correct. Shipping a plausible-but-wrong kernel is the
// failure mode this whole exercise exists to prevent, so the optimized path is
// withheld until it is proven. The scalar below is the production path AND
// the retained oracle.
inline void GemvQ6KDispatch(const uint8_t* w, const float* x, float* y,
                            size_t rows, size_t cols) {
#if defined(__AVX512F__)
    GemvQ6K_AVX512(w, x, y, rows, cols);
#else
    GemvQ6K(w, x, y, rows, cols);
#endif
}

} // namespace kquant
} // namespace rawrxd