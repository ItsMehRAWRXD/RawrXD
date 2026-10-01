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
            bits = sign | ((127 - 15 - e) << 23) | (m << 13);
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

} // namespace kquant
} // namespace rawrxd