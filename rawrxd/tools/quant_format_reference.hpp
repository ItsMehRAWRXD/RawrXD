// ============================================================================
// quant_format_reference.hpp — RAWRXD_QUANT_FORMAT_REFERENCE_001
// ============================================================================
// Canonical GGUF/ggml block decoders, used ONLY as the reference side of a
// comparison against the production decode in src/deep2/QuantKernelRegistry.
// Never compiled into a shipping binary.
//
// ---------------------------------------------------------------------------
// PROVENANCE — every decoder below is a transcription, not a recollection
// ---------------------------------------------------------------------------
//   ggml-common.h   ggml-org/llama.cpp, branch `master`
//   ggml-quants.c
//   retrieved 2026-10-04 from
//     https://raw.githubusercontent.com/ggml-org/llama.cpp/master/ggml/src/ggml-common.h
//     https://raw.githubusercontent.com/ggml-org/llama.cpp/master/ggml/src/ggml-quants.c
//
//   Each function is a transcription of the corresponding `dequantize_row_*` in
//   ggml-quants.c, laid out against the `block_*` definition and its
//   `static_assert` in ggml-common.h. Where the two disagree the assert wins,
//   because the assert is a checked statement about bytes on disk.
//
//   The two files were also pinned to disk so the transcription can be re-checked
//   without a network fetch:
//     ggml-quants.c  226847 B  SHA256 5574A2DCCF7C07E75B143733E04A5412D3D8C819E7945F5217A7B83A2B2FF8AB
//     ggml-common.h  135161 B  SHA256 0061131B615C5721FC88A78FEEB22C1F8C450F1C2646A317D80796A653BF595C
//   Function line numbers in that copy of ggml-quants.c, for the decoders here:
//     q4_0 459   q4_1 479   q5_0 500   q5_1 526   q8_0 553
//     q2_K 961   q3_K 1306  q4_K 1530  q5_K 1732  q6_K 1940  q8_K 2808
//     get_scale_min_k4 880
//
// Nothing here is transcribed from memory, and nothing is transcribed from
// src/deep2/QuantKernelRegistry.hpp. A reference decoder that agreed with
// production by construction could not detect a production defect, which is the
// entire reason this file exists separately from the code under test.
//
// ---------------------------------------------------------------------------
// WHY THIS IS A NEW SOURCE RATHER THAN MORE CASES IN quant_block_oracle.cpp
// ---------------------------------------------------------------------------
// Measured 2026-10-04 on the two files the Q2_K-vs-Q4_K question is actually
// about, with the pre-existing oracle built and run as committed:
//
//   quant_block_oracle.exe G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf
//     Q8_0 0 tensors -> NO_BLOCKS_FOUND
//     Q4_0 0 tensors -> NO_BLOCKS_FOUND
//     Q5_0 0 tensors -> NO_BLOCKS_FOUND
//     VERDICT=NO_VERDICT_NONE_OF_THE_TYPES_UNDER_TEST_APPEAR_IN_THIS_MODEL
//
//   quant_block_oracle.exe F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf
//     same three rows, same NO_VERDICT
//
// The oracle had exactly one decoder per legacy type and every legacy type is
// absent from both files. The dominant types are Q2_K (10), Q3_K (11), Q6_K
// (14) and F32 (0) in the target, and Q4_K (12), Q6_K (14) and F32 (0) in the
// control. The instrument had no coverage of the subject at all, so the
// Q4_0/Q5_0 "disagreement from element 0" in the previous session was measured
// against a different file and says nothing about the model under test.
//
// ---------------------------------------------------------------------------
// WHAT IS DELIBERATELY ABSENT, AND WHY IT MATTERS
// ---------------------------------------------------------------------------
// COVERAGE IS DERIVED, NOT GUESSED. A census of all 115 GGUF files on this
// machine (F:\OllamaModels, G:\~dev\rawrxd\models, F:\~dev, F:\Franken, every
// file over 1 MB) yields exactly ten distinct tensor types:
//
//   F32 Q4_0 Q5_0 Q8_0 Q2_K Q3_K Q4_K Q5_K Q6_K BF16
//
// All ten have a decoder below. Nothing in the local corpus needs Q4_1, Q5_1,
// Q8_K, TQ1_0, TQ2_0 or any IQ type, so no decoder was written for them: a
// reference implementation that has never been compared against anything is an
// unverified claim, and this file's entire value is that it can be trusted
// against production. When a model that does need one appears,
// lookupReferenceDecoder() returns false, the caller reports NO_REFERENCE and
// counts the bytes, and the verdict degrades. Codestral-22B-v0.1-Q4_K_M.gguf
// exercised that path for real before Q5_K was added:
//
//   Q5_K  11  501743616  ...  NO_REFERENCE
//   UNJUDGED_TENSOR_BYTES=501743616 (3.9633% of 12659613696)
//   VERDICT=PARTIAL_PARITY_WITH_UNJUDGED_BYTES     exit 1
//
// It did not skip the type and did not report a clean pass. That is the property
// this file is protecting.
//
// ---------------------------------------------------------------------------
// PRECISION CONTRACT
// ---------------------------------------------------------------------------
// Arithmetic is float32 throughout, in the same association order as upstream,
// because the oracle compares bit patterns (memcmp on the float), not
// tolerances. A tolerance would hide the defect class this file exists to find.
// half_to_float() is exact for every input including subnormals, inf and NaN;
// upstream uses lookup tables, which is the same function.
//
// build: no dependencies. Include it from a tool, not from a library.
// ============================================================================

#ifndef RAWRXD_QUANT_FORMAT_REFERENCE_HPP
#define RAWRXD_QUANT_FORMAT_REFERENCE_HPP

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace rawrxd {
namespace qref {

// ---------------------------------------------------------------------------
// fp16 -> fp32, transcribed from the IEEE-754 binary16 definition.
// One explicit branch per encoding class, so a host FPU quirk cannot decide
// whether this reference agrees with production.
// ---------------------------------------------------------------------------
inline float half_to_float(std::uint16_t h) {
    const std::uint32_t sign = std::uint32_t(h >> 15) & 1u;
    const std::uint32_t exp  = std::uint32_t(h >> 10) & 0x1Fu;
    const std::uint32_t man  = std::uint32_t(h) & 0x3FFu;
    std::uint32_t bits;
    if (exp == 0u) {
        if (man == 0u) {
            bits = sign << 31;                                  // +/- zero
        } else {
            int e = -1;                                          // subnormal
            std::uint32_t m = man;
            do { ++e; m <<= 1; } while ((m & 0x400u) == 0u);
            m &= 0x3FFu;
            bits = (sign << 31) | (std::uint32_t(127 - 15 - e) << 23) | (m << 13);
        }
    } else if (exp == 31u) {
        bits = (sign << 31) | 0x7F800000u | (man << 13);         // inf / NaN
    } else {
        bits = (sign << 31) | ((exp + 127u - 15u) << 23) | (man << 13);
    }
    float out;
    std::memcpy(&out, &bits, sizeof out);
    return out;
}

inline bool half_is_nonfinite(std::uint16_t h) {
    return (std::uint32_t(h >> 10) & 0x1Fu) == 31u;
}

using DecodeFn = void (*)(const std::uint8_t* blk, std::size_t nBlocks, float* out);

struct ReferenceType {
    int         ggmlType      = -1;
    const char* name          = nullptr;
    std::size_t blockBytes    = 0;
    std::size_t elemsPerBlock = 0;
    DecodeFn    decode        = nullptr;
};

// ===========================================================================
// Unquantised types
// ===========================================================================

// GGML_TYPE_F32 (0): n raw little-endian float32.
inline void decode_f32(const std::uint8_t* p, std::size_t n, float* out) {
    std::memcpy(out, p, n * sizeof(float));
}

// GGML_TYPE_F16 (1): n raw little-endian binary16.
inline void decode_f16(const std::uint8_t* p, std::size_t n, float* out) {
    for (std::size_t i = 0; i < n; ++i) {
        std::uint16_t h;
        std::memcpy(&h, p + 2 * i, 2);
        out[i] = half_to_float(h);
    }
}

// GGML_TYPE_BF16 (30): n raw big-endian-ordered-in-memory bfloat16, i.e. the
// upper 16 bits of a float32. On a little-endian host that is a 16-bit left
// shift; the shift is written explicitly rather than assumed.
inline void decode_bf16(const std::uint8_t* p, std::size_t n, float* out) {
    for (std::size_t i = 0; i < n; ++i) {
        std::uint32_t w;
        std::memcpy(&w, p + 2 * i, 2);
        w <<= 16;
        float f;
        std::memcpy(&f, &w, sizeof f);
        out[i] = f;
    }
}

// ===========================================================================
// Legacy 32-value blocks
// ===========================================================================

// block_q4_0 (ggml-common.h): QK4_0 = 32
//   { ggml_half d; uint8_t qs[QK4_0/2]; }                        18 B
// static_assert(sizeof(block_q4_0) == sizeof(ggml_half) + QK4_0/2)
//
// dequantize_row_q4_0:
//   for j in [0,16):  x0 = (qs[j] & 0x0F) - 8 ;  x1 = (qs[j] >> 4) - 8
//                     y[j]    = x0*d ;  y[j+16] = x1*d
//
// TWO properties that a plausible-looking rewrite gets wrong, and that the
// previous revision of the oracle got wrong:
//
//   1. There is NO second fp16 field. block_q4_0 carries `d` only. The
//      20-byte `{d, m, qs[16]}` reading is block_q4_1, a different format.
//      Reading an `m` shifts every nibble by two bytes.
//   2. The pairing is SPLIT, not interleaved. Byte j supplies element j and
//      element j+16. The interleaved reading (`element 2j from qs[j] low`)
//      is a different format and differs from element 0 onward.
//
// The zero point IS -8. That is not a hypothesis; it is `quantize_row_q4_0_ref`
// in the same file: `d = max / -8`, codes clamped to [0,15].
inline void decode_q4_0(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 32, kBytes = 18;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk = p + b * kBytes;
        std::uint16_t d16;
        std::memcpy(&d16, blk, 2);
        const float d = half_to_float(d16);
        float* y = out + b * kPer;
        for (std::size_t j = 0; j < kPer / 2; ++j) {
            const int x0 = int(blk[2 + j] & 0x0Fu) - 8;
            const int x1 = int(blk[2 + j] >> 4) - 8;
            y[j]          = float(x0) * d;
            y[j + kPer/2] = float(x1) * d;
        }
    }
}

// block_q5_0 (ggml-common.h): QK5_0 = 32
//   { ggml_half d; uint8_t qh[4]; uint8_t qs[QK5_0/2]; }          22 B
// static_assert(sizeof(block_q5_0) == sizeof(ggml_half) + sizeof(uint32_t)
//                                     + QK5_0/2)
//
// dequantize_row_q5_0:
//   qh read as a uint32 (memcpy, host order)
//   for j in [0,16):
//       xh_0 = ((qh >> (j + 0)) << 4) & 0x10
//       xh_1 = ((qh >> (j + 12))     ) & 0x10
//       x0 = ((qs[j] & 0x0F) | xh_0) - 16
//       x1 = ((qs[j] >>   4) | xh_1) - 16
//       y[j]    = x0*d ;  y[j+16] = x1*d
//
// The high-bit indices are `j` and `j + 12`. They are NOT `(i/4) + (i%2)`; that
// schedule is a misreading of the quantizer's write loop and it disagrees from
// element 0. `qh` occupies bytes 2..5 and `qs` bytes 6..21.
inline void decode_q5_0(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 32, kBytes = 22;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk = p + b * kBytes;
        std::uint16_t d16;
        std::memcpy(&d16, blk, 2);
        const float d = half_to_float(d16);
        std::uint32_t qh;
        std::memcpy(&qh, blk + 2, sizeof qh);
        float* y = out + b * kPer;
        for (std::size_t j = 0; j < kPer / 2; ++j) {
            const std::uint8_t xh0 = std::uint8_t(((qh >> (j + 0)) << 4) & 0x10u);
            const std::uint8_t xh1 = std::uint8_t(((qh >> (j + 12))     ) & 0x10u);
            const int x0 = int((blk[6 + j] & 0x0Fu) | xh0) - 16;
            const int x1 = int((blk[6 + j] >> 4)   | xh1) - 16;
            y[j]          = float(x0) * d;
            y[j + kPer/2] = float(x1) * d;
        }
    }
}

// block_q8_0 (ggml-common.h): QK8_0 = 32
//   { ggml_half d; int8_t qs[QK8_0]; }                           34 B
// dequantize_row_q8_0: y[i] = qs[i] * d.  No zero point.
inline void decode_q8_0(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 32, kBytes = 34;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk = p + b * kBytes;
        std::uint16_t d16;
        std::memcpy(&d16, blk, 2);
        const float d = half_to_float(d16);
        float* y = out + b * kPer;
        for (std::size_t i = 0; i < kPer; ++i)
            y[i] = float(std::int8_t(blk[2 + i])) * d;
    }
}

// ===========================================================================
// Super-blocks: QK_K = 256
// ===========================================================================

// block_q2_K (ggml-common.h)
//   { uint8_t scales[QK_K/16];   // 16 B  @ 0
//     uint8_t qs[QK_K/4];        // 64 B  @ 16
//     ggml_half d;               //       @ 80
//     ggml_half dmin; }          //       @ 82                            84 B
// static_assert(sizeof(block_q2_K) == 2*sizeof(ggml_half) + QK_K/16 + QK_K/4)
//
// dequantize_row_q2_K:
//   is = 0; q = qs
//   for n in {0,128}, shift = 0, for j in [0,4):
//       sc = scales[is++]; dl = d*(sc & 0xF); ml = dmin*(sc >> 4)
//         y[n + j*32 + l     ] = dl * ((q[l]     >> shift) & 3) - ml   for l in [0,16)
//       sc = scales[is++]; dl = d*(sc & 0xF); ml = dmin*(sc >> 4)
//         y[n + j*32 + 16 + l] = dl * ((q[l + 16] >> shift) & 3) - ml   for l in [0,16)
//       shift += 2
//     q += 32
//
// The field order is scales/qs/d/dmin. This is the single most consequential
// line in the file: block_q2_K is the ONLY block_* in ggml-common.h whose
// super-block scale is NOT first, and a reader that assumes the Q4_K shape
// reads fp16 scale words out of 2-bit quant data. That produces a d of order
// 1e6-1e7 and every downstream number becomes noise while every structural
// check still passes, because the block size is 84 either way.
inline void decode_q2_K(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 256, kBytes = 84;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk    = p + b * kBytes;
        const std::uint8_t* scales = blk;          // @ 0
        const std::uint8_t* q      = blk + 16;     // @ 16
        std::uint16_t d16, m16;
        std::memcpy(&d16,  blk + 80, 2);
        std::memcpy(&m16,  blk + 82, 2);
        const float d    = half_to_float(d16);
        const float dmin = half_to_float(m16);
        float* y = out + b * kPer;

        const std::uint8_t* qq = q;
        int is = 0;
        for (int n = 0; n < int(kPer); n += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                std::uint8_t sc = scales[is++];
                float dl = d * float(sc & 0x0Fu);
                float ml = dmin * float(sc >> 4);
                for (int l = 0; l < 16; ++l)
                    y[n + j*32 + l] =
                        dl * float((qq[l] >> shift) & 3) - ml;
                sc = scales[is++];
                dl = d * float(sc & 0x0Fu);
                ml = dmin * float(sc >> 4);
                for (int l = 0; l < 16; ++l)
                    y[n + j*32 + 16 + l] =
                        dl * float((qq[l + 16] >> shift) & 3) - ml;
                shift += 2;
            }
            qq += 32;
        }
    }
}

// block_q3_K (ggml-common.h)
//   { uint8_t hmask[QK_K/8];  // 32 B  @ 0
//     uint8_t qs[QK_K/4];     // 64 B  @ 32
//     uint8_t scales[12];     // 12 B  @ 96
//     ggml_half d; }          //       @ 108                          110 B
//
// dequantize_row_q3_K: unpack twelve bytes into sixteen 6-bit SIGNED scales,
// then walk a single bit `m` through hmask across the whole super-block. `m`
// starts at 1 and is shifted once per j, i.e. four times per 128-chunk, and it
// is NOT reset between the two chunks. That carry is load-bearing: resetting it
// makes the high 128 values read the wrong hmask bits.
inline void decode_q3_K(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 256, kBytes = 110;
    constexpr std::uint32_t kmask1 = 0x03030303u;
    constexpr std::uint32_t kmask2 = 0x0f0f0f0fu;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk  = p + b * kBytes;
        const std::uint8_t* hm   = blk;          // @ 0
        const std::uint8_t* q    = blk + 32;     // @ 32
        const std::uint8_t* scr  = blk + 96;     // @ 96
        std::uint16_t d16;
        std::memcpy(&d16, blk + 108, 2);
        const float d = half_to_float(d16);

        std::uint32_t aux[4];
        std::memcpy(aux, scr, 12);
        const std::uint32_t tmp = aux[2];
        aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
        aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
        aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
        aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
        const std::int8_t* scales = reinterpret_cast<const std::int8_t*>(aux);

        float* y = out + b * kPer;
        const std::uint8_t* qq = q;
        std::uint8_t m = 1;
        int is = 0;
        for (int n = 0; n < int(kPer); n += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                float dl = d * float(int(scales[is++]) - 32);
                for (int l = 0; l < 16; ++l)
                    y[n + j*32 + l] = dl * float(
                        int((qq[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4));
                dl = d * float(int(scales[is++]) - 32);
                for (int l = 0; l < 16; ++l)
                    y[n + j*32 + 16 + l] = dl * float(
                        int((qq[l + 16] >> shift) & 3) - ((hm[l + 16] & m) ? 0 : 4));
                shift += 2;
                m = std::uint8_t(m << 1);
            }
            qq += 32;
        }
    }
}

// ggml get_scale_min_k4, verbatim in structure. Reads one 6-bit scale and one
// 6-bit min out of the 12-byte K_SCALE_SIZE field.
inline void ref_get_scale_min_k4(int j, const std::uint8_t* q,
                                 std::uint8_t& d, std::uint8_t& m) {
    if (j < 4) {
        d = std::uint8_t(q[j] & 63);
        m = std::uint8_t(q[j + 4] & 63);
    } else {
        d = std::uint8_t((q[j + 4] & 0x0F) | ((q[j - 4] >> 6) << 4));
        m = std::uint8_t((q[j + 4] >>   4) | ((q[j - 0] >> 6) << 4));
    }
}

// block_q4_K (ggml-common.h)
//   { ggml_half d; ggml_half dmin; uint8_t scales[12]; uint8_t qs[128]; }
//     2 + 2 + 12 + 128                                                    144 B
// dequantize_row_q4_K: four 64-value groups, two (scale,min) pairs per group.
inline void decode_q4_K(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 256, kBytes = 144;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk    = p + b * kBytes;
        std::uint16_t d16, m16;
        std::memcpy(&d16, blk, 2);
        std::memcpy(&m16, blk + 2, 2);
        const float d    = half_to_float(d16);
        const float dmin = half_to_float(m16);
        const std::uint8_t* scales = blk + 4;
        const std::uint8_t* q      = blk + 16;

        float* y = out + b * kPer;
        int is = 0;
        for (int j = 0; j < int(kPer); j += 64) {
            std::uint8_t sc, mn;
            ref_get_scale_min_k4(is + 0, scales, sc, mn);
            const float d1 = d * float(sc), m1 = dmin * float(mn);
            ref_get_scale_min_k4(is + 1, scales, sc, mn);
            const float d2 = d * float(sc), m2 = dmin * float(mn);
            for (int l = 0; l < 32; ++l)
                y[j + l]     = d1 * float(q[l] & 0x0F) - m1;
            for (int l = 0; l < 32; ++l)
                y[j + 32 + l] = d2 * float(q[l] >> 4) - m2;
            q  += 32;
            is += 2;
        }
    }
}

// block_q5_K (ggml-common.h)
//   { ggml_half d;                  // @ 0
//     ggml_half dmin;               // @ 2
//     uint8_t scales[K_SCALE_SIZE]; // @ 4,  12 B
//     uint8_t qh[QK_K/8];           // @ 16, 32 B
//     uint8_t qs[QK_K/2]; }         // @ 48, 128 B                      176 B
// static_assert(sizeof(block_q5_K) == 2*sizeof(ggml_half) + K_SCALE_SIZE
//                                      + QK_K/2 + QK_K/8)
//
// dequantize_row_q5_K: four 64-value groups, two (scale,min) pairs per group,
// and a fifth-bit mask that advances by TWO BITS per group — u1 = 1, 4, 16, 64
// for the low nibbles and u2 = 2, 8, 32, 128 for the high nibbles:
//
//     for l in [0,32):  y[j + l]     = d1 * ((ql[l] & 0xF) + (qh[l] & u1 ? 16 : 0)) - m1
//     for l in [0,32):  y[j + 32 + l] = d2 * ((ql[l] >>  4)  + (qh[l] & u2 ? 16 : 0)) - m2
//
// TWO THINGS THAT ARE EASY TO GET WRONG AND ARE BOTH WRONG IN PRODUCTION:
//
//   1. The pairing is SPLIT, as in every other K-quant: byte l of qs supplies
//      element l and element l+32. Indexing qs by (element/2) with a 4-bit shift
//      per element is an interleaved reading of a different format.
//   2. The qh bit index is a property of the GROUP, not of the element. Element
//      l of group g takes its high bit from bit 2g of qh[l] (low nibble) or bit
//      2g+1 (high nibble). It is not (element % 8) and not (element/8, element%8).
//
// Both mistakes produce plausible magnitudes and in-vocabulary-looking weights,
// because d and dmin are read correctly and only the 256 quants are permuted.
//
// A THIRD THING, WHICH WAS WRONG IN THE FIRST DRAFT OF THIS FUNCTION, is
// recorded here because the bit-exact comparison caught it and nothing else
// would have. Upstream is
//
//     *y++ = d1 * ((ql[l] & 0xF) + (qh[l] & u1 ? 16 : 0)) - m1;
//
// i.e. `(d1 * q) - m1`. This function first read `d1 * (q - m1)`. The paren is
// invisible to review, both forms are finite, both are in a plausible numeric
// range, and the resulting mismatch looked exactly like a production defect —
// production values appearing at shifted indices with a max_abs_diff of 0.026.
//
// It was not a production defect. It was this file being wrong on the day it
// was written, and the only reason it surfaced within one run instead of
// becoming a retracted claim is that the comparison is memcmp on the float with
// no tolerance. An earlier instrument in this repository used a magnitude
// heuristic and would have scored this pair as consistent.
//
// Note the contrast with Q3_K, where upstream really is `dl * (q - adj)`:
//     *y++ = dl * ((int8_t)((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4));
// so the two look alike and mean opposite things. Copying the shape from the
// neighbouring function is exactly the error.
inline void decode_q5_K(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 256, kBytes = 176;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk    = p + b * kBytes;
        std::uint16_t d16, m16;
        std::memcpy(&d16, blk, 2);
        std::memcpy(&m16, blk + 2, 2);
        const float d    = half_to_float(d16);
        const float dmin = half_to_float(m16);
        const std::uint8_t* scales = blk + 4;
        const std::uint8_t* qh     = blk + 16;
        const std::uint8_t* ql     = blk + 48;

        float* y = out + b * kPer;
        const std::uint8_t* q = ql;
        int is = 0;
        std::uint8_t u1 = 1, u2 = 2;
        for (int j = 0; j < int(kPer); j += 64) {
            std::uint8_t sc, mn;
            ref_get_scale_min_k4(is + 0, scales, sc, mn);
            const float d1 = d * float(sc), m1 = dmin * float(mn);
            ref_get_scale_min_k4(is + 1, scales, sc, mn);
            const float d2 = d * float(sc), m2 = dmin * float(mn);
            for (int l = 0; l < 32; ++l)
                y[j + l] = d1 * float(int(q[l] & 0x0Fu) + ((qh[l] & u1) ? 16 : 0)) - m1;
            for (int l = 0; l < 32; ++l)
                y[j + 32 + l] = d2 * float(int(q[l] >> 4)  + ((qh[l] & u2) ? 16 : 0)) - m2;
            q  += 32;
            is += 2;
            u1 = std::uint8_t(u1 << 2);
            u2 = std::uint8_t(u2 << 2);
        }
    }
}

// block_q6_K (ggml-common.h)
//   { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; ggml_half d; }
//     128 + 64 + 16 + 2                                                    210 B
// dequantize_row_q6_K: two 128-value chunks; inside a chunk each of 32 lanes
// produces four values at +0/+32/+64/+96, with the 2-bit high half taken from
// qh at bit offsets 0/2/4/6 and the scale index stepping by 2.
inline void decode_q6_K(const std::uint8_t* p, std::size_t nBlocks, float* out) {
    constexpr std::size_t kPer = 256, kBytes = 210;
    for (std::size_t b = 0; b < nBlocks; ++b) {
        const std::uint8_t* blk = p + b * kBytes;
        const std::uint8_t* l4  = blk;          // ql  @ 0
        const std::uint8_t* h2  = blk + 128;    // qh  @ 128
        const std::int8_t*  s8  =
            reinterpret_cast<const std::int8_t*>(blk + 192);   // scales @ 192
        std::uint16_t d16;
        std::memcpy(&d16, blk + 208, 2);
        const float d = half_to_float(d16);

        float* y = out + b * kPer;
        for (int n = 0; n < int(kPer); n += 128) {
            for (int l = 0; l < 32; ++l) {
                const int is = l / 16;
                const int q1 = int((l4[l]    & 0x0F) | (((h2[l] >> 0) & 3) << 4)) - 32;
                const int q2 = int((l4[l+32] & 0x0F) | (((h2[l] >> 2) & 3) << 4)) - 32;
                const int q3 = int((l4[l]    >>   4) | (((h2[l] >> 4) & 3) << 4)) - 32;
                const int q4 = int((l4[l+32] >>   4) | (((h2[l] >> 6) & 3) << 4)) - 32;
                y[n + l]      = d * float(s8[is + 0]) * float(q1);
                y[n + l + 32] = d * float(s8[is + 2]) * float(q2);
                y[n + l + 64] = d * float(s8[is + 4]) * float(q3);
                y[n + l + 96] = d * float(s8[is + 6]) * float(q4);
            }
            l4 += 64;
            h2 += 32;
            s8 += 8;
        }
    }
}

// ===========================================================================
// Registry of reference decoders
// ===========================================================================

inline const ReferenceType* referenceTypes(std::size_t& count) {
    static const ReferenceType kTable[] = {
        {  0, "F32",  4,   1, decode_f32  },
        {  1, "F16",  2,   1, decode_f16  },
        {  2, "Q4_0", 18,  32, decode_q4_0 },
        {  6, "Q5_0", 22,  32, decode_q5_0 },
        {  8, "Q8_0", 34,  32, decode_q8_0 },
        { 10, "Q2_K", 84, 256, decode_q2_K },
        { 11, "Q3_K", 110, 256, decode_q3_K },
        { 12, "Q4_K", 144, 256, decode_q4_K },
        { 13, "Q5_K", 176, 256, decode_q5_K },
        { 14, "Q6_K", 210, 256, decode_q6_K },
        { 30, "BF16", 2,   1, decode_bf16 },
    };
    count = sizeof kTable / sizeof kTable[0];
    return kTable;
}

inline const ReferenceType* findReferenceType(int ggmlType) {
    std::size_t n = 0;
    const ReferenceType* t = referenceTypes(n);
    for (std::size_t i = 0; i < n; ++i)
        if (t[i].ggmlType == ggmlType) return &t[i];
    return nullptr;
}

// Human-readable ggml type id, for reports. Not a decoder: naming a type is not
// judging it.
inline const char* ggmlTypeName(int t) {
    switch (t) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 6:  return "Q5_0";
        case 7:  return "Q5_1";
        case 8:  return "Q8_0";
        case 9:  return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        case 16: return "IQ2_XXS";
        case 17: return "IQ2_XS";
        case 18: return "IQ3_XXS";
        case 19: return "IQ1_S";
        case 20: return "IQ4_NL";
        case 21: return "IQ3_S";
        case 22: return "IQ2_S";
        case 23: return "IQ4_XS";
        case 24: return "I8";
        case 25: return "I16";
        case 26: return "I32";
        case 27: return "I64";
        case 28: return "F64";
        case 29: return "IQ1_M";
        case 30: return "BF16";
        default: return nullptr;
    }
}

} // namespace qref
} // namespace rawrxd

#endif // RAWRXD_QUANT_FORMAT_REFERENCE_HPP