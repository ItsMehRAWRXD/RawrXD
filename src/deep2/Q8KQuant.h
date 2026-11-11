// =============================================================================
// Q8KQuant.h — Deep2 Q8_K activation quantisation, ggml-exact
// =============================================================================
// The single production owner of Q8_K activation preparation for Deep2. Both
// the interleaved-layout builder and the parity-harness path route through
// this header so there cannot be two implementations again.
//
// PROVENANCE — verified byte-level against the vendored llama.cpp source in
// this repository:
//   authority : 3rdparty/ggml/src/ggml-quants.c :: quantize_row_q8_K_ref
//               (line 2555), which ggml-cpu/arch/x86/quants.c::quantize_row_q8_K
//               dispatches to, so this IS the protocol the reference runs.
//   layout    : 3rdparty/ggml/src/ggml-common.h :: block_q8_K (line 339)
//                   float d;  int8_t qs[256];  int16_t bsums[16];   // 292 B
//
// FOUR properties this header restores. Each was independently wrong in
// src/deep2/runtime_graph_executor.cpp, proven by src/deep2/Q8KParity.cpp:
//
//   1. SIGNED EXTREMUM SCALE. The reference derives the scale from the signed
//      value with the greatest absolute magnitude (iscale = -127.f / max), and
//      stores d = 1/iscale. Deep2 used unsigned amax / 127.
//      Observed: ggml 0xBCD9E6F9 (-0.0266) vs Deep2 0x3CD9E6F9 (+0.0266) —
//      identical magnitude, opposite sign bit.
//
//   2. ROUNDING. ggml's nearest_int is round-half-to-EVEN. Deep2 used
//      std::lround, which is half-away-from-zero, so every exact halfway case
//      diverged. Observed: 751 differing qs values across 4 of 8 blocks once
//      halfway ties were injected.
//
//   3. CLAMP. The reference writes MIN(127, v). Deep2 wrote the raw rounded
//      value, which can reach +128 and does not match the reference byte.
//
//   4. d IS FP32. block_q8_K::d is a 32-bit float; the FP16 scale fields belong
//      to Q4_K/Q6_K, which store WEIGHTS. Q8_K is an activation format and is
//      never FP16. Rounding d to FP16 would ADD error the reference does not
//      have, so it is deliberately NOT done here.
//
// NOTE ON THE SIGN FLIP: flipping both d and qs is mathematically neutral for a
// dequantise-then-dot, but the interleaved layout bytes then differ from what
// ggml produces, so any consumer that assumes ggml block semantics disagrees.
// Matching the reference byte-for-byte removes that entire class of question.
// =============================================================================
#pragma once

#include <cmath>
#include <cstring>
#include <cstdint>

namespace RawrXD {
namespace Deep2 {

constexpr int kQkK = 256;              // ggml QK_K
constexpr size_t kQ8Stride = 273;      // floats per super-block: d, qs[256], bsums[16]

// ggml's reference nearest_int(): snaps through the 2^23 constant, giving
// round-half-to-even. Do NOT substitute std::lround (half away from zero).
inline int32_t GgmlNearestInt(float x) {
    // Matches ggml-quants.c's scalar reference for the finite inputs this
    // quantiser sees; non-finite input cannot occur because amax==0 short-circuits.
    return static_cast<int32_t>(std::nearbyint(x));
}

// ggml block_q8_K geometry (see 3rdparty/ggml/src/ggml-common.h:339).
struct Q8KBlock {
    float   d;
    int8_t  qs[kQkK];
    int16_t bsums[kQkK / 16];
};
static_assert(sizeof(Q8KBlock) == 292, "Q8_K block must be 292 bytes");

// ---------------------------------------------------------------------------
// Reference-exact Q8_K quantisation
// ---------------------------------------------------------------------------
// Mirrors quantize_row_q8_K_ref line for line. `out` must hold (k/256) blocks.
inline void QuantizeRowQ8K(const float* x, Q8KBlock* out, int64_t k) {
    const int64_t nb = k / kQkK;
    for (int64_t i = 0; i < nb; ++i) {
        float amax = 0.0f;
        float max  = 0.0f;
        for (int j = 0; j < kQkK; ++j) {
            const float ax = std::fabs(x[j]);
            if (ax > amax) { amax = ax; max = x[j]; }
        }
        if (amax == 0.0f) {
            out[i].d = 0.0f;
            std::memset(out[i].qs, 0, kQkK);
            std::memset(out[i].bsums, 0, sizeof(out[i].bsums));
            x += kQkK;
            continue;
        }
        // Signed extremum, negative slope: iscale = -127.f / max.
        const float iscale = -127.0f / max;
        for (int j = 0; j < kQkK; ++j) {
            const int v = GgmlNearestInt(iscale * x[j]);
            out[i].qs[j] = static_cast<int8_t>(v < 127 ? v : 127);   // MIN(127, v)
        }
        for (int j = 0; j < kQkK / 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) sum += out[i].qs[j * 16 + ii];
            out[i].bsums[j] = static_cast<int16_t>(sum);
        }
        out[i].d = 1.0f / iscale;      // FP32, stored unconverted
        x += kQkK;
    }
}

// ---------------------------------------------------------------------------
// Interleaved layout: per 256-value super-block, d then qs[256] then bsums[16].
// This is what the GPU shader and the CPU reference dot both consume.
// `q8` must have capacity (n_in/256) * kQ8Stride.
// The final super-block is PARTIAL when n_in % 256 != 0: only the populated
// values are quantised and the remaining qs/bsums stay zero, matching the
// reference which never reads unwritten tails.
// ---------------------------------------------------------------------------
inline void BuildInterleavedQ8K(const float* x, size_t n_in, float* q8) {
    const size_t n_sb = (n_in + kQkK - 1u) / kQkK;
    for (size_t b = 0; b < n_sb; ++b) {
        const size_t off   = b * kQkK;
        const size_t elems = (n_in - off < kQkK) ? (n_in - off) : kQkK;

        float* blk = q8 + b * kQ8Stride;
        // Zero the whole super-block first so a partial tail is genuinely zero
        // rather than uninitialised, and an all-zero block reproduces the
        // reference's memset path exactly.
        std::memset(blk, 0, kQ8Stride * sizeof(float));

        float amax = 0.0f;
        float max  = 0.0f;
        for (size_t i = 0; i < elems; ++i) {
            const float ax = std::fabs(x[off + i]);
            if (ax > amax) { amax = ax; max = x[off + i]; }
        }
        if (amax == 0.0f) {
            continue;                       // d = 0, qs/bsums already zeroed
        }

        const float iscale = -127.0f / max;
        int32_t bsums[kQkK / 16] = {0};
        for (size_t i = 0; i < elems; ++i) {
            const int v = GgmlNearestInt(iscale * x[off + i]);
            const int8_t q = static_cast<int8_t>(v < 127 ? v : 127);
            blk[1 + i] = static_cast<float>(q);
            bsums[i / 16] += q;
        }
        blk[0] = 1.0f / iscale;            // FP32 scale, no FP16 rounding
        for (size_t j = 0; j < kQkK / 16; ++j) {
            blk[257 + j] = static_cast<float>(bsums[j]);
        }
    }
}

} // namespace Deep2
} // namespace RawrXD
