// =============================================================================
// Q8KParity.h — Byte-level Q8_K activation parity harness (decisive experiment)
// =============================================================================
// Localises the residual Deep2 != llama.cpp divergence without speculating about
// FP16 scale rounding, attention, RoPE, KV or residuals.
//
// Ground truth: the vendored llama.cpp source in this repository, i.e.
//   3rdparty/ggml/src/ggml-quants.c :: quantize_row_q8_K_ref (line 2555)
//   which is what ggml-cpu/arch/x86/quants.c::quantize_row_q8_K dispatches to
//   on the parity platform.
// The block it fills is 3rdparty/ggml/src/ggml-common.h :: block_q8_K:
//      float d;  int8_t qs[256];  int16_t bsums[16];      // 292 bytes
//
// DECISIVE FACT, verified from the source in this repository:
//   block_q8_K::d is a 32-bit FLOAT. block_q6_K::d and the Q4_K/Q5_K sub-block
//   scales are ggml_half (FP16) because those formats store WEIGHTS. Q8_K is an
//   ACTIVATION/intermediate format and is never FP16. Therefore the proposed
//   "round the Q8_K scale to FP16" change is REJECTED: it would introduce error
//   that the reference does not have and make Deep2 LESS accurate.
//
// HOW TO USE the decision table produced here:
//   d bits differ                      -> scale selection / calculation
//   d matches, qs differ               -> rounding, clamp or conversion semantics
//   qs matches, bsums differ           -> signed accumulation or indexing
//   all Q8_K fields match, dot differs -> Q4_K/Q6_K decoding or dot arithmetic
//   dots match, logits differ          -> higher-level operation ordering
//
// One correctly chosen projection with a byte-level comparison resolves more
// uncertainty than another full 67-position run.
// =============================================================================
#pragma once

#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <optional>
#include <nlohmann/json.hpp>

// The shared, production Q8_K block geometry. The oracle and the repaired
// implementation MUST agree on one type, otherwise the comparison could drift.
#include "Q8KQuant.h"

using json = nlohmann::json;

namespace RawrXD {
namespace Parity {

// ---------------------------------------------------------------------------
// ggml block_q8_K layout (identical to 3rdparty/ggml/src/ggml-common.h:339)
// ---------------------------------------------------------------------------
constexpr int QK_K = 256;

// Re-exported from the production header so this file is never a second source
// of truth for the 292-byte geometry.
using Q8KBlock = ::RawrXD::Deep2::Q8KBlock;
static_assert(sizeof(Q8KBlock) == 292, "Q8_K block must be 292 bytes");
static_assert(sizeof(Q8KBlock::qs) == 256, "Q8_K qs must be 256 bytes");
static_assert(sizeof(Q8KBlock::bsums) == 32, "Q8_K bsums must be 16 int16_t");

// ---------------------------------------------------------------------------
// Reference Q8_K quantizer — exact semantics of ggml quantize_row_q8_K_ref
// ---------------------------------------------------------------------------
// Reproduced from 3rdparty/ggml/src/ggml-quants.c:2555-2592. This is the
// authoritative protocol. Do not "fix" it to match Deep2; fix Deep2 to match it.
//
// Key details that Deep2 currently gets wrong:
//   1. The scale is derived from the SIGNED value with the greatest absolute
//      magnitude, not from amax:  iscale = -127.f / max,  d = 1/iscale.
//   2. Quantisation uses ggml's nearest_int, NOT std::lround. On x86 the
//      generic reference nearest_int is round-to-NEAREST-EVEN, so halfway cases
//      differ from std::lround's half-away-from-zero.
//   3. The result is clamped: y[i].qs[j] = MIN(127, v).
// ---------------------------------------------------------------------------

// ggml's reference nearest_int() in ggml-quants.c: it snaps through the
// 2^23 double-round trick, which yields round-half-to-even.
inline int32_t GgmlNearestIntRef(float x) {
    // Equivalent to the "magic constant" snap used by ggml's scalar reference.
    return static_cast<int32_t>(std::nearbyint(x));
}

inline void QuantizeRowQ8KReference(const float* x, Q8KBlock* y, int64_t k) {
    const int64_t nb = k / QK_K;
    for (int64_t i = 0; i < nb; ++i) {
        float amax = 0.0f;
        float max  = 0.0f;
        for (int j = 0; j < QK_K; ++j) {
            const float ax = std::fabs(x[j]);
            if (ax > amax) { amax = ax; max = x[j]; }
        }
        if (amax == 0.0f) {
            y[i].d = 0.0f;
            std::memset(y[i].qs, 0, QK_K);
            std::memset(y[i].bsums, 0, sizeof(y[i].bsums));
            x += QK_K;
            continue;
        }
        const float iscale = -127.0f / max;   // SIGNED extremum, negative slope
        for (int j = 0; j < QK_K; ++j) {
            const int v = GgmlNearestIntRef(iscale * x[j]);
            y[i].qs[j] = static_cast<int8_t>(v < 127 ? v : 127);  // MIN(127, v)
        }
        for (int j = 0; j < QK_K / 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = static_cast<int16_t>(sum);
        }
        y[i].d = 1.0f / iscale;   // FP32, stored as-is (no FP16)
        x += QK_K;
    }
}

// ---------------------------------------------------------------------------
// Deep2 CURRENT implementation (verbatim from the two call sites in
// src/deep2/runtime_graph_executor.cpp: BuildInterleavedQ8 @:40 and the
// parity-harness path @:716). Both are byte-identical in behaviour.
// Kept here so the harness can demonstrate the divergence, not to endorse it.
// ---------------------------------------------------------------------------
inline void QuantizeRowQ8KDeep2Current(const float* x, Q8KBlock* y, int64_t k) {
    const int64_t nb = k / QK_K;
    for (int64_t b = 0; b < nb; ++b) {
        float mx = 0.0f;
        for (int i = 0; i < QK_K; ++i) {
            mx = std::max(mx, std::fabs(x[b * QK_K + i]));
        }
        const float d = mx / 127.0f;                       // unsigned amax
        const float inv = d > 0.0f ? 1.0f / d : 0.0f;
        y[b].d = d;
        int32_t bsums[16] = {0};
        for (int i = 0; i < QK_K; ++i) {
            const int32_t v = static_cast<int32_t>(std::lround(x[b * QK_K + i] * inv));  // std::lround
            y[b].qs[i] = static_cast<int8_t>(v);           // no clamp
            bsums[i / 16] += v;
        }
        for (int j = 0; j < 16; ++j) {
            y[b].bsums[j] = static_cast<int16_t>(bsums[j]);
        }
    }
}

// ---------------------------------------------------------------------------
// Block-level differential result
// ---------------------------------------------------------------------------
struct Q8KBlockDiff {
    int     block_index = -1;
    bool    d_bits_match     = false;
    bool    qs_match         = false;
    bool    bsums_match      = false;
    int     qs_mismatches    = 0;      // count of differing indices
    int     bsum_mismatches  = 0;
    int     first_qs_index   = -1;     // first differing qs index, for the trace

    // The diagnosis implied by this block's diff, per the decision table.
    std::string Verdict() const {
        if (!d_bits_match) {
            return "scale-selection: ggml uses the SIGNED extremum "
                   "(iscale=-127/max, d=1/iscale); Deep2 uses unsigned amax/127";
        }
        if (!qs_match) {
            return "rounding-or-clamp: ggml nearest_int (half-to-even) + MIN(127,v); "
                   "Deep2 uses std::lround (half-away-from-zero) with no clamp";
        }
        if (!bsums_match) {
            return "block-sum: signed accumulation or grouping";
        }
        return "identical-Q8_K-fields: divergence is downstream (dot/decode)";
    }
};

struct Q8KParityReport {
    int64_t   blocks_compared = 0;
    int64_t   d_bits_mismatches = 0;
    int64_t   qs_mismatch_blocks = 0;
    int64_t   bsum_mismatch_blocks = 0;
    int64_t   qs_value_mismatches = 0;
    int64_t   bsum_value_mismatches = 0;
    int       first_bad_block = -1;
    bool      fully_identical = false;
    std::vector<std::string> distinct_verdicts;
    std::optional<Q8KBlockDiff> first_difference;

    json ToJson() const;
};

// ---------------------------------------------------------------------------
// Compare two Q8_K ring buffers field by field
// ---------------------------------------------------------------------------
Q8KParityReport CompareQ8KBlocks(const float* activation, int64_t k,
                                  const Q8KBlock* reference,
                                  const Q8KBlock* candidate,
                                  int64_t max_detail_blocks = 8);

// Convenience: run Deep2's current implementation against the reference.
Q8KParityReport DiffDeep2VsReference(const float* activation, int64_t k);

// ---------------------------------------------------------------------------
// Interleaved-layout differs (273 floats per super-block: d, qs[256], bsums[16])
// This is the layout the GPU shader and the CPU reference dot both consume.
// ---------------------------------------------------------------------------
struct InterleavedQ8Diff {
    int64_t super_block = -1;
    bool    d_match = false;
    int     qs_mismatches = 0;
    int     bsum_mismatches = 0;
};

Q8KParityReport CompareInterleavedQ8(const float* deep2_interleaved,
                                     const float* ggml_interleaved,
                                     int64_t n_in);

} // namespace Parity
} // namespace RawrXD
