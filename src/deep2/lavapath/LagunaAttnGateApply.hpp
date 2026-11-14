// LagunaAttnGateApply.hpp — per-head gate after SDPA, before O-proj (≤99)
// Order matches llama.cpp step35-iswa (gate then wo). Laguna tip uses softplus
// (TOK hi); step35 ref uses sigmoid — FIRST_DIVERGENCE act OPEN until ULP.
#pragma once
#include <cmath>
#include <cstdio>
#include <cstddef>

namespace Deep2 {
namespace laguna_gate {

inline float softplus(float x) {
    if (x > 20.f) return x;
    if (x < -20.f) return expf(x);
    return log1pf(expf(x));
}

/* gateLogits[heads] = Linear(W[heads,hidden], x); then
 * headScratch[h*hd:(h+1)*hd] *= softplus(gateLogits[h]).
 * Order: post-SDPA / pre-O (NOT post-O). */
inline void applyPerHeadSoftplus(float* headScratch, const float* gateLogits,
                                 size_t numHeads, size_t headDim,
                                 size_t layer, bool logOnce) {
    if (!headScratch || !gateLogits || numHeads == 0 || headDim == 0)
        return;
    for (size_t h = 0; h < numHeads; ++h) {
        const float s = softplus(gateLogits[h]);
        float* ho = headScratch + h * headDim;
        for (size_t i = 0; i < headDim; ++i)
            ho[i] *= s;
    }
    if (logOnce && layer == 0) {
        fprintf(stderr,
                "[ATTN_GATE] APPLY softplus per-head ly=0 heads=%zu hd=%zu "
                "g0=%.6g s0=%.6g (pre-O)\n",
                numHeads, headDim, (double)gateLogits[0],
                (double)softplus(gateLogits[0]));
        fflush(stderr);
    }
}

inline void applyPerHeadGate(float* headScratch, const float* gateLogits,
                             size_t numHeads, size_t headDim,
                             size_t layer, bool logOnce) {
    applyPerHeadSoftplus(headScratch, gateLogits, numHeads, headDim, layer,
                         logOnce);
}

} // namespace laguna_gate
} // namespace Deep2
