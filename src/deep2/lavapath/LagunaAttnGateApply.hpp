// LagunaAttnGateApply.hpp — softplus per-head gate before O-proj (≤99)
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
 * headScratch[h*hd:(h+1)*hd] *= softplus(gateLogits[h]). */
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
                "g0=%.6g s0=%.6g\n",
                numHeads, headDim, (double)gateLogits[0],
                (double)softplus(gateLogits[0]));
        fflush(stderr);
    }
}

} // namespace laguna_gate
} // namespace Deep2
