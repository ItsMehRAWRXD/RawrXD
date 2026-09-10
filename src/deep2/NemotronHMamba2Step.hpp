#pragma once
/* One-token Nemotron-H Mamba2 (CPU). PROD_DECODE=0 until REAL=21. ≤99.
   ssm_norm is often [groups, group_size]=[8,960] — index flat, never MaxRC. */
#include "NemotronHGeometry.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>

namespace Deep2 {
namespace nemotron_h {

struct StepBuf {
    float* proj = nullptr;
    float* yInner = nullptr;
    float* state = nullptr;
    float* conv = nullptr;
};

template <typename LinearFn>
inline int RunMamba2Token(size_t layer, const LayerWeights& lw, const Geo& g,
                          const float* in, float* out, StepBuf b,
                          LinearFn lin) {
    if (!g.ok || !SsmNemotronComplete(lw) || !b.proj || !b.yInner || !b.state ||
        !b.conv || !in || !out)
        return 0;
    const size_t H = g.ssmHeads, D = g.ssmHeadDim, N = g.ssmState, G = g.ssmGroups;
    const size_t I = g.ssmInner, Cdim = g.ssmConvDim, K = g.ssmConvK, GS = g.ssmGroupState;
    std::memset(b.proj, 0, g.ssmInRows * sizeof(float));
    lin(lw.ssmIn, in, nullptr, b.proj, g.ssmInRows);
    float* z = b.proj;
    float* xBC = b.proj + I;
    float* dt = b.proj + I + Cdim;
    float* cSt = b.conv + layer * Cdim * K;
    for (size_t i = 0; i < Cdim; ++i) {
        for (size_t k = K; k-- > 1;)
            cSt[k * Cdim + i] = cSt[(k - 1) * Cdim + i];
        cSt[i] = xBC[i];
        float sum = lw.ssmConv1dBias.data ? ((const float*)lw.ssmConv1dBias.data)[i] : 0.f;
        if (lw.ssmConv1d.data) {
            const float* w = (const float*)lw.ssmConv1d.data;
            for (size_t k = 0; k < K; ++k) sum += w[i * K + k] * cSt[k * Cdim + i];
        }
        xBC[i] = sum * (1.f / (1.f + expf(-sum)));
    }
    float* x = xBC;
    float* B = xBC + I;
    float* C = xBC + I + GS;
    const float* A = (const float*)lw.ssmA.data;
    const float* Dv = (const float*)lw.ssmD.data;
    const float* dtb = (const float*)lw.ssmDtBias.data;
    float* st = b.state + layer * I * N;
    for (size_t h = 0; h < H; ++h) {
        float dth = dt[h] + (dtb ? dtb[h] : 0.f);
        if (dth > 20.f)
            dth = dth;
        else if (dth > -20.f)
            dth = logf(1.f + expf(dth));
        else
            dth = expf(dth);
        if (dth < 1e-4f) dth = 1e-4f;
        const float Ah = -expf(A ? A[h] : 0.f);
        const size_t gi = h / (H / G);
        for (size_t d = 0; d < D; ++d) {
            const float xd = x[h * D + d];
            float y = 0.f;
            for (size_t n = 0; n < N; ++n) {
                float& s = st[(h * D + d) * N + n];
                s = s * expf(dth * Ah) + (dth * B[gi * N + n]) * xd;
                y += s * C[gi * N + n];
            }
            b.yInner[h * D + d] = y + xd * (Dv ? Dv[h] : 0.f);
        }
    }
    const float* nw =
        lw.ssmNorm.data ? (const float*)lw.ssmNorm.data : nullptr;
    const size_t nW =
        nw ? (lw.ssmNorm.sizeBytes / sizeof(float)) : 0;
    const size_t gs = G ? (I / G) : I;
    for (size_t gi = 0; gi < (G ? G : 1); ++gi) {
        float rms = 0.f;
        for (size_t i = 0; i < gs; ++i)
            rms += b.yInner[gi * gs + i] * b.yInner[gi * gs + i];
        rms = sqrtf(rms / (float)gs + 1e-5f);
        for (size_t i = 0; i < gs; ++i) {
            const size_t ix = gi * gs + i;
            const float gate = z[ix] * (1.f / (1.f + expf(-z[ix])));
            float yv = b.yInner[ix] / rms;
            if (nw && ix < nW) yv *= nw[ix];
            b.yInner[ix] = yv * gate;
        }
    }
    std::memset(out, 0, g.hidden * sizeof(float));
    lin(lw.ssmOut, b.yInner, nullptr, out, g.hidden);
    return 1;
}

} /* namespace nemotron_h */
} /* namespace Deep2 */
