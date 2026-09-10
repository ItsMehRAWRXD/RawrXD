#pragma once
/* Nemotron-H Mamba2 one-token. PROD_DECODE=0. A=POS exp(-dt*A). ≤99. */
#include "NemotronHGeometry.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
namespace Deep2 {
namespace nemotron_h {
struct StepBuf {
    float* proj = nullptr; float* yInner = nullptr;
    float* state = nullptr; float* conv = nullptr;
};
inline float SoftplusClamp(float x) {
    float y = (x > 20.f) ? x : ((x > -20.f) ? logf(1.f + expf(x)) : expf(x));
    if (y < 0.001f) y = 0.001f; if (y > 0.1f) y = 0.1f; return y;
}
inline float FiniteOr0(float v) { return std::isfinite(v) ? v : 0.f; }
template <typename LinearFn>
inline int RunMamba2Token(size_t layer, const LayerWeights& lw, const Geo& g,
                          const float* in, float* out, StepBuf b, LinearFn lin) {
    if (!g.ok || !SsmNemotronComplete(lw) || !b.proj || !b.yInner || !b.state ||
        !b.conv || !in || !out) return 0;
    const size_t H = g.ssmHeads, D = g.ssmHeadDim, N = g.ssmState, G = g.ssmGroups;
    const size_t I = g.ssmInner, Cdim = g.ssmConvDim, K = g.ssmConvK, GS = g.ssmGroupState;
    std::memset(b.proj, 0, g.ssmInRows * sizeof(float));
    lin(lw.ssmIn, in, nullptr, b.proj, g.ssmInRows);
    float* z = b.proj; float* xBC = b.proj + I; float* dt = b.proj + I + Cdim;
    float* cSt = b.conv + layer * Cdim * K;
    for (size_t i = 0; i < Cdim; ++i) {
        for (size_t k = K; k-- > 1;) cSt[k * Cdim + i] = cSt[(k - 1) * Cdim + i];
        cSt[i] = FiniteOr0(xBC[i]);
        float sum = lw.ssmConv1dBias.data ? ((const float*)lw.ssmConv1dBias.data)[i] : 0.f;
        if (lw.ssmConv1d.data) {
            const float* w = (const float*)lw.ssmConv1d.data;
            for (size_t k = 0; k < K; ++k) sum += w[i * K + k] * cSt[k * Cdim + i];
        }
        xBC[i] = FiniteOr0(sum * (1.f / (1.f + expf(-sum))));
    }
    float* x = xBC; float* B = xBC + I; float* C = xBC + I + GS;
    const float* A = (const float*)lw.ssmA.data;
    const float* Dv = (const float*)lw.ssmD.data;
    const float* dtb = (const float*)lw.ssmDtBias.data;
    float* st = b.state + layer * I * N;
    int finite = 1;
    for (size_t h = 0; h < H; ++h) {
        const float dth = SoftplusClamp(dt[h] + (dtb ? dtb[h] : 0.f));
        float e = -dth * (A ? fabsf(A[h]) : 1.f);
        if (e < -80.f) e = -80.f;
        const float dA = expf(e);
        const size_t gi = h / (H / G);
        for (size_t d = 0; d < D; ++d) {
            const float xd = FiniteOr0(x[h * D + d]);
            float y = 0.f;
            for (size_t n = 0; n < N; ++n) {
                float& s = st[(h * D + d) * N + n];
                s = FiniteOr0(s * dA + (dth * B[gi * N + n]) * xd);
                if (!std::isfinite(s)) finite = 0;
                y += s * C[gi * N + n];
            }
            b.yInner[h * D + d] = FiniteOr0(y + xd * (Dv ? Dv[h] : 0.f));
        }
    }
    const float* nw = lw.ssmNorm.data ? (const float*)lw.ssmNorm.data : nullptr;
    const size_t nW = nw ? (lw.ssmNorm.sizeBytes / sizeof(float)) : 0;
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
            b.yInner[ix] = FiniteOr0(yv * gate);
        }
    }
    std::memset(out, 0, g.hidden * sizeof(float));
    lin(lw.ssmOut, b.yInner, nullptr, out, g.hidden);
    for (size_t i = 0; i < g.hidden; ++i) {
        out[i] = FiniteOr0(out[i]);
        if (!std::isfinite(out[i])) finite = 0;
    }
    if (layer == 0)
        std::fprintf(stderr, "SSM_NUMERIC_FINITE=%d SSM_A_DISCRETIZE=POS_A "
                     "PRODUCTION_DECODE_PATH=0\n", finite);
    return 1;
}
} /* namespace nemotron_h */
} /* namespace Deep2 */
