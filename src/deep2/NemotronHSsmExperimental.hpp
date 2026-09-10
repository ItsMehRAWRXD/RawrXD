#pragma once
/* Nemotron-H SSM experimental (ALLOW). ≠ CERT. ≤99.
   Unsafe dims → return 0 → identity scaffold. PROD_DECODE=0. */
#include "NemotronHSsmMap.hpp"
#include "lavapath/ExperimentalSsmAuth.hpp"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
namespace Deep2 {
namespace nemotron_ssm {
struct Buf {
    float* x = nullptr; float* y = nullptr; float* temp = nullptr;
    float* state = nullptr; float* conv = nullptr;
};
template <typename LinearFn>
inline int RunExperimental(size_t layer, const LayerWeights& lw, size_t hiddenDim,
                           size_t stateDim, size_t convK, const float* input,
                           float* output, Buf b, LinearFn linearW) {
    if (!SsmNemotronComplete(lw) || WtOk(lw.ssmAlpha)) return 0;
    if (!b.x || !b.temp || !b.state || !input || !output) return 0;
    const size_t outCols = lw.ssmOut.cols ? lw.ssmOut.cols : hiddenDim;
    if (outCols != hiddenDim) {
        std::fprintf(stderr,
                     "[SSM_NEMOTRON_EXP] layer=%zu DEFER_SCAFFOLD=1 "
                     "ssm_out=%zux%zu hidden=%zu PRODUCTION_DECODE_PATH=0 "
                     "SSM_CERT=NOT_CERTIFIED\n",
                     layer, lw.ssmOut.rows, outCols, hiddenDim);
        std::fflush(stderr);
        return 0;
    }
    const size_t mid = lw.ssmIn.rows ? lw.ssmIn.rows : stateDim;
    const size_t sd = stateDim < hiddenDim ? stateDim : hiddenDim;
    float* midBuf = b.temp; float* owned = nullptr;
    if (mid > hiddenDim) {
        owned = (float*)std::malloc(mid * sizeof(float));
        if (!owned) return 0;
        midBuf = owned;
    }
    std::fprintf(stderr,
                 "[SSM_NEMOTRON_EXP] layer=%zu mid=%zu sd=%zu "
                 "EXPERIMENTAL_DECODE=1 PRODUCTION_DECODE_PATH=0 "
                 "SSM_CERT=NOT_CERTIFIED\n", layer, mid, sd);
    std::fflush(stderr);
    std::memset(midBuf, 0, mid * sizeof(float));
    linearW(lw.ssmIn, input, nullptr, midBuf, mid);
    float* st = b.state + layer * stateDim;
    const float* A = lw.ssmA.data ? (const float*)lw.ssmA.data : nullptr;
    const float* dtB =
        lw.ssmDtBias.data ? (const float*)lw.ssmDtBias.data : nullptr;
    float* cSt = b.conv ? b.conv + layer * convK * hiddenDim : nullptr;
    for (size_t i = 0; i < sd; ++i) {
        float x = midBuf[i];
        if (cSt && convK) {
            for (size_t k = convK - 1; k > 0; --k)
                cSt[k * hiddenDim + i] = cSt[(k - 1) * hiddenDim + i];
            cSt[i] = x;
            if (lw.ssmConv1d.data) {
                const float* w = (const float*)lw.ssmConv1d.data;
                float sum = 0.f; const size_t ch = hiddenDim * 2;
                for (size_t k = 0; k < convK; ++k) {
                    const size_t wi = k * ch + i;
                    if (wi < lw.ssmConv1d.rows * lw.ssmConv1d.cols)
                        sum += w[wi] * cSt[k * hiddenDim + i];
                }
                x = sum;
            }
        }
        float dt = dtB ? dtB[i] : 1.f;
        if (dt <= 0.f) dt = 0.001f;
        st[i] = expf((A ? A[i] : -1.f) * dt) * st[i] + dt * x;
        b.x[i] = st[i];
    }
    for (size_t i = sd; i < hiddenDim; ++i) b.x[i] = 0.f;
    if (lw.ssmNorm.data) {
        float rms = 0.f;
        for (size_t i = 0; i < sd; ++i) rms += b.x[i] * b.x[i];
        rms = sqrtf(rms / (float)sd + 1e-6f);
        const float* nw = (const float*)lw.ssmNorm.data;
        const size_t nrm = lw.ssmNorm.rows ? lw.ssmNorm.rows : 1;
        for (size_t i = 0; i < sd; ++i) b.x[i] = b.x[i] / rms * nw[i % nrm];
    }
    std::memset(output, 0, hiddenDim * sizeof(float));
    linearW(lw.ssmOut, b.x, nullptr, output, hiddenDim);
    if (lw.ssmD.data) {
        const float* d = (const float*)lw.ssmD.data;
        for (size_t i = 0; i < sd; ++i) output[i] += d[i] * input[i];
    }
    Deep2::experimental_ssm::EmitAuthResume(stderr, 1);
    if (owned) std::free(owned);
    return 1;
}
} /* namespace nemotron_ssm */
} /* namespace Deep2 */
