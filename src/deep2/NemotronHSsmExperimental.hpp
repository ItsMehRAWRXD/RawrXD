#pragma once
/* Nemotron-H SSM experimental scan (ALLOW + SCAN). ≠ CERT. ≤99.
   ssm_in:17504x3136  ssm_out:3136x7680 → d_inner=cols, out rows=hidden.
   DEFER on outCols!=hidden was WRONG (cols is in_proj width). */
#include "NemotronHSsmMap.hpp"
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
                           size_t stateDim, size_t /*convK*/, const float* input,
                           float* output, Buf b, LinearFn linearW) {
    if (!SsmNemotronComplete(lw) || WtOk(lw.ssmAlpha)) return 0;
    if (!b.state || !input || !output) return 0;
    const char* scan = std::getenv("RAWRXD_DEEP2_NEMOTRON_SSM_SCAN");
    if (!scan || (scan[0] != '1' && scan[0] != 'y' && scan[0] != 'Y')) return 0;
    if (lw.ssmIn.cols && lw.ssmIn.cols != hiddenDim) return 0;
    if (lw.ssmOut.rows != hiddenDim) return 0;
    const size_t mid = lw.ssmIn.rows;
    const size_t dIn = lw.ssmOut.cols;
    const size_t sd = stateDim < 96ull ? stateDim : 96ull;
    if (!mid || !dIn) return 0;
    float* midBuf = (float*)std::malloc(mid * sizeof(float));
    float* xin = (float*)std::malloc(dIn * sizeof(float));
    if (!midBuf || !xin) { std::free(midBuf); std::free(xin); return 0; }
    std::fprintf(stderr,
                 "[SSM_NEMOTRON_EXP] layer=%zu mid=%zu d_inner=%zu sd=%zu "
                 "EXPERIMENTAL_DECODE=1 PRODUCTION_DECODE_PATH=0 "
                 "SSM_CERT=NOT_CERTIFIED\n",
                 layer, mid, dIn, sd);
    std::fflush(stderr);
    std::memset(midBuf, 0, mid * sizeof(float));
    linearW(lw.ssmIn, input, nullptr, midBuf, mid);
    std::memset(xin, 0, dIn * sizeof(float));
    std::memcpy(xin, midBuf, (dIn < mid ? dIn : mid) * sizeof(float));
    float* st = b.state + layer * stateDim;
    const float* A = lw.ssmA.data ? (const float*)lw.ssmA.data : nullptr;
    const float* dtB =
        lw.ssmDtBias.data ? (const float*)lw.ssmDtBias.data : nullptr;
    for (size_t i = 0; i < sd; ++i) {
        float x = xin[i];
        float dt = dtB ? dtB[i] : 1.f;
        if (dt <= 0.f) dt = 0.001f;
        st[i] = expf((A ? A[i] : -1.f) * dt) * st[i] + dt * x;
        xin[i] = st[i];
    }
    std::memset(output, 0, hiddenDim * sizeof(float));
    linearW(lw.ssmOut, xin, nullptr, output, hiddenDim);
    if (lw.ssmD.data) {
        const float* d = (const float*)lw.ssmD.data;
        for (size_t i = 0; i < sd && i < hiddenDim; ++i)
            output[i] += d[i] * input[i];
    }
    std::free(midBuf);
    std::free(xin);
    (void)b;
    return 1;
}
} /* namespace nemotron_ssm */
} /* namespace Deep2 */
