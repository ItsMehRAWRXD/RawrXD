#pragma once
/* Arm Nemotron-H Mamba2 scratch (experimental). ≤99.
   PRODUCTION_DECODE_PATH stays 0 until SSM_CERT. */
#include "NemotronHGeometry.hpp"
#include <cstdio>
#include <cstring>
namespace Deep2 {
namespace nemotron_h {
struct Arm {
    float* proj = nullptr;
    float* yInner = nullptr;
    float* state = nullptr;
    float* conv = nullptr;
    Geo g{};
    size_t layers = 0;
    int armed = 0;
};
template <typename FreeFn>
inline void FreeArm(Arm& a, FreeFn freeFn) {
    if (a.proj) freeFn(a.proj);
    if (a.yInner) freeFn(a.yInner);
    if (a.state) freeFn(a.state);
    if (a.conv) freeFn(a.conv);
    a = Arm{};
}
template <typename AllocFn, typename FreeFn>
inline int TryArm(Arm& a, const LayerWeights& lw, size_t hidden, size_t layers,
                  AllocFn alloc, FreeFn freeFn) {
    FreeArm(a, freeFn);
    a.g = ResolveFromLayer(lw, hidden);
    a.layers = layers;
    Emit(stderr, a.g);
    if (!a.g.ok || !hidden || !layers) {
        std::fprintf(stderr,
                     "SSM_MAMBA2_ARM=0 reason=GEO_OR_DIM "
                     "PRODUCTION_DECODE_PATH=0\n");
        return 0;
    }
    const size_t stN = layers * a.g.ssmInner * a.g.ssmState;
    const size_t cvN = layers * a.g.ssmConvDim * a.g.ssmConvK;
    a.proj = alloc(a.g.ssmInRows);
    a.yInner = alloc(a.g.ssmInner);
    a.state = alloc(stN);
    a.conv = alloc(cvN);
    if (!a.proj || !a.yInner || !a.state || !a.conv) {
        FreeArm(a, freeFn);
        std::fprintf(stderr, "SSM_MAMBA2_ARM=0 reason=ALLOC\n");
        return 0;
    }
    std::memset(a.state, 0, stN * sizeof(float));
    std::memset(a.conv, 0, cvN * sizeof(float));
    a.armed = 1;
    std::fprintf(stderr,
                 "SSM_MAMBA2_ARM=1 layers=%zu state_elems=%zu "
                 "PRODUCTION_DECODE_PATH=0 SSM_CERT=NOT_CERTIFIED\n",
                 layers, stN);
    return 1;
}
} /* namespace nemotron_h */
} /* namespace Deep2 */
