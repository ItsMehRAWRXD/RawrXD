// FinalNormProduce.hpp — FinalHidden only from acquired Input+Weight.
#pragma once
#include "FinalNormAcquire.hpp"
#include "StageProof.hpp"
#include <cmath>

namespace Deep2 {
namespace FinalNorm {

inline Proof::View WeightAsProof(const View& w, size_t n) {
    Proof::View v;
    v.tensorId = "output_norm.weight";
    v.type = 0; // F32
    v.elementCount = n;
    v.byteCount = w.bytes;
    v.mapped = w.weight;
    v.acquired = w.fulfilled != 0 && w.weight != nullptr;
    return v;
}

// Produces FinalHidden, or fails naming the absent prerequisite.
inline Proof::Artifact ProduceFinalHidden(float* dst, const float* src,
                                          const View& weight, size_t n,
                                          float eps) {
    if (!src) return Proof::Fail("FinalHidden", "InputHidden");
    if (!dst) return Proof::Fail("FinalHidden", "FinalHiddenDst");
    if (n == 0) return Proof::Fail("FinalHidden", "HiddenDim");

    const Proof::View wv = WeightAsProof(weight, n);
    const char* miss = nullptr;
    if (!Proof::RequireAcquired(wv, n, 0, &miss))
        return Proof::Fail("FinalHidden", miss ? miss : "WeightView");

    if (!weight.fulfilled || !weight.weight)
        return Proof::Fail("FinalHidden", "WeightView");

    double inL2 = 0.0;
    for (size_t i = 0; i < n; ++i) inL2 += (double)src[i] * (double)src[i];
    if (inL2 < 1e-24)
        return Proof::Fail("FinalHidden", "InputHidden");

    if (!Apply(dst, src, weight, n, eps))
        return Proof::Fail("FinalHidden", "FinalNormExecute");

    Proof::View out;
    out.tensorId = "FinalHidden";
    out.type = 0;
    out.elementCount = n;
    out.byteCount = n * sizeof(float);
    out.mapped = dst;
    out.acquired = true;
    return Proof::Ok("FinalHidden", out);
}

} // namespace FinalNorm
} // namespace Deep2
