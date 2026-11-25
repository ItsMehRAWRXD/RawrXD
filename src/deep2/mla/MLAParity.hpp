#pragma once
#include <cmath>
#include <cstddef>
#include <algorithm>
namespace rawrxd::mla {
struct Parity {
    bool finite = false;
    bool argmaxMatch = false;
    double cosine = 0.0;
    double rms = 0.0;
    double maxAbs = 0.0;
    double relativeL2 = 0.0;
};
inline Parity compare(const float* reference, const float* actual, size_t count) {
    Parity p;
    if (!reference || !actual || !count) return p;
    double dot = 0.0, aa = 0.0, bb = 0.0, error = 0.0;
    size_t argA = 0, argB = 0;
    for (size_t i = 0; i < count; ++i) {
        const double a = reference[i], b = actual[i];
        if (!std::isfinite(a) || !std::isfinite(b)) return p;
        const double d = a - b;
        dot += a * b; aa += a * a; bb += b * b; error += d * d;
        p.maxAbs = std::max(p.maxAbs, std::abs(d));
        if (reference[i] > reference[argA]) argA = i;
        if (actual[i] > actual[argB]) argB = i;
    }
    if (aa <= 0.0 || bb <= 0.0) return p;
    p.cosine = std::clamp(dot / (std::sqrt(aa) * std::sqrt(bb)), -1.0, 1.0);
    p.rms = std::sqrt(error / double(count));
    p.relativeL2 = std::sqrt(error / aa);
    p.finite = std::isfinite(p.cosine) && std::isfinite(p.rms) && std::isfinite(p.relativeL2);
    p.argmaxMatch = argA == argB;
    return p;
}
}