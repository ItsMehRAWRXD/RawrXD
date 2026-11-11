#pragma once
#include <cmath>
#include <cstddef>
#include <vector>
namespace Deep2 {
struct LogitsAudit {
    int finite = 1;
    int hasVariance = 0;
    float maxAbs = 0.f;
};
inline LogitsAudit AuditLogits(const float* logits, size_t n) {
    LogitsAudit a{};
    if (!logits || n == 0) { a.finite = 0; return a; }
    float mn = logits[0], mx = logits[0];
    for (size_t i = 0; i < n; ++i) {
        float v = logits[i];
        if (!std::isfinite(v)) { a.finite = 0; break; }
        float av = v < 0 ? -v : v;
        if (av > a.maxAbs) a.maxAbs = av;
        if (v < mn) mn = v;
        if (v > mx) mx = v;
    }
    a.hasVariance = (mx - mn) > 1e-6f ? 1 : 0;
    return a;
}
} // namespace Deep2
