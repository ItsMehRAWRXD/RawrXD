#pragma once
#include <cmath>
#include <cstddef>
namespace Deep2 {
struct QuantParityAudit {
    int ok = 0;
    float maxAbsDiff = 0.f;
};
inline QuantParityAudit AuditQuantParity(const float* a, const float* b,
                                         size_t n, float tol = 1e-2f) {
    QuantParityAudit r{};
    if (!a || !b || !n) return r;
    float mx = 0.f;
    for (size_t i = 0; i < n; ++i) {
        float d = a[i] - b[i];
        if (d < 0) d = -d;
        if (d > mx) mx = d;
    }
    r.maxAbsDiff = mx;
    r.ok = mx <= tol ? 1 : 0;
    return r;
}
} // namespace Deep2
