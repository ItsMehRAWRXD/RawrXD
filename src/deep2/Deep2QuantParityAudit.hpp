#pragma once
#include <cmath>
#include <cstddef>
namespace Deep2 {
struct QuantParityAudit {
    int ok = 0;
    float maxAbsDiff = 0.f;
    int firstSignificantIndex = -1; // first |a-b| > tol; -1 if none
    int fnvDiffOnly = 0;            // set by caller if FNV differs but ok==1
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
        if (r.firstSignificantIndex < 0 && d > tol)
            r.firstSignificantIndex = static_cast<int>(i);
    }
    r.maxAbsDiff = mx;
    r.ok = mx <= tol ? 1 : 0;
    return r;
}
} // namespace Deep2
