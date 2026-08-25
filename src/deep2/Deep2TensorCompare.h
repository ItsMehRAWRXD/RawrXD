#pragma once

#include <cstddef>
#include <cmath>
#include <cstdint>
#include <limits>

namespace RawrXD::Deep2 {

struct TensorCompareResult {
    bool pass = false;

    size_t count = 0;
    size_t first_bad = SIZE_MAX;
    size_t nonfinite_a = 0;
    size_t nonfinite_b = 0;

    float max_abs = 0.0f;
    float max_rel = 0.0f;
    float rms = 0.0f;

    float a_at_max = 0.0f;
    float b_at_max = 0.0f;
};

inline TensorCompareResult CompareTensor(
    const float* a,
    const float* b,
    size_t n,
    float abs_tol = 1e-4f,
    float rel_tol = 1e-3f)
{
    TensorCompareResult r;
    r.count = n;

    double sumsq = 0.0;

    for (size_t i = 0; i < n; ++i) {
        const float av = a[i];
        const float bv = b[i];

        if (!std::isfinite(av))
            ++r.nonfinite_a;

        if (!std::isfinite(bv))
            ++r.nonfinite_b;

        if (!std::isfinite(av) ||
            !std::isfinite(bv)) {
            if (r.first_bad == SIZE_MAX)
                r.first_bad = i;
            continue;
        }

        const float abs_err =
            std::fabs(av - bv);

        const float denom =
            std::max(std::fabs(av),
                     std::fabs(bv));

        const float rel_err =
            denom > 1e-20f
                ? abs_err / denom
                : abs_err;

        if (abs_err > r.max_abs) {
            r.max_abs = abs_err;
            r.a_at_max = av;
            r.b_at_max = bv;
        }

        r.max_rel =
            std::max(r.max_rel, rel_err);

        sumsq +=
            (double)abs_err *
            (double)abs_err;

        if (abs_err > abs_tol &&
            rel_err > rel_tol &&
            r.first_bad == SIZE_MAX)
            r.first_bad = i;
    }

    r.rms =
        n
            ? (float)std::sqrt(sumsq / (double)n)
            : 0.0f;

    r.pass =
        r.nonfinite_a == 0 &&
        r.nonfinite_b == 0 &&
        r.first_bad == SIZE_MAX;

    return r;
}

}
