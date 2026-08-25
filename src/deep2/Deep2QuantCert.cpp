#include "Deep2QuantCert.h"

#include <algorithm>
#include <cmath>

namespace RawrXD::Deep2 {

QuantCertResult CertifyQuantizedOutput(
    const float* reference,
    const float* actual,
    std::size_t count,
    float abs_tolerance,
    float rel_tolerance)
{
    QuantCertResult r;
    r.count = count;

    if (!reference || !actual || count == 0)
        return r;

    r.valid = true;
    r.finite = true;

    double sum_sq = 0.0;

    for (std::size_t i = 0; i < count; ++i) {
        const float a = reference[i];
        const float b = actual[i];

        if (!std::isfinite(a) || !std::isfinite(b)) {
            r.finite = false;

            if (r.first_bad == SIZE_MAX)
                r.first_bad = i;

            continue;
        }

        const float abs_error = std::fabs(a - b);

        const float scale =
            std::max(std::fabs(a), std::fabs(b));

        const float rel_error =
            scale > 1.0e-20f
                ? abs_error / scale
                : abs_error;

        r.max_abs_error =
            std::max(r.max_abs_error, abs_error);

        r.max_rel_error =
            std::max(r.max_rel_error, rel_error);

        sum_sq +=
            static_cast<double>(abs_error) *
            static_cast<double>(abs_error);

        if (abs_error > abs_tolerance &&
            rel_error > rel_tolerance &&
            r.first_bad == SIZE_MAX)
        {
            r.first_bad = i;
        }
    }

    r.rms_error = static_cast<float>(
        std::sqrt(sum_sq /
                  static_cast<double>(count)));

    r.pass =
        r.valid &&
        r.finite &&
        r.first_bad == SIZE_MAX;

    return r;
}

} // namespace RawrXD::Deep2
