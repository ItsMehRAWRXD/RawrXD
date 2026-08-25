#pragma once

#include <cstddef>
#include <cstdint>

namespace RawrXD::Deep2 {

struct QuantCertResult {
    bool valid = false;
    bool finite = false;
    bool pass = false;

    std::size_t count = 0;
    std::size_t first_bad = SIZE_MAX;

    float max_abs_error = 0.0f;
    float max_rel_error = 0.0f;
    float rms_error = 0.0f;
};

QuantCertResult CertifyQuantizedOutput(
    const float* reference,
    const float* actual,
    std::size_t count,
    float abs_tolerance = 1.0e-4f,
    float rel_tolerance = 1.0e-3f);

} // namespace RawrXD::Deep2

