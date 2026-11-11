#pragma once

#include <cstddef>
#include <vector>
#include <string>

namespace rawrxd {
namespace validation {

struct TensorComparison {
    float max_error;
    float mean_error;
    size_t mismatch_count;
    bool passed;
    
    std::string toString() const {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "max_error=%.9f, mean_error=%.9f, mismatches=%zu, %s",
            max_error, mean_error, mismatch_count,
            passed ? "PASS" : "FAIL");
        return std::string(buf);
    }
};

/**
 * Compare two tensors element-wise
 * @param expected Reference tensor data
 * @param actual Tensor data to validate
 * @param count Number of elements
 * @param tolerance Maximum acceptable error
 * @return Comparison results
 */
TensorComparison compareTensor(
    const float* expected,
    const float* actual,
    size_t count,
    float tolerance = 1e-5f
);

/**
 * Compare tensors with relative error tolerance
 * Useful for comparing across different quantization formats
 */
TensorComparison compareTensorRelaxed(
    const float* expected,
    const float* actual,
    size_t count,
    float abs_tolerance = 1e-5f,
    float rel_tolerance = 1e-4f
);

/**
 * AVX-512 accelerated tensor comparison
 * Processes 16 elements per iteration
 */
TensorComparison compareTensorAVX512(
    const float* expected,
    const float* actual,
    size_t count,
    float tolerance = 1e-5f
);

} // namespace validation
} // namespace rawrxd
