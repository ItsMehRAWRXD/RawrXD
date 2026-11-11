#include "tensor_compare.hpp"
#include <cmath>
#include <cstdio>
#include <immintrin.h>

namespace rawrxd {
namespace validation {

TensorComparison compareTensor(
    const float* expected,
    const float* actual,
    size_t count,
    float tolerance)
{
    TensorComparison result{};
    result.max_error = 0.0f;
    result.mean_error = 0.0f;
    result.mismatch_count = 0;
    result.passed = true;

    float total_error = 0.0f;

    for (size_t i = 0; i < count; i++) {
        float err = std::fabs(expected[i] - actual[i]);
        total_error += err;
        
        if (err > result.max_error) {
            result.max_error = err;
        }
        
        if (err > tolerance) {
            result.mismatch_count++;
        }
    }

    result.mean_error = total_error / count;
    result.passed = (result.max_error <= tolerance) && (result.mismatch_count == 0);

    return result;
}

TensorComparison compareTensorRelaxed(
    const float* expected,
    const float* actual,
    size_t count,
    float abs_tolerance,
    float rel_tolerance)
{
    TensorComparison result{};
    result.max_error = 0.0f;
    result.mean_error = 0.0f;
    result.mismatch_count = 0;
    result.passed = true;

    float total_error = 0.0f;

    for (size_t i = 0; i < count; i++) {
        float abs_err = std::fabs(expected[i] - actual[i]);
        float rel_err = abs_err / (std::fabs(expected[i]) + 1e-8f);
        
        total_error += abs_err;
        
        if (abs_err > result.max_error) {
            result.max_error = abs_err;
        }
        
        // Mismatch if both absolute and relative exceed thresholds
        if (abs_err > abs_tolerance && rel_err > rel_tolerance) {
            result.mismatch_count++;
        }
    }

    result.mean_error = total_error / count;
    result.passed = (result.mismatch_count == 0);

    return result;
}

TensorComparison compareTensorAVX512(
    const float* expected,
    const float* actual,
    size_t count,
    float tolerance)
{
    TensorComparison result{};
    result.max_error = 0.0f;
    result.mean_error = 0.0f;
    result.mismatch_count = 0;
    result.passed = true;

    const __m512 vtolerance = _mm512_set1_ps(tolerance);
    __m512 vmax_error = _mm512_setzero_ps();
    __m512 vsum_error = _mm512_setzero_ps();
    __m512i vmismatch = _mm512_setzero_si512();

    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= count; i += 16) {
        __m512 vexp = _mm512_loadu_ps(&expected[i]);
        __m512 vact = _mm512_loadu_ps(&actual[i]);
        
        // Compute absolute error
        __m512 vdiff = _mm512_sub_ps(vexp, vact);
        __m512 vabs = _mm512_abs_ps(vdiff);
        
        // Update max error
        vmax_error = _mm512_max_ps(vmax_error, vabs);
        
        // Update sum
        vsum_error = _mm512_add_ps(vsum_error, vabs);
        
        // Check tolerance
        __mmask16 mask = _mm512_cmp_ps_mask(vabs, vtolerance, _CMP_GT_OQ);
        vmismatch = _mm512_add_epi32(vmismatch, _mm512_maskz_set1_epi32(mask, 1));
    }

    // Horizontal reduction
    float max_vals[16];
    _mm512_storeu_ps(max_vals, vmax_error);
    for (int j = 0; j < 16; j++) {
        if (max_vals[j] > result.max_error) {
            result.max_error = max_vals[j];
        }
    }

    float sum_vals[16];
    _mm512_storeu_ps(sum_vals, vsum_error);
    for (int j = 0; j < 16; j++) {
        result.mean_error += sum_vals[j];
    }

    int mismatch_vals[16];
    _mm512_storeu_si512((__m512i*)mismatch_vals, vmismatch);
    for (int j = 0; j < 16; j++) {
        result.mismatch_count += mismatch_vals[j];
    }

    // Process remaining elements
    for (; i < count; i++) {
        float err = std::fabs(expected[i] - actual[i]);
        result.mean_error += err;
        
        if (err > result.max_error) {
            result.max_error = err;
        }
        
        if (err > tolerance) {
            result.mismatch_count++;
        }
    }

    result.mean_error /= count;
    result.passed = (result.max_error <= tolerance) && (result.mismatch_count == 0);

    return result;
}

} // namespace validation
} // namespace rawrxd
