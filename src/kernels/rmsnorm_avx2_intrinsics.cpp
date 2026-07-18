/**
 * @file rmsnorm_avx2_intrinsics.cpp
 * @brief RMSNorm AVX2 implementation using C++ intrinsics
 * Target: >3x speedup, <1e-5 max error
 */

#include <immintrin.h>
#include <cmath>
#include <cstddef>

extern "C" void rmsnorm_avx2_f32(const float* input, float* output, size_t n, float epsilon) {
    // Phase 1: Compute sum of squares using AVX2
    __m256 sum_vec = _mm256_setzero_ps();
    size_t i = 0;
    
    // Process 8 floats at a time
    for (; i + 8 <= n; i += 8) {
        __m256 x = _mm256_loadu_ps(&input[i]);
        sum_vec = _mm256_fmadd_ps(x, x, sum_vec);  // sum += x * x
    }
    
    // Horizontal sum of sum_vec
    __m128 sum_low = _mm256_castps256_ps128(sum_vec);
    __m128 sum_high = _mm256_extractf128_ps(sum_vec, 1);
    sum_low = _mm_add_ps(sum_low, sum_high);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    float sum_sq = _mm_cvtss_f32(sum_low);
    
    // Handle remaining elements
    for (; i < n; ++i) {
        sum_sq += input[i] * input[i];
    }
    
    // Compute RMS
    float mean = sum_sq / static_cast<float>(n);
    float rms = std::sqrt(mean + epsilon);
    float inv_rms = 1.0f / rms;
    
    // Phase 2: Normalize using AVX2
    __m256 inv_rms_vec = _mm256_set1_ps(inv_rms);
    i = 0;
    for (; i + 8 <= n; i += 8) {
        __m256 x = _mm256_loadu_ps(&input[i]);
        __m256 y = _mm256_mul_ps(x, inv_rms_vec);
        _mm256_storeu_ps(&output[i], y);
    }
    
    // Handle remaining elements
    for (; i < n; ++i) {
        output[i] = input[i] * inv_rms;
    }
}
