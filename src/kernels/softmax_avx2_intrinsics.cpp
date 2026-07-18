/**
 * @file softmax_avx2_intrinsics.cpp
 * @brief Softmax AVX2 implementation using C++ intrinsics
 * Target: >2x speedup, sum=1.0, no NaN
 */

#include <immintrin.h>
#include <cmath>
#include <cstddef>
#include <algorithm>

extern "C" void softmax_avx2_f32(const float* input, float* output, size_t n) {
    if (n == 0) return;
    
    // Phase 1: Find max value using AVX2
    __m256 max_vec = _mm256_set1_ps(input[0]);
    size_t i = 0;
    
    for (; i + 8 <= n; i += 8) {
        __m256 x = _mm256_loadu_ps(&input[i]);
        max_vec = _mm256_max_ps(max_vec, x);
    }
    
    // Horizontal max
    __m128 max_low = _mm256_castps256_ps128(max_vec);
    __m128 max_high = _mm256_extractf128_ps(max_vec, 1);
    max_low = _mm_max_ps(max_low, max_high);
    max_low = _mm_max_ps(max_low, _mm_movehl_ps(max_low, max_low));
    max_low = _mm_max_ps(max_low, _mm_shuffle_ps(max_low, max_low, 1));
    float max_val = _mm_cvtss_f32(max_low);
    
    // Handle remaining elements
    for (; i < n; ++i) {
        max_val = std::max(max_val, input[i]);
    }
    
    // Phase 2: Compute exp(x - max) and sum using AVX2
    __m256 max_vec_broadcast = _mm256_set1_ps(max_val);
    __m256 sum_vec = _mm256_setzero_ps();
    i = 0;
    
    for (; i + 8 <= n; i += 8) {
        __m256 x = _mm256_loadu_ps(&input[i]);
        __m256 diff = _mm256_sub_ps(x, max_vec_broadcast);
        
        // Clamp to avoid overflow
        __m256 clamped = _mm256_min_ps(diff, _mm256_set1_ps(88.0f));
        clamped = _mm256_max_ps(clamped, _mm256_set1_ps(-88.0f));
        
        // exp approximation using polynomial
        // exp(x) ≈ 1 + x + x^2/2 + x^3/6 + x^4/24 + x^5/120 + x^6/720
        __m256 x2 = _mm256_mul_ps(clamped, clamped);
        __m256 x3 = _mm256_mul_ps(x2, clamped);
        __m256 x4 = _mm256_mul_ps(x3, clamped);
        __m256 x5 = _mm256_mul_ps(x4, clamped);
        __m256 x6 = _mm256_mul_ps(x5, clamped);
        
        __m256 term0 = _mm256_set1_ps(1.0f);
        __m256 term1 = clamped;
        __m256 term2 = _mm256_mul_ps(x2, _mm256_set1_ps(0.5f));
        __m256 term3 = _mm256_mul_ps(x3, _mm256_set1_ps(0.16666667f));
        __m256 term4 = _mm256_mul_ps(x4, _mm256_set1_ps(0.04166667f));
        __m256 term5 = _mm256_mul_ps(x5, _mm256_set1_ps(0.00833333f));
        __m256 term6 = _mm256_mul_ps(x6, _mm256_set1_ps(0.00138889f));
        
        __m256 exp_val = term0;
        exp_val = _mm256_add_ps(exp_val, term1);
        exp_val = _mm256_add_ps(exp_val, term2);
        exp_val = _mm256_add_ps(exp_val, term3);
        exp_val = _mm256_add_ps(exp_val, term4);
        exp_val = _mm256_add_ps(exp_val, term5);
        exp_val = _mm256_add_ps(exp_val, term6);
        
        sum_vec = _mm256_add_ps(sum_vec, exp_val);
        _mm256_storeu_ps(&output[i], exp_val);
    }
    
    // Horizontal sum
    __m128 sum_low = _mm256_castps256_ps128(sum_vec);
    __m128 sum_high = _mm256_extractf128_ps(sum_vec, 1);
    sum_low = _mm_add_ps(sum_low, sum_high);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    sum_low = _mm_hadd_ps(sum_low, sum_low);
    float sum = _mm_cvtss_f32(sum_low);
    
    // Handle remaining elements (scalar)
    for (; i < n; ++i) {
        float diff = input[i] - max_val;
        diff = std::min(diff, 88.0f);
        diff = std::max(diff, -88.0f);
        
        float x2 = diff * diff;
        float x3 = x2 * diff;
        float x4 = x3 * diff;
        float x5 = x4 * diff;
        float x6 = x5 * diff;
        
        float exp_val = 1.0f + diff + x2 * 0.5f + x3 * 0.16666667f + 
                        x4 * 0.04166667f + x5 * 0.00833333f + x6 * 0.00138889f;
        
        sum += exp_val;
        output[i] = exp_val;
    }
    
    // Phase 3: Normalize using AVX2
    __m256 inv_sum_vec = _mm256_set1_ps(1.0f / sum);
    i = 0;
    for (; i + 8 <= n; i += 8) {
        __m256 x = _mm256_loadu_ps(&output[i]);
        __m256 y = _mm256_mul_ps(x, inv_sum_vec);
        _mm256_storeu_ps(&output[i], y);
    }
    
    // Handle remaining elements
    float inv_sum = 1.0f / sum;
    for (; i < n; ++i) {
        output[i] *= inv_sum;
    }
}
