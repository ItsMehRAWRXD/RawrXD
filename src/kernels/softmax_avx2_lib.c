/*
 * RawrXD AVX2 Optimized Softmax (Library Version)
 * High-performance softmax using AVX2 intrinsics
 */

#include <immintrin.h>
#include <math.h>

/* Fast approximate exp using polynomial approximation */
static inline __m256 fast_exp_ps(__m256 x) {
    /* Clamp to avoid overflow/underflow */
    __m256 max_val = _mm256_set1_ps(88.0f);
    __m256 min_val = _mm256_set1_ps(-88.0f);
    x = _mm256_max_ps(x, min_val);
    x = _mm256_min_ps(x, max_val);
    
    /* Coefficients for exp(x) approximation */
    const float c1 = 1.0f / 120.0f;
    const float c2 = 1.0f / 24.0f;
    const float c3 = 1.0f / 6.0f;
    const float c4 = 1.0f / 2.0f;
    const float c5 = 1.0f;
    
    __m256 c1_vec = _mm256_set1_ps(c1);
    __m256 c2_vec = _mm256_set1_ps(c2);
    __m256 c3_vec = _mm256_set1_ps(c3);
    __m256 c4_vec = _mm256_set1_ps(c4);
    __m256 c5_vec = _mm256_set1_ps(c5);
    __m256 one = _mm256_set1_ps(1.0f);
    
    /* Taylor series: 1 + x + x^2/2! + x^3/3! + x^4/4! + x^5/5! */
    __m256 x2 = _mm256_mul_ps(x, x);
    __m256 x3 = _mm256_mul_ps(x2, x);
    __m256 x4 = _mm256_mul_ps(x3, x);
    __m256 x5 = _mm256_mul_ps(x4, x);
    
    __m256 result = one;
    result = _mm256_add_ps(result, _mm256_mul_ps(x, c5_vec));
    result = _mm256_add_ps(result, _mm256_mul_ps(x2, c4_vec));
    result = _mm256_add_ps(result, _mm256_mul_ps(x3, c3_vec));
    result = _mm256_add_ps(result, _mm256_mul_ps(x4, c2_vec));
    result = _mm256_add_ps(result, _mm256_mul_ps(x5, c1_vec));
    
    return result;
}

/* AVX2 softmax - find max, subtract, exp, normalize */
void softmax_avx2(const float* input, float* output, int dim) {
    /* Find max for numerical stability */
    float max_val = input[0];
    
    /* Process 8 elements at a time for max */
    int i = 0;
    if (dim >= 8) {
        __m256 max_vec = _mm256_loadu_ps(&input[0]);
        
        for (i = 8; i <= dim - 8; i += 8) {
            __m256 vec = _mm256_loadu_ps(&input[i]);
            max_vec = _mm256_max_ps(max_vec, vec);
        }
        
        /* Reduce max_vec to scalar */
        float max_arr[8];
        _mm256_storeu_ps(max_arr, max_vec);
        for (int j = 0; j < 8; j++) {
            if (max_arr[j] > max_val) max_val = max_arr[j];
        }
    }
    
    /* Handle remainder for max */
    for (; i < dim; i++) {
        if (input[i] > max_val) max_val = input[i];
    }
    
    /* Compute exp(x - max) and sum using AVX2 */
    __m256 max_broadcast = _mm256_set1_ps(max_val);
    __m256 sum_vec = _mm256_setzero_ps();
    
    /* Process 8 elements at a time for exp and sum */
    i = 0;
    for (; i <= dim - 8; i += 8) {
        __m256 vec = _mm256_loadu_ps(&input[i]);
        __m256 shifted = _mm256_sub_ps(vec, max_broadcast);
        __m256 exp_val = fast_exp_ps(shifted);
        _mm256_storeu_ps(&output[i], exp_val);
        sum_vec = _mm256_add_ps(sum_vec, exp_val);
    }
    
    /* Reduce sum_vec to scalar */
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_vec);
    float sum = 0.0f;
    for (int j = 0; j < 8; j++) {
        sum += sum_arr[j];
    }
    
    /* Handle remainder */
    for (; i < dim; i++) {
        float exp_val = expf(input[i] - max_val);
        output[i] = exp_val;
        sum += exp_val;
    }
    
    /* Normalize by sum using AVX2 */
    __m256 sum_inv_vec = _mm256_set1_ps(1.0f / sum);
    i = 0;
    for (; i <= dim - 8; i += 8) {
        __m256 vec = _mm256_loadu_ps(&output[i]);
        vec = _mm256_mul_ps(vec, sum_inv_vec);
        _mm256_storeu_ps(&output[i], vec);
    }
    
    /* Handle remainder */
    float sum_inv = 1.0f / sum;
    for (; i < dim; i++) {
        output[i] *= sum_inv;
    }
}
