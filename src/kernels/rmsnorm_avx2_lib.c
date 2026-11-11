/*
 * RawrXD AVX2 Optimized RMSNorm - Library Version
 * High-performance kernel using AVX2 intrinsics
 */

#include <immintrin.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #define aligned_malloc(size, align) _aligned_malloc(size, align)
    #define aligned_free(ptr) _aligned_free(ptr)
#else
    #include <stdlib.h>
    #define aligned_malloc(size, align) aligned_alloc(align, size)
    #define aligned_free(ptr) free(ptr)
#endif

/* Forward declaration */
void rmsnorm_avx2(const float* input, float* output, int dim, float eps);

/* Benchmark function for performance testing */
double benchmark_rmsnorm_avx2(int dim, int iterations) {
    float* input = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output = (float*)aligned_malloc(dim * sizeof(float), 32);
    
    if (!input || !output) {
        aligned_free(input);
        aligned_free(output);
        return -1.0;
    }
    
    /* Initialize with random values */
    srand(42);
    for (int i = 0; i < dim; i++) {
        input[i] = (float)rand() / RAND_MAX * 2.0f - 1.0f;
    }
    
    float eps = 1e-6f;
    
    /* Warmup */
    for (int i = 0; i < 10; i++) {
        rmsnorm_avx2(input, output, dim, eps);
    }
    
    /* Benchmark */
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        rmsnorm_avx2(input, output, dim, eps);
    }
    clock_t end = clock();
    
    double total_time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    aligned_free(input);
    aligned_free(output);
    
    return total_time_ms / iterations; /* Return time per iteration */
}

/* AVX2 optimized RMSNorm - library version (no main) */
void rmsnorm_avx2(const float* input, float* output, int dim, float eps) {
    /* Compute sum of squares using AVX2 */
    __m256 sum_vec = _mm256_setzero_ps();
    int i = 0;
    
    /* Process 8 elements at a time */
    for (; i <= dim - 8; i += 8) {
        __m256 x = _mm256_loadu_ps(&input[i]);
        sum_vec = _mm256_fmadd_ps(x, x, sum_vec);
    }
    
    /* Horizontal sum of the vector */
    __m256 hsum = _mm256_hadd_ps(sum_vec, sum_vec);
    hsum = _mm256_hadd_ps(hsum, hsum);
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, hsum);
    float sum_sq = sum_arr[0] + sum_arr[4];
    
    /* Handle remaining elements */
    for (; i < dim; i++) {
        sum_sq += input[i] * input[i];
    }
    
    /* Compute RMS and inverse RMS */
    float rms = sqrtf(sum_sq / dim + eps);
    float inv_rms = 1.0f / rms;
    __m256 inv_rms_vec = _mm256_set1_ps(inv_rms);
    
    /* Normalize using AVX2 */
    i = 0;
    for (; i <= dim - 8; i += 8) {
        __m256 x = _mm256_loadu_ps(&input[i]);
        __m256 result = _mm256_mul_ps(x, inv_rms_vec);
        _mm256_storeu_ps(&output[i], result);
    }
    
    /* Handle remaining elements */
    for (; i < dim; i++) {
        output[i] = input[i] * inv_rms;
    }
}
