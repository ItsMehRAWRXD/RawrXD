/*
 * RawrXD AVX2 Optimized RMSNorm
 * High-performance RMS normalization using AVX2 intrinsics
 */

#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
    #include <windows.h>
    #define aligned_malloc(size, align) _aligned_malloc(size, align)
    #define aligned_free(ptr) _aligned_free(ptr)
#else
    #define aligned_malloc(size, align) aligned_alloc(align, size)
    #define aligned_free(ptr) free(ptr)
#endif

/* Fast reciprocal square root using AVX2 */
static inline float fast_rsqrt(float x) {
    /* Use SSE rsqrt as approximation, then Newton-Raphson iteration */
    __m128 x_vec = _mm_set_ss(x);
    __m128 rsqrt = _mm_rsqrt_ss(x_vec);
    
    /* One Newton-Raphson iteration for accuracy */
    /* rsqrt = rsqrt * (1.5 - (x * 0.5) * rsqrt * rsqrt) */
    __m128 half = _mm_set_ss(0.5f);
    __m128 three_half = _mm_set_ss(1.5f);
    __m128 x_half = _mm_mul_ss(x_vec, half);
    __m128 rsqrt_sq = _mm_mul_ss(rsqrt, rsqrt);
    __m128 term = _mm_mul_ss(x_half, rsqrt_sq);
    __m128 correction = _mm_sub_ss(three_half, term);
    rsqrt = _mm_mul_ss(rsqrt, correction);
    
    float result;
    _mm_store_ss(&result, rsqrt);
    return result;
}

/* AVX2 RMSNorm - compute RMS, then normalize */
void rmsnorm_avx2(const float* input, float* output, int dim, float eps) {
    /* Compute sum of squares using AVX2 */
    __m256 sum_vec = _mm256_setzero_ps();
    int i = 0;
    
    for (; i <= dim - 8; i += 8) {
        __m256 vec = _mm256_loadu_ps(&input[i]);
        sum_vec = _mm256_fmadd_ps(vec, vec, sum_vec);
    }
    
    /* Reduce sum_vec to scalar */
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_vec);
    float sum_sq = 0.0f;
    for (int j = 0; j < 8; j++) {
        sum_sq += sum_arr[j];
    }
    
    /* Handle remainder */
    for (; i < dim; i++) {
        sum_sq += input[i] * input[i];
    }
    
    /* Compute RMS */
    float rms = sqrtf(sum_sq / dim + eps);
    float inv_rms = 1.0f / rms;
    
    /* Normalize using AVX2 */
    __m256 inv_rms_vec = _mm256_set1_ps(inv_rms);
    
    i = 0;
    for (; i <= dim - 8; i += 8) {
        __m256 vec = _mm256_loadu_ps(&input[i]);
        __m256 result = _mm256_mul_ps(vec, inv_rms_vec);
        _mm256_storeu_ps(&output[i], result);
    }
    
    /* Handle remainder */
    for (; i < dim; i++) {
        output[i] = input[i] * inv_rms;
    }
}

/* High-resolution timer for Windows */
#ifdef _WIN32
    #include <windows.h>
    static inline double get_time_ms() {
        LARGE_INTEGER freq, count;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&count);
        return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
    }
#else
    #include <time.h>
    static inline double get_time_ms() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
    }
#endif

/* Benchmark function - only compiled for standalone benchmark */
#ifdef RMSNORM_AVX2_STANDALONE_BENCHMARK
double benchmark_rmsnorm_avx2(int dim, int iterations) {
    float* input = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output = (float*)aligned_malloc(dim * sizeof(float), 32);
    
    if (!input || !output) {
        aligned_free(input);
        aligned_free(output);
        return 0.0;
    }
    
    /* Initialize */
    for (int i = 0; i < dim; i++) {
        input[i] = (float)rand() / RAND_MAX;
    }
    
    float eps = 1e-6f;
    
    /* Warmup */
    for (int i = 0; i < 100; i++) {
        rmsnorm_avx2(input, output, dim, eps);
    }
    
    /* Benchmark */
    double start = get_time_ms();
    
    for (int iter = 0; iter < iterations; iter++) {
        rmsnorm_avx2(input, output, dim, eps);
    }
    
    double end = get_time_ms();
    double time_ms = end - start;
    
    /* Calculate M ops/sec */
    double ops = dim * 4.0 * iterations; /* approx ops per rmsnorm */
    double mops = (ops / (time_ms / 1000.0)) / 1e6;
    
    aligned_free(input);
    aligned_free(output);
    
    return mops;
}

int main() {
    printf("RawrXD AVX2 RMSNorm Benchmark\n");
    printf("=============================\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* Benchmark different sizes */
    int sizes[] = {1024, 2048, 4096, 8192};
    int iterations[] = {1000, 500, 250, 100};
    
    printf("Size    Iterations    M ops/s     Time (ms)\n");
    printf("-------------------------------------------\n");
    
    for (int i = 0; i < 4; i++) {
        int dim = sizes[i];
        int iter = iterations[i];
        
        double mops = benchmark_rmsnorm_avx2(dim, iter);
        double time_ms = (dim * 4.0 * iter) / (mops * 1e6) * 1000.0;
        
        printf("%-7d %-13d %-11.2f %.2f\n", dim, iter, mops, time_ms);
    }
    
    printf("\n✓ AVX2 RMSNorm benchmark complete\n");
    
    return 0;
}
#endif /* RMSNORM_AVX2_STANDALONE_BENCHMARK */
