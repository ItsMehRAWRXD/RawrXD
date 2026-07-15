/*
 * RawrXD AVX2 Optimized Softmax
 * High-performance softmax using AVX2 intrinsics
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

/* Process 8 exp values using standard expf for accuracy */
static inline void exp8_ps(const float* x, float* result) {
    for (int i = 0; i < 8; i++) {
        result[i] = expf(x[i]);
    }
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
        float shifted_arr[8];
        _mm256_storeu_ps(shifted_arr, shifted);
        float exp_arr[8];
        exp8_ps(shifted_arr, exp_arr);
        __m256 exp_val = _mm256_loadu_ps(exp_arr);
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
    
    /* Normalize by sum */
    __m256 sum_broadcast = _mm256_set1_ps(sum);
    
    i = 0;
    for (; i <= dim - 8; i += 8) {
        __m256 vec = _mm256_loadu_ps(&output[i]);
        vec = _mm256_div_ps(vec, sum_broadcast);
        _mm256_storeu_ps(&output[i], vec);
    }
    
    /* Handle remainder */
    for (; i < dim; i++) {
        output[i] /= sum;
    }
}

/* High-resolution timer for Windows */
#ifdef _WIN32
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

/* Benchmark function */
double benchmark_softmax_avx2(int dim, int iterations) {
    float* input = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output = (float*)aligned_malloc(dim * sizeof(float), 32);
    
    if (!input || !output) {
        aligned_free(input);
        aligned_free(output);
        return 0.0;
    }
    
    /* Initialize with random values */
    for (int i = 0; i < dim; i++) {
        input[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
    }
    
    /* Warmup */
    for (int i = 0; i < 100; i++) {
        softmax_avx2(input, output, dim);
    }
    
    /* Benchmark */
    double start = get_time_ms();
    
    for (int iter = 0; iter < iterations; iter++) {
        softmax_avx2(input, output, dim);
    }
    
    double end = get_time_ms();
    double time_ms = end - start;
    
    /* Calculate M ops/sec */
    double ops = dim * 10.0 * iterations; /* approx ops per softmax */
    double mops = (ops / (time_ms / 1000.0)) / 1e6;
    
    aligned_free(input);
    aligned_free(output);
    
    return mops;
}

int main() {
    printf("RawrXD AVX2 Softmax Benchmark\n");
    printf("=============================\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* Benchmark different sizes */
    int sizes[] = {1024, 2048, 4096, 8192, 32000};
    int iterations[] = {1000, 500, 250, 100, 50};
    
    printf("Size    Iterations    M ops/s     Time (ms)\n");
    printf("-------------------------------------------\n");
    
    for (int i = 0; i < 5; i++) {
        int dim = sizes[i];
        int iter = iterations[i];
        
        double mops = benchmark_softmax_avx2(dim, iter);
        double time_ms = (dim * 10.0 * iter) / (mops * 1e6) * 1000.0;
        
        printf("%-7d %-13d %-11.2f %.2f\n", dim, iter, mops, time_ms);
    }
    
    printf("\n✓ AVX2 Softmax benchmark complete\n");
    
    return 0;
}
