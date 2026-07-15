/*
 * RawrXD Validation Framework
 * Kernel Test: Softmax with AVX2 optimization
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <immintrin.h>

#define TEST_NAME "Softmax"
#define DIM 32000

typedef float f32;

void softmax_ref(const f32* x, f32* out, int n) {
    /* Find max for numerical stability */
    f32 max_val = x[0];
    for (int i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    /* Compute exp(x - max) and sum */
    f32 sum = 0.0f;
    for (int i = 0; i < n; i++) {
        out[i] = expf(x[i] - max_val);
        sum += out[i];
    }
    
    /* Normalize */
    f32 inv_sum = 1.0f / sum;
    for (int i = 0; i < n; i++) {
        out[i] *= inv_sum;
    }
}

void softmax_opt(const f32* x, f32* out, int n) {
    /* AVX2 optimized softmax with numerical stability */
    if (n < 8) {
        softmax_ref(x, out, n);
        return;
    }
    
    /* Phase 1: Find max for numerical stability using AVX2 */
    __m256 vmax = _mm256_loadu_ps(x);
    int i = 8;
    for (; i + 8 <= n; i += 8) {
        __m256 v = _mm256_loadu_ps(x + i);
        vmax = _mm256_max_ps(vmax, v);
    }
    
    /* Horizontal max reduction */
    __m256 vmax_perm = _mm256_permute2f128_ps(vmax, vmax, 1);
    __m256 vmax_max = _mm256_max_ps(vmax, vmax_perm);
    vmax_max = _mm256_max_ps(vmax_max, _mm256_shuffle_ps(vmax_max, vmax_max, 0x4E));
    vmax_max = _mm256_max_ps(vmax_max, _mm256_shuffle_ps(vmax_max, vmax_max, 0xB1));
    float max_val = _mm_cvtss_f32(_mm256_castps256_ps128(vmax_max));
    
    /* Process remaining elements */
    for (; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    /* Phase 2: Compute exp(x - max) and sum using AVX2 */
    __m256 v_max_broadcast = _mm256_set1_ps(max_val);
    __m256 vsum = _mm256_setzero_ps();
    i = 0;
    
    for (; i + 8 <= n; i += 8) {
        __m256 v = _mm256_loadu_ps(x + i);
        v = _mm256_sub_ps(v, v_max_broadcast);
        /* Store intermediate for scalar exp */
        _mm256_storeu_ps(out + i, v);
    }
    
    /* Process remaining elements */
    for (; i < n; i++) {
        out[i] = x[i] - max_val;
    }
    
    /* Scalar exp for accuracy */
    float sum = 0.0f;
    for (int j = 0; j < n; j++) {
        out[j] = expf(out[j]);
        sum += out[j];
    }
    
    /* Phase 3: Normalize using AVX2 */
    __m256 vinv_sum = _mm256_set1_ps(1.0f / sum);
    i = 0;
    for (; i + 8 <= n; i += 8) {
        __m256 v = _mm256_loadu_ps(out + i);
        v = _mm256_mul_ps(v, vinv_sum);
        _mm256_storeu_ps(out + i, v);
    }
    
    /* Process remaining elements */
    for (; i < n; i++) {
        out[i] /= sum;
    }
}

f32 compute_max_error(const f32* ref, const f32* opt, int n) {
    f32 max_err = 0.0f;
    for (int i = 0; i < n; i++) {
        f32 err = fabsf(ref[i] - opt[i]);
        if (err > max_err) max_err = err;
    }
    return max_err;
}

static inline double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    
    f32* input = malloc(DIM * sizeof(f32));
    f32* ref_output = malloc(DIM * sizeof(f32));
    f32* opt_output = malloc(DIM * sizeof(f32));
    
    if (!input || !ref_output || !opt_output) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    /* Test with logits */
    for (int i = 0; i < DIM; i++) {
        input[i] = (f32)(i % 10) - 5.0f;
    }
    
    /* Warmup */
    for (int i = 0; i < 10; i++) {
        softmax_ref(input, ref_output, DIM);
        softmax_opt(input, opt_output, DIM);
    }
    
    /* Benchmark reference */
    double t0 = get_time_ms();
    for (int i = 0; i < 100; i++) {
        softmax_ref(input, ref_output, DIM);
    }
    double ref_time = get_time_ms() - t0;
    
    /* Benchmark optimized */
    t0 = get_time_ms();
    for (int i = 0; i < 100; i++) {
        softmax_opt(input, opt_output, DIM);
    }
    double opt_time = get_time_ms() - t0;
    
    /* Verify correctness */
    softmax_ref(input, ref_output, DIM);
    softmax_opt(input, opt_output, DIM);
    
    f32 max_error = compute_max_error(ref_output, opt_output, DIM);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    printf("[%s] Reference: %.2f ms (%.2f GB/s)\n", TEST_NAME, ref_time, 
           (DIM * sizeof(f32) * 100) / (ref_time * 1e6));
    printf("[%s] Optimized: %.2f ms (%.2f GB/s)\n", TEST_NAME, opt_time,
           (DIM * sizeof(f32) * 100) / (opt_time * 1e6));
    printf("[%s] Speedup: %.2fx\n", TEST_NAME, ref_time / opt_time);
    
    /* Verify probabilities sum to 1 */
    f32 sum = 0.0f;
    for (int i = 0; i < DIM; i++) {
        sum += opt_output[i];
    }
    
    free(input);
    free(ref_output);
    free(opt_output);
    
    if (max_error < 1e-5f && fabsf(sum - 1.0f) < 1e-3f) {
        printf("[%s] PASS (sum=%f)\n", TEST_NAME, sum);
        return 0;
    } else {
        printf("[%s] FAIL (sum=%f, max_err=%e)\n", TEST_NAME, sum, max_error);
        return 1;
    }
}
