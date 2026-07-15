/*
 * RawrXD Validation Framework
 * Kernel Test: RMS Normalization
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_NAME "RMS Normalization"
#define DIM 4096
#define EPS 1e-6f

typedef float f32;

void rms_norm_ref(const f32* x, f32* out, int n, f32 eps) {
    f32 sum_sq = 0.0f;
    for (int i = 0; i < n; i++) {
        sum_sq += x[i] * x[i];
    }
    f32 rms = sqrtf(sum_sq / n + eps);
    f32 scale = 1.0f / rms;
    for (int i = 0; i < n; i++) {
        out[i] = x[i] * scale;
    }
}

#include <immintrin.h>

void rms_norm_opt(const f32* x, f32* out, int n, f32 eps) {
    /* AVX-512 RMS Normalization */
    const __m512 vzero = _mm512_setzero_ps();
    const __m512 veps = _mm512_set1_ps(eps);
    
    /* Step 1: Compute sum of squares */
    __m512 vsum_sq = vzero;
    int i = 0;
    for (; i <= n - 16; i += 16) {
        __m512 vx = _mm512_loadu_ps(&x[i]);
        vsum_sq = _mm512_fmadd_ps(vx, vx, vsum_sq);
    }
    
    /* Horizontal sum reduction */
    float sum_sq = _mm512_reduce_add_ps(vsum_sq);
    for (; i < n; i++) sum_sq += x[i] * x[i];
    
    /* Step 2: Compute RMS and scale */
    float rms = sqrtf(sum_sq / n + eps);
    float scale = 1.0f / rms;
    
    __m512 vscale = _mm512_set1_ps(scale);
    
    /* Step 3: Normalize */
    i = 0;
    for (; i <= n - 16; i += 16) {
        __m512 vx = _mm512_loadu_ps(&x[i]);
        __m512 vout = _mm512_mul_ps(vx, vscale);
        _mm512_storeu_ps(&out[i], vout);
    }
    
    /* Scalar fallback */
    for (; i < n; i++) {
        out[i] = x[i] * scale;
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

int main(void) {
    printf("[%s] Starting...\n", TEST_NAME);
    
    f32* input = malloc(DIM * sizeof(f32));
    f32* ref_output = malloc(DIM * sizeof(f32));
    f32* opt_output = malloc(DIM * sizeof(f32));
    
    if (!input || !ref_output || !opt_output) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    /* Test with random values */
    for (int i = 0; i < DIM; i++) {
        input[i] = (f32)(i % 100) / 100.0f;
    }
    
    rms_norm_ref(input, ref_output, DIM, EPS);
    rms_norm_opt(input, opt_output, DIM, EPS);
    
    f32 max_error = compute_max_error(ref_output, opt_output, DIM);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    
    free(input);
    free(ref_output);
    free(opt_output);
    
    if (max_error < 1e-6f) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL\n", TEST_NAME);
        return 1;
    }
}
