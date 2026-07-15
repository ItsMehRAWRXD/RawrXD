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

void rms_norm_opt(const f32* x, f32* out, int n, f32 eps) {
    /* Optimized RMS normalization */
    /* TODO: Implement AVX-512 version */
    rms_norm_ref(x, out, n, eps);
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
