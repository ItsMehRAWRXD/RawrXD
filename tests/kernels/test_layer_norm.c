/*
 * RawrXD Validation Framework
 * Kernel Test: Layer Normalization
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_NAME "Layer Normalization"
#define DIM 4096
#define EPS 1e-6f

typedef float f32;

void layer_norm_ref(const f32* x, f32* out, int n, f32 eps) {
    /* Compute mean */
    f32 mean = 0.0f;
    for (int i = 0; i < n; i++) {
        mean += x[i];
    }
    mean /= n;
    
    /* Compute variance */
    f32 var = 0.0f;
    for (int i = 0; i < n; i++) {
        f32 diff = x[i] - mean;
        var += diff * diff;
    }
    var /= n;
    
    /* Normalize */
    f32 scale = 1.0f / sqrtf(var + eps);
    for (int i = 0; i < n; i++) {
        out[i] = (x[i] - mean) * scale;
    }
}

void layer_norm_opt(const f32* x, f32* out, int n, f32 eps) {
    /* Optimized Layer Normalization */
    /* TODO: Implement AVX-512 version */
    layer_norm_ref(x, out, n, eps);
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
    
    layer_norm_ref(input, ref_output, DIM, EPS);
    layer_norm_opt(input, opt_output, DIM, EPS);
    
    f32 max_error = compute_max_error(ref_output, opt_output, DIM);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    
    free(input);
    free(ref_output);
    free(opt_output);
    
    if (max_error < 1e-5f) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL\n", TEST_NAME);
        return 1;
    }
}
