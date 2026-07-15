/*
 * RawrXD Validation Framework
 * Kernel Test: Softmax
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

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
    for (int i = 0; i < n; i++) {
        out[i] /= sum;
    }
}

void softmax_opt(const f32* x, f32* out, int n) {
    /* Optimized softmax */
    /* TODO: Implement AVX-512 version */
    softmax_ref(x, out, n);
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
    
    /* Test with logits */
    for (int i = 0; i < DIM; i++) {
        input[i] = (f32)(i % 10) - 5.0f;
    }
    
    softmax_ref(input, ref_output, DIM);
    softmax_opt(input, opt_output, DIM);
    
    f32 max_error = compute_max_error(ref_output, opt_output, DIM);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    
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
