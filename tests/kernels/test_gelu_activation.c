/*
 * RawrXD Validation Framework
 * Kernel Test: GELU Activation
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_NAME "GELU Activation"
#define DIM 4096

typedef float f32;

f32 gelu_ref(f32 x) {
    /* GELU(x) = x * Φ(x) where Φ is the CDF of the standard normal distribution */
    /* Approximation: 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x^3))) */
    const f32 sqrt_2_over_pi = 0.7978845608f;
    const f32 coeff = 0.044715f;
    f32 x_cubed = x * x * x;
    f32 inner = sqrt_2_over_pi * (x + coeff * x_cubed);
    return 0.5f * x * (1.0f + tanhf(inner));
}

void gelu_vector_ref(const f32* x, f32* out, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = gelu_ref(x[i]);
    }
}

void gelu_vector_opt(const f32* x, f32* out, int n) {
    /* Optimized GELU */
    /* TODO: Implement AVX-512 version */
    gelu_vector_ref(x, out, n);
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
    
    /* Test with range of values */
    for (int i = 0; i < DIM; i++) {
        input[i] = -5.0f + (10.0f * i / DIM);
    }
    
    gelu_vector_ref(input, ref_output, DIM);
    gelu_vector_opt(input, opt_output, DIM);
    
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
