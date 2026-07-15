/*
 * RawrXD Validation Framework
 * Kernel Test: SiLU Activation
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_NAME "SiLU Activation"
#define DIM 4096

typedef float f32;

f32 silu_ref(f32 x) {
    return x * (1.0f / (1.0f + expf(-x)));
}

void silu_vector_ref(const f32* x, f32* out, int n) {
    for (int i = 0; i < n; i++) {
        out[i] = silu_ref(x[i]);
    }
}

#include <immintrin.h>

void silu_vector_opt(const f32* x, f32* out, int n) {
    /* AVX-512 SiLU: x * sigmoid(x) */
    const __m512 vone = _mm512_set1_ps(1.0f);
    const __m512 vneg_one = _mm512_set1_ps(-1.0f);
    
    int i = 0;
    for (; i <= n - 16; i += 16) {
        __m512 vx = _mm512_loadu_ps(&x[i]);
        
        /* Compute sigmoid: 1 / (1 + exp(-x)) */
        __m512 vneg_x = _mm512_mul_ps(vx, vneg_one);
        __m512 vexp = _mm512_exp_ps(vneg_x);  /* AVX-512 ER exp approximation */
        __m512 vsigmoid = _mm512_div_ps(vone, _mm512_add_ps(vone, vexp));
        
        /* SiLU: x * sigmoid(x) */
        __m512 vsilu = _mm512_mul_ps(vx, vsigmoid);
        
        _mm512_storeu_ps(&out[i], vsilu);
    }
    
    /* Scalar fallback for remaining elements */
    for (; i < n; i++) {
        out[i] = silu_ref(x[i]);
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
    
    /* Test with range of values */
    for (int i = 0; i < DIM; i++) {
        input[i] = -10.0f + (20.0f * i / DIM);
    }
    
    silu_vector_ref(input, ref_output, DIM);
    silu_vector_opt(input, opt_output, DIM);
    
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
