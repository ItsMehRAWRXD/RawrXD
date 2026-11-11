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

/* 
 * Fast and accurate exp(-x) using range reduction + polynomial
 * Based on Cephes exp implementation adapted for AVX-512
 */
static inline __m512 fast_exp_neg_ps(__m512 x) {
    const __m512 vln2 = _mm512_set1_ps(0.6931471805599453f);
    const __m512 vinv_ln2 = _mm512_set1_ps(1.4426950408889634f);
    
    /* Clamp input to avoid overflow/underflow */
    const __m512 vmin = _mm512_set1_ps(-88.0f);
    const __m512 vmax = _mm512_set1_ps(88.0f);
    x = _mm512_max_ps(x, vmin);
    x = _mm512_min_ps(x, vmax);
    
    /* Range reduction: exp(x) = 2^k * exp(r) where x = k*ln2 + r */
    __m512 fx = _mm512_mul_ps(x, vinv_ln2);
    fx = _mm512_add_ps(fx, _mm512_set1_ps(0.5f));
    
    __m512i k = _mm512_cvtps_epi32(fx);
    __m512 fk = _mm512_cvtepi32_ps(k);
    
    /* r = x - k*ln2 */
    __m512 r = _mm512_sub_ps(x, _mm512_mul_ps(fk, vln2));
    
    /* Polynomial approximation for exp(r) on [-ln2/2, ln2/2] */
    const __m512 c0 = _mm512_set1_ps(1.000000000f);
    const __m512 c1 = _mm512_set1_ps(0.999999999f);
    const __m512 c2 = _mm512_set1_ps(0.500000000f);
    const __m512 c3 = _mm512_set1_ps(0.166666667f);
    const __m512 c4 = _mm512_set1_ps(0.041666667f);
    const __m512 c5 = _mm512_set1_ps(0.008333333f);
    const __m512 c6 = _mm512_set1_ps(0.001388889f);
    const __m512 c7 = _mm512_set1_ps(0.000198413f);
    
    /* Horner's method */
    __m512 result = c7;
    result = _mm512_fmadd_ps(result, r, c6);
    result = _mm512_fmadd_ps(result, r, c5);
    result = _mm512_fmadd_ps(result, r, c4);
    result = _mm512_fmadd_ps(result, r, c3);
    result = _mm512_fmadd_ps(result, r, c2);
    result = _mm512_fmadd_ps(result, r, c1);
    result = _mm512_fmadd_ps(result, r, c0);
    
    /* Apply 2^k scaling */
    __m512i ki = _mm512_add_epi32(k, _mm512_set1_epi32(127));
    ki = _mm512_slli_epi32(ki, 23);
    __m512 scale = _mm512_castsi512_ps(ki);
    
    return _mm512_mul_ps(result, scale);
}

void silu_vector_opt(const f32* x, f32* out, int n) {
    /* AVX-512 SiLU: x * sigmoid(x) */
    const __m512 vone = _mm512_set1_ps(1.0f);
    const __m512 vneg_one = _mm512_set1_ps(-1.0f);
    
    int i = 0;
    for (; i <= n - 16; i += 16) {
        __m512 vx = _mm512_loadu_ps(&x[i]);
        
        /* Compute sigmoid: 1 / (1 + exp(-x)) */
        __m512 vneg_x = _mm512_mul_ps(vx, vneg_one);
        __m512 vexp = fast_exp_neg_ps(vneg_x);
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
    f32 max_rel_err = 0.0f;
    int max_err_idx = 0;
    
    for (int i = 0; i < n; i++) {
        f32 err = fabsf(ref[i] - opt[i]);
        f32 rel_err = err / (fabsf(ref[i]) + 1e-7f);
        
        if (err > max_err) {
            max_err = err;
            max_err_idx = i;
        }
        if (rel_err > max_rel_err) {
            max_rel_err = rel_err;
        }
    }
    
    printf("  Max error at index %d: ref=%e, opt=%e\n", 
           max_err_idx, ref[max_err_idx], opt[max_err_idx]);
    printf("  Max relative error: %e\n", max_rel_err);
    
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
    
    /* Test with range of values covering typical activation ranges */
    for (int i = 0; i < DIM; i++) {
        /* Range: -10 to +10 covers 99.9% of activation values */
        input[i] = -10.0f + (20.0f * i / DIM);
    }
    
    printf("[%s] Computing reference (scalar)...\n", TEST_NAME);
    silu_vector_ref(input, ref_output, DIM);
    
    printf("[%s] Computing optimized (AVX-512)...\n", TEST_NAME);
    silu_vector_opt(input, opt_output, DIM);
    
    printf("[%s] Comparing results...\n", TEST_NAME);
    f32 max_error = compute_max_error(ref_output, opt_output, DIM);
    
    printf("[%s] Max absolute error: %e\n", TEST_NAME, max_error);
    
    free(input);
    free(ref_output);
    free(opt_output);
    
    /* Tolerance: 1e-5 for fast math kernels */
    if (max_error < 1e-5f) {
        printf("[%s] PASS (error < 1e-5)\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL (error >= 1e-5)\n", TEST_NAME);
        return 1;
    }
}
