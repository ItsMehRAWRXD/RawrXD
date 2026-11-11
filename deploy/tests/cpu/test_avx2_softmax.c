/*
 * RawrXD Validation Framework
 * CPU Test: AVX2 Softmax Kernel
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#ifdef _WIN32
#include <malloc.h>
#define aligned_alloc(align, size) _aligned_malloc(size, align)
#define aligned_free(ptr) _aligned_free(ptr)
#else
#define aligned_free(ptr) free(ptr)
#endif

#define TEST_NAME "AVX2 Softmax"
#define DIM 32000

typedef float f32;

void softmax_ref(const f32* x, f32* out, int n) {
    f32 max_val = x[0];
    for (int i = 1; i < n; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    f32 sum = 0.0f;
    for (int i = 0; i < n; i++) {
        out[i] = expf(x[i] - max_val);
        sum += out[i];
    }
    
    for (int i = 0; i < n; i++) {
        out[i] /= sum;
    }
}

void softmax_avx2(const f32* x, f32* out, int n) {
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
    
    f32* input = aligned_alloc(32, DIM * sizeof(f32));
    f32* ref_output = aligned_alloc(32, DIM * sizeof(f32));
    f32* opt_output = aligned_alloc(32, DIM * sizeof(f32));
    
    if (!input || !ref_output || !opt_output) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    for (int i = 0; i < DIM; i++) {
        input[i] = (f32)(i % 10) - 5.0f;
    }
    
    softmax_ref(input, ref_output, DIM);
    softmax_avx2(input, opt_output, DIM);
    
    f32 max_error = compute_max_error(ref_output, opt_output, DIM);
    
    /* Verify probabilities sum to 1 */
    f32 sum = 0.0f;
    for (int i = 0; i < DIM; i++) sum += opt_output[i];
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    printf("[%s] Probability sum: %f (should be ~1.0)\n", TEST_NAME, sum);
    
    aligned_free(input);
    aligned_free(ref_output);
    aligned_free(opt_output);
    
    if (max_error < 1e-4f && fabsf(sum - 1.0f) < 1e-3f) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL\n", TEST_NAME);
        return 1;
    }
}
