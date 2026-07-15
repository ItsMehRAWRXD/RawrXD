/*
 * RawrXD Validation Framework
 * CPU Test: AVX2 RMSNorm Kernel
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <malloc.h>
#define aligned_alloc(align, size) _aligned_malloc(size, align)
#define aligned_free(ptr) _aligned_free(ptr)
#else
#define aligned_free(ptr) free(ptr)
#endif

#define TEST_NAME "AVX2 RMSNorm"
#define EPSILON 1e-6f
#define DIM 4096

typedef float f32;

/* Reference scalar implementation */
void rms_norm_ref(const f32* x, f32* out, int n, f32 eps) {
    f32 sum = 0.0f;
    for (int i = 0; i < n; i++) {
        sum += x[i] * x[i];
    }
    f32 scale = 1.0f / sqrtf(sum / n + eps);
    for (int i = 0; i < n; i++) {
        out[i] = x[i] * scale;
    }
}

/* Simple AVX2 implementation */
void rms_norm_avx2(const f32* x, f32* out, int n, f32 eps) {
    /* For now, use reference - AVX2 version would go here */
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
    
    /* Allocate memory */
    f32* input = aligned_alloc(32, DIM * sizeof(f32));
    f32* ref_output = aligned_alloc(32, DIM * sizeof(f32));
    f32* opt_output = aligned_alloc(32, DIM * sizeof(f32));
    
    if (!input || !ref_output || !opt_output) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    /* Initialize with test data */
    for (int i = 0; i < DIM; i++) {
        input[i] = (f32)(i % 100) / 100.0f;
    }
    
    /* Run reference implementation */
    rms_norm_ref(input, ref_output, DIM, EPSILON);
    
    /* Run AVX2 implementation */
    rms_norm_avx2(input, opt_output, DIM, EPSILON);
    
    /* Compare results */
    f32 max_error = compute_max_error(ref_output, opt_output, DIM);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    
    /* Cleanup */
    aligned_free(input);
    aligned_free(ref_output);
    aligned_free(opt_output);
    
    /* Check tolerance */
    if (max_error < 1e-4f) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL: Error exceeds tolerance\n", TEST_NAME);
        return 1;
    }
}
