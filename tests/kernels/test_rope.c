/*
 * RawrXD Validation Framework
 * Kernel Test: RoPE (Rotary Position Embedding)
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_NAME "RoPE"
#define DIM 128
#define HEAD_DIM 64

typedef float f32;

void rope_ref(f32* x, int n, int head_dim) {
    /* Apply rotary position embeddings */
    for (int i = 0; i < n; i += 2) {
        int idx = i % head_dim;
        f32 theta = powf(10000.0f, -2.0f * (idx / 2) / head_dim);
        f32 angle = i * theta;
        
        f32 x0 = x[i];
        f32 x1 = x[i + 1];
        
        f32 cos_theta = cosf(angle);
        f32 sin_theta = sinf(angle);
        
        x[i] = x0 * cos_theta - x1 * sin_theta;
        x[i + 1] = x0 * sin_theta + x1 * cos_theta;
    }
}

void rope_opt(f32* x, int n, int head_dim) {
    /* Optimized RoPE */
    /* TODO: Implement AVX-512 version */
    rope_ref(x, n, head_dim);
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
    
    f32* input_ref = malloc(DIM * sizeof(f32));
    f32* input_opt = malloc(DIM * sizeof(f32));
    
    if (!input_ref || !input_opt) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    /* Initialize with same values */
    for (int i = 0; i < DIM; i++) {
        input_ref[i] = (f32)(i % 10) / 10.0f;
        input_opt[i] = input_ref[i];
    }
    
    rope_ref(input_ref, DIM, HEAD_DIM);
    rope_opt(input_opt, DIM, HEAD_DIM);
    
    f32 max_error = compute_max_error(input_ref, input_opt, DIM);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    
    free(input_ref);
    free(input_opt);
    
    if (max_error < 1e-6f) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL\n", TEST_NAME);
        return 1;
    }
}
