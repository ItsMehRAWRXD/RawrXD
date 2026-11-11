/*
 * RawrXD Validation Framework
 * Kernel Test: Matrix Multiplication
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define TEST_NAME "Matrix Multiplication"
#define M 256
#define N 256
#define K 256

typedef float f32;

void matmul_ref(const f32* A, const f32* B, f32* C,
                int m, int n, int k) {
    /* C[m][n] = A[m][k] * B[k][n] */
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < n; j++) {
            f32 sum = 0.0f;
            for (int l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
}

void matmul_opt(const f32* A, const f32* B, f32* C,
                int m, int n, int k) {
    /* Optimized matrix multiplication */
    /* TODO: Implement AVX-512 version with tiling */
    matmul_ref(A, B, C, m, n, k);
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
    
    f32* A = malloc(M * K * sizeof(f32));
    f32* B = malloc(K * N * sizeof(f32));
    f32* ref_C = malloc(M * N * sizeof(f32));
    f32* opt_C = malloc(M * N * sizeof(f32));
    
    if (!A || !B || !ref_C || !opt_C) {
        printf("[%s] FAIL: Memory allocation failed\n", TEST_NAME);
        return 1;
    }
    
    /* Initialize with test values */
    for (int i = 0; i < M * K; i++) {
        A[i] = (f32)(i % 10) / 10.0f;
    }
    for (int i = 0; i < K * N; i++) {
        B[i] = (f32)((i + 5) % 10) / 10.0f;
    }
    
    matmul_ref(A, B, ref_C, M, N, K);
    matmul_opt(A, B, opt_C, M, N, K);
    
    f32 max_error = compute_max_error(ref_C, opt_C, M * N);
    
    printf("[%s] Max error: %e\n", TEST_NAME, max_error);
    
    free(A);
    free(B);
    free(ref_C);
    free(opt_C);
    
    if (max_error < 1e-4f) {
        printf("[%s] PASS\n", TEST_NAME);
        return 0;
    } else {
        printf("[%s] FAIL\n", TEST_NAME);
        return 1;
    }
}
