/*
 * RawrXD Quick Performance Smoke Test
 * Milestone 3: Performance Baselines (Fast Version)
 */

#include "perf_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Quick matmul: 128x128x128 with 100 iterations */
void quick_matmul(float* C, const float* A, const float* B, int N) {
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < N; k++) {
                sum += A[i * N + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

/* Quick softmax on 1024 elements */
void quick_softmax(float* out, const float* in, int n) {
    float max_val = in[0];
    for (int i = 1; i < n; i++) {
        if (in[i] > max_val) max_val = in[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < n; i++) {
        out[i] = expf(in[i] - max_val);
        sum += out[i];
    }
    
    for (int i = 0; i < n; i++) {
        out[i] /= sum;
    }
}

/* Quick RMSNorm on 4096 elements */
void quick_rmsnorm(float* out, const float* in, int n, float eps) {
    float sum_sq = 0.0f;
    for (int i = 0; i < n; i++) {
        sum_sq += in[i] * in[i];
    }
    float rms = sqrtf(sum_sq / n + eps);
    for (int i = 0; i < n; i++) {
        out[i] = in[i] / rms;
    }
}

int main() {
    printf("RawrXD Quick Performance Smoke Test\n");
    printf("====================================\n\n");
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    /* Test 1: Matmul 128x128x128 */
    {
        int N = 128;
        int iters = 100;
        size_t size = N * N * sizeof(float);
        
        float* A = (float*)malloc(size);
        float* B = (float*)malloc(size);
        float* C = (float*)malloc(size);
        
        for (int i = 0; i < N * N; i++) {
            A[i] = (float)(i % 10) / 10.0f;
            B[i] = (float)(i % 10 + 1) / 11.0f;
        }
        
        perf_warmup(A, size);
        
        perf_counter_t start, end;
        perf_get_time(&start);
        
        for (int iter = 0; iter < iters; iter++) {
            quick_matmul(C, A, B, N);
        }
        
        perf_get_time(&end);
        
        double elapsed = perf_get_elapsed_ms(&start, &end);
        size_t ops = (size_t)N * N * N * 2 * iters;
        double gops = perf_calc_throughput_gops(ops, elapsed);
        
        printf("Matmul 128x128x128 (x%d):\n", iters);
        printf("  Elapsed: %.3f ms\n", elapsed);
        printf("  Throughput: %.3f GOPS\n", gops);
        
        /* Baseline: ~650ms for 100 iterations */
        if (elapsed < 1000.0) {
            printf("  ✓ PASS (within tolerance)\n");
            tests_passed++;
        } else {
            printf("  ✗ FAIL (too slow: %.1f ms)\n", elapsed);
            tests_failed++;
        }
        
        free(A); free(B); free(C);
    }
    
    printf("\n");
    
    /* Test 2: Softmax 1024 elements */
    {
        int n = 1024;
        int iters = 1000;
        size_t size = n * sizeof(float);
        
        float* in = (float*)malloc(size);
        float* out = (float*)malloc(size);
        
        for (int i = 0; i < n; i++) {
            in[i] = (float)(i % 10) / 5.0f;
        }
        
        perf_warmup(in, size);
        
        perf_counter_t start, end;
        perf_get_time(&start);
        
        for (int iter = 0; iter < iters; iter++) {
            quick_softmax(out, in, n);
        }
        
        perf_get_time(&end);
        
        double elapsed = perf_get_elapsed_ms(&start, &end);
        printf("Softmax 1024 elements (x%d):\n", iters);
        printf("  Elapsed: %.3f ms\n", elapsed);
        printf("  Throughput: %.2f ops/sec\n", iters / (elapsed / 1000.0));
        
        /* Baseline: ~50ms for 1000 iterations */
        if (elapsed < 100.0) {
            printf("  ✓ PASS (within tolerance)\n");
            tests_passed++;
        } else {
            printf("  ✗ FAIL (too slow: %.1f ms)\n", elapsed);
            tests_failed++;
        }
        
        free(in); free(out);
    }
    
    printf("\n");
    
    /* Test 3: RMSNorm 4096 elements (LLM hidden dim) */
    {
        int n = 4096;
        int iters = 500;
        size_t size = n * sizeof(float);
        
        float* in = (float*)malloc(size);
        float* out = (float*)malloc(size);
        
        for (int i = 0; i < n; i++) {
            in[i] = (float)(i % 10) / 10.0f;
        }
        
        perf_warmup(in, size);
        
        perf_counter_t start, end;
        perf_get_time(&start);
        
        for (int iter = 0; iter < iters; iter++) {
            quick_rmsnorm(out, in, n, 1e-6f);
        }
        
        perf_get_time(&end);
        
        double elapsed = perf_get_elapsed_ms(&start, &end);
        printf("RMSNorm 4096 elements (x%d):\n", iters);
        printf("  Elapsed: %.3f ms\n", elapsed);
        printf("  Throughput: %.2f ops/sec\n", iters / (elapsed / 1000.0));
        
        /* Baseline: ~30ms for 500 iterations */
        if (elapsed < 60.0) {
            printf("  ✓ PASS (within tolerance)\n");
            tests_passed++;
        } else {
            printf("  ✗ FAIL (too slow: %.1f ms)\n", elapsed);
            tests_failed++;
        }
        
        free(in); free(out);
    }
    
    /* Summary */
    printf("\n====================================\n");
    printf("Performance Smoke Test Summary\n");
    printf("====================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests:  %d\n", tests_passed + tests_failed);
    
    if (tests_failed == 0) {
        printf("\n✓ ALL PERFORMANCE TESTS PASSED\n");
        return 0;
    } else {
        printf("\n✗ SOME PERFORMANCE TESTS FAILED\n");
        return 1;
    }
}
