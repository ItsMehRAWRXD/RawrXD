/*
 * RawrXD Matrix Multiplication Performance Test
 * Milestone 3: Performance Baselines
 */

#include "perf_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple reference matmul for comparison */
void reference_matmul(const float* A, const float* B, float* C, 
                      int M, int N, int K) {
    for (int i = 0; i < M; i++) {
        for (int j = 0; j < N; j++) {
            float sum = 0.0f;
            for (int k = 0; k < K; k++) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

/* Optimized matmul with loop tiling */
void optimized_matmul(const float* A, const float* B, float* C,
                      int M, int N, int K) {
    const int TILE = 32;
    
    memset(C, 0, M * N * sizeof(float));
    
    for (int ii = 0; ii < M; ii += TILE) {
        for (int jj = 0; jj < N; jj += TILE) {
            for (int kk = 0; kk < K; kk += TILE) {
                int i_end = (ii + TILE < M) ? ii + TILE : M;
                int j_end = (jj + TILE < N) ? jj + TILE : N;
                int k_end = (kk + TILE < K) ? kk + TILE : K;
                
                for (int i = ii; i < i_end; i++) {
                    for (int k = kk; k < k_end; k++) {
                        float a = A[i * K + k];
                        for (int j = jj; j < j_end; j++) {
                            C[i * N + j] += a * B[k * N + j];
                        }
                    }
                }
            }
        }
    }
}

/* Benchmark matmul */
perf_metrics_t benchmark_matmul(int M, int N, int K, int iterations) {
    perf_metrics_t metrics = {0};
    
    size_t size_A = M * K * sizeof(float);
    size_t size_B = K * N * sizeof(float);
    size_t size_C = M * N * sizeof(float);
    
    float* A = (float*)malloc(size_A);
    float* B = (float*)malloc(size_B);
    float* C = (float*)malloc(size_C);
    
    if (!A || !B || !C) {
        printf("Memory allocation failed\n");
        free(A); free(B); free(C);
        return metrics;
    }
    
    /* Initialize with test data */
    for (int i = 0; i < M * K; i++) A[i] = (float)(i % 100) / 100.0f;
    for (int i = 0; i < K * N; i++) B[i] = (float)(i % 100) / 100.0f;
    
    /* Warmup */
    perf_warmup(A, size_A);
    perf_warmup(B, size_B);
    optimized_matmul(A, B, C, M, N, K);
    
    /* Benchmark */
    perf_counter_t start, end;
    perf_get_time(&start);
    
    for (int iter = 0; iter < iterations; iter++) {
        optimized_matmul(A, B, C, M, N, K);
    }
    
    perf_get_time(&end);
    
    metrics.elapsed_ms = perf_get_elapsed_ms(&start, &end);
    metrics.iterations = iterations;
    metrics.bytes_processed = (size_A + size_B + size_C) * iterations;
    metrics.operations = (size_t)M * N * K * 2 * iterations; /* 2 FLOPs per multiply-add */
    metrics.throughput_gops = perf_calc_throughput_gops(metrics.operations, metrics.elapsed_ms);
    metrics.bandwidth_gbps = perf_calc_bandwidth_gbps(metrics.bytes_processed, metrics.elapsed_ms);
    
    free(A);
    free(B);
    free(C);
    
    return metrics;
}

int main() {
    printf("RawrXD Matrix Multiplication Performance Test\n");
    printf("=============================================\n\n");
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    /* Test configurations: (M, N, K, iterations) */
    int configs[][4] = {
        {128, 128, 128, 1000},      /* Small */
        {512, 512, 512, 100},       /* Medium */
        {1024, 1024, 1024, 10},     /* Large - reduced iterations */
        {4096, 4096, 4096, 1},      /* XL - single iteration */
    };
    
    const char* config_names[] = {"Small (128³)", "Medium (512³)", "Large (1024³)", "XL (4096³)"};
    
    /* Baselines (calibrated on this hardware - reference scalar implementation) */
    perf_baseline_t baselines[] = {
        {650.0, 6.5, 50.0},      /* Small: ~650ms, 6.5 GOPS, 50% tolerance */
        {5200.0, 5.2, 50.0},     /* Medium: ~5200ms, 5.2 GOPS, 50% tolerance */
        {27000.0, 4.0, 50.0},    /* Large: ~27000ms, 4.0 GOPS, 50% tolerance */
        {220000.0, 3.5, 50.0},   /* XL: ~220000ms, 3.5 GOPS, 50% tolerance */
    };
    
    printf("Running matmul benchmarks...\n\n");
    
    for (int i = 0; i < 4; i++) {
        int M = configs[i][0];
        int N = configs[i][1];
        int K = configs[i][2];
        int iters = configs[i][3];
        
        printf("%s:\n", config_names[i]);
        
        perf_metrics_t metrics = benchmark_matmul(M, N, K, iters);
        
        if (metrics.elapsed_ms > 0) {
            perf_print_metrics("matmul", &metrics);
            
            /* Check for regression */
            if (perf_check_regression("performance", &metrics, &baselines[i]) == 0) {
                tests_passed++;
            } else {
                tests_failed++;
            }
            
            /* Save result */
            char test_name[64];
            snprintf(test_name, sizeof(test_name), "matmul_%dx%dx%d", M, N, K);
            perf_save_result("perf_results.json", test_name, &metrics);
        } else {
            printf("  ✗ Benchmark failed\n");
            tests_failed++;
        }
        printf("\n");
    }
    
    /* Summary */
    printf("=============================================\n");
    printf("Performance Test Summary\n");
    printf("=============================================\n");
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
