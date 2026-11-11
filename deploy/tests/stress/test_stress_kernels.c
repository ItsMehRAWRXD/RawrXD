/*
 * RawrXD Kernel Stress Test
 * Heavy load testing for core kernels
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define STRESS_ITERATIONS 10000
#define WARMUP_ITERATIONS 100

typedef struct {
    const char* name;
    int (*func)(void);
    int iterations;
    double max_time_ms;
} stress_test_t;

/* Test results */
int tests_passed = 0;
int tests_failed = 0;

/* Get current time in milliseconds */
double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/* Stress test: Repeated matmul operations */
int stress_matmul() {
    const int N = 64;  // Small matrices for speed
    float *A = malloc(N * N * sizeof(float));
    float *B = malloc(N * N * sizeof(float));
    float *C = malloc(N * N * sizeof(float));
    
    if (!A || !B || !C) return -1;
    
    /* Initialize */
    for (int i = 0; i < N * N; i++) {
        A[i] = (float)(i % 10) / 10.0f;
        B[i] = (float)(i % 10 + 1) / 11.0f;
    }
    
    double start = get_time_ms();
    
    /* Stress loop */
    for (int iter = 0; iter < STRESS_ITERATIONS; iter++) {
        memset(C, 0, N * N * sizeof(float));
        
        for (int i = 0; i < N; i++) {
            for (int k = 0; k < N; k++) {
                float a = A[i * N + k];
                for (int j = 0; j < N; j++) {
                    C[i * N + j] += a * B[k * N + j];
                }
            }
        }
        
        /* Verify result periodically */
        if (iter % 1000 == 0 && C[0] == 0.0f) {
            free(A); free(B); free(C);
            return -1;
        }
    }
    
    double elapsed = get_time_ms() - start;
    
    free(A); free(B); free(C);
    
    printf("    Completed %d matmul operations in %.2f ms\n", STRESS_ITERATIONS, elapsed);
    printf("    Throughput: %.2f ops/sec\n", STRESS_ITERATIONS / (elapsed / 1000.0));
    
    return 0;
}

/* Stress test: Repeated softmax operations */
int stress_softmax() {
    const int N = 1024;
    float *input = malloc(N * sizeof(float));
    float *output = malloc(N * sizeof(float));
    
    if (!input || !output) return -1;
    
    for (int i = 0; i < N; i++) {
        input[i] = (float)(i % 10) / 5.0f;
    }
    
    double start = get_time_ms();
    
    for (int iter = 0; iter < STRESS_ITERATIONS; iter++) {
        /* Find max */
        float max_val = input[0];
        for (int i = 1; i < N; i++) {
            if (input[i] > max_val) max_val = input[i];
        }
        
        /* Compute exp and sum */
        float sum = 0.0f;
        for (int i = 0; i < N; i++) {
            output[i] = expf(input[i] - max_val);
            sum += output[i];
        }
        
        /* Normalize */
        for (int i = 0; i < N; i++) {
            output[i] /= sum;
        }
        
        /* Verify sum is approximately 1 */
        if (iter % 1000 == 0) {
            float check_sum = 0.0f;
            for (int i = 0; i < N; i++) check_sum += output[i];
            if (fabsf(check_sum - 1.0f) > 0.01f) {
                free(input); free(output);
                return -1;
            }
        }
    }
    
    double elapsed = get_time_ms() - start;
    
    free(input); free(output);
    
    printf("    Completed %d softmax operations in %.2f ms\n", STRESS_ITERATIONS, elapsed);
    printf("    Throughput: %.2f ops/sec\n", STRESS_ITERATIONS / (elapsed / 1000.0));
    
    return 0;
}

/* Stress test: Memory allocation patterns */
int stress_memory() {
    const int num_allocs = 1000;
    const int max_size = 1024 * 1024;  // 1MB max
    void** ptrs = malloc(num_allocs * sizeof(void*));
    
    if (!ptrs) return -1;
    
    double start = get_time_ms();
    
    /* Allocate */
    for (int iter = 0; iter < 100; iter++) {
        for (int i = 0; i < num_allocs; i++) {
            size_t size = (rand() % max_size) + 1;
            ptrs[i] = malloc(size);
            if (ptrs[i]) {
                memset(ptrs[i], i % 256, size < 1024 ? size : 1024);
            }
        }
        
        /* Free in random order */
        for (int i = num_allocs - 1; i >= 0; i--) {
            free(ptrs[i]);
            ptrs[i] = NULL;
        }
    }
    
    double elapsed = get_time_ms() - start;
    
    free(ptrs);
    
    printf("    Completed %d allocation cycles in %.2f ms\n", 100, elapsed);
    printf("    Throughput: %.2f cycles/sec\n", 100 / (elapsed / 1000.0));
    
    return 0;
}

/* Run a stress test */
void run_stress_test(const char* name, int (*func)(void), int iterations) {
    printf("\n  Testing: %s\n", name);
    printf("  ");
    for (int i = 0; i < 50; i++) printf("-");
    printf("\n");
    
    int result = func();
    
    if (result == 0) {
        printf("  ✓ %s PASSED\n", name);
        tests_passed++;
    } else {
        printf("  ✗ %s FAILED\n", name);
        tests_failed++;
    }
}

int main() {
    printf("RawrXD Kernel Stress Test\n");
    printf("=========================\n");
    printf("Iterations per test: %d\n", STRESS_ITERATIONS);
    printf("\n");
    
    srand((unsigned int)time(NULL));
    
    /* Warmup */
    printf("Warming up...\n");
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        volatile int x = i * i;
        (void)x;
    }
    printf("Done.\n");
    
    /* Run stress tests */
    run_stress_test("Matrix Multiplication", stress_matmul, STRESS_ITERATIONS);
    run_stress_test("Softmax", stress_softmax, STRESS_ITERATIONS);
    run_stress_test("Memory Allocation", stress_memory, 100);
    
    /* Summary */
    printf("\n");
    printf("=========================\n");
    printf("Stress Test Summary\n");
    printf("=========================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests:  %d\n", tests_passed + tests_failed);
    
    if (tests_failed == 0) {
        printf("\n✓ ALL STRESS TESTS PASSED\n");
        return 0;
    } else {
        printf("\n✗ SOME STRESS TESTS FAILED\n");
        return 1;
    }
}
