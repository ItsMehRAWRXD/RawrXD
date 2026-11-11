/*
 * RawrXD Performance Benchmark Runner
 * Fast, non-blocking benchmark execution
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

#define WARMUP_ITERATIONS 10
#define BENCHMARK_ITERATIONS 100
#define MAX_DIM 1024

typedef struct {
    const char* name;
    double gops;
    double time_ms;
    int passed;
} benchmark_result_t;

/* High-resolution timer */
double get_time_ms() {
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
#endif
}

/* Simple matrix multiplication benchmark */
double benchmark_matmul(int dim) {
    double* A = (double*)malloc(dim * dim * sizeof(double));
    double* B = (double*)malloc(dim * dim * sizeof(double));
    double* C = (double*)malloc(dim * dim * sizeof(double));
    
    if (!A || !B || !C) {
        free(A); free(B); free(C);
        return 0.0;
    }
    
    /* Initialize */
    for (int i = 0; i < dim * dim; i++) {
        A[i] = (double)rand() / RAND_MAX;
        B[i] = (double)rand() / RAND_MAX;
        C[i] = 0.0;
    }
    
    /* Warmup */
    for (int iter = 0; iter < WARMUP_ITERATIONS; iter++) {
        for (int i = 0; i < dim; i++) {
            for (int j = 0; j < dim; j++) {
                double sum = 0.0;
                for (int k = 0; k < dim; k++) {
                    sum += A[i * dim + k] * B[k * dim + j];
                }
                C[i * dim + j] = sum;
            }
        }
    }
    
    /* Benchmark */
    double start = get_time_ms();
    
    for (int iter = 0; iter < BENCHMARK_ITERATIONS; iter++) {
        for (int i = 0; i < dim; i++) {
            for (int j = 0; j < dim; j++) {
                double sum = 0.0;
                for (int k = 0; k < dim; k++) {
                    sum += A[i * dim + k] * B[k * dim + j];
                }
                C[i * dim + j] = sum;
            }
        }
    }
    
    double end = get_time_ms();
    double total_time = end - start;
    
    /* Calculate GOPS: 2 * dim^3 operations per iteration */
    double ops_per_iter = 2.0 * dim * dim * dim;
    double total_ops = ops_per_iter * BENCHMARK_ITERATIONS;
    double gops = (total_ops / (total_time / 1000.0)) / 1e9;
    
    free(A);
    free(B);
    free(C);
    
    return gops;
}

/* Softmax benchmark */
double benchmark_softmax(int dim) {
    double* input = (double*)malloc(dim * sizeof(double));
    double* output = (double*)malloc(dim * sizeof(double));
    
    if (!input || !output) {
        free(input); free(output);
        return 0.0;
    }
    
    /* Initialize */
    for (int i = 0; i < dim; i++) {
        input[i] = (double)rand() / RAND_MAX;
    }
    
    /* Warmup */
    for (int iter = 0; iter < WARMUP_ITERATIONS; iter++) {
        double max_val = input[0];
        for (int i = 1; i < dim; i++) {
            if (input[i] > max_val) max_val = input[i];
        }
        
        double sum = 0.0;
        for (int i = 0; i < dim; i++) {
            output[i] = exp(input[i] - max_val);
            sum += output[i];
        }
        
        for (int i = 0; i < dim; i++) {
            output[i] /= sum;
        }
    }
    
    /* Benchmark */
    double start = get_time_ms();
    
    for (int iter = 0; iter < BENCHMARK_ITERATIONS; iter++) {
        double max_val = input[0];
        for (int i = 1; i < dim; i++) {
            if (input[i] > max_val) max_val = input[i];
        }
        
        double sum = 0.0;
        for (int i = 0; i < dim; i++) {
            output[i] = exp(input[i] - max_val);
            sum += output[i];
        }
        
        for (int i = 0; i < dim; i++) {
            output[i] /= sum;
        }
    }
    
    double end = get_time_ms();
    double total_time = end - start;
    
    /* Calculate ops/sec */
    double ops_per_iter = dim * 6; /* approx operations per softmax */
    double total_ops = ops_per_iter * BENCHMARK_ITERATIONS;
    double ops_per_sec = total_ops / (total_time / 1000.0);
    
    free(input);
    free(output);
    
    return ops_per_sec / 1e6; /* Return in millions */
}

/* RMSNorm benchmark */
double benchmark_rmsnorm(int dim) {
    double* input = (double*)malloc(dim * sizeof(double));
    double* output = (double*)malloc(dim * sizeof(double));
    
    if (!input || !output) {
        free(input); free(output);
        return 0.0;
    }
    
    /* Initialize */
    for (int i = 0; i < dim; i++) {
        input[i] = (double)rand() / RAND_MAX;
    }
    
    double eps = 1e-6;
    
    /* Warmup */
    for (int iter = 0; iter < WARMUP_ITERATIONS; iter++) {
        double sum_sq = 0.0;
        for (int i = 0; i < dim; i++) {
            sum_sq += input[i] * input[i];
        }
        double rms = sqrt(sum_sq / dim + eps);
        for (int i = 0; i < dim; i++) {
            output[i] = input[i] / rms;
        }
    }
    
    /* Benchmark */
    double start = get_time_ms();
    
    for (int iter = 0; iter < BENCHMARK_ITERATIONS; iter++) {
        double sum_sq = 0.0;
        for (int i = 0; i < dim; i++) {
            sum_sq += input[i] * input[i];
        }
        double rms = sqrt(sum_sq / dim + eps);
        for (int i = 0; i < dim; i++) {
            output[i] = input[i] / rms;
        }
    }
    
    double end = get_time_ms();
    double total_time = end - start;
    
    /* Calculate ops/sec */
    double ops_per_iter = dim * 4; /* approx operations per rmsnorm */
    double total_ops = ops_per_iter * BENCHMARK_ITERATIONS;
    double ops_per_sec = total_ops / (total_time / 1000.0);
    
    free(input);
    free(output);
    
    return ops_per_sec / 1e6; /* Return in millions */
}

int main() {
    printf("RawrXD Performance Benchmark Runner\n");
    printf("====================================\n\n");
    
    srand((unsigned int)time(NULL));
    
    benchmark_result_t results[3];
    int num_benchmarks = 0;
    
    /* Matmul benchmark */
    printf("Running matmul benchmark (128x128)...\n");
    double matmul_gops = benchmark_matmul(128);
    results[num_benchmarks].name = "Matmul";
    results[num_benchmarks].gops = matmul_gops;
    results[num_benchmarks].passed = (matmul_gops > 0.1);
    printf("  Result: %.2f GOPS\n\n", matmul_gops);
    num_benchmarks++;
    
    /* Softmax benchmark */
    printf("Running softmax benchmark (4096 elements)...\n");
    double softmax_mops = benchmark_softmax(4096);
    results[num_benchmarks].name = "Softmax";
    results[num_benchmarks].gops = softmax_mops;
    results[num_benchmarks].passed = (softmax_mops > 0.1);
    printf("  Result: %.2f M ops/sec\n\n", softmax_mops);
    num_benchmarks++;
    
    /* RMSNorm benchmark */
    printf("Running RMSNorm benchmark (4096 elements)...\n");
    double rmsnorm_mops = benchmark_rmsnorm(4096);
    results[num_benchmarks].name = "RMSNorm";
    results[num_benchmarks].gops = rmsnorm_mops;
    results[num_benchmarks].passed = (rmsnorm_mops > 0.1);
    printf("  Result: %.2f M ops/sec\n\n", rmsnorm_mops);
    num_benchmarks++;
    
    /* Summary */
    printf("====================================\n");
    printf("Benchmark Summary\n");
    printf("====================================\n");
    
    int passed = 0;
    for (int i = 0; i < num_benchmarks; i++) {
        printf("%s: ", results[i].name);
        if (results[i].passed) {
            printf("✓ PASS (%.2f)\n", results[i].gops);
            passed++;
        } else {
            printf("✗ FAIL\n");
        }
    }
    
    printf("\nTotal: %d/%d passed\n", passed, num_benchmarks);
    
    return (passed == num_benchmarks) ? 0 : 1;
}
