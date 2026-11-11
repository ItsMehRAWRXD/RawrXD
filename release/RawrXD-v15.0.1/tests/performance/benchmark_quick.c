/*
 * RawrXD Quick Performance Benchmark
 * Fast benchmark with minimal iterations
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

int main() {
    printf("RawrXD Quick Performance Benchmark\n");
    printf("===================================\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* Matmul 64x64 - quick test */
    printf("Matmul (64x64): ");
    int dim = 64;
    int iter = 50;
    
    double* A = (double*)malloc(dim * dim * sizeof(double));
    double* B = (double*)malloc(dim * dim * sizeof(double));
    double* C = (double*)malloc(dim * dim * sizeof(double));
    
    if (A && B && C) {
        for (int i = 0; i < dim * dim; i++) {
            A[i] = (double)rand() / RAND_MAX;
            B[i] = (double)rand() / RAND_MAX;
        }
        
        clock_t start = clock();
        for (int n = 0; n < iter; n++) {
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
        clock_t end = clock();
        
        double time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
        double ops = 2.0 * dim * dim * dim * iter;
        double gops = (ops / (time_ms / 1000.0)) / 1e9;
        
        printf("%.2f GOPS (%.1f ms)\n", gops, time_ms);
    }
    
    free(A); free(B); free(C);
    
    /* Softmax quick test */
    printf("Softmax (1024): ");
    int dim_s = 1024;
    int iter_s = 100;
    
    double* input = (double*)malloc(dim_s * sizeof(double));
    double* output = (double*)malloc(dim_s * sizeof(double));
    
    if (input && output) {
        for (int i = 0; i < dim_s; i++) {
            input[i] = (double)rand() / RAND_MAX;
        }
        
        clock_t start = clock();
        for (int n = 0; n < iter_s; n++) {
            double max_val = input[0];
            for (int i = 1; i < dim_s; i++) {
                if (input[i] > max_val) max_val = input[i];
            }
            double sum = 0.0;
            for (int i = 0; i < dim_s; i++) {
                output[i] = exp(input[i] - max_val);
                sum += output[i];
            }
            for (int i = 0; i < dim_s; i++) {
                output[i] /= sum;
            }
        }
        clock_t end = clock();
        
        double time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
        double ops_per_sec = (dim_s * 6.0 * iter_s) / (time_ms / 1000.0);
        
        printf("%.2f M ops/sec (%.1f ms)\n", ops_per_sec / 1e6, time_ms);
    }
    
    free(input); free(output);
    
    /* RMSNorm quick test */
    printf("RMSNorm (1024): ");
    int dim_r = 1024;
    int iter_r = 100;
    
    input = (double*)malloc(dim_r * sizeof(double));
    output = (double*)malloc(dim_r * sizeof(double));
    
    if (input && output) {
        for (int i = 0; i < dim_r; i++) {
            input[i] = (double)rand() / RAND_MAX;
        }
        
        clock_t start = clock();
        for (int n = 0; n < iter_r; n++) {
            double sum_sq = 0.0;
            for (int i = 0; i < dim_r; i++) {
                sum_sq += input[i] * input[i];
            }
            double rms = sqrt(sum_sq / dim_r + 1e-6);
            for (int i = 0; i < dim_r; i++) {
                output[i] = input[i] / rms;
            }
        }
        clock_t end = clock();
        
        double time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
        double time_sec = time_ms / 1000.0;
        if (time_sec < 0.001) time_sec = 0.001; /* Prevent div by zero */
        double ops_per_sec = (dim_r * 4.0 * iter_r) / time_sec;
        
        printf("%.2f M ops/sec (%.2f ms)\n", ops_per_sec / 1e6, time_ms);
    }
    
    free(input); free(output);
    
    printf("\n===================================\n");
    printf("✓ Benchmarks complete\n");
    
    return 0;
}
