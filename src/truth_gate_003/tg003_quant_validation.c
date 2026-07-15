/*
 * Truth Gate 003 - Phase 1: Quantization Validation Harness
 * 
 * Compares RawrXD dequantization against reference values
 * from llama.cpp or known-good sources.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

/* Validation metrics */
typedef struct {
    float max_abs_error;
    float mean_squared_error;
    float mean_abs_error;
    float relative_error;
    int num_samples;
} validation_metrics_t;

/* Calculate validation metrics */
void calculate_metrics(const float *reference, const float *test, 
                       int n, validation_metrics_t *metrics) {
    double max_err = 0.0;
    double mse = 0.0;
    double mae = 0.0;
    double rel_err = 0.0;
    int rel_count = 0;
    
    for (int i = 0; i < n; i++) {
        double err = fabs(reference[i] - test[i]);
        
        if (err > max_err) max_err = err;
        mse += err * err;
        mae += err;
        
        /* Relative error (avoid div by zero) */
        if (fabs(reference[i]) > 1e-6) {
            rel_err += err / fabs(reference[i]);
            rel_count++;
        }
    }
    
    metrics->max_abs_error = (float)max_err;
    metrics->mean_squared_error = (float)(mse / n);
    metrics->mean_abs_error = (float)(mae / n);
    metrics->relative_error = rel_count > 0 ? (float)(rel_err / rel_count) : 0.0f;
    metrics->num_samples = n;
}

/* Print metrics */
void print_metrics(const validation_metrics_t *m) {
    printf("Validation Metrics (%d samples):\n", m->num_samples);
    printf("  Max Absolute Error:  %.6f\n", m->max_abs_error);
    printf("  Mean Squared Error:  %.6f\n", m->mean_squared_error);
    printf("  Mean Absolute Error: %.6f\n", m->mean_abs_error);
    printf("  Relative Error:      %.6f%%\n", m->relative_error * 100.0f);
}

/* Check if metrics pass tolerance */
int check_tolerance(const validation_metrics_t *m, 
                    float max_abs_tol, float mse_tol, float rel_tol) {
    int pass = 1;
    
    printf("\nTolerance Check:\n");
    printf("  Max Abs Error: %.6f <= %.6f ", m->max_abs_error, max_abs_tol);
    if (m->max_abs_error > max_abs_tol) {
        printf("[FAIL]\n");
        pass = 0;
    } else {
        printf("[PASS]\n");
    }
    
    printf("  MSE:           %.6f <= %.6f ", m->mean_squared_error, mse_tol);
    if (m->mean_squared_error > mse_tol) {
        printf("[FAIL]\n");
        pass = 0;
    } else {
        printf("[PASS]\n");
    }
    
    printf("  Rel Error:     %.2f%% <= %.2f%% ", m->relative_error * 100.0f, rel_tol * 100.0f);
    if (m->relative_error > rel_tol) {
        printf("[FAIL]\n");
        pass = 0;
    } else {
        printf("[PASS]\n");
    }
    
    return pass;
}

/* Generate synthetic reference data for testing */
void generate_synthetic_reference(float *data, int n, int type) {
    switch (type) {
        case 0: /* Linear ramp */
            for (int i = 0; i < n; i++) {
                data[i] = (float)i / n;
            }
            break;
        case 1: /* Sine wave */
            for (int i = 0; i < n; i++) {
                data[i] = sinf(2.0f * 3.14159f * i / n);
            }
            break;
        case 2: /* Random small values */
            for (int i = 0; i < n; i++) {
                data[i] = ((float)(i % 17) - 8.0f) / 16.0f;
            }
            break;
        default:
            memset(data, 0, n * sizeof(float));
    }
}

/* Simulate quantization error */
void simulate_quantization(const float *input, float *output, int n, int bits) {
    int levels = 1 << bits; /* 2^bits levels */
    
    /* Find range */
    float min_val = input[0], max_val = input[0];
    for (int i = 1; i < n; i++) {
        if (input[i] < min_val) min_val = input[i];
        if (input[i] > max_val) max_val = input[i];
    }
    
    float scale = (max_val - min_val) / (levels - 1);
    
    for (int i = 0; i < n; i++) {
        int q = (int)((input[i] - min_val) / scale + 0.5f);
        if (q >= levels) q = levels - 1;
        output[i] = min_val + q * scale;
    }
}

/* Test harness */
void test_validation_harness() {
    printf("Truth Gate 003 - Phase 1: Quantization Validation Harness\n");
    printf("===========================================================\n\n");
    
    const int N = 256;
    float reference[N];
    float test[N];
    validation_metrics_t metrics;
    
    /* Test 1: Perfect match */
    printf("Test 1: Perfect match\n");
    generate_synthetic_reference(reference, N, 0);
    memcpy(test, reference, N * sizeof(float));
    calculate_metrics(reference, test, N, &metrics);
    print_metrics(&metrics);
    check_tolerance(&metrics, 0.001f, 0.000001f, 0.01f);
    
    /* Test 2: Simulated Q4_0 error */
    printf("\nTest 2: Simulated Q4_0 quantization (4-bit)\n");
    generate_synthetic_reference(reference, N, 2);
    simulate_quantization(reference, test, N, 4);
    calculate_metrics(reference, test, N, &metrics);
    print_metrics(&metrics);
    check_tolerance(&metrics, 0.5f, 0.1f, 0.5f);
    
    /* Test 3: Simulated Q4_K error (better precision) */
    printf("\nTest 3: Simulated Q4_K quantization (4-bit with block scales)\n");
    generate_synthetic_reference(reference, N, 2);
    /* Q4_K has better precision due to per-block scaling */
    for (int i = 0; i < N; i++) {
        float noise = ((float)(i % 5) - 2.0f) / 256.0f; /* Small noise */
        test[i] = reference[i] + noise;
    }
    calculate_metrics(reference, test, N, &metrics);
    print_metrics(&metrics);
    check_tolerance(&metrics, 0.1f, 0.001f, 0.1f);
    
    printf("\n===========================================================\n");
    printf("Validation harness ready for real model comparison\n");
    printf("Next: Load real Q4_K tensor from tinyllama-1.1b.Q4_K_M.gguf\n");
}

int main() {
    test_validation_harness();
    return 0;
}
