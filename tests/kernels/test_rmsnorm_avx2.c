/*
 * Test suite for AVX2 RMSNorm kernel
 * Validates correctness against scalar reference implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #define aligned_malloc(size, align) _aligned_malloc(size, align)
    #define aligned_free(ptr) _aligned_free(ptr)
#else
    #include <stdlib.h>
    #define aligned_malloc(size, align) aligned_alloc(align, size)
    #define aligned_free(ptr) free(ptr)
#endif

/* Reference scalar RMSNorm */
void rmsnorm_scalar(const float* input, float* output, int dim, float eps) {
    float sum_sq = 0.0f;
    for (int i = 0; i < dim; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = sqrtf(sum_sq / dim + eps);
    float inv_rms = 1.0f / rms;
    for (int i = 0; i < dim; i++) {
        output[i] = input[i] * inv_rms;
    }
}

/* External AVX2 implementation */
extern void rmsnorm_avx2(const float* input, float* output, int dim, float eps);
extern double benchmark_rmsnorm_avx2(int dim, int iterations);

/* Test result structure */
typedef struct {
    const char* name;
    int passed;
    float max_error;
    float mean_error;
    double execution_time_ms;
} TestResult;

/* Compare two arrays and compute error metrics */
void compute_errors(const float* expected, const float* actual, int dim,
                    float* max_error, float* mean_error) {
    float max_err = 0.0f;
    float sum_err = 0.0f;
    
    for (int i = 0; i < dim; i++) {
        float err = fabsf(expected[i] - actual[i]);
        if (err > max_err) max_err = err;
        sum_err += err;
    }
    
    *max_error = max_err;
    *mean_error = sum_err / dim;
}

/* Test 1: Basic functionality with small dimension */
TestResult test_basic_small(void) {
    TestResult result = {"Basic small (dim=8)", 0, 0.0f, 0.0f, 0.0};
    
    int dim = 8;
    float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float output_avx2[8];
    float output_scalar[8];
    float eps = 1e-6f;
    
    rmsnorm_scalar(input, output_scalar, dim, eps);
    rmsnorm_avx2(input, output_avx2, dim, eps);
    
    compute_errors(output_scalar, output_avx2, dim, 
                   &result.max_error, &result.mean_error);
    
    /* Pass if max error < 1e-5 (reasonable for float32) */
    result.passed = (result.max_error < 1e-5f);
    
    return result;
}

/* Test 2: Standard dimension (4096 - common for LLMs) */
TestResult test_standard_dim(void) {
    TestResult result = {"Standard dim (4096)", 0, 0.0f, 0.0f, 0.0};
    
    int dim = 4096;
    float* input = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_avx2 = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_scalar = (float*)aligned_malloc(dim * sizeof(float), 32);
    
    if (!input || !output_avx2 || !output_scalar) {
        aligned_free(input);
        aligned_free(output_avx2);
        aligned_free(output_scalar);
        return result;
    }
    
    /* Initialize with random values */
    srand(42);
    for (int i = 0; i < dim; i++) {
        input[i] = (float)rand() / RAND_MAX * 2.0f - 1.0f;
    }
    
    float eps = 1e-6f;
    
    /* Time the AVX2 version */
    clock_t start = clock();
    rmsnorm_avx2(input, output_avx2, dim, eps);
    clock_t end = clock();
    result.execution_time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    /* Compute scalar reference */
    rmsnorm_scalar(input, output_scalar, dim, eps);
    
    compute_errors(output_scalar, output_avx2, dim,
                   &result.max_error, &result.mean_error);
    
    result.passed = (result.max_error < 1e-5f);
    
    aligned_free(input);
    aligned_free(output_avx2);
    aligned_free(output_scalar);
    
    return result;
}

/* Test 3: Edge case - all zeros */
TestResult test_all_zeros(void) {
    TestResult result = {"All zeros", 0, 0.0f, 0.0f, 0.0};
    
    int dim = 256;
    float* input = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_avx2 = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_scalar = (float*)aligned_malloc(dim * sizeof(float), 32);
    
    if (!input || !output_avx2 || !output_scalar) {
        aligned_free(input);
        aligned_free(output_avx2);
        aligned_free(output_scalar);
        return result;
    }
    
    memset(input, 0, dim * sizeof(float));
    float eps = 1e-6f;
    
    rmsnorm_scalar(input, output_scalar, dim, eps);
    rmsnorm_avx2(input, output_avx2, dim, eps);
    
    compute_errors(output_scalar, output_avx2, dim,
                   &result.max_error, &result.mean_error);
    
    /* With epsilon, zeros should produce near-zero outputs */
    result.passed = (result.max_error < 1e-5f);
    
    aligned_free(input);
    aligned_free(output_avx2);
    aligned_free(output_scalar);
    
    return result;
}

/* Test 4: Edge case - all ones */
TestResult test_all_ones(void) {
    TestResult result = {"All ones", 0, 0.0f, 0.0f, 0.0};
    
    int dim = 256;
    float* input = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_avx2 = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_scalar = (float*)aligned_malloc(dim * sizeof(float), 32);
    
    if (!input || !output_avx2 || !output_scalar) {
        aligned_free(input);
        aligned_free(output_avx2);
        aligned_free(output_scalar);
        return result;
    }
    
    for (int i = 0; i < dim; i++) {
        input[i] = 1.0f;
    }
    
    float eps = 1e-6f;
    
    rmsnorm_scalar(input, output_scalar, dim, eps);
    rmsnorm_avx2(input, output_avx2, dim, eps);
    
    compute_errors(output_scalar, output_avx2, dim,
                   &result.max_error, &result.mean_error);
    
    result.passed = (result.max_error < 1e-5f);
    
    aligned_free(input);
    aligned_free(output_avx2);
    aligned_free(output_scalar);
    
    return result;
}

/* Test 5: Non-multiple of 8 dimension */
TestResult test_non_multiple_of_8(void) {
    TestResult result = {"Non-multiple of 8 (dim=100)", 0, 0.0f, 0.0f, 0.0};
    
    int dim = 100;  /* Not divisible by 8 */
    float* input = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_avx2 = (float*)aligned_malloc(dim * sizeof(float), 32);
    float* output_scalar = (float*)aligned_malloc(dim * sizeof(float), 32);
    
    if (!input || !output_avx2 || !output_scalar) {
        aligned_free(input);
        aligned_free(output_avx2);
        aligned_free(output_scalar);
        return result;
    }
    
    srand(42);
    for (int i = 0; i < dim; i++) {
        input[i] = (float)rand() / RAND_MAX;
    }
    
    float eps = 1e-6f;
    
    rmsnorm_scalar(input, output_scalar, dim, eps);
    rmsnorm_avx2(input, output_avx2, dim, eps);
    
    compute_errors(output_scalar, output_avx2, dim,
                   &result.max_error, &result.mean_error);
    
    result.passed = (result.max_error < 1e-5f);
    
    aligned_free(input);
    aligned_free(output_avx2);
    aligned_free(output_scalar);
    
    return result;
}

/* Print test results */
void print_results(TestResult* results, int count) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║           RMSNorm AVX2 Test Results                            ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ %-40s %8s %12s ║\n", "Test", "Status", "Max Error");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    
    int passed = 0;
    int failed = 0;
    
    for (int i = 0; i < count; i++) {
        const char* status = results[i].passed ? "✓ PASS" : "✗ FAIL";
        printf("║ %-40s %8s %12.2e ║\n", 
               results[i].name, status, results[i].max_error);
        
        if (results[i].passed) passed++;
        else failed++;
    }
    
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ Total: %d | Passed: %d | Failed: %d                              ║\n", 
           count, passed, failed);
    printf("╚════════════════════════════════════════════════════════════════╝\n");
}

int main(void) {
    printf("RMSNorm AVX2 Kernel Test Suite\n");
    printf("==============================\n\n");
    
    /* Run all tests */
    TestResult results[5];
    results[0] = test_basic_small();
    results[1] = test_standard_dim();
    results[2] = test_all_zeros();
    results[3] = test_all_ones();
    results[4] = test_non_multiple_of_8();
    
    /* Print results */
    print_results(results, 5);
    
    /* Print timing info for standard dimension */
    printf("\nPerformance (dim=4096): %.3f ms\n", results[1].execution_time_ms);
    
    /* Return 0 if all passed, 1 otherwise */
    for (int i = 0; i < 5; i++) {
        if (!results[i].passed) return 1;
    }
    
    printf("\n✓ All tests passed!\n");
    return 0;
}
