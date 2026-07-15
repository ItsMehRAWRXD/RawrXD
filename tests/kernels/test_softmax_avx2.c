/*
 * RawrXD AVX2 Softmax Test Suite
 * Validates correctness of AVX2 softmax implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* Reference scalar softmax for validation */
void softmax_scalar(const float* input, float* output, int dim) {
    /* Find max for numerical stability */
    float max_val = input[0];
    for (int i = 1; i < dim; i++) {
        if (input[i] > max_val) max_val = input[i];
    }
    
    /* Compute exp(x - max) and sum */
    float sum = 0.0f;
    for (int i = 0; i < dim; i++) {
        output[i] = expf(input[i] - max_val);
        sum += output[i];
    }
    
    /* Normalize */
    for (int i = 0; i < dim; i++) {
        output[i] /= sum;
    }
}

/* External AVX2 implementation */
extern void softmax_avx2(const float* input, float* output, int dim);

/* Test result structure */
typedef struct {
    const char* name;
    int passed;
    double max_error;
    double time_ms;
} TestResult;

/* Run a single test */
TestResult run_test(const char* name, int dim, const float* input) {
    TestResult result = {name, 1, 0.0, 0.0};
    
    float* output_scalar = (float*)malloc(dim * sizeof(float));
    float* output_avx2 = (float*)malloc(dim * sizeof(float));
    
    if (!output_scalar || !output_avx2) {
        result.passed = 0;
        free(output_scalar);
        free(output_avx2);
        return result;
    }
    
    /* Run both implementations */
    softmax_scalar(input, output_scalar, dim);
    softmax_avx2(input, output_avx2, dim);
    
    /* Compare results */
    double max_error = 0.0;
    for (int i = 0; i < dim; i++) {
        double error = fabs(output_avx2[i] - output_scalar[i]);
        if (error > max_error) max_error = error;
    }
    
    result.max_error = max_error;
    
    /* Check if results are close enough (allow for approximation error) */
    /* Using relative tolerance since softmax outputs are probabilities */
    double tolerance = 0.01; /* 1% relative tolerance for approximate exp */
    for (int i = 0; i < dim; i++) {
        double rel_error = fabs(output_avx2[i] - output_scalar[i]) / (output_scalar[i] + 1e-10);
        if (rel_error > tolerance) {
            result.passed = 0;
            break;
        }
    }
    
    /* Additional check: sum should be close to 1.0 */
    float sum_avx2 = 0.0f;
    for (int i = 0; i < dim; i++) {
        sum_avx2 += output_avx2[i];
    }
    if (fabs(sum_avx2 - 1.0f) > 0.01f) {
        result.passed = 0;
    }
    
    free(output_scalar);
    free(output_avx2);
    
    return result;
}

int main() {
    printf("Softmax AVX2 Kernel Test Suite\n");
    printf("==============================\n\n");
    
    int num_tests = 0;
    int num_passed = 0;
    TestResult results[10];
    
    /* Test 1: Basic small dimension */
    {
        float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 3.0f, 2.0f, 1.0f, 0.0f};
        results[num_tests++] = run_test("Basic small (dim=8)", 8, input);
    }
    
    /* Test 2: Standard dimension (vocab size) */
    {
        float input[4096];
        for (int i = 0; i < 4096; i++) {
            input[i] = sinf(i * 0.01f) * 2.0f;
        }
        results[num_tests++] = run_test("Standard dim (4096)", 4096, input);
    }
    
    /* Test 3: All zeros */
    {
        float input[64];
        for (int i = 0; i < 64; i++) input[i] = 0.0f;
        results[num_tests++] = run_test("All zeros", 64, input);
    }
    
    /* Test 4: All same value */
    {
        float input[64];
        for (int i = 0; i < 64; i++) input[i] = 5.0f;
        results[num_tests++] = run_test("All same value", 64, input);
    }
    
    /* Test 5: Large positive values */
    {
        float input[64];
        for (int i = 0; i < 64; i++) input[i] = 50.0f + i;
        results[num_tests++] = run_test("Large positive values", 64, input);
    }
    
    /* Test 6: Large negative values */
    {
        float input[64];
        for (int i = 0; i < 64; i++) input[i] = -50.0f - i;
        results[num_tests++] = run_test("Large negative values", 64, input);
    }
    
    /* Test 7: Mixed positive and negative */
    {
        float input[64];
        for (int i = 0; i < 64; i++) {
            input[i] = (i % 2 == 0) ? 10.0f : -10.0f;
        }
        results[num_tests++] = run_test("Mixed +/- values", 64, input);
    }
    
    /* Test 8: Non-multiple of 8 */
    {
        float input[100];
        for (int i = 0; i < 100; i++) {
            input[i] = (float)i / 10.0f;
        }
        results[num_tests++] = run_test("Non-multiple of 8 (dim=100)", 100, input);
    }
    
    /* Test 9: Large vocab size (32K) */
    {
        float* input = (float*)malloc(32000 * sizeof(float));
        for (int i = 0; i < 32000; i++) {
            input[i] = cosf(i * 0.001f) * 5.0f;
        }
        results[num_tests++] = run_test("Large vocab (32000)", 32000, input);
        free(input);
    }
    
    /* Test 10: Single spike */
    {
        float input[256];
        for (int i = 0; i < 256; i++) input[i] = 0.0f;
        input[128] = 100.0f; /* Single large value */
        results[num_tests++] = run_test("Single spike", 256, input);
    }
    
    /* Print results table */
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║           Softmax AVX2 Test Results                            ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ %-40s %-8s %-12s ║\n", "Test", "Status", "Max Error");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    
    for (int i = 0; i < num_tests; i++) {
        const char* status = results[i].passed ? "✓ PASS" : "✗ FAIL";
        printf("║ %-40s %-8s %.2e ║\n", 
               results[i].name, status, results[i].max_error);
        if (results[i].passed) num_passed++;
    }
    
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ Total: %d | Passed: %d | Failed: %d%-26s║\n", 
           num_tests, num_passed, num_tests - num_passed, "");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    /* Performance test */
    printf("\nPerformance (dim=4096): ");
    float* perf_input = (float*)malloc(4096 * sizeof(float));
    float* perf_output = (float*)malloc(4096 * sizeof(float));
    for (int i = 0; i < 4096; i++) {
        perf_input[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
    }
    
    /* Warmup */
    for (int i = 0; i < 100; i++) {
        softmax_avx2(perf_input, perf_output, 4096);
    }
    
    /* Time it */
    clock_t start = clock();
    for (int i = 0; i < 1000; i++) {
        softmax_avx2(perf_input, perf_output, 4096);
    }
    clock_t end = clock();
    double time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    printf("%.3f ms/iter\n", time_ms / 1000.0);
    
    free(perf_input);
    free(perf_output);
    
    if (num_passed == num_tests) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed!\n");
        return 1;
    }
}
