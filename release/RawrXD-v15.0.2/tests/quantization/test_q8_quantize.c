/*
 * RawrXD Q8 Quantization Test Suite
 * Validates correctness of Q8 quantization/dequantization
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* Include the Q8 header */
#include "../../src/quantization/q8_quantize.h"

/* External AVX2 functions */
extern void q8_quantize_block_avx2(const float* input, q8_block_t* block, int size);
extern void q8_dequantize_block_avx2(const q8_block_t* block, float* output, int size);

/* Test result structure */
typedef struct {
    const char* name;
    int passed;
    double max_error;
    double snr;  /* Signal-to-noise ratio */
} TestResult;

/* Calculate SNR between original and reconstructed */
double calculate_snr(const float* original, const float* reconstructed, int size) {
    double signal_power = 0.0;
    double noise_power = 0.0;
    
    for (int i = 0; i < size; i++) {
        signal_power += original[i] * original[i];
        double error = original[i] - reconstructed[i];
        noise_power += error * error;
    }
    
    if (noise_power < 1e-20) return 100.0;  /* Perfect reconstruction */
    return 10.0 * log10(signal_power / noise_power);
}

/* Run quantization test */
TestResult run_quantize_test(const char* name, const float* input, int size) {
    TestResult result = {name, 1, 0.0, 0.0};
    
    q8_block_t block_scalar, block_avx2;
    float* output_scalar = (float*)malloc(size * sizeof(float));
    float* output_avx2 = (float*)malloc(size * sizeof(float));
    
    if (!output_scalar || !output_avx2) {
        result.passed = 0;
        free(output_scalar);
        free(output_avx2);
        return result;
    }
    
    /* Quantize with both methods */
    q8_quantize_block(input, &block_scalar, size);
    q8_quantize_block_avx2(input, &block_avx2, size);
    
    /* Dequantize with both methods */
    q8_dequantize_block(&block_scalar, output_scalar, size);
    q8_dequantize_block_avx2(&block_avx2, output_avx2, size);
    
    /* Compare scalar vs AVX2 */
    double max_error = 0.0;
    for (int i = 0; i < size; i++) {
        double error = fabs(output_avx2[i] - output_scalar[i]);
        if (error > max_error) max_error = error;
    }
    result.max_error = max_error;
    
    /* Calculate SNR for AVX2 vs original */
    result.snr = calculate_snr(input, output_avx2, size);
    
    /* Check if results match (within tolerance) */
    /* Allow small difference due to rounding differences */
    double tolerance = 1e-4;
    for (int i = 0; i < size; i++) {
        if (fabs(output_avx2[i] - output_scalar[i]) > tolerance) {
            result.passed = 0;
            break;
        }
    }
    
    /* Additional check: SNR should be reasonable (> 30 dB) */
    if (result.snr < 30.0 && result.snr > 0) {
        result.passed = 0;
    }
    
    free(output_scalar);
    free(output_avx2);
    
    return result;
}

int main() {
    printf("Q8 Quantization Test Suite\n");
    printf("==========================\n\n");
    
    srand((unsigned int)time(NULL));
    
    int num_tests = 0;
    int num_passed = 0;
    TestResult results[20];
    
    /* Test 1: Basic small block (32 elements) */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = (float)i / 16.0f - 1.0f;
        results[num_tests++] = run_quantize_test("Basic block (32)", input, 32);
    }
    
    /* Test 2: All zeros */
    {
        float input[32] = {0};
        results[num_tests++] = run_quantize_test("All zeros", input, 32);
    }
    
    /* Test 3: All ones */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = 1.0f;
        results[num_tests++] = run_quantize_test("All ones", input, 32);
    }
    
    /* Test 4: Alternating signs */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = (i % 2 == 0) ? 1.0f : -1.0f;
        results[num_tests++] = run_quantize_test("Alternating signs", input, 32);
    }
    
    /* Test 5: Large values */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = 100.0f * sinf(i * 0.5f);
        results[num_tests++] = run_quantize_test("Large values", input, 32);
    }
    
    /* Test 6: Small values */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = 0.001f * i;
        results[num_tests++] = run_quantize_test("Small values", input, 32);
    }
    
    /* Test 7: Sine wave */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = sinf(i * 0.2f);
        results[num_tests++] = run_quantize_test("Sine wave", input, 32);
    }
    
    /* Test 8: Random values */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
        results[num_tests++] = run_quantize_test("Random values", input, 32);
    }
    
    /* Test 9: Single spike */
    {
        float input[32] = {0};
        input[16] = 10.0f;
        results[num_tests++] = run_quantize_test("Single spike", input, 32);
    }
    
    /* Test 10: Gradient */
    {
        float input[32];
        for (int i = 0; i < 32; i++) input[i] = (float)i;
        results[num_tests++] = run_quantize_test("Gradient", input, 32);
    }
    
    /* Test 11: Large block (256 elements) */
    {
        float input[256];
        for (int i = 0; i < 256; i++) {
            input[i] = sinf(i * 0.1f) * cosf(i * 0.05f);
        }
        results[num_tests++] = run_quantize_test("Large block (256)", input, 256);
    }
    
    /* Test 12: Non-full block (20 elements) */
    {
        float input[20];
        for (int i = 0; i < 20; i++) input[i] = (float)i / 10.0f - 1.0f;
        results[num_tests++] = run_quantize_test("Non-full block (20)", input, 20);
    }
    
    /* Print results table */
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║           Q8 Quantization Test Results                         ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ %-35s %-8s %-10s %-8s ║\n", "Test", "Status", "Max Error", "SNR (dB)");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    
    for (int i = 0; i < num_tests; i++) {
        const char* status = results[i].passed ? "✓ PASS" : "✗ FAIL";
        printf("║ %-35s %-8s %.2e %8.2f ║\n", 
               results[i].name, status, results[i].max_error, results[i].snr);
        if (results[i].passed) num_passed++;
    }
    
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ Total: %d | Passed: %d | Failed: %d%-29s║\n", 
           num_tests, num_passed, num_tests - num_passed, "");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    /* Performance comparison */
    printf("\nPerformance Comparison (quantizing 1M floats):\n");
    printf("----------------------------------------------\n");
    
    float* perf_input = (float*)malloc(1000000 * sizeof(float));
    for (int i = 0; i < 1000000; i++) {
        perf_input[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
    }
    
    int num_blocks = q8_calculate_num_blocks(1000000);
    q8_block_t* blocks_scalar = (q8_block_t*)malloc(num_blocks * sizeof(q8_block_t));
    q8_block_t* blocks_avx2 = (q8_block_t*)malloc(num_blocks * sizeof(q8_block_t));
    
    /* Warmup */
    for (int i = 0; i < 10; i++) {
        for (int b = 0; b < num_blocks; b++) {
            q8_quantize_block(perf_input + b * 32, &blocks_scalar[b], 32);
            q8_quantize_block_avx2(perf_input + b * 32, &blocks_avx2[b], 32);
        }
    }
    
    /* Time scalar */
    clock_t start = clock();
    for (int iter = 0; iter < 10; iter++) {
        for (int b = 0; b < num_blocks; b++) {
            q8_quantize_block(perf_input + b * 32, &blocks_scalar[b], 32);
        }
    }
    clock_t end = clock();
    double scalar_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    /* Time AVX2 */
    start = clock();
    for (int iter = 0; iter < 10; iter++) {
        for (int b = 0; b < num_blocks; b++) {
            q8_quantize_block_avx2(perf_input + b * 32, &blocks_avx2[b], 32);
        }
    }
    end = clock();
    double avx2_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    printf("Scalar:  %.2f ms (%.2f MB/s)\n", scalar_time, 
           (1000000 * sizeof(float)) / (scalar_time / 10.0) / 1000.0);
    printf("AVX2:    %.2f ms (%.2f MB/s)\n", avx2_time,
           (1000000 * sizeof(float)) / (avx2_time / 10.0) / 1000.0);
    printf("Speedup: %.2fx\n", scalar_time / avx2_time);
    
    free(perf_input);
    free(blocks_scalar);
    free(blocks_avx2);
    
    if (num_passed == num_tests) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed!\n");
        return 1;
    }
}
