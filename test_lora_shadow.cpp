// Simple test harness for LoRA kernel
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// LoRAContext structure (64-byte aligned)
struct alignas(64) LoRAContext {
    uint64_t magic = 0x4141524F4C;  // "LORAA"
    uint32_t rank = 8;
    uint32_t hidden_dim = 768;
    uint32_t input_dim = 768;
    uint32_t reserved;
    float* matrix_A = nullptr;
    float* matrix_B = nullptr;
    float alpha = 1.0f;
    float scale = 1.0f;
    uint64_t status_flags = 0;
};

// External MASM function
extern "C" int ApplyLoRA_Optimized(
    float* base_output,
    float* input,
    float* result,
    LoRAContext* context,
    uint32_t token_count
);

int main() {
    printf("LoRA Kernel Shadow Run Test\n");
    printf("===========================\n\n");
    
    // Allocate aligned memory
    float* base_output = (float*)_aligned_malloc(768 * sizeof(float), 32);
    float* input = (float*)_aligned_malloc(768 * sizeof(float), 32);
    float* result = (float*)_aligned_malloc(768 * sizeof(float), 32);
    float* matrix_A = (float*)_aligned_malloc(768 * 8 * sizeof(float), 32);
    float* matrix_B = (float*)_aligned_malloc(768 * 8 * sizeof(float), 32);
    
    if (!base_output || !input || !result || !matrix_A || !matrix_B) {
        printf("ERROR: Memory allocation failed\n");
        return 1;
    }
    
    // Initialize data
    for (int i = 0; i < 768; i++) {
        base_output[i] = (float)i * 0.001f;
        input[i] = (float)i * 0.01f;
        result[i] = 0.0f;
    }
    
    for (int i = 0; i < 768 * 8; i++) {
        matrix_A[i] = 0.001f;
        matrix_B[i] = 0.001f;
    }
    
    // Setup context
    LoRAContext context;
    context.matrix_A = matrix_A;
    context.matrix_B = matrix_B;
    
    printf("Context setup:\n");
    printf("  Magic: 0x%llX\n", context.magic);
    printf("  Rank: %u\n", context.rank);
    printf("  Hidden dim: %u\n", context.hidden_dim);
    printf("  Alpha: %.4f\n", context.alpha);
    printf("\n");
    
    // Run kernel
    printf("Running ApplyLoRA_Optimized...\n");
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    int ret = ApplyLoRA_Optimized(base_output, input, result, &context, 1);
    
    QueryPerformanceCounter(&end);
    double elapsed_us = ((double)(end.QuadPart - start.QuadPart) * 1000000.0) / freq.QuadPart;
    
    printf("  Return code: %d\n", ret);
    printf("  Execution time: %.2f us\n", elapsed_us);
    printf("\n");
    
    // Verify results
    printf("Result verification (first 8 values):\n");
    for (int i = 0; i < 8; i++) {
        printf("  result[%d] = %.6f\n", i, result[i]);
    }
    printf("\n");
    
    // Check for NaN or Inf
    bool has_nan = false;
    bool has_inf = false;
    for (int i = 0; i < 768; i++) {
        if (result[i] != result[i]) has_nan = true;
        if (result[i] == INFINITY || result[i] == -INFINITY) has_inf = true;
    }
    
    if (has_nan) printf("WARNING: Result contains NaN values!\n");
    if (has_inf) printf("WARNING: Result contains Inf values!\n");
    
    if (!has_nan && !has_inf) {
        printf("\u2713 Shadow Run PASSED: No NaN/Inf detected\n");
    }
    
    // Cleanup
    _aligned_free(base_output);
    _aligned_free(input);
    _aligned_free(result);
    _aligned_free(matrix_A);
    _aligned_free(matrix_B);
    
    printf("\nTest complete.\n");
    return 0;
}
