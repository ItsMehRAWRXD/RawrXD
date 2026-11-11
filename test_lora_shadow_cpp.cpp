// LoRA Kernel Shadow Run Test - C++ Harness
// test_lora_shadow_cpp.cpp
// ============================================================================
// Validates the MASM LoRA kernel produces valid output
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <cmath>

// LoRAContext structure (64-byte aligned)
#pragma pack(push, 1)
struct LoRAContext {
    uint64_t magic;
    uint32_t rank;
    uint32_t hidden_dim;
    uint32_t input_dim;
    uint32_t reserved;
    float* matrix_A;
    float* matrix_B;
    float alpha;
    float scale;
    uint64_t status_flags;
};
#pragma pack(pop)

// External MASM function
extern "C" int ApplyLoRA_Optimized(
    float* base_output,
    float* input,
    float* result,
    LoRAContext* context,
    uint32_t token_count
);

#define HIDDEN_DIM 768
#define RANK 8

int main() {
    printf("========================================\n");
    printf("LoRA Kernel Shadow Run Test\n");
    printf("========================================\n\n");
    
    // Allocate aligned memory
    float* base_output = (float*)_aligned_malloc(HIDDEN_DIM * sizeof(float), 32);
    float* input = (float*)_aligned_malloc(HIDDEN_DIM * sizeof(float), 32);
    float* result = (float*)_aligned_malloc(HIDDEN_DIM * sizeof(float), 32);
    float* matrix_A = (float*)_aligned_malloc(HIDDEN_DIM * RANK * sizeof(float), 32);
    float* matrix_B = (float*)_aligned_malloc(HIDDEN_DIM * RANK * sizeof(float), 32);
    
    if (!base_output || !input || !result || !matrix_A || !matrix_B) {
        printf("ERROR: Memory allocation failed\n");
        return 1;
    }
    
    // Initialize data
    for (int i = 0; i < HIDDEN_DIM; i++) {
        base_output[i] = (float)i * 0.001f;
        input[i] = (float)i * 0.01f;
        result[i] = 0.0f;
    }
    
    for (int i = 0; i < HIDDEN_DIM * RANK; i++) {
        matrix_A[i] = 0.001f;
        matrix_B[i] = 0.001f;
    }
    
    // Setup context
    LoRAContext context;
    context.magic = 0x4141524F4C;  // "LORAA"
    context.rank = RANK;
    context.hidden_dim = HIDDEN_DIM;
    context.input_dim = HIDDEN_DIM;
    context.reserved = 0;
    context.matrix_A = matrix_A;
    context.matrix_B = matrix_B;
    context.alpha = 1.0f;
    context.scale = 1.0f;
    context.status_flags = 0;
    
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
    
    if (ret != 0) {
        printf("ERROR: Kernel returned non-zero: %d\n", ret);
        _aligned_free(base_output);
        _aligned_free(input);
        _aligned_free(result);
        _aligned_free(matrix_A);
        _aligned_free(matrix_B);
        return 1;
    }
    
    // Verify results
    printf("Result verification (first 8 values):\n");
    for (int i = 0; i < 8 && i < HIDDEN_DIM; i++) {
        printf("  result[%d] = %.6f\n", i, result[i]);
    }
    printf("\n");
    
    // Check for NaN or Inf
    bool has_nan = false;
    bool has_inf = false;
    int nan_count = 0;
    int inf_count = 0;
    
    for (int i = 0; i < HIDDEN_DIM; i++) {
        if (std::isnan(result[i])) {
            has_nan = true;
            nan_count++;
        }
        if (std::isinf(result[i])) {
            has_inf = true;
            inf_count++;
        }
    }
    
    printf("Validation results:\n");
    printf("  Total elements: %d\n", HIDDEN_DIM);
    printf("  NaN count: %d\n", nan_count);
    printf("  Inf count: %d\n", inf_count);
    printf("\n");
    
    // Cleanup
    _aligned_free(base_output);
    _aligned_free(input);
    _aligned_free(result);
    _aligned_free(matrix_A);
    _aligned_free(matrix_B);
    
    if (has_nan || has_inf) {
        printf("SHADOW RUN FAILED: Invalid values detected\n");
        return 2;
    }
    
    printf("SHADOW RUN PASSED: Kernel executed successfully\n");
    printf("  - Return code: 0\n");
    printf("  - No NaN/Inf detected\n");
    printf("  - Execution time: %.2f us\n", elapsed_us);
    printf("\n");
    
    return 0;
}
