// Diagnostic Test Harness for LoRA Kernel
// test_lora_diagnostic.cpp

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Return codes from diagnostic kernel
#define RET_SUCCESS      0
#define RET_NULL_PTR     1
#define RET_ALIGN_ERROR  2
#define RET_MAGIC_FAIL   3

// LoRAContext structure (must match MASM layout)
struct alignas(64) LoRAContext {
    uint64_t magic = 0x4141524F4C;  // "LORAA"
    uint32_t rank = 8;
    uint32_t hidden_dim = 768;
    uint32_t input_dim = 768;
    uint32_t reserved = 0;
    float* matrix_A = nullptr;
    float* matrix_B = nullptr;
    float alpha = 1.0f;
    float scale = 1.0f;
    uint64_t status_flags = 0;
};

// External MASM function
extern "C" uint64_t ApplyLoRA_Diagnostic(
    float* base_output,
    float* input,
    float* result,
    LoRAContext* context,
    uint32_t token_count
);

const char* GetErrorString(uint64_t code) {
    switch (code) {
        case RET_SUCCESS:     return "SUCCESS";
        case RET_NULL_PTR:    return "NULL POINTER";
        case RET_ALIGN_ERROR: return "ALIGNMENT ERROR";
        case RET_MAGIC_FAIL:  return "MAGIC NUMBER MISMATCH";
        default:              return "UNKNOWN ERROR";
    }
}

int main() {
    printf("========================================\n");
    printf("LoRA Diagnostic Kernel Test\n");
    printf("========================================\n\n");
    
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
    printf("  Magic: 0x%llX (expected: 0x4141524F4C)\n", context.magic);
    printf("  Rank: %u\n", context.rank);
    printf("  Hidden Dim: %u\n", context.hidden_dim);
    printf("  Matrix A: %p\n", (void*)context.matrix_A);
    printf("  Matrix B: %p\n", (void*)context.matrix_B);
    printf("  Context size: %zu bytes\n\n", sizeof(LoRAContext));
    
    // Test 1: Valid call
    printf("[Test 1] Valid call...\n");
    uint64_t ret1 = ApplyLoRA_Diagnostic(base_output, input, result, &context, 1);
    printf("  Return: %llu (%s)\n", ret1, GetErrorString(ret1));
    if (ret1 == RET_SUCCESS) {
        printf("  Status: PASS ✓\n\n");
    } else {
        printf("  Status: FAIL ✗\n\n");
    }
    
    // Test 2: NULL pointer
    printf("[Test 2] NULL pointer test...\n");
    uint64_t ret2 = ApplyLoRA_Diagnostic(nullptr, input, result, &context, 1);
    printf("  Return: %llu (%s)\n", ret2, GetErrorString(ret2));
    if (ret2 == RET_NULL_PTR) {
        printf("  Status: PASS ✓ (correctly detected NULL)\n\n");
    } else {
        printf("  Status: FAIL ✗\n\n");
    }
    
    // Test 3: Bad magic
    printf("[Test 3] Bad magic number...\n");
    LoRAContext bad_context = context;
    bad_context.magic = 0xDEADBEEF;
    uint64_t ret3 = ApplyLoRA_Diagnostic(base_output, input, result, &bad_context, 1);
    printf("  Return: %llu (%s)\n", ret3, GetErrorString(ret3));
    if (ret3 == RET_MAGIC_FAIL) {
        printf("  Status: PASS ✓ (correctly detected bad magic)\n\n");
    } else {
        printf("  Status: FAIL ✗\n\n");
    }
    
    // Cleanup
    _aligned_free(base_output);
    _aligned_free(input);
    _aligned_free(result);
    _aligned_free(matrix_A);
    _aligned_free(matrix_B);
    
    printf("========================================\n");
    printf("Diagnostic Test Complete\n");
    printf("========================================\n");
    
    return (ret1 == RET_SUCCESS) ? 0 : 1;
}
