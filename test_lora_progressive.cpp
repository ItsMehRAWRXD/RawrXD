// Progressive Test Harness for LoRA Kernel
// test_lora_progressive.cpp

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// External MASM functions
extern "C" {
    uint64_t ApplyLoRA_Level0();
    uint64_t ApplyLoRA_Level1(float* base, float* input, float* result, void* beacon);
    uint64_t ApplyLoRA_Level2(float* base, float* input, float* result, void* beacon);
    uint64_t ApplyLoRA_Level3(float* base, float* input, float* result, void* beacon);
    uint64_t ApplyLoRA_Level4(float* base, float* input, float* result, void* beacon);
    uint64_t ApplyLoRA_Optimized(float* base, float* input, float* result, void* beacon, uint64_t token_count);
}

// Simple beacon structure
struct alignas(64) LoRAContext {
    uint64_t magic = 0x4141524F4C;
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

int main() {
    printf("========================================\n");
    printf("LoRA Progressive Kernel Test\n");
    printf("========================================\n\n");
    
    // Allocate aligned memory
    float* base_output = (float*)_aligned_malloc(768 * sizeof(float), 32);
    float* input = (float*)_aligned_malloc(768 * sizeof(float), 32);
    float* result = (float*)_aligned_malloc(768 * sizeof(float), 32);
    
    if (!base_output || !input || !result) {
        printf("ERROR: Memory allocation failed\n");
        return 1;
    }
    
    // Initialize data
    for (int i = 0; i < 768; i++) {
        base_output[i] = (float)i * 0.001f;
        input[i] = (float)i * 0.01f;
        result[i] = 0.0f;
    }
    
    LoRAContext context;
    
    // Test Level 0: Just return
    printf("[Level 0] Just return...\n");
    uint64_t ret0 = ApplyLoRA_Level0();
    printf("  Return: %llu\n", ret0);
    printf("  Status: PASS ✓\n\n");
    
    // Test Level 1: Access parameters
    printf("[Level 1] Access parameters...\n");
    uint64_t ret1 = ApplyLoRA_Level1(base_output, input, result, &context);
    printf("  Return: %llu\n", ret1);
    printf("  Status: PASS ✓\n\n");
    
    // Test Level 2: Simple memory copy
    printf("[Level 2] Simple memory copy...\n");
    uint64_t ret2 = ApplyLoRA_Level2(base_output, input, result, &context);
    printf("  Return: %llu\n", ret2);
    // Verify copy worked
    bool copy_ok = true;
    for (int i = 0; i < 768; i++) {
        if (result[i] != input[i]) {
            copy_ok = false;
            break;
        }
    }
    printf("  Copy verification: %s\n", copy_ok ? "PASS ✓" : "FAIL ✗");
    printf("  Status: %s\n\n", (ret2 == 0 && copy_ok) ? "PASS ✓" : "FAIL ✗");
    
    // Reset result
    for (int i = 0; i < 768; i++) result[i] = 0.0f;
    
    // Test Level 3: AVX load/store
    printf("[Level 3] AVX load/store...\n");
    uint64_t ret3 = ApplyLoRA_Level3(base_output, input, result, &context);
    printf("  Return: %llu\n", ret3);
    printf("  Status: %s\n\n", (ret3 == 0) ? "PASS ✓" : "FAIL ✗");
    
    // Reset result
    for (int i = 0; i < 768; i++) result[i] = 0.0f;
    
    // Test Level 4: AVX FMA
    printf("[Level 4] AVX FMA operation...\n");
    uint64_t ret4 = ApplyLoRA_Level4(base_output, input, result, &context);
    printf("  Return: %llu\n", ret4);
    printf("  Status: %s\n\n", (ret4 == 0) ? "PASS ✓" : "FAIL ✗");
    
    // Test Level 5: Full ApplyLoRA_Optimized kernel
    printf("[Level 5] Full ApplyLoRA_Optimized kernel...\n");
    uint64_t ret5 = ApplyLoRA_Optimized(base_output, input, result, &context, 1);
    printf("  Return: %llu\n", ret5);
    printf("  Status: %s\n\n", (ret5 == 0) ? "PASS ✓" : "FAIL ✗");
    
    // Cleanup
    _aligned_free(base_output);
    _aligned_free(input);
    _aligned_free(result);
    
    printf("========================================\n");
    printf("Progressive Test Complete\n");
    printf("========================================\n");
    
    return 0;
}
