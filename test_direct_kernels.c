//==============================================================================
// test_direct_kernels.c
// Minimal test that calls kernels directly (bypassing Titan dispatch)
//
// This will tell us if the issue is:
// - Kernel loading (function pointers are null)
// - Parameter passing (struct layout mismatch)
// - Kernel implementation (kernels don't work)
//==============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <windows.h>

// Include kernel dispatch header
extern "C" {
    #include "../src/asm/Sovereign_KernelDispatch.h"
}

// Helper: Check if floats are approximately equal
int approx_equal(float a, float b, float epsilon) {
    return fabsf(a - b) < epsilon;
}

// Test 1: Direct RMSNorm call
int test_direct_rmsnorm() {
    printf("\n=== Test 1: Direct RMSNorm Call ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    
    int initResult = Sovereign_InitKernelTable(&table);
    printf("Init result: %d\n", initResult);
    
    if (!table.rms_norm_f32) {
        printf("FAIL: rms_norm_f32 is NULL\n");
        return 1;
    }
    
    printf("rms_norm_f32 pointer: %p\n", table.rms_norm_f32);
    
    // Test data
    float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float output[8] = {0};
    
    printf("Input:  ");
    for (int i = 0; i < 8; i++) printf("%.2f ", input[i]);
    printf("\n");
    
    // Call kernel directly
    printf("Calling rms_norm_f32...\n");
    int result = table.rms_norm_f32(input, output, weight, 8, 1e-6f);
    printf("Kernel returned: %d\n", result);
    
    printf("Output: ");
    for (int i = 0; i < 8; i++) printf("%.4f ", output[i]);
    printf("\n");
    
    // Verify output is normalized (RMS should be close to 1)
    float sum_sq = 0.0f;
    for (int i = 0; i < 8; i++) {
        sum_sq += output[i] * output[i];
    }
    float rms = sqrtf(sum_sq / 8.0f);
    printf("Output RMS: %.6f (expected ~1.0)\n", rms);
    
    if (approx_equal(rms, 1.0f, 0.01f)) {
        printf("PASS: RMS normalized correctly\n");
        return 0;
    } else {
        printf("FAIL: RMS not normalized (got %.6f)\n", rms);
        return 1;
    }
}

// Test 2: Direct Residual Add call
int test_direct_residual_add() {
    printf("\n=== Test 2: Direct Residual Add Call ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    if (!table.residual_add_f32) {
        printf("FAIL: residual_add_f32 is NULL\n");
        return 1;
    }
    
    printf("residual_add_f32 pointer: %p\n", table.residual_add_f32);
    
    float input[4] = {1.0f, 2.0f, 3.0f, 4.0f};
    float residual[4] = {0.5f, 0.5f, 0.5f, 0.5f};
    float output[4] = {0};
    
    printf("Calling residual_add_f32...\n");
    int result = table.residual_add_f32(input, residual, output, 4);
    printf("Kernel returned: %d\n", result);
    
    printf("Output: ");
    for (int i = 0; i < 4; i++) printf("%.2f ", output[i]);
    printf("\n");
    
    // Verify: output = input + residual
    int pass = 1;
    for (int i = 0; i < 4; i++) {
        float expected = input[i] + residual[i];
        if (!approx_equal(output[i], expected, 0.001f)) {
            printf("FAIL at %d: got %.4f, expected %.4f\n", i, output[i], expected);
            pass = 0;
        }
    }
    
    if (pass) {
        printf("PASS: All values correct\n");
        return 0;
    }
    return 1;
}

// Test 3: Check all function pointers
void test_function_pointers() {
    printf("\n=== Test 3: Function Pointer Values ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    printf("Kernel function pointers:\n");
    printf("  rms_norm_f32:              %p\n", table.rms_norm_f32);
    printf("  layer_norm_f32:            %p\n", table.layer_norm_f32);
    printf("  rope_apply_f32:            %p\n", table.rope_apply_f32);
    printf("  residual_add_f32:          %p\n", table.residual_add_f32);
    printf("  residual_add_f32_scaled:   %p\n", table.residual_add_f32_scaled);
    printf("  q4k_dequant_tensor:        %p\n", table.q4k_dequant_tensor);
    printf("  q4q8_matmul_intrinsics:   %p\n", table.q4q8_matmul_intrinsics);
    printf("  q4_0_q8_0_matmul:          %p\n", table.q4_0_q8_0_matmul);
    printf("  flash_attention_v2_intr:   %p\n", table.flash_attention_v2_intrinsics);
    printf("  flash_attention_v2_f32:    %p\n", table.flash_attention_v2_f32);
    
    int loaded = 0;
    if (table.rms_norm_f32) loaded++;
    if (table.layer_norm_f32) loaded++;
    if (table.residual_add_f32) loaded++;
    if (table.q4q8_matmul_intrinsics || table.q4_0_q8_0_matmul) loaded++;
    if (table.flash_attention_v2_intrinsics || table.flash_attention_v2_f32) loaded++;
    
    printf("\nLoaded: %d/5 critical kernels\n", loaded);
}

int main() {
    printf("==============================================================================\n");
    printf("Direct Kernel Test - Bypassing Titan Dispatch\n");
    printf("==============================================================================\n");
    
    test_function_pointers();
    
    int failures = 0;
    failures += test_direct_rmsnorm();
    failures += test_direct_residual_add();
    
    printf("\n==============================================================================\n");
    if (failures == 0) {
        printf("ALL TESTS PASSED\n");
    } else {
        printf("TESTS FAILED: %d failures\n", failures);
    }
    printf("==============================================================================\n");
    
    return failures;
}
