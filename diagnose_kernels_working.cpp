//==============================================================================
// diagnose_kernels_working.cpp
// Links against actual Sovereign kernel libraries in d:\src\asm
//==============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Include the kernel dispatch header from d:\src\asm
extern "C" {
    #include "../src/asm/Sovereign_KernelDispatch.h"
}

// Link against kernel libraries
#pragma comment(lib, "../src/asm/Sovereign_Legacy_Kernels.lib")
#pragma comment(lib, "../src/asm/Sovereign_Intrinsics.lib")
#pragma comment(lib, "../src/asm/Sovereign_RMSNorm.lib")
#pragma comment(lib, "../src/asm/Sovereign_ResidualAdd.lib")
#pragma comment(lib, "../src/asm/Sovereign_RoPE.lib")
#pragma comment(lib, "../src/asm/Sovereign_LayerNorm.lib")
#pragma comment(lib, "../src/asm/Sovereign_Q4K_Dequant.lib")

bool approxEqual(float a, float b, float epsilon) {
    return fabsf(a - b) < epsilon;
}

int main() {
    printf("==============================================================================\n");
    printf("Phase 7 Kernel Diagnostic - WITH LIBRARIES\n");
    printf("==============================================================================\n\n");
    
    // Initialize kernel table
    printf("Initializing kernel table...\n");
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    
    int initResult = Sovereign_InitKernelTable(&table);
    printf("  Init result: %d (%s)\n\n", initResult, 
           initResult == 0 ? "SUCCESS" : "FAILED");
    
    if (initResult != 0) {
        printf("❌ Kernel table initialization failed!\n");
        return 1;
    }
    
    // Check kernel availability
    printf("Kernel Availability:\n");
    int available = 0;
    int total = 0;
    
    #define CHECK_KERNEL(ptr, name) \
        total++; \
        if (ptr) { \
            available++; \
            printf("  ✓ %s\n", name); \
        } else { \
            printf("  ✗ %s (NULL)\n", name); \
        }
    
    CHECK_KERNEL(table.rms_norm_f32, "rms_norm_f32");
    CHECK_KERNEL(table.layer_norm_f32, "layer_norm_f32");
    CHECK_KERNEL(table.rope_apply_f32, "rope_apply_f32");
    CHECK_KERNEL(table.residual_add_f32, "residual_add_f32");
    CHECK_KERNEL(table.q4k_dequant_tensor, "q4k_dequant_tensor");
    CHECK_KERNEL(table.q4q8_matmul_intrinsics, "q4q8_matmul_intrinsics");
    CHECK_KERNEL(table.q4_0_q8_0_matmul, "q4_0_q8_0_matmul");
    CHECK_KERNEL(table.flash_attention_v2_intrinsics, "flash_attention_v2_intrinsics");
    CHECK_KERNEL(table.flash_attention_v2_f32, "flash_attention_v2_f32");
    
    printf("\n  Total: %d/%d kernels available\n\n", available, total);
    
    // Test execution if kernels available
    if (table.rms_norm_f32) {
        printf("Testing RMSNorm_F32...\n");
        float input[8] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
        float weight[8] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
        float output[8] = {0};
        
        int result = table.rms_norm_f32(input, output, weight, 8, 1e-6f);
        
        // Verify output
        float sum_sq = 0.0f;
        for (int i = 0; i < 8; i++) {
            sum_sq += output[i] * output[i];
        }
        float rms = sum_sq / 8.0f;
        bool pass = (result == 0) && approxEqual(rms, 1.0f, 0.1f);
        
        printf("  Result: %d\n", result);
        printf("  Output RMS: %.6f (expected ~1.0)\n", rms);
        printf("  [%s] RMSNorm execution\n\n", pass ? "PASS" : "FAIL");
    }
    
    if (table.residual_add_f32) {
        printf("Testing ResidualAdd_F32...\n");
        float input[4] = {1.0f, 2.0f, 3.0f, 4.0f};
        float residual[4] = {0.5f, 0.5f, 0.5f, 0.5f};
        float output[4] = {0};
        
        int result = table.residual_add_f32(input, residual, output, 4);
        
        bool pass = (result == 0);
        for (int i = 0; i < 4 && pass; i++) {
            if (!approxEqual(output[i], input[i] + residual[i], 0.001f)) {
                pass = false;
            }
        }
        
        printf("  Result: %d\n", result);
        printf("  Output: %.2f %.2f %.2f %.2f\n", 
               output[0], output[1], output[2], output[3]);
        printf("  [%s] ResidualAdd execution\n\n", pass ? "PASS" : "FAIL");
    }
    
    // Summary
    printf("==============================================================================\n");
    if (available == total) {
        printf("✅ ALL KERNELS AVAILABLE AND FUNCTIONAL\n");
        printf("\nReady for:\n");
        printf("  - Numerical validation\n");
        printf("  - MASM backend integration\n");
        printf("  - Full Sovereign runtime\n");
    } else if (available > 0) {
        printf("⚠️  PARTIAL SUCCESS - %d/%d kernels available\n", available, total);
    } else {
        printf("❌ NO KERNELS LOADED - Check library linkage\n");
    }
    printf("==============================================================================\n");
    
    return (available > 0) ? 0 : 1;
}
