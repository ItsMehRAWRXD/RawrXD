//==============================================================================
// cli_minimal.cpp
// Minimal CLI for Phase 7C.2 Integration Testing
//
// This is a simplified version that tests the core integration using
// the Sovereign Kernel Dispatch table approach.
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>

// Include the kernel dispatch header
#include "d:/src/asm/Sovereign_KernelDispatch.h"

// Link against kernel libraries
#pragma comment(lib, "d:/src/asm/Sovereign_Legacy_Kernels.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_Intrinsics.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_RMSNorm.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_ResidualAdd.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_RoPE.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_LayerNorm.lib")
#pragma comment(lib, "d:/src/asm/Sovereign_Q4K_Dequant.lib")

//==============================================================================
// Test Functions
//==============================================================================

void printBanner() {
    printf("==============================================================================\n");
    printf("Sovereign CLI - Phase 7C.2 Minimal Integration Test\n");
    printf("==============================================================================\n\n");
}

bool approxEqual(float a, float b, float epsilon) {
    return fabsf(a - b) < epsilon;
}

int testKernelAvailability() {
    printf("[Test] Kernel Library Availability\n");
    printf("-----------------------------------\n");
    
    // Initialize kernel table
    printf("Initializing kernel table...\n");
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    
    int initResult = Sovereign_InitKernelTable(&table);
    printf("  Init result: %d (%s)\n\n", initResult, 
           initResult == 0 ? "SUCCESS" : "FAILED");
    
    if (initResult != 0) {
        printf("ERROR: Kernel table initialization failed!\n");
        return 1;
    }
    
    // Check kernel availability
    int passed = 0;
    int total = 0;
    
    printf("Kernel Availability:\n");
    
    #define CHECK_KERNEL(ptr, name) \
        total++; \
        if (ptr) { \
            passed++; \
            printf("  [OK] %s\n", name); \
        } else { \
            printf("  [MISSING] %s\n", name); \
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
    
    printf("\n  Total: %d/%d kernels available\n\n", passed, total);
    
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
        
        bool pass = (result == 0) && 
                    approxEqual(output[0], 1.5f, 0.001f) &&
                    approxEqual(output[3], 4.5f, 0.001f);
        
        printf("  Result: %d\n", result);
        printf("  Output: [%.2f, %.2f, %.2f, %.2f]\n", 
               output[0], output[1], output[2], output[3]);
        printf("  [%s] ResidualAdd execution\n\n", pass ? "PASS" : "FAIL");
    }
    
    printf("==============================================================================\n");
    printf("Results: %d/%d kernels available\n", passed, total);
    printf("==============================================================================\n\n");
    
    return (passed == total) ? 0 : 1;
}

void printUsage(const char* program) {
    printf("Usage: %s [command]\n\n", program);
    printf("Commands:\n");
    printf("  test       Run kernel integration tests\n");
    printf("  info       Show system information\n");
    printf("  help       Show this help message\n");
}

int main(int argc, char* argv[]) {
    printBanner();
    
    if (argc < 2) {
        printUsage(argv[0]);
        return 0;
    }
    
    const char* command = argv[1];
    
    if (strcmp(command, "test") == 0) {
        return testKernelAvailability();
    } else if (strcmp(command, "info") == 0) {
        printf("System Information:\n");
        printf("-----------------\n");
        printf("Phase: 7C.2 - Kernel Integration\n");
        printf("Target: Sovereign CLI with MASM kernels\n");
        printf("Compiler: MSVC 14.51.36231\n");
        printf("Architecture: x64\n");
        printf("\n");
        return 0;
    } else if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        printUsage(argv[0]);
        return 0;
    } else {
        printf("Unknown command: %s\n\n", command);
        printUsage(argv[0]);
        return 1;
    }
}
