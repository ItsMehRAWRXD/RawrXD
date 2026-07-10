//==============================================================================
// test_titan_integration.cpp
// Test Titan Kernel Integration with real Sovereign kernels
//
// Date: July 10, 2026
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>

#include "src/core/execution/Titan_KernelIntegration.h"

// Helper to check if two floats are approximately equal
bool approx_equal(float a, float b, float epsilon = 1e-5f) {
    return fabsf(a - b) < epsilon;
}

// Test RMSNorm kernel
bool test_rms_norm() {
    printf("Testing RMSNorm_F32...\n");
    
    const size_t n = 8;
    float input[n] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float weight[n] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float output[n] = {0};
    
    RMSNormParams params = {
        input,
        output,
        weight,
        n,
        1e-6f
    };
    
    GPU_KERNEL_DESCRIPTOR desc = {0};
    desc.kernelName = KERNEL_RMSNORM_F32;
    desc.paramData = (uint64_t)&params;
    desc.paramCount = sizeof(params);
    
    int result = Titan_ExecuteComputeKernel(&desc, nullptr, 0);
    
    if (result != 0) {
        printf("  FAILED: Kernel returned error %d\n", result);
        return false;
    }
    
    // Verify output is normalized (RMS should be close to 1)
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; i++) {
        sum_sq += output[i] * output[i];
    }
    float rms = sqrtf(sum_sq / n);
    
    printf("  Output RMS: %.6f (expected ~1.0)\n", rms);
    printf("  Execution time: %llu us\n", desc.executionTimeUs);
    
    if (approx_equal(rms, 1.0f, 0.01f)) {
        printf("  PASSED\n\n");
        return true;
    } else {
        printf("  FAILED: RMS not normalized\n\n");
        return false;
    }
}

// Test Residual Add kernel
bool test_residual_add() {
    printf("Testing ResidualAdd_F32...\n");
    
    const size_t n = 8;
    float input[n] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float residual[n] = {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f};
    float output[n] = {0};
    
    ResidualAddParams params = {
        input,
        residual,
        output,
        n,
        1.0f  // No scaling
    };
    
    GPU_KERNEL_DESCRIPTOR desc = {0};
    desc.kernelName = KERNEL_RESIDUAL_ADD;
    desc.paramData = (uint64_t)&params;
    desc.paramCount = sizeof(params);
    
    int result = Titan_ExecuteComputeKernel(&desc, nullptr, 0);
    
    if (result != 0) {
        printf("  FAILED: Kernel returned error %d\n", result);
        return false;
    }
    
    // Verify: output = input + residual
    bool correct = true;
    for (size_t i = 0; i < n; i++) {
        float expected = input[i] + residual[i];
        if (!approx_equal(output[i], expected)) {
            printf("  Mismatch at %zu: got %.6f, expected %.6f\n", i, output[i], expected);
            correct = false;
        }
    }
    
    printf("  Execution time: %llu us\n", desc.executionTimeUs);
    
    if (correct) {
        printf("  PASSED\n\n");
        return true;
    } else {
        printf("  FAILED\n\n");
        return false;
    }
}

// Test Q4Q8 MatMul kernel
bool test_q4q8_matmul() {
    printf("Testing Q4Q8_MatMul...\n");
    
    // Simple 2x2 x 2x2 test
    // Note: This is a simplified test - real Q4_0/Q8_0 format is more complex
    const size_t m = 2, n = 2, k = 2;
    
    // Allocate aligned buffers
    float A_float[m * k] = {1.0f, 2.0f, 3.0f, 4.0f};
    float B_float[k * n] = {0.5f, 0.5f, 0.5f, 0.5f};
    float C[m * n] = {0};
    
    // For this test, we'll use the kernels directly with float data
    // In production, A would be Q4_0 and B would be Q8_0
    
    Q4Q8MatMulParams params = {
        A_float,
        B_float,
        C,
        m,
        n,
        k
    };
    
    GPU_KERNEL_DESCRIPTOR desc = {0};
    desc.kernelName = KERNEL_Q4Q8_MATMUL;
    desc.paramData = (uint64_t)&params;
    desc.paramCount = sizeof(params);
    
    int result = Titan_ExecuteComputeKernel(&desc, nullptr, 0);
    
    if (result != 0) {
        printf("  FAILED: Kernel returned error %d\n", result);
        return false;
    }
    
    printf("  Result matrix:\n");
    printf("    [%.3f, %.3f]\n", C[0], C[1]);
    printf("    [%.3f, %.3f]\n", C[2], C[3]);
    printf("  Execution time: %llu us\n", desc.executionTimeUs);
    
    // Expected: [1.5, 1.5], [3.5, 3.5]
    bool correct = approx_equal(C[0], 1.5f) && approx_equal(C[1], 1.5f) &&
                   approx_equal(C[2], 3.5f) && approx_equal(C[3], 3.5f);
    
    if (correct) {
        printf("  PASSED\n\n");
        return true;
    } else {
        printf("  FAILED: Results don't match expected\n\n");
        return false;
    }
}

// Test kernel availability
void test_kernel_availability() {
    printf("Checking kernel availability...\n");
    
    struct {
        uint64_t kernel;
        const char* name;
    } kernels[] = {
        {KERNEL_RMSNORM_F32, "RMSNorm_F32"},
        {KERNEL_LAYERNORM_F32, "LayerNorm_F32"},
        {KERNEL_ROPE_APPLY, "RoPE_Apply"},
        {KERNEL_RESIDUAL_ADD, "Residual_Add"},
        {KERNEL_Q4K_DEQUANT, "Q4K_Dequant"},
        {KERNEL_Q4Q8_MATMUL, "Q4Q8_MatMul"},
        {KERNEL_FLASH_ATTENTION, "FlashAttention"},
        {0, nullptr}
    };
    
    int available = 0;
    int total = 0;
    
    for (int i = 0; kernels[i].name != nullptr; i++) {
        bool is_avail = Titan_IsKernelAvailable(kernels[i].kernel);
        printf("  %s: %s\n", kernels[i].name, is_avail ? "AVAILABLE" : "NOT FOUND");
        if (is_avail) available++;
        total++;
    }
    
    printf("\nTotal: %d/%d kernels available\n\n", available, total);
}

int main() {
    printf("================================================================================\n");
    printf("Titan Kernel Integration Test\n");
    printf("================================================================================\n\n");
    
    // Initialize kernel system
    printf("Initializing kernel system...\n");
    int init_result = Titan_InitializeKernelSystem();
    if (init_result != 0) {
        printf("FAILED: Initialization returned %d\n", init_result);
        return 1;
    }
    printf("OK: Kernel system initialized\n\n");
    
    // Print version
    const char* version = Titan_GetKernelVersion();
    printf("Kernel version: %s\n\n", version);
    
    // Check availability
    test_kernel_availability();
    
    // Run tests
    int passed = 0;
    int total = 0;
    
    if (Titan_IsKernelAvailable(KERNEL_RMSNORM_F32)) {
        if (test_rms_norm()) passed++;
        total++;
    }
    
    if (Titan_IsKernelAvailable(KERNEL_RESIDUAL_ADD)) {
        if (test_residual_add()) passed++;
        total++;
    }
    
    if (Titan_IsKernelAvailable(KERNEL_Q4Q8_MATMUL)) {
        if (test_q4q8_matmul()) passed++;
        total++;
    }
    
    // Summary
    printf("================================================================================\n");
    printf("Test Summary: %d/%d passed\n", passed, total);
    printf("================================================================================\n");
    
    return (passed == total) ? 0 : 1;
}
