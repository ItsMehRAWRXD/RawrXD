//==============================================================================
// test_kernel_validation.cpp
// Validate kernel function pointers and basic execution
//
// This test verifies:
// 1. Kernel table is properly initialized
// 2. Function pointers are valid
// 3. Basic execution works (not full numerical validation)
//
// Date: July 10, 2026
//==============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <windows.h>

// Include the kernel dispatch header directly
extern "C" {
    #include "../src/asm/Sovereign_KernelDispatch.h"
}

// Test result tracking
struct TestResults {
    int total;
    int passed;
    int failed;
};

static TestResults g_results = {0, 0, 0};

#define TEST_ASSERT(cond, msg) do { \
    g_results.total++; \
    if (cond) { \
        g_results.passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        g_results.failed++; \
        printf("  [FAIL] %s\n", msg); \
    } \
} while(0)

//==============================================================================
// Test 1: Kernel Table Initialization
//==============================================================================
bool test_kernel_table_init() {
    printf("\n=== Test 1: Kernel Table Initialization ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    
    int result = Sovereign_InitKernelTable(&table);
    TEST_ASSERT(result == 0, "Sovereign_InitKernelTable returns 0");
    
    // Check that at least some kernels were loaded
    int loadedCount = 0;
    if (table.rms_norm_f32) loadedCount++;
    if (table.layer_norm_f32) loadedCount++;
    if (table.residual_add_f32) loadedCount++;
    if (table.q4q8_matmul_intrinsics || table.q4_0_q8_0_matmul) loadedCount++;
    if (table.flash_attention_v2_intrinsics || table.flash_attention_v2_f32) loadedCount++;
    
    printf("  Loaded kernels: %d\n", loadedCount);
    TEST_ASSERT(loadedCount > 0, "At least one kernel loaded");
    
    return g_results.failed == 0;
}

//==============================================================================
// Test 2: Function Pointer Validation
//==============================================================================
bool test_function_pointers() {
    printf("\n=== Test 2: Function Pointer Validation ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    // Print all function pointers
    printf("  Kernel function pointers:\n");
    printf("    rms_norm_f32:              %p\n", (void*)table.rms_norm_f32);
    printf("    layer_norm_f32:            %p\n", (void*)table.layer_norm_f32);
    printf("    rope_apply_f32:            %p\n", (void*)table.rope_apply_f32);
    printf("    residual_add_f32:          %p\n", (void*)table.residual_add_f32);
    printf("    q4q8_matmul_intrinsics:    %p\n", (void*)table.q4q8_matmul_intrinsics);
    printf("    q4_0_q8_0_matmul:          %p\n", (void*)table.q4_0_q8_0_matmul);
    printf("    flash_attention_v2_intr: %p\n", (void*)table.flash_attention_v2_intrinsics);
    printf("    flash_attention_v2_f32:    %p\n", (void*)table.flash_attention_v2_f32);
    
    // Validate critical pointers are not null
    TEST_ASSERT(table.rms_norm_f32 != nullptr, "rms_norm_f32 is not null");
    TEST_ASSERT(table.layer_norm_f32 != nullptr, "layer_norm_f32 is not null");
    TEST_ASSERT(table.residual_add_f32 != nullptr, "residual_add_f32 is not null");
    
    // MatMul should have at least one implementation
    bool hasMatMul = (table.q4q8_matmul_intrinsics != nullptr) || 
                     (table.q4_0_q8_0_matmul != nullptr);
    TEST_ASSERT(hasMatMul, "At least one MatMul kernel available");
    
    // FlashAttention should have at least one implementation
    bool hasFlashAttn = (table.flash_attention_v2_intrinsics != nullptr) ||
                        (table.flash_attention_v2_f32 != nullptr);
    TEST_ASSERT(hasFlashAttn, "At least one FlashAttention kernel available");
    
    return g_results.failed == 0;
}

//==============================================================================
// Test 3: Basic RMSNorm Execution
//==============================================================================
bool test_rmsnorm_basic() {
    printf("\n=== Test 3: Basic RMSNorm Execution ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    if (!table.rms_norm_f32) {
        printf("  [SKIP] rms_norm_f32 not available\n");
        return true;
    }
    
    // Simple test
    const size_t n = 8;
    float input[n] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    float output[n] = {0};
    float weight[n] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    
    printf("  Input:  [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0]\n");
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    int result = table.rms_norm_f32(input, output, weight, n, 1e-6f);
    
    QueryPerformanceCounter(&end);
    double timeUs = ((end.QuadPart - start.QuadPart) * 1000000.0) / freq.QuadPart;
    
    printf("  Output: [%.6f, %.6f, %.6f, %.6f, ...]\n", 
           output[0], output[1], output[2], output[3]);
    printf("  Result: %d, Time: %.2f us\n", result, timeUs);
    
    TEST_ASSERT(result == 0, "rms_norm_f32 returns 0");
    
    // For input of all 1.0s, output should be normalized
    // RMS = sqrt(8 * 1.0 / 8) = 1.0, so output = input / RMS = 1.0
    bool correct = true;
    for (size_t i = 0; i < n; i++) {
        if (fabsf(output[i] - 1.0f) > 0.01f) {
            correct = false;
            break;
        }
    }
    TEST_ASSERT(correct, "Output values are normalized (expected ~1.0)");
    
    return g_results.failed == 0;
}

//==============================================================================
// Test 4: Basic ResidualAdd Execution
//==============================================================================
bool test_residual_add_basic() {
    printf("\n=== Test 4: Basic ResidualAdd Execution ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    if (!table.residual_add_f32) {
        printf("  [SKIP] residual_add_f32 not available\n");
        return true;
    }
    
    const size_t n = 8;
    float input[n] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float residual[n] = {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f};
    float output[n] = {0};
    
    printf("  Input:    [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]\n");
    printf("  Residual: [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]\n");
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    int result = table.residual_add_f32(input, residual, output, n);
    
    QueryPerformanceCounter(&end);
    double timeUs = ((end.QuadPart - start.QuadPart) * 1000000.0) / freq.QuadPart;
    
    printf("  Output:   [%.6f, %.6f, %.6f, %.6f, ...]\n",
           output[0], output[1], output[2], output[3]);
    printf("  Result: %d, Time: %.2f us\n", result, timeUs);
    
    TEST_ASSERT(result == 0, "residual_add_f32 returns 0");
    
    // Verify: output[i] = input[i] + residual[i]
    bool correct = true;
    for (size_t i = 0; i < n; i++) {
        float expected = input[i] + residual[i];
        if (fabsf(output[i] - expected) > 0.001f) {
            printf("    Mismatch at %zu: got %.6f, expected %.6f\n", i, output[i], expected);
            correct = false;
        }
    }
    TEST_ASSERT(correct, "Output = Input + Residual");
    
    return g_results.failed == 0;
}

//==============================================================================
// Test 5: MatMul Function Pointer Check
//==============================================================================
bool test_matmul_pointer() {
    printf("\n=== Test 5: MatMul Function Pointer Check ===\n");
    
    Sovereign_KernelTable table;
    memset(&table, 0, sizeof(table));
    Sovereign_InitKernelTable(&table);
    
    // Check which implementation is available
    if (table.q4q8_matmul_intrinsics) {
        printf("  Using: q4q8_matmul_intrinsics (Phase 7B)\n");
        TEST_ASSERT(true, "Intrinsics implementation available");
    } else if (table.q4_0_q8_0_matmul) {
        printf("  Using: q4_0_q8_0_matmul (Phase 7A)\n");
        TEST_ASSERT(true, "MASM implementation available");
    } else {
        printf("  ERROR: No MatMul implementation available!\n");
        TEST_ASSERT(false, "At least one MatMul implementation available");
    }
    
    return g_results.failed == 0;
}

//==============================================================================
// Main
//==============================================================================
int main() {
    printf("==============================================================================\n");
    printf("Sovereign Kernel Validation Test\n");
    printf("==============================================================================\n");
    printf("\n");
    printf("This test validates:\n");
    printf("  1. Kernel table initialization\n");
    printf("  2. Function pointer loading\n");
    printf("  3. Basic kernel execution\n");
    printf("\n");
    
    // Run tests
    test_kernel_table_init();
    test_function_pointers();
    test_rmsnorm_basic();
    test_residual_add_basic();
    test_matmul_pointer();
    
    // Summary
    printf("\n==============================================================================\n");
    printf("Test Summary: %d/%d passed, %d failed\n", 
           g_results.passed, g_results.total, g_results.failed);
    printf("==============================================================================\n");
    
    return (g_results.failed == 0) ? 0 : 1;
}
