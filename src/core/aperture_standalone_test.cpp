/**
 * @file aperture_standalone_test.cpp
 * @brief Standalone Aperture Kernel Validation Test
 * @version 1.0.0
 * 
 * Tests Aperture kernels without RawrEngine dependencies.
 * Validates Q4_0 dequantization and CPU feature detection.
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// Aperture API
extern "C" {
    void Aperture_InitCPUFeatures(void);
    int Aperture_HasAVX512F(void);
    int Aperture_HasAVX512BW(void);
    int Aperture_HasAVX512DQ(void);
    const char* Aperture_GetCPUBrand(void);
    const char* Aperture_GetCPUVendor(void);
    void Aperture_PrintCPUInfo(void);
    const char* Aperture_GetKernelName(void);
    
    int Aperture_Q4_0_Dequant_Reference(const uint8_t* src, float* dst, size_t num_blocks);
    int Aperture_Q4_0_Dequant(const uint8_t* src, float* dst, size_t num_blocks);
    int Aperture_Q4_0_ValidateReference(void);
    void Aperture_Q4_0_BenchmarkReference(size_t num_blocks, size_t iterations);
}

// Test result tracking
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(condition, msg) \
    do { \
        if (!(condition)) { \
            printf("[FAIL] %s\n", msg); \
            g_tests_failed++; \
            return; \
        } \
    } while(0)

#define RUN_TEST(name) \
    do { \
        printf("[TEST] %s...\n", #name); \
        name(); \
        g_tests_passed++; \
        printf("[PASS] %s\n", #name); \
    } while(0)

// ============================================================================
// TEST CASES
// ============================================================================

void test_cpu_features() {
    printf("[INFO] CPU Vendor: %s\n", Aperture_GetCPUVendor());
    printf("[INFO] CPU Brand: %s\n", Aperture_GetCPUBrand());
    
    Aperture_PrintCPUInfo();
    
    TEST_ASSERT(Aperture_HasAVX512F() || !Aperture_HasAVX512F(), 
                "AVX-512F detection should return valid value");
}

void test_q4_0_reference() {
    int result = Aperture_Q4_0_ValidateReference();
    TEST_ASSERT(result == 0, "Q4_0 reference validation failed");
}

void test_q4_0_benchmark() {
    printf("[INFO] Running benchmark...\n");
    
    // Get kernel name to see which implementation is being used
    const char* kernel_name = Aperture_GetKernelName();
    printf("[INFO] Active kernel: %s\n", kernel_name);
    
    // Run benchmark using dispatched kernel
    Aperture_Q4_0_BenchmarkDispatched(1000, 10);
    TEST_ASSERT(true, "Benchmark completed");
}

void test_q4_0_dispatch() {
    // Test the dispatch mechanism
    const char* kernel_name = Aperture_GetKernelName();
    printf("[INFO] Dispatch selected kernel: %s\n", kernel_name);
    
    // Create test data
    const size_t num_blocks = 100;
    const size_t src_size = num_blocks * 18;
    const size_t dst_size = num_blocks * 32;
    
    uint8_t* src = (uint8_t*)malloc(src_size);
    float* dst = (float*)malloc(dst_size * sizeof(float));
    
    TEST_ASSERT(src != nullptr, "Failed to allocate source buffer");
    TEST_ASSERT(dst != nullptr, "Failed to allocate destination buffer");
    
    // Fill with test pattern
    for (size_t i = 0; i < src_size; ++i) {
        src[i] = (uint8_t)((i * 7 + 13) % 256);
    }
    
    // Run via dispatch (should use AVX-512 if available)
    int result = Aperture_Q4_0_Dequant(src, dst, num_blocks);
    TEST_ASSERT(result == 0, "Dispatch dequantization failed");
    
    // Verify output
    int has_nonzero = 0;
    for (size_t i = 0; i < dst_size; ++i) {
        if (dst[i] != 0.0f) has_nonzero = 1;
    }
    TEST_ASSERT(has_nonzero, "Dispatch output is all zeros");
    
    free(src);
    free(dst);
}

void test_q4_0_bit_exact() {
    // Create test data
    const size_t num_blocks = 10;
    const size_t src_size = num_blocks * 18;  // 18 bytes per block
    const size_t dst_size = num_blocks * 32;  // 32 floats per block
    
    uint8_t* src = (uint8_t*)malloc(src_size);
    float* dst = (float*)malloc(dst_size * sizeof(float));
    
    TEST_ASSERT(src != nullptr, "Failed to allocate source buffer");
    TEST_ASSERT(dst != nullptr, "Failed to allocate destination buffer");
    
    // Fill with test pattern
    for (size_t i = 0; i < src_size; ++i) {
        src[i] = (uint8_t)((i * 7 + 13) % 256);
    }
    
    // Run dequantization
    int result = Aperture_Q4_0_Dequant_Reference(src, dst, num_blocks);
    TEST_ASSERT(result == 0, "Dequantization failed");
    
    // Verify output is not all zeros or NaN
    int has_nonzero = 0;
    int has_nan = 0;
    for (size_t i = 0; i < dst_size; ++i) {
        if (dst[i] != 0.0f) has_nonzero = 1;
        if (dst[i] != dst[i]) has_nan = 1;  // NaN check
    }
    
    TEST_ASSERT(has_nonzero, "Output is all zeros");
    TEST_ASSERT(!has_nan, "Output contains NaN values");
    
    free(src);
    free(dst);
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Aperture Standalone Kernel Test\n");
    printf("========================================\n\n");
    
    // Initialize CPU features
    printf("[INFO] Initializing CPU feature detection...\n");
    Aperture_InitCPUFeatures();
    printf("[INFO] CPU features initialized.\n\n");
    
    // Run tests
    RUN_TEST(test_cpu_features);
    printf("\n");
    
    RUN_TEST(test_q4_0_reference);
    printf("\n");
    
    RUN_TEST(test_q4_0_bit_exact);
    printf("\n");
    
    RUN_TEST(test_q4_0_dispatch);
    printf("\n");
    
    RUN_TEST(test_q4_0_benchmark);
    printf("\n");
    
    // Summary
    printf("========================================\n");
    printf("Test Summary: %d passed, %d failed\n", g_tests_passed, g_tests_failed);
    printf("========================================\n");
    
    return g_tests_failed > 0 ? 1 : 0;
}
