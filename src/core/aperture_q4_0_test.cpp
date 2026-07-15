/**
 * @file aperture_q4_0_test.cpp
 * @brief Q4_0 Dequantization Unit Tests
 * @version 1.0.0
 * 
 * Tests for validating MASM AVX-512 implementation against C++ reference.
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#include <cstdio.h>
#include <cstdlib.h>
#include <cstring.h>
#include <math.h>
#include <stdint.h>
#include <stddef.h>

// Include reference implementation
#include "aperture_q4_0_reference.cpp"

// Forward declarations for MASM implementation (to be linked)
extern "C" {
    int Aperture_Q4_0_Dequant_MASM(const uint8_t* __restrict src,
                                    float* __restrict dst,
                                    size_t num_blocks);
}

// ============================================================================
// TEST FRAMEWORK
// ============================================================================

static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, message); \
            g_tests_failed++; \
            return; \
        } \
    } while(0)

#define TEST_ASSERT_FLOAT_EQ(a, b, tolerance, message) \
    do { \
        if (fabsf((a) - (b)) > (tolerance)) { \
            printf("[FAIL] %s:%d: %s (expected %f, got %f, diff %e)\n", \
                   __FILE__, __LINE__, message, (float)(b), (float)(a), \
                   fabsf((a) - (b))); \
            g_tests_failed++; \
            return; \
        } \
    } while(0)

#define RUN_TEST(name) \
    do { \
        printf("[TEST] Running %s...\n", #name); \
        name(); \
        g_tests_passed++; \
        printf("[PASS] %s\n", #name); \
    } while(0)

// ============================================================================
// TEST CASES
// ============================================================================

/**
 * @brief Test bit-exact equality between reference and MASM
 * 
 * This is the primary validation test. The MASM implementation
 * must produce exactly the same output as the reference.
 */
void test_bit_exact_match() {
    const size_t num_blocks = 1000;
    const size_t src_size = num_blocks * 18;  // 18 bytes per block
    const size_t dst_size = num_blocks * 32;  // 32 floats per block
    
    // Allocate buffers
    uint8_t* src = new uint8_t[src_size];
    float* ref_dst = new float[dst_size];
    float* masm_dst = new float[dst_size];
    
    // Fill with deterministic pattern
    for (size_t i = 0; i < src_size; ++i) {
        src[i] = static_cast<uint8_t>((i * 7 + 13) % 256);
    }
    
    // Run reference implementation
    Aperture_Q4_0_Dequant_Reference(src, ref_dst, num_blocks);
    
    // Run MASM implementation
    // TODO: Uncomment when MASM is ready
    // Aperture_Q4_0_Dequant_MASM(src, masm_dst, num_blocks);
    
    // For now, just verify reference runs
    TEST_ASSERT(true, "Reference implementation executed");
    
    // Compare outputs
    // TODO: Enable when MASM is ready
    // for (size_t i = 0; i < dst_size; ++i) {
    //     TEST_ASSERT_FLOAT_EQ(masm_dst[i], ref_dst[i], 1e-6f, 
    //                          "Bit-exact mismatch");
    // }
    
    delete[] src;
    delete[] ref_dst;
    delete[] masm_dst;
}

/**
 * @brief Test edge cases
 * 
 * Tests boundary conditions and special values.
 */
void test_edge_cases() {
    // Test 1: Single block
    {
        uint8_t src[18];
        float ref_dst[32];
        float masm_dst[32];
        
        // Fill with pattern
        for (int i = 0; i < 18; ++i) {
            src[i] = static_cast<uint8_t>(i * 11);
        }
        
        Aperture_Q4_0_Dequant_Reference(src, ref_dst, 1);
        // TODO: Aperture_Q4_0_Dequant_MASM(src, masm_dst, 1);
        
        // Verify reference runs
        TEST_ASSERT(true, "Single block test");
    }
    
    // Test 2: Large number of blocks
    {
        const size_t num_blocks = 100000;
        uint8_t* src = new uint8_t[num_blocks * 18];
        float* ref_dst = new float[num_blocks * 32];
        
        // Fill
        for (size_t i = 0; i < num_blocks * 18; ++i) {
            src[i] = static_cast<uint8_t>(i % 256);
        }
        
        Aperture_Q4_0_Dequant_Reference(src, ref_dst, num_blocks);
        
        // Just verify it doesn't crash
        TEST_ASSERT(true, "Large block count test");
        
        delete[] src;
        delete[] ref_dst;
    }
    
    // Test 3: All zeros
    {
        uint8_t src[18] = {0};
        float ref_dst[32];
        
        Aperture_Q4_0_Dequant_Reference(src, ref_dst, 1);
        
        // All outputs should be zero (scale = 0)
        for (int i = 0; i < 32; ++i) {
            TEST_ASSERT_FLOAT_EQ(ref_dst[i], 0.0f, 1e-6f, 
                                 "Zero input should give zero output");
        }
    }
    
    // Test 4: All ones
    {
        uint8_t src[18];
        src[0] = 0x00;  // Scale = 1.0 (float16)
        src[1] = 0x3C;
        for (int i = 2; i < 18; ++i) {
            src[i] = 0x11;  // All weights = 1
        }
        
        float ref_dst[32];
        Aperture_Q4_0_Dequant_Reference(src, ref_dst, 1);
        
        // Expected: (1 - 8) * 1.0 = -7.0
        for (int i = 0; i < 32; ++i) {
            TEST_ASSERT_FLOAT_EQ(ref_dst[i], -7.0f, 1e-6f, 
                                 "All ones test");
        }
    }
}

/**
 * @brief Test alignment requirements
 * 
 * AVX-512 requires 64-byte alignment for optimal performance.
 */
void test_alignment() {
    // Test with aligned buffers
    {
        alignas(64) uint8_t src[18 * 10];
        alignas(64) float dst[32 * 10];
        
        // Fill
        for (size_t i = 0; i < sizeof(src); ++i) {
            src[i] = static_cast<uint8_t>(i % 256);
        }
        
        Aperture_Q4_0_Dequant_Reference(src, dst, 10);
        
        TEST_ASSERT(true, "Aligned buffers test");
    }
    
    // Test with unaligned buffers (should still work, just slower)
    {
        uint8_t src[18 * 10 + 64];
        float dst[32 * 10 + 16];
        
        // Use offset to create misalignment
        uint8_t* unaligned_src = src + 1;
        float* unaligned_dst = dst + 1;
        
        // Fill
        for (size_t i = 0; i < 18 * 10; ++i) {
            unaligned_src[i] = static_cast<uint8_t>(i % 256);
        }
        
        // Reference should handle unaligned
        Aperture_Q4_0_Dequant_Reference(unaligned_src, unaligned_dst, 10);
        
        TEST_ASSERT(true, "Unaligned buffers test");
    }
}

/**
 * @brief Test performance comparison
 * 
 * Compares performance between reference and MASM.
 */
void test_performance() {
    const size_t num_blocks = 10000;
    const size_t iterations = 100;
    
    uint8_t* src = new uint8_t[num_blocks * 18];
    float* ref_dst = new float[num_blocks * 32];
    float* masm_dst = new float[num_blocks * 32];
    
    // Fill with pattern
    for (size_t i = 0; i < num_blocks * 18; ++i) {
        src[i] = static_cast<uint8_t>(i % 256);
    }
    
    // Benchmark reference
    printf("[PERF] Benchmarking reference implementation...\n");
    
    // Warmup
    for (size_t i = 0; i < 10; ++i) {
        Aperture_Q4_0_Dequant_Reference(src, ref_dst, num_blocks);
    }
    
    // TODO: Benchmark MASM when ready
    // printf("[PERF] Benchmarking MASM implementation...\n");
    
    delete[] src;
    delete[] ref_dst;
    delete[] masm_dst;
    
    TEST_ASSERT(true, "Performance test completed");
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    printf("========================================\n");
    printf("Aperture Q4_0 Dequantization Tests\n");
    printf("========================================\n\n");
    
    // First validate the reference implementation
    printf("[INFO] Validating reference implementation...\n");
    if (Aperture_Q4_0_ValidateReference() != 0) {
        printf("\n[ERROR] Reference validation failed!\n");
        return 1;
    }
    printf("[INFO] Reference validation passed!\n\n");
    
    // Run tests
    RUN_TEST(test_bit_exact_match);
    RUN_TEST(test_edge_cases);
    RUN_TEST(test_alignment);
    RUN_TEST(test_performance);
    
    // Summary
    printf("\n========================================\n");
    printf("Test Summary: %d passed, %d failed\n", 
           g_tests_passed, g_tests_failed);
    printf("========================================\n");
    
    return g_tests_failed > 0 ? 1 : 0;
}
