/**
 * @file test_avx512_kernels.cpp
 * @brief AVX512 Kernels Test Suite
 *
 * Tests AVX512-optimized matrix operations and vector functions.
 *
 * @copyright RawrXD 2026
 */

#include "avx512_kernels.hpp"
#include "avx2_kernels.hpp"

#include <iostream>
#include <iomanip>
#include <vector>
#include <cmath>

using namespace rawrxd::kernels;

// ============================================================================
// Test Utilities
// ============================================================================

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) std::cout << "\n[TEST] " << #name << std::endl;
#define ASSERT(cond) do { \
    if (!(cond)) { \
        std::cerr << "  FAILED: " << #cond << " at line " << __LINE__ << std::endl; \
        tests_failed++; \
        return false; \
    } \
} while(0)

#define ASSERT_NEAR(a, b, eps) do { \
    if (std::abs((a) - (b)) > (eps)) { \
        std::cerr << "  FAILED: |" << #a << " - " << #b << "| > " << #eps \
                  << " (|" << (a) << " - " << (b) << "| = " << std::abs((a)-(b)) \
                  << ") at line " << __LINE__ << std::endl; \
        tests_failed++; \
        return false; \
    } \
} while(0)

// ============================================================================
// Test Cases
// ============================================================================

bool Test_CPUFeaturesAVX512() {
    TEST(CPUFeaturesAVX512);
    
    CPUFeatures features = CPUFeatures::Detect();
    
    std::cout << "  AVX512F: " << (features.has_avx512f ? "Yes" : "No") << "\n";
    std::cout << "  AVX512DQ: " << (features.has_avx512dq ? "Yes" : "No") << "\n";
    
    // Test can run even without AVX512 (will use fallback)
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_VecDotF32_AVX512() {
    TEST(VecDotF32_AVX512);
    
    // Test with 32 elements (2 AVX512 vectors)
    std::vector<float> A(32);
    std::vector<float> B(32);
    
    for (size_t i = 0; i < 32; ++i) {
        A[i] = static_cast<float>(i + 1);
        B[i] = static_cast<float>(i + 2);
    }
    
    float result_avx512 = VecDotF32_AVX512(A.data(), B.data(), A.size());
    float result_avx2 = VecDotF32(A.data(), B.data(), A.size());
    
    // Results should be identical
    ASSERT_NEAR(result_avx512, result_avx2, 0.001f);
    
    // Expected: sum of (i+1)*(i+2) for i=0 to 31
    float expected = 0.0f;
    for (size_t i = 0; i < 32; ++i) {
        expected += A[i] * B[i];
    }
    
    ASSERT_NEAR(result_avx512, expected, 0.001f);
    
    std::cout << "  Result: " << result_avx512 << " (expected: " << expected << ")" << std::endl;
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_MatMulF32_AVX512() {
    TEST(MatMulF32_AVX512);
    
    // 2x3 @ 3x2 = 2x2
    std::vector<float> A = {1.0f, 2.0f, 3.0f,
                            4.0f, 5.0f, 6.0f};
    std::vector<float> B = {7.0f, 8.0f,
                            9.0f, 10.0f,
                            11.0f, 12.0f};
    std::vector<float> C_avx512(4);
    std::vector<float> C_avx2(4);
    
    MatMulF32_AVX512(A.data(), B.data(), C_avx512.data(), 2, 2, 3);
    MatMulF32(A.data(), B.data(), C_avx2.data(), 2, 2, 3);
    
    // Results should be identical
    for (size_t i = 0; i < 4; ++i) {
        ASSERT_NEAR(C_avx512[i], C_avx2[i], 0.001f);
    }
    
    // Expected values
    ASSERT_NEAR(C_avx512[0], 58.0f, 0.001f);
    ASSERT_NEAR(C_avx512[1], 64.0f, 0.001f);
    ASSERT_NEAR(C_avx512[2], 139.0f, 0.001f);
    ASSERT_NEAR(C_avx512[3], 154.0f, 0.001f);
    
    std::cout << "  Result: [" << C_avx512[0] << ", " << C_avx512[1] << ", " 
              << C_avx512[2] << ", " << C_avx512[3] << "]" << std::endl;
    std::cout << "  Expected: [58, 64, 139, 154]" << std::endl;
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_Dispatch() {
    TEST(Dispatch);
    
    // Test that dispatch selects correct implementation
    std::vector<float> A(32, 1.0f);
    std::vector<float> B(32, 2.0f);
    
    float result = KernelDispatch::VecDotF32(A.data(), B.data(), A.size());
    
    // Expected: 32 * 1.0 * 2.0 = 64
    ASSERT_NEAR(result, 64.0f, 0.001f);
    
    std::cout << "  Result: " << result << " (expected: 64)" << std::endl;
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_BenchmarkComparison() {
    TEST(BenchmarkComparison);
    
    std::cout << "  Running AVX512 vs AVX2 benchmarks..." << std::endl;
    
    KernelBenchmarkAVX512 results[10];
    BenchmarkAVX512(results, 10);
    PrintBenchmarkComparison(results, 2);
    
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "AVX512 Kernels Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    Test_CPUFeaturesAVX512();
    Test_VecDotF32_AVX512();
    Test_MatMulF32_AVX512();
    Test_Dispatch();
    Test_BenchmarkComparison();
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
