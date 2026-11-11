/**
 * @file test_avx2_kernels.cpp
 * @brief AVX2 Kernels Test Suite
 *
 * Tests AVX2-optimized matrix operations and vector functions.
 *
 * @copyright RawrXD 2026
 */

#include "avx2_kernels.hpp"

#include <iostream>
#include <iomanip>
#include <vector>
#include <cmath>
#include <chrono>

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

bool Test_CPUFeatures() {
    TEST(CPUFeatures);
    
    CPUFeatures::Print();
    
    CPUFeatures features = CPUFeatures::Detect();
    ASSERT(features.has_sse4_2);  // Should have SSE4.2 on modern CPUs
    
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_VecDotF32() {
    TEST(VecDotF32);
    
    std::vector<float> A = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    std::vector<float> B = {2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f};
    
    float result = VecDotF32(A.data(), B.data(), A.size());
    
    // Expected: 1*2 + 2*3 + 3*4 + 4*5 + 5*6 + 6*7 + 7*8 + 8*9 = 2 + 6 + 12 + 20 + 30 + 42 + 56 + 72 = 240
    float expected = 240.0f;
    ASSERT_NEAR(result, expected, 0.001f);
    
    std::cout << "  Result: " << result << " (expected: " << expected << ")" << std::endl;
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_VecAddF32() {
    TEST(VecAddF32);
    
    std::vector<float> A = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    std::vector<float> B = {2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f};
    std::vector<float> C(A.size());
    
    VecAddF32(A.data(), B.data(), C.data(), A.size());
    
    // Expected: {3, 5, 7, 9, 11, 13, 15, 17}
    for (size_t i = 0; i < A.size(); ++i) {
        ASSERT_NEAR(C[i], A[i] + B[i], 0.001f);
    }
    
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_VecScaleF32() {
    TEST(VecScaleF32);
    
    std::vector<float> X = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float scale = 2.5f;
    std::vector<float> Y(X.size());
    
    VecScaleF32(X.data(), scale, Y.data(), X.size());
    
    // Expected: {2.5, 5.0, 7.5, 10.0, 12.5, 15.0, 17.5, 20.0}
    for (size_t i = 0; i < X.size(); ++i) {
        ASSERT_NEAR(Y[i], X[i] * scale, 0.001f);
    }
    
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_MatMulF32() {
    TEST(MatMulF32);
    
    // 2x3 @ 3x2 = 2x2
    std::vector<float> A = {1.0f, 2.0f, 3.0f,  // Row 0
                            4.0f, 5.0f, 6.0f}; // Row 1
    std::vector<float> B = {7.0f, 8.0f,        // Col 0
                            9.0f, 10.0f,       // Col 1
                            11.0f, 12.0f};     // Col 2
    std::vector<float> C(4);
    
    MatMulF32(A.data(), B.data(), C.data(), 2, 2, 3);
    
    // Expected:
    // C[0,0] = 1*7 + 2*9 + 3*11 = 7 + 18 + 33 = 58
    // C[0,1] = 1*8 + 2*10 + 3*12 = 8 + 20 + 36 = 64
    // C[1,0] = 4*7 + 5*9 + 6*11 = 28 + 45 + 66 = 139
    // C[1,1] = 4*8 + 5*10 + 6*12 = 32 + 50 + 72 = 154
    ASSERT_NEAR(C[0], 58.0f, 0.001f);
    ASSERT_NEAR(C[1], 64.0f, 0.001f);
    ASSERT_NEAR(C[2], 139.0f, 0.001f);
    ASSERT_NEAR(C[3], 154.0f, 0.001f);
    
    std::cout << "  Result: [" << C[0] << ", " << C[1] << ", " << C[2] << ", " << C[3] << "]" << std::endl;
    std::cout << "  Expected: [58, 64, 139, 154]" << std::endl;
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_RMSNormF32() {
    TEST(RMSNormF32);
    
    std::vector<float> X = {1.0f, 2.0f, 3.0f, 4.0f};
    std::vector<float> weight = {1.0f, 1.0f, 1.0f, 1.0f};
    std::vector<float> Y(X.size());
    
    RMSNormF32(X.data(), weight.data(), 1e-6f, Y.data(), X.size());
    
    // RMS = sqrt((1 + 4 + 9 + 16) / 4) = sqrt(30/4) = sqrt(7.5) = 2.7386
    // Y[i] = X[i] / RMS * weight[i]
    float rms = std::sqrt(7.5f);
    for (size_t i = 0; i < X.size(); ++i) {
        ASSERT_NEAR(Y[i], X[i] / rms, 0.001f);
    }
    
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_SoftmaxF32() {
    TEST(SoftmaxF32);
    
    std::vector<float> X = {1.0f, 2.0f, 3.0f};
    std::vector<float> Y(X.size());
    
    SoftmaxF32(X.data(), Y.data(), X.size());
    
    // Check that probabilities sum to 1
    float sum = 0.0f;
    for (float y : Y) {
        sum += y;
        ASSERT(y >= 0.0f && y <= 1.0f);
    }
    ASSERT_NEAR(sum, 1.0f, 0.001f);
    
    // Check that highest input has highest output
    ASSERT(Y[2] > Y[1] && Y[1] > Y[0]);
    
    std::cout << "  Softmax: [" << Y[0] << ", " << Y[1] << ", " << Y[2] << "]" << std::endl;
    std::cout << "  Sum: " << sum << std::endl;
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

bool Test_Benchmark() {
    TEST(Benchmark);
    
    std::cout << "  Running kernel benchmarks..." << std::endl;
    
    KernelBenchmark results[10];
    BenchmarkKernels(results, 10);
    PrintBenchmarkResults(results, 2);
    
    std::cout << "  PASSED" << std::endl;
    tests_passed++;
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "AVX2 Kernels Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    Test_CPUFeatures();
    Test_VecDotF32();
    Test_VecAddF32();
    Test_VecScaleF32();
    Test_MatMulF32();
    Test_RMSNormF32();
    Test_SoftmaxF32();
    Test_Benchmark();
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
