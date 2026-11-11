// ============================================================================
// AVX-512 Kernel Test Suite
// ============================================================================

#include "avx512_kernels.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cmath>
#include <cstring>

using namespace SEG;

// Test utilities
static bool FloatEquals(float a, float b, float epsilon = 1e-4f) {
    return std::abs(a - b) < epsilon;
}

static void PrintTestHeader(const char* name) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test: " << name << std::endl;
    std::cout << "========================================" << std::endl;
}

// ============================================================================
// Test 1: CPU Feature Detection
// ============================================================================
static bool TestCPUFeatures() {
    PrintTestHeader("CPU Feature Detection");
    
    const CPUFeatures& features = CPUFeatures::Get();
    
    std::cout << "CPU Features:" << std::endl;
    std::cout << "  AVX512F: " << (features.hasAVX512F ? "YES" : "NO") << std::endl;
    std::cout << "  AVX512DQ: " << (features.hasAVX512DQ ? "YES" : "NO") << std::endl;
    std::cout << "  AVX512VL: " << (features.hasAVX512VL ? "YES" : "NO") << std::endl;
    std::cout << "  FMA: " << (features.hasFMA ? "YES" : "NO") << std::endl;
    std::cout << "  AVX2: " << (features.hasAVX2 ? "YES" : "NO") << std::endl;
    
    return true;  // Always pass - just informational
}

// ============================================================================
// Test 2: MatMul Correctness
// ============================================================================
static bool TestMatMulCorrectness() {
    PrintTestHeader("MatMul Correctness");
    
    // Small test: 4x3 @ 3x5 = 4x5
    const size_t M = 4, N = 5, K = 3;
    
    float A[M * K] = {
        1, 2, 3,
        4, 5, 6,
        7, 8, 9,
        10, 11, 12
    };
    
    float B[K * N] = {
        1, 0, 0, 1, 0,
        0, 1, 0, 0, 1,
        0, 0, 1, 1, 1
    };
    
    float C[M * N];
    
    // Compute using AVX-512 (or scalar fallback)
    KernelDispatch::MatMulF32(A, B, C, M, N, K);
    
    // Expected result
    float expected[M * N] = {
        1, 2, 3, 4, 5,
        4, 5, 6, 10, 11,
        7, 8, 9, 16, 17,
        10, 11, 12, 22, 23
    };
    
    std::cout << "A @ B = C:" << std::endl;
    bool pass = true;
    for (size_t i = 0; i < M * N; ++i) {
        if (!FloatEquals(C[i], expected[i])) {
            std::cout << "  C[" << i << "]=" << C[i] << " expected=" << expected[i] << std::endl;
            pass = false;
        }
    }
    
    if (pass) {
        std::cout << "  All values match!" << std::endl;
    }
    
    return pass;
}

// ============================================================================
// Test 3: MatMul Performance (FFN-sized)
// ============================================================================
static bool TestMatMulPerformance() {
    PrintTestHeader("MatMul Performance (FFN-sized)");
    
    // FFN dimensions: [4096, 14336]
    const size_t M = 4096;
    const size_t N = 14336;
    const size_t K = 4096;
    
    std::cout << "Matrix size: [" << M << "x" << K << "] @ [" << K << "x" << N << "]" << std::endl;
    std::cout << "Total elements: " << (M * K + K * N + M * N) << std::endl;
    
    // Allocate aligned memory for AVX-512
    float* A = (float*)_aligned_malloc(M * K * sizeof(float), 64);
    float* B = (float*)_aligned_malloc(K * N * sizeof(float), 64);
    float* C = (float*)_aligned_malloc(M * N * sizeof(float), 64);
    
    if (!A || !B || !C) {
        std::cout << "Memory allocation failed - skipping large test" << std::endl;
        return true;  // Skip on memory failure
    }
    
    // Initialize with small random values
    for (size_t i = 0; i < M * K; ++i) A[i] = (i % 10) * 0.01f;
    for (size_t i = 0; i < K * N; ++i) B[i] = (i % 10) * 0.01f;
    
    // Warmup
    KernelDispatch::MatMulF32(A, B, C, M, N, K);
    
    // Benchmark
    const int iterations = 3;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        std::memset(C, 0, M * N * sizeof(float));
        KernelDispatch::MatMulF32(A, B, C, M, N, K);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    double avg_time = duration.count() / static_cast<double>(iterations);
    double gflops = (2.0 * M * N * K) / (avg_time / 1000.0) / 1e9;
    
    std::cout << "Iterations: " << iterations << std::endl;
    std::cout << "Avg time: " << std::fixed << std::setprecision(1) << avg_time << " ms" << std::endl;
    std::cout << "Performance: " << std::setprecision(2) << gflops << " GFLOP/s" << std::endl;
    
    const CPUFeatures& features = CPUFeatures::Get();
    if (features.hasAVX512F) {
        std::cout << "Using: AVX-512 (16-wide)" << std::endl;
    } else {
        std::cout << "Using: Scalar fallback" << std::endl;
    }
    
    _aligned_free(A);
    _aligned_free(B);
    _aligned_free(C);
    
    return true;
}

// ============================================================================
// Test 4: Vector Operations
// ============================================================================
static bool TestVectorOperations() {
    PrintTestHeader("Vector Operations");
    
    const size_t N = 64;
    float A[N], B[N], C[N];
    
    for (size_t i = 0; i < N; ++i) {
        A[i] = static_cast<float>(i);
        B[i] = static_cast<float>(N - i);
    }
    
    // Test VecAdd
    KernelDispatch::VecAddF32(A, B, C, N);
    bool add_pass = true;
    for (size_t i = 0; i < N; ++i) {
        if (!FloatEquals(C[i], A[i] + B[i])) {
            add_pass = false;
            break;
        }
    }
    std::cout << "VecAdd: " << (add_pass ? "PASS" : "FAIL") << std::endl;
    
    // Test VecDot
    float dot = KernelDispatch::VecDotF32(A, B, N);
    float expected_dot = 0.0f;
    for (size_t i = 0; i < N; ++i) expected_dot += A[i] * B[i];
    bool dot_pass = FloatEquals(dot, expected_dot, 1e-3f);
    std::cout << "VecDot: " << (dot_pass ? "PASS" : "FAIL") << " (" << dot << ")" << std::endl;
    
    // Test VecScale
    KernelDispatch::VecScaleF32(A, 2.5f, C, N);
    bool scale_pass = true;
    for (size_t i = 0; i < N; ++i) {
        if (!FloatEquals(C[i], A[i] * 2.5f)) {
            scale_pass = false;
            break;
        }
    }
    std::cout << "VecScale: " << (scale_pass ? "PASS" : "FAIL") << std::endl;
    
    return add_pass && dot_pass && scale_pass;
}

// ============================================================================
// Test 5: SiLU Activation
// ============================================================================
static bool TestSiLU() {
    PrintTestHeader("SiLU Activation");
    
    const size_t N = 64;
    float X[N], Y[N];
    
    for (size_t i = 0; i < N; ++i) {
        X[i] = (static_cast<float>(i) - 32.0f) * 0.1f;  // Range: -3.2 to 3.1
    }
    
    KernelDispatch::SiLUF32(X, Y, N);
    
    // Verify SiLU: x * sigmoid(x)
    bool pass = true;
    for (size_t i = 0; i < N; ++i) {
        float expected = X[i] / (1.0f + std::exp(-X[i]));
        if (!FloatEquals(Y[i], expected, 1e-3f)) {
            std::cout << "Y[" << i << "]=" << Y[i] << " expected=" << expected << std::endl;
            pass = false;
            break;
        }
    }
    
    std::cout << "SiLU: " << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

// ============================================================================
// Test 6: RMSNorm
// ============================================================================
static bool TestRMSNorm() {
    PrintTestHeader("RMSNorm");
    
    const size_t N = 64;
    float X[N], weight[N], Y[N];
    
    for (size_t i = 0; i < N; ++i) {
        X[i] = static_cast<float>(i) * 0.1f;
        weight[i] = 1.0f;
    }
    
    KernelDispatch::RMSNormF32(X, weight, 1e-6f, Y, N);
    
    // Verify output is normalized
    float sum = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        sum += Y[i] * Y[i];
    }
    float rms = std::sqrt(sum / N);
    
    std::cout << "Output RMS: " << rms << std::endl;
    std::cout << "Expected ~1.0" << std::endl;
    
    // Should be close to 1.0 (normalized)
    return FloatEquals(rms, 1.0f, 0.1f);
}

// ============================================================================
// Test 7: Small MatMul (edge cases)
// ============================================================================
static bool TestSmallMatMul() {
    PrintTestHeader("Small MatMul (Edge Cases)");
    
    // Test with sizes not divisible by 16
    const size_t M = 5, N = 7, K = 3;
    
    float A[M * K], B[K * N], C[M * N];
    
    for (size_t i = 0; i < M * K; ++i) A[i] = static_cast<float>(i + 1);
    for (size_t i = 0; i < K * N; ++i) B[i] = static_cast<float>(i + 1);
    
    KernelDispatch::MatMulF32(A, B, C, M, N, K);
    
    // Just verify it runs without crash and produces reasonable output
    bool has_nonzero = false;
    for (size_t i = 0; i < M * N; ++i) {
        if (C[i] != 0.0f) {
            has_nonzero = true;
            break;
        }
    }
    
    std::cout << "Non-zero output: " << (has_nonzero ? "YES" : "NO") << std::endl;
    return has_nonzero;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "AVX-512 Kernel Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Initialize dispatch
    KernelDispatch::Initialize();
    
    int passed = 0;
    int total = 0;
    
    if (TestCPUFeatures()) ++passed; ++total;
    if (TestMatMulCorrectness()) ++passed; ++total;
    if (TestVectorOperations()) ++passed; ++total;
    if (TestSiLU()) ++passed; ++total;
    if (TestRMSNorm()) ++passed; ++total;
    if (TestSmallMatMul()) ++passed; ++total;
    if (TestMatMulPerformance()) ++passed; ++total;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << "/" << total << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    const CPUFeatures& features = CPUFeatures::Get();
    if (features.hasAVX512F) {
        std::cout << "\n✅ AVX-512 is available and will be used" << std::endl;
    } else {
        std::cout << "\n⚠️  AVX-512 not available - using scalar fallback" << std::endl;
    }
    
    return (passed == total) ? 0 : 1;
}
