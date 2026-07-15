// ============================================================================
// SEG Kernel Bridge Test
// ============================================================================
// Validates integration between SEG and AVX512 kernels
// ============================================================================

#include "seg_kernel_bridge.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>
#include <chrono>

using namespace SEG;

// Test utilities
static bool FloatEquals(float a, float b, float epsilon = 1e-5f) {
    return std::abs(a - b) < epsilon;
}

static bool TestVecDot() {
    std::cout << "Testing VecDot... ";
    
    const size_t N = 64;
    float A[N], B[N];
    
    for (size_t i = 0; i < N; ++i) {
        A[i] = static_cast<float>(i);
        B[i] = static_cast<float>(N - i);
    }
    
    float result = KernelBridge::VecDot(A, B, N);
    
    // Expected: sum(i * (64-i)) for i=0..63
    float expected = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        expected += A[i] * B[i];
    }
    
    if (FloatEquals(result, expected)) {
        std::cout << "PASS (result=" << result << ")" << std::endl;
        return true;
    } else {
        std::cout << "FAIL (got=" << result << ", expected=" << expected << ")" << std::endl;
        return false;
    }
}

static bool TestVecAdd() {
    std::cout << "Testing VecAdd... ";
    
    const size_t N = 64;
    float A[N], B[N], C[N];
    
    for (size_t i = 0; i < N; ++i) {
        A[i] = static_cast<float>(i);
        B[i] = static_cast<float>(i * 2);
    }
    
    KernelBridge::VecAdd(A, B, C, N);
    
    bool pass = true;
    for (size_t i = 0; i < N; ++i) {
        if (!FloatEquals(C[i], A[i] + B[i])) {
            pass = false;
            break;
        }
    }
    
    std::cout << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

static bool TestVecScale() {
    std::cout << "Testing VecScale... ";
    
    const size_t N = 64;
    float X[N], Y[N];
    float scale = 2.5f;
    
    for (size_t i = 0; i < N; ++i) {
        X[i] = static_cast<float>(i);
    }
    
    KernelBridge::VecScale(X, scale, Y, N);
    
    bool pass = true;
    for (size_t i = 0; i < N; ++i) {
        if (!FloatEquals(Y[i], X[i] * scale)) {
            pass = false;
            break;
        }
    }
    
    std::cout << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

static bool TestMatMul() {
    std::cout << "Testing MatMul... ";
    
    // 4x3 @ 3x5 = 4x5
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
    
    KernelBridge::MatMul(A, B, C, M, N, K);
    
    // Expected:
    // Row 0: [1, 2, 3, 4, 5]
    // Row 1: [4, 5, 6, 10, 11]
    // Row 2: [7, 8, 9, 16, 17]
    // Row 3: [10, 11, 12, 22, 23]
    float expected[M * N] = {
        1, 2, 3, 4, 5,
        4, 5, 6, 10, 11,
        7, 8, 9, 16, 17,
        10, 11, 12, 22, 23
    };
    
    bool pass = true;
    for (size_t i = 0; i < M * N; ++i) {
        if (!FloatEquals(C[i], expected[i])) {
            pass = false;
            std::cout << "\n  C[" << i << "]=" << C[i] << " expected=" << expected[i];
        }
    }
    
    std::cout << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

static bool TestAttentionQK() {
    std::cout << "Testing AttentionQK... ";
    
    const size_t seq_len = 4;
    const size_t head_dim = 8;
    const float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    float Q[seq_len * head_dim];
    float K[seq_len * head_dim];
    float scores[seq_len * seq_len];
    
    // Initialize with simple values
    for (size_t i = 0; i < seq_len * head_dim; ++i) {
        Q[i] = static_cast<float>(i % head_dim) * 0.1f;
        K[i] = static_cast<float>(i % head_dim) * 0.1f;
    }
    
    KernelBridge::AttentionQK(Q, K, scores, seq_len, head_dim, scale);
    
    // Verify scores are computed (non-zero)
    bool pass = true;
    float sum = 0.0f;
    for (size_t i = 0; i < seq_len * seq_len; ++i) {
        sum += scores[i];
        if (std::isnan(scores[i]) || std::isinf(scores[i])) {
            pass = false;
        }
    }
    
    if (sum == 0.0f) pass = false;
    
    std::cout << (pass ? "PASS" : "FAIL") << " (sum=" << sum << ")" << std::endl;
    return pass;
}

static bool TestSoftmax() {
    std::cout << "Testing Softmax... ";
    
    const size_t N = 8;
    float X[N] = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f};
    float Y[N];
    
    KernelBridge::Softmax(X, Y, N);
    
    // Verify softmax properties
    float sum = 0.0f;
    bool pass = true;
    
    for (size_t i = 0; i < N; ++i) {
        sum += Y[i];
        if (Y[i] < 0.0f || Y[i] > 1.0f) pass = false;
    }
    
    if (!FloatEquals(sum, 1.0f, 1e-4f)) pass = false;
    
    // Verify ordering is preserved
    for (size_t i = 1; i < N; ++i) {
        if (Y[i] <= Y[i-1]) pass = false;
    }
    
    std::cout << (pass ? "PASS" : "FAIL") << " (sum=" << sum << ")" << std::endl;
    return pass;
}

static bool TestRMSNorm() {
    std::cout << "Testing RMSNorm... ";
    
    const size_t N = 32;
    float X[N], weight[N], Y[N];
    
    for (size_t i = 0; i < N; ++i) {
        X[i] = static_cast<float>(i) * 0.1f;
        weight[i] = 1.0f;
    }
    
    KernelBridge::RMSNorm(X, weight, 1e-6f, Y, N);
    
    // Verify output is normalized
    bool pass = true;
    for (size_t i = 0; i < N; ++i) {
        if (std::isnan(Y[i]) || std::isinf(Y[i])) {
            pass = false;
            break;
        }
    }
    
    std::cout << (pass ? "PASS" : "FAIL") << std::endl;
    return pass;
}

static void BenchmarkMatMul() {
    std::cout << "\n=== MatMul Benchmark ===" << std::endl;
    
    const size_t M = 256, N = 256, K = 256;
    float* A = new float[M * K];
    float* B = new float[K * N];
    float* C = new float[M * N];
    
    // Initialize
    for (size_t i = 0; i < M * K; ++i) A[i] = static_cast<float>(i % 10) * 0.1f;
    for (size_t i = 0; i < K * N; ++i) B[i] = static_cast<float>(i % 10) * 0.1f;
    
    // Warmup
    KernelBridge::MatMul(A, B, C, M, N, K);
    
    // Benchmark
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        KernelBridge::MatMul(A, B, C, M, N, K);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double avg_us = static_cast<double>(duration.count()) / iterations;
    double gflops = (2.0 * M * N * K) / (avg_us * 1000.0);  // GFLOP/s
    
    std::cout << "Size: " << M << "x" << N << "x" << K << std::endl;
    std::cout << "Avg time: " << std::fixed << std::setprecision(2) << avg_us << " us" << std::endl;
    std::cout << "Throughput: " << std::setprecision(2) << gflops << " GFLOP/s" << std::endl;
    
    delete[] A;
    delete[] B;
    delete[] C;
}

static void BenchmarkVecDot() {
    std::cout << "\n=== VecDot Benchmark ===" << std::endl;
    
    const size_t N = 4096;
    float* A = new float[N];
    float* B = new float[N];
    
    for (size_t i = 0; i < N; ++i) {
        A[i] = static_cast<float>(i % 10) * 0.1f;
        B[i] = static_cast<float>((i + 5) % 10) * 0.1f;
    }
    
    // Warmup
    volatile float result = KernelBridge::VecDot(A, B, N);
    (void)result;
    
    // Benchmark
    const int iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        result = KernelBridge::VecDot(A, B, N);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    
    double avg_ns = static_cast<double>(duration.count()) / iterations;
    double bandwidth = (2.0 * N * sizeof(float)) / (avg_ns / 1e9) / 1e9;  // GB/s
    
    std::cout << "Size: " << N << std::endl;
    std::cout << "Avg time: " << std::fixed << std::setprecision(2) << avg_ns << " ns" << std::endl;
    std::cout << "Bandwidth: " << std::setprecision(2) << bandwidth << " GB/s" << std::endl;
    
    delete[] A;
    delete[] B;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SEG Kernel Bridge Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Initialize kernel bridge
    KernelBridge::Initialize();
    
    std::cout << "\nCPU Capabilities:" << std::endl;
    std::cout << "  AVX512: " << (KernelBridge::HasAVX512() ? "YES" : "NO") << std::endl;
    std::cout << "  AVX2:   " << (KernelBridge::HasAVX2() ? "YES" : "NO") << std::endl;
    std::cout << "  Optimal block size: " << KernelBridge::GetOptimalBlockSize(64) << std::endl;
    
    std::cout << "\n=== Functional Tests ===" << std::endl;
    
    int passed = 0;
    int total = 0;
    
    if (TestVecDot()) ++passed; ++total;
    if (TestVecAdd()) ++passed; ++total;
    if (TestVecScale()) ++passed; ++total;
    if (TestMatMul()) ++passed; ++total;
    if (TestAttentionQK()) ++passed; ++total;
    if (TestSoftmax()) ++passed; ++total;
    if (TestRMSNorm()) ++passed; ++total;
    
    std::cout << "\n=== Performance Tests ===" << std::endl;
    BenchmarkVecDot();
    BenchmarkMatMul();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << "/" << total << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return (passed == total) ? 0 : 1;
}
