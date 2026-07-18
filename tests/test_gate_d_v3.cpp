/**
 * @file test_gate_d_v3.cpp
 * @brief Gate D v3 Kernel Validation - Correctness First
 * 
 * Validates fixed RMSNorm and Softmax AVX2 kernels
 * Target: RMSNorm >3x speedup, <1e-5 error
 *         Softmax >2x speedup, sum=1.0, no NaN
 */

#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>
#include <random>
#include <cstring>
#include <numeric>

// External ASM functions (v3)
extern "C" {
    void rmsnorm_avx2_f32(const float* input, float* output, size_t n, float epsilon);
    void softmax_avx2_f32(const float* input, float* output, size_t n);
}

// Scalar reference implementations
void rmsnorm_scalar(const float* input, float* output, size_t n, float epsilon) {
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        sum_sq += input[i] * input[i];
    }
    float mean = sum_sq / n;
    float rms = std::sqrt(mean + epsilon);
    for (size_t i = 0; i < n; ++i) {
        output[i] = input[i] / rms;
    }
}

void softmax_scalar(const float* input, float* output, size_t n) {
    float max_val = input[0];
    for (size_t i = 1; i < n; ++i) {
        max_val = std::max(max_val, input[i]);
    }
    
    float sum = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        output[i] = std::exp(input[i] - max_val);
        sum += output[i];
    }
    
    for (size_t i = 0; i < n; ++i) {
        output[i] /= sum;
    }
}

// Check for NaN
bool has_nan(const std::vector<float>& data) {
    for (float x : data) {
        if (std::isnan(x)) return true;
    }
    return false;
}

// Test RMSNorm
bool test_rmsnorm() {
    std::cout << "[TEST] RMSNorm AVX2 v3..." << std::endl;
    
    const size_t n = 4096;
    const float epsilon = 1e-6f;
    
    std::vector<float> input(n);
    std::vector<float> output_avx2(n);
    std::vector<float> output_scalar(n);
    
    // Initialize with random values
    std::mt19937 gen(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (size_t i = 0; i < n; ++i) {
        input[i] = dist(gen);
    }
    
    // Run both implementations
    rmsnorm_avx2_f32(input.data(), output_avx2.data(), n, epsilon);
    rmsnorm_scalar(input.data(), output_scalar.data(), n, epsilon);
    
    // Check for NaN
    if (has_nan(output_avx2)) {
        std::cout << "  FAILED: AVX2 output contains NaN" << std::endl;
        return false;
    }
    
    // Compare results
    float max_error = 0.0f;
    float sum_error = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        float error = std::abs(output_avx2[i] - output_scalar[i]);
        max_error = std::max(max_error, error);
        sum_error += error;
    }
    float mean_error = sum_error / n;
    
    // Benchmark
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        rmsnorm_avx2_f32(input.data(), output_avx2.data(), n, epsilon);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto avx2_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        rmsnorm_scalar(input.data(), output_scalar.data(), n, epsilon);
    }
    end = std::chrono::high_resolution_clock::now();
    auto scalar_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    float speedup = static_cast<float>(scalar_time) / avx2_time;
    
    std::cout << "  Max error: " << max_error << " (target: <1e-5)" << std::endl;
    std::cout << "  Mean error: " << mean_error << std::endl;
    std::cout << "  AVX2 time: " << avx2_time << " us" << std::endl;
    std::cout << "  Scalar time: " << scalar_time << " us" << std::endl;
    std::cout << "  Speedup: " << speedup << "x (target: >3x)" << std::endl;
    
    // Validation criteria
    bool pass = true;
    if (max_error > 1e-5f) {
        std::cout << "  ❌ FAILED: Max error exceeds 1e-5" << std::endl;
        pass = false;
    } else {
        std::cout << "  ✅ Numerical accuracy PASS" << std::endl;
    }
    
    if (speedup < 3.0f) {
        std::cout << "  ⚠️  WARNING: Speedup below 3x target" << std::endl;
    } else {
        std::cout << "  ✅ Speedup target PASS" << std::endl;
    }
    
    return pass;
}

// Test Softmax
bool test_softmax() {
    std::cout << "[TEST] Softmax AVX2 v3..." << std::endl;
    
    const size_t n = 4096;
    
    std::vector<float> input(n);
    std::vector<float> output_avx2(n);
    std::vector<float> output_scalar(n);
    
    // Initialize with random values
    std::mt19937 gen(42);
    std::uniform_real_distribution<float> dist(-2.0f, 2.0f);
    for (size_t i = 0; i < n; ++i) {
        input[i] = dist(gen);
    }
    
    // Run both implementations
    softmax_avx2_f32(input.data(), output_avx2.data(), n);
    softmax_scalar(input.data(), output_scalar.data(), n);
    
    // Check for NaN
    if (has_nan(output_avx2)) {
        std::cout << "  FAILED: AVX2 output contains NaN" << std::endl;
        return false;
    }
    
    // Check sum = 1.0
    float sum_avx2 = std::accumulate(output_avx2.begin(), output_avx2.end(), 0.0f);
    float sum_scalar = std::accumulate(output_scalar.begin(), output_scalar.end(), 0.0f);
    
    // Compare results
    float max_error = 0.0f;
    for (size_t i = 0; i < n; ++i) {
        float error = std::abs(output_avx2[i] - output_scalar[i]);
        max_error = std::max(max_error, error);
    }
    
    // Benchmark
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        softmax_avx2_f32(input.data(), output_avx2.data(), n);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto avx2_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        softmax_scalar(input.data(), output_scalar.data(), n);
    }
    end = std::chrono::high_resolution_clock::now();
    auto scalar_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    float speedup = static_cast<float>(scalar_time) / avx2_time;
    
    std::cout << "  Max error: " << max_error << std::endl;
    std::cout << "  Sum (AVX2): " << sum_avx2 << " (target: 0.99999-1.00001)" << std::endl;
    std::cout << "  Sum (scalar): " << sum_scalar << std::endl;
    std::cout << "  AVX2 time: " << avx2_time << " us" << std::endl;
    std::cout << "  Scalar time: " << scalar_time << " us" << std::endl;
    std::cout << "  Speedup: " << speedup << "x (target: >2x)" << std::endl;
    
    // Validation criteria
    bool pass = true;
    if (max_error > 1e-4f) {
        std::cout << "  ❌ FAILED: Max error exceeds 1e-4" << std::endl;
        pass = false;
    } else {
        std::cout << "  ✅ Numerical accuracy PASS" << std::endl;
    }
    
    if (sum_avx2 < 0.99999f || sum_avx2 > 1.00001f) {
        std::cout << "  ❌ FAILED: Sum not in valid range" << std::endl;
        pass = false;
    } else {
        std::cout << "  ✅ Sum validation PASS" << std::endl;
    }
    
    if (speedup < 2.0f) {
        std::cout << "  ⚠️  WARNING: Speedup below 2x target" << std::endl;
    } else {
        std::cout << "  ✅ Speedup target PASS" << std::endl;
    }
    
    return pass;
}

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    
    std::cout << "========================================" << std::endl;
    std::cout << "Gate D v3 Kernel Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    if (test_rmsnorm()) passed++; else failed++;
    std::cout << std::endl;
    if (test_softmax()) passed++; else failed++;
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return failed == 0 ? 0 : 1;
}
