/**
 * @file test_gate_d_v4.cpp
 * @brief Gate D v4 Kernel Validation - Direct sqrt + 6th-degree exp
 * 
 * Target: RMSNorm >3x speedup, <1e-5 error
 *         Softmax >2x speedup, sum=1.0, no NaN
 */

#include <iostream>
#include <vector>
#include <cmath>
#include <chrono>
#include <random>
#include <numeric>

extern "C" {
    void rmsnorm_avx2_f32(const float* input, float* output, size_t n, float epsilon);
    void softmax_avx2_f32(const float* input, float* output, size_t n);
}

void rmsnorm_scalar(const float* input, float* output, size_t n, float epsilon) {
    float sum_sq = 0.0f;
    for (size_t i = 0; i < n; ++i) sum_sq += input[i] * input[i];
    float rms = std::sqrt(sum_sq / n + epsilon);
    for (size_t i = 0; i < n; ++i) output[i] = input[i] / rms;
}

void softmax_scalar(const float* input, float* output, size_t n) {
    float max_val = input[0];
    for (size_t i = 1; i < n; ++i) max_val = std::max(max_val, input[i]);
    float sum = 0.0f;
    for (size_t i = 0; i < n; ++i) { output[i] = std::exp(input[i] - max_val); sum += output[i]; }
    for (size_t i = 0; i < n; ++i) output[i] /= sum;
}

bool has_nan(const std::vector<float>& data) {
    for (float x : data) if (std::isnan(x)) return true;
    return false;
}

bool test_rmsnorm() {
    std::cout << "[TEST] RMSNorm AVX2 v4..." << std::endl;
    const size_t n = 4096;
    const float epsilon = 1e-6f;
    std::vector<float> input(n), output_avx2(n), output_scalar(n);
    
    std::mt19937 gen(42);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    for (size_t i = 0; i < n; ++i) input[i] = dist(gen);
    
    rmsnorm_avx2_f32(input.data(), output_avx2.data(), n, epsilon);
    rmsnorm_scalar(input.data(), output_scalar.data(), n, epsilon);
    
    if (has_nan(output_avx2)) { std::cout << "  FAILED: NaN detected" << std::endl; return false; }
    
    float max_error = 0.0f;
    for (size_t i = 0; i < n; ++i) max_error = std::max(max_error, std::abs(output_avx2[i] - output_scalar[i]));
    
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) rmsnorm_avx2_f32(input.data(), output_avx2.data(), n, epsilon);
    auto avx2_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) rmsnorm_scalar(input.data(), output_scalar.data(), n, epsilon);
    auto scalar_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    
    float speedup = static_cast<float>(scalar_time) / avx2_time;
    
    std::cout << "  Max error: " << max_error << " (target: <1e-5)" << std::endl;
    std::cout << "  Speedup: " << speedup << "x (target: >3x)" << std::endl;
    
    bool pass = true;
    if (max_error > 1e-5f) { std::cout << "  ❌ FAILED: Error too large" << std::endl; pass = false; }
    else std::cout << "  ✅ Numerical accuracy PASS" << std::endl;
    if (speedup >= 3.0f) std::cout << "  ✅ Speedup PASS" << std::endl;
    else std::cout << "  ⚠️  Speedup below target" << std::endl;
    
    return pass;
}

bool test_softmax() {
    std::cout << "[TEST] Softmax AVX2 v4..." << std::endl;
    const size_t n = 4096;
    std::vector<float> input(n), output_avx2(n), output_scalar(n);
    
    std::mt19937 gen(42);
    std::uniform_real_distribution<float> dist(-2.0f, 2.0f);
    for (size_t i = 0; i < n; ++i) input[i] = dist(gen);
    
    softmax_avx2_f32(input.data(), output_avx2.data(), n);
    softmax_scalar(input.data(), output_scalar.data(), n);
    
    if (has_nan(output_avx2)) { std::cout << "  FAILED: NaN detected" << std::endl; return false; }
    
    float sum_avx2 = std::accumulate(output_avx2.begin(), output_avx2.end(), 0.0f);
    float max_error = 0.0f;
    for (size_t i = 0; i < n; ++i) max_error = std::max(max_error, std::abs(output_avx2[i] - output_scalar[i]));
    
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) softmax_avx2_f32(input.data(), output_avx2.data(), n);
    auto avx2_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) softmax_scalar(input.data(), output_scalar.data(), n);
    auto scalar_time = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    
    float speedup = static_cast<float>(scalar_time) / avx2_time;
    
    std::cout << "  Max error: " << max_error << std::endl;
    std::cout << "  Sum: " << sum_avx2 << " (target: 0.99999-1.00001)" << std::endl;
    std::cout << "  Speedup: " << speedup << "x (target: >2x)" << std::endl;
    
    bool pass = true;
    if (max_error > 1e-3f) { std::cout << "  ❌ FAILED: Error too large" << std::endl; pass = false; }
    else std::cout << "  ✅ Numerical accuracy PASS" << std::endl;
    if (sum_avx2 < 0.99999f || sum_avx2 > 1.00001f) { std::cout << "  ❌ FAILED: Sum invalid" << std::endl; pass = false; }
    else std::cout << "  ✅ Sum validation PASS" << std::endl;
    if (speedup >= 2.0f) std::cout << "  ✅ Speedup PASS" << std::endl;
    else std::cout << "  ⚠️  Speedup below target" << std::endl;
    
    return pass;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Gate D v4 Kernel Validation" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;
    
    int passed = 0, failed = 0;
    if (test_rmsnorm()) passed++; else failed++;
    std::cout << std::endl;
    if (test_softmax()) passed++; else failed++;
    
    std::cout << std::endl << "========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return failed == 0 ? 0 : 1;
}
