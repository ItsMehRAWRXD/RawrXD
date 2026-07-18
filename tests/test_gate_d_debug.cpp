/**
 * @file test_gate_d_debug.cpp
 * @brief Debug version to understand numerical errors
 */

#include <iostream>
#include <vector>
#include <cmath>

extern "C" {
    void rmsnorm_avx2_f32(const float* input, float* output, size_t n, float epsilon);
}

int main() {
    const size_t n = 8;  // Small test
    const float epsilon = 1e-6f;
    
    // Simple test case: all ones
    std::vector<float> input(n, 1.0f);
    std::vector<float> output(n);
    
    std::cout << "Input: ";
    for (float x : input) std::cout << x << " ";
    std::cout << std::endl;
    
    // Expected: RMS = sqrt(1 + epsilon) ≈ 1.0
    // Output should be ≈ 1.0
    float expected_sum_sq = n * 1.0f;  // 8
    float expected_mean = expected_sum_sq / n;  // 1.0
    float expected_rms = std::sqrt(expected_mean + epsilon);  // sqrt(1.000001)
    float expected_inv_rms = 1.0f / expected_rms;
    
    std::cout << "Expected sum_sq: " << expected_sum_sq << std::endl;
    std::cout << "Expected mean: " << expected_mean << std::endl;
    std::cout << "Expected rms: " << expected_rms << std::endl;
    std::cout << "Expected inv_rms: " << expected_inv_rms << std::endl;
    std::cout << "Expected output: ~" << expected_inv_rms << std::endl;
    std::cout << std::endl;
    
    rmsnorm_avx2_f32(input.data(), output.data(), n, epsilon);
    
    std::cout << "AVX2 Output: ";
    for (float x : output) std::cout << x << " ";
    std::cout << std::endl;
    
    // Check if output is reasonable
    float expected = 1.0f / std::sqrt(1.0f + epsilon);
    std::cout << "Expected value: " << expected << std::endl;
    std::cout << "First output: " << output[0] << std::endl;
    std::cout << "Error: " << std::abs(output[0] - expected) << std::endl;
    
    return 0;
}
