/**
 * @file test_activations_dispatch.cpp
 * @brief Test AVX512 SiLU and GELU dispatch
 */

#include "avx2_kernels.hpp"
#include "avx512_kernels.hpp"
#include <iostream>
#include <vector>
#include <cmath>

using namespace rawrxd::kernels;

bool test_silu() {
    std::cout << "Testing SiLU dispatch...\n";
    
    std::vector<float> input(64);
    for (size_t i = 0; i < input.size(); ++i) {
        input[i] = (float)i * 0.1f - 3.0f;  // Range: -3.0 to 3.3
    }
    
    std::vector<float> output_avx2(input.size());
    std::vector<float> output_dispatch(input.size());
    
    // Compute reference with AVX2
    SiLUF32(input.data(), output_avx2.data(), input.size());
    
    // Compute with dispatch
    KernelDispatch::SiLUF32(input.data(), output_dispatch.data(), input.size());
    
    // Compare
    float max_error = 0.0f;
    for (size_t i = 0; i < input.size(); ++i) {
        float error = std::abs(output_avx2[i] - output_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    
    if (max_error < 1e-5f) {
        std::cout << "  PASS\n";
        return true;
    } else {
        std::cout << "  FAIL\n";
        return false;
    }
}

bool test_gelu() {
    std::cout << "Testing GELU dispatch...\n";
    
    std::vector<float> input(64);
    for (size_t i = 0; i < input.size(); ++i) {
        input[i] = (float)i * 0.1f - 3.0f;
    }
    
    std::vector<float> output_avx2(input.size());
    std::vector<float> output_dispatch(input.size());
    
    // Compute reference with AVX2
    GELUF32(input.data(), output_avx2.data(), input.size());
    
    // Compute with dispatch
    KernelDispatch::GELUF32(input.data(), output_dispatch.data(), input.size());
    
    // Compare
    float max_error = 0.0f;
    for (size_t i = 0; i < input.size(); ++i) {
        float error = std::abs(output_avx2[i] - output_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    
    if (max_error < 1e-5f) {
        std::cout << "  PASS\n";
        return true;
    } else {
        std::cout << "  FAIL\n";
        return false;
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "AVX512 Activation Dispatch Tests\n";
    std::cout << "========================================\n\n";
    
    // Print CPU features
    CPUFeatures::Print();
    std::cout << "\n";
    
    int passed = 0;
    int total = 0;
    
    if (test_silu()) passed++;
    total++;
    
    if (test_gelu()) passed++;
    total++;
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << "/" << total << " tests passed\n";
    std::cout << "========================================\n";
    
    return (passed == total) ? 0 : 1;
}
