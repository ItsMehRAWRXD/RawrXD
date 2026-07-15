/**
 * @file test_layernorm_dispatch.cpp
 * @brief Test AVX512 LayerNorm dispatch
 */

#include "avx2_kernels.hpp"
#include "avx512_kernels.hpp"
#include <iostream>
#include <vector>
#include <cmath>

using namespace rawrxd::kernels;

bool test_layernorm() {
    std::cout << "Testing LayerNorm dispatch...\n";
    
    const size_t N = 64;
    std::vector<float> X(N), gamma(N), beta(N), Y_avx2(N), Y_dispatch(N);
    
    // Initialize test data
    for (size_t i = 0; i < N; ++i) {
        X[i] = (float)i * 0.1f - 3.0f;
        gamma[i] = 1.0f + (float)i * 0.01f;
        beta[i] = (float)i * 0.001f;
    }
    
    float eps = 1e-5f;
    
    // Compute with AVX2
    LayerNormF32(X.data(), gamma.data(), beta.data(), eps, Y_avx2.data(), N);
    
    // Compute with dispatch
    KernelDispatch::LayerNormF32(X.data(), gamma.data(), beta.data(), eps, Y_dispatch.data(), N);
    
    // Compare
    float max_error = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        float error = std::abs(Y_avx2[i] - Y_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    return max_error < 1e-4f;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "AVX512 LayerNorm Dispatch Test\n";
    std::cout << "========================================\n\n";
    
    CPUFeatures::Print();
    std::cout << "\n";
    
    if (test_layernorm()) {
        std::cout << "  PASS\n";
    } else {
        std::cout << "  FAIL\n";
        return 1;
    }
    
    std::cout << "\n========================================\n";
    std::cout << "LayerNorm test completed\n";
    std::cout << "========================================\n";
    
    return 0;
}
