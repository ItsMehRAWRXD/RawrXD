/**
 * @file test_vector_dispatch.cpp
 * @brief Test AVX512 vector operations dispatch
 */

#include "avx2_kernels.hpp"
#include "avx512_kernels.hpp"
#include <iostream>
#include <vector>
#include <cmath>

using namespace rawrxd::kernels;

bool test_vecadd() {
    std::cout << "Testing VecAdd dispatch...\n";
    
    std::vector<float> A(64), B(64), C_dispatch(64), C_ref(64);
    for (size_t i = 0; i < A.size(); ++i) {
        A[i] = (float)i * 0.5f;
        B[i] = (float)i * 0.3f;
    }
    
    // Reference with AVX2
    VecAddF32(A.data(), B.data(), C_ref.data(), A.size());
    
    // Dispatch
    KernelDispatch::VecAddF32(A.data(), B.data(), C_dispatch.data(), A.size());
    
    float max_error = 0.0f;
    for (size_t i = 0; i < A.size(); ++i) {
        float error = std::abs(C_ref[i] - C_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    return max_error < 1e-5f;
}

bool test_vecmul() {
    std::cout << "Testing VecMul dispatch...\n";
    
    std::vector<float> A(64), B(64), C_dispatch(64), C_ref(64);
    for (size_t i = 0; i < A.size(); ++i) {
        A[i] = (float)i * 0.5f;
        B[i] = (float)i * 0.3f;
    }
    
    // Reference with AVX2
    VecMulF32(A.data(), B.data(), C_ref.data(), A.size());
    
    // Dispatch
    KernelDispatch::VecMulF32(A.data(), B.data(), C_dispatch.data(), A.size());
    
    float max_error = 0.0f;
    for (size_t i = 0; i < A.size(); ++i) {
        float error = std::abs(C_ref[i] - C_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    return max_error < 1e-5f;
}

bool test_vecscale() {
    std::cout << "Testing VecScale dispatch...\n";
    
    std::vector<float> X(64), Y_dispatch(64), Y_ref(64);
    float scale = 2.5f;
    for (size_t i = 0; i < X.size(); ++i) {
        X[i] = (float)i * 0.5f;
    }
    
    // Reference with AVX2
    VecScaleF32(X.data(), scale, Y_ref.data(), X.size());
    
    // Dispatch
    KernelDispatch::VecScaleF32(X.data(), scale, Y_dispatch.data(), X.size());
    
    float max_error = 0.0f;
    for (size_t i = 0; i < X.size(); ++i) {
        float error = std::abs(Y_ref[i] - Y_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    return max_error < 1e-5f;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "AVX512 Vector Operations Dispatch Tests\n";
    std::cout << "========================================\n\n";
    
    CPUFeatures::Print();
    std::cout << "\n";
    
    int passed = 0;
    int total = 0;
    
    if (test_vecadd()) { passed++; std::cout << "  PASS\n\n"; } 
    else { std::cout << "  FAIL\n\n"; }
    total++;
    
    if (test_vecmul()) { passed++; std::cout << "  PASS\n\n"; } 
    else { std::cout << "  FAIL\n\n"; }
    total++;
    
    if (test_vecscale()) { passed++; std::cout << "  PASS\n\n"; } 
    else { std::cout << "  FAIL\n\n"; }
    total++;
    
    std::cout << "========================================\n";
    std::cout << "Results: " << passed << "/" << total << " tests passed\n";
    std::cout << "========================================\n";
    
    return (passed == total) ? 0 : 1;
}
