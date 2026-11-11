// ============================================================================
// BlockedGemm_CPP.cpp - Stub implementation for testing
// ============================================================================
#include <iostream>

extern "C" void BlockedGemm_CPP(
    const float* A, const float* B, float* C,
    int M, int N, int K, float alpha, float beta
) {
    std::cout << "BlockedGemm_CPP called with:" << std::endl;
    std::cout << "  A: " << A << std::endl;
    std::cout << "  B: " << B << std::endl;
    std::cout << "  C: " << C << std::endl;
    std::cout << "  M: " << M << std::endl;
    std::cout << "  N: " << N << std::endl;
    std::cout << "  K: " << K << std::endl;
    std::cout << "  alpha: " << alpha << std::endl;
    std::cout << "  beta: " << beta << std::endl;
}