#include <iostream>
#include <cstdint>

// Forward declaration of raw pointer version
extern "C" int BlockedGemm_Single(
    const float* A,
    const float* B,
    float* C,
    int32_t M,
    int32_t N,
    int32_t K,
    float alpha,
    float beta
);

int main() {
    std::cout << "Testing BlockedGemm_Single (raw pointer version)..." << std::endl;
    
    // Simple test
    const int M = 4, N = 4, K = 4;
    float A[M * K] = {0};
    float B[K * N] = {0};
    float C[M * N] = {0};
    
    for (int i = 0; i < M * K; i++) A[i] = 2.0f;
    for (int i = 0; i < K * N; i++) B[i] = 3.0f;
    
    int result = BlockedGemm_Single(A, B, C, M, N, K, 1.0f, 0.0f);
    
    std::cout << "Result: " << result << std::endl;
    std::cout << "C[0] = " << C[0] << " (expected: 24.0)" << std::endl;
    
    return 0;
}