/**
 * @file test_attention_dispatch.cpp
 * @brief Test AVX512 attention operations dispatch
 */

#include "avx2_kernels.hpp"
#include "avx512_kernels.hpp"
#include <iostream>
#include <vector>
#include <cmath>

using namespace rawrxd::kernels;

bool test_attention_qk() {
    std::cout << "Testing AttentionQK dispatch...\n";
    
    const size_t seq_len = 32;
    const size_t head_dim = 64;
    const float scale = 1.0f / std::sqrt((float)head_dim);
    
    std::vector<float> Q(seq_len * head_dim);
    std::vector<float> K(seq_len * head_dim);
    std::vector<float> scores_avx2(seq_len * seq_len);
    std::vector<float> scores_dispatch(seq_len * seq_len);
    
    // Initialize with test values
    for (size_t i = 0; i < Q.size(); ++i) {
        Q[i] = (float)(i % 10) * 0.1f;
        K[i] = (float)(i % 7) * 0.15f;
    }
    
    // Compute with AVX2
    AttentionQKF32(Q.data(), K.data(), scores_avx2.data(), seq_len, head_dim, scale);
    
    // Compute with dispatch
    KernelDispatch::AttentionQKF32(Q.data(), K.data(), scores_dispatch.data(), seq_len, head_dim, scale);
    
    // Compare
    float max_error = 0.0f;
    for (size_t i = 0; i < scores_avx2.size(); ++i) {
        float error = std::abs(scores_avx2[i] - scores_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    return max_error < 1e-4f;
}

bool test_attention_softmax_v() {
    std::cout << "Testing AttentionSoftmaxV dispatch...\n";
    
    const size_t seq_len = 32;
    const size_t head_dim = 64;
    
    std::vector<float> scores(seq_len * seq_len);
    std::vector<float> V(seq_len * head_dim);
    std::vector<float> output_avx2(seq_len * head_dim);
    std::vector<float> output_dispatch(seq_len * head_dim);
    
    // Initialize with test values
    for (size_t i = 0; i < scores.size(); ++i) {
        scores[i] = (float)(i % 5) * 0.2f;
    }
    for (size_t i = 0; i < V.size(); ++i) {
        V[i] = (float)(i % 8) * 0.1f;
    }
    
    // Compute with AVX2
    AttentionSoftmaxVF32(scores.data(), V.data(), output_avx2.data(), seq_len, head_dim);
    
    // Compute with dispatch
    KernelDispatch::AttentionSoftmaxVF32(scores.data(), V.data(), output_dispatch.data(), seq_len, head_dim);
    
    // Compare
    float max_error = 0.0f;
    for (size_t i = 0; i < output_avx2.size(); ++i) {
        float error = std::abs(output_avx2[i] - output_dispatch[i]);
        max_error = std::max(max_error, error);
    }
    
    std::cout << "  Max error: " << max_error << "\n";
    return max_error < 1e-4f;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "AVX512 Attention Operations Dispatch Tests\n";
    std::cout << "========================================\n\n";
    
    CPUFeatures::Print();
    std::cout << "\n";
    
    int passed = 0;
    int total = 0;
    
    if (test_attention_qk()) { passed++; std::cout << "  PASS\n\n"; } 
    else { std::cout << "  FAIL\n\n"; }
    total++;
    
    if (test_attention_softmax_v()) { passed++; std::cout << "  PASS\n\n"; } 
    else { std::cout << "  FAIL\n\n"; }
    total++;
    
    std::cout << "========================================\n";
    std::cout << "Results: " << passed << "/" << total << " tests passed\n";
    std::cout << "========================================\n";
    
    return (passed == total) ? 0 : 1;
}
