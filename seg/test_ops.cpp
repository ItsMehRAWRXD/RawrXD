// ============================================================================
// Basic Operations Test
// ============================================================================

#include <iostream>
#include <iomanip>
#include <cmath>
#include <vector>
#include <chrono>

void RMSNorm(const float* input, float* output, const float* weights, 
             uint32_t size, float epsilon) {
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        sum_sq += input[i] * input[i];
    }
    float rms = std::sqrt(sum_sq / size + epsilon);
    float inv_rms = 1.0f / rms;
    
    for (uint32_t i = 0; i < size; i++) {
        output[i] = input[i] * inv_rms * weights[i];
    }
}

void MatMul(const float* A, const float* B, float* C,
            uint32_t m, uint32_t k, uint32_t n) {
    for (uint32_t i = 0; i < m; i++) {
        for (uint32_t j = 0; j < n; j++) {
            float sum = 0.0f;
            for (uint32_t l = 0; l < k; l++) {
                sum += A[i * k + l] * B[l * n + j];
            }
            C[i * n + j] = sum;
        }
    }
}

void Softmax(const float* input, float* output, uint32_t size) {
    float max_val = input[0];
    for (uint32_t i = 1; i < size; i++) {
        max_val = std::max(max_val, input[i]);
    }
    
    float sum_exp = 0.0f;
    for (uint32_t i = 0; i < size; i++) {
        output[i] = std::exp(input[i] - max_val);
        sum_exp += output[i];
    }
    
    float inv_sum = 1.0f / sum_exp;
    for (uint32_t i = 0; i < size; i++) {
        output[i] *= inv_sum;
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Basic Operations Test\n";
    std::cout << "========================================\n\n";
    
    // Test RMSNorm
    std::cout << "=== RMSNorm Test ===\n";
    {
        std::vector<float> input = {1.0f, 2.0f, 3.0f, 4.0f};
        std::vector<float> weights = {1.0f, 1.0f, 1.0f, 1.0f};
        std::vector<float> output(4);
        
        RMSNorm(input.data(), output.data(), weights.data(), 4, 1e-6f);
        
        std::cout << "Input:  [";
        for (auto v : input) std::cout << v << " ";
        std::cout << "]\n";
        
        std::cout << "Output: [";
        for (auto v : output) std::cout << v << " ";
        std::cout << "]\n";
        
        float rms = std::sqrt(30.0f / 4.0f);
        bool pass = true;
        for (size_t i = 0; i < input.size(); i++) {
            float expected = input[i] / rms;
            if (std::abs(output[i] - expected) > 1e-5f) {
                pass = false;
            }
        }
        std::cout << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // Test MatMul
    std::cout << "=== MatMul Test ===\n";
    {
        std::vector<float> A = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
        std::vector<float> B = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
        std::vector<float> C(4);
        
        MatMul(A.data(), B.data(), C.data(), 2, 3, 2);
        
        std::cout << "A @ B = [";
        for (auto v : C) std::cout << v << " ";
        std::cout << "]\n";
        
        std::vector<float> expected = {22.0f, 28.0f, 49.0f, 64.0f};
        bool pass = true;
        for (size_t i = 0; i < C.size(); i++) {
            if (std::abs(C[i] - expected[i]) > 1e-5f) {
                pass = false;
            }
        }
        std::cout << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // Test Softmax
    std::cout << "=== Softmax Test ===\n";
    {
        std::vector<float> input = {1.0f, 2.0f, 3.0f};
        std::vector<float> output(3);
        
        Softmax(input.data(), output.data(), 3);
        
        std::cout << "Input:  [";
        for (auto v : input) std::cout << v << " ";
        std::cout << "]\n";
        
        std::cout << "Output: [";
        for (auto v : output) std::cout << v << " ";
        std::cout << "]\n";
        
        float sum = 0.0f;
        for (auto v : output) sum += v;
        bool pass = std::abs(sum - 1.0f) < 1e-5f;
        std::cout << "Sum: " << sum << "\n";
        std::cout << (pass ? "PASS" : "FAIL") << "\n\n";
    }
    
    // Benchmark MatMul
    std::cout << "=== MatMul Benchmark ===\n";
    {
        const uint32_t M = 512, K = 512, N = 512;
        std::vector<float> A(M * K, 0.01f);
        std::vector<float> B(K * N, 0.01f);
        std::vector<float> C(M * N);
        
        // Warmup
        for (int i = 0; i < 5; i++) {
            MatMul(A.data(), B.data(), C.data(), M, K, N);
        }
        
        // Benchmark
        auto start = std::chrono::high_resolution_clock::now();
        int iterations = 10;
        for (int i = 0; i < iterations; i++) {
            MatMul(A.data(), B.data(), C.data(), M, K, N);
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double avg_ms = elapsed_ms / iterations;
        double flops = 2.0 * M * K * N * iterations / (elapsed_ms / 1000.0) / 1e9;
        
        std::cout << "Matrix: [" << M << "x" << K << "] @ [" << K << "x" << N << "]\n";
        std::cout << "Iterations: " << iterations << "\n";
        std::cout << "Total time: " << std::fixed << std::setprecision(2) << elapsed_ms << " ms\n";
        std::cout << "Avg time: " << std::fixed << std::setprecision(3) << avg_ms << " ms\n";
        std::cout << "Performance: " << std::fixed << std::setprecision(2) << flops << " GFLOPS\n\n";
    }
    
    std::cout << "========================================\n";
    std::cout << "All Tests Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
