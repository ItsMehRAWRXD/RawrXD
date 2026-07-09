// ============================================================================
// Quantized MatMul Benchmark
// ============================================================================
// Compares standard vs quantized matrix multiplication
// ============================================================================

#include "quantized_matmul_fast.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <random>

using namespace SEG;

// Standard MatMul for comparison
void StandardMatMul(const float* input, const float* weights,
                    float* output, size_t N, size_t K) {
    for (size_t n = 0; n < N; n++) {
        float sum = 0.0f;
        for (size_t k = 0; k < K; k++) {
            sum += input[k] * weights[n * K + k];
        }
        output[n] = sum;
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Quantized MatMul Benchmark\n";
    std::cout << "========================================\n\n";
    
    // Test dimensions matching transformer FFN
    size_t K = 4096;   // Input dimension
    size_t N = 14336;  // Output dimension (FFN intermediate)
    
    std::cout << "Matrix dimensions:\n";
    std::cout << "  Input: " << K << "\n";
    std::cout << "  Output: " << N << "\n";
    std::cout << "  Weights: " << K << "x" << N << "\n\n";
    
    // Allocate data
    std::vector<float> input(K);
    std::vector<float> weights(N * K);
    std::vector<float> output_standard(N);
    std::vector<float> output_fast(N);
    
    // Initialize with random values
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-0.1f, 0.1f);
    
    for (size_t i = 0; i < K; i++) {
        input[i] = dist(rng);
    }
    for (size_t i = 0; i < N * K; i++) {
        weights[i] = dist(rng);
    }
    
    // Warmup
    StandardMatMul(input.data(), weights.data(), output_standard.data(), N, K);
    FastVecMatMul(input.data(), weights.data(), output_fast.data(), N, K);
    
    // Benchmark standard MatMul
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        StandardMatMul(input.data(), weights.data(), output_standard.data(), N, K);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto standard_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f / iterations;
    
    // Benchmark fast MatMul
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        FastVecMatMul(input.data(), weights.data(), output_fast.data(), N, K);
    }
    end = std::chrono::high_resolution_clock::now();
    auto fast_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f / iterations;
    
    // Verify correctness
    float max_diff = 0.0f;
    for (size_t i = 0; i < N; i++) {
        max_diff = std::max(max_diff, std::abs(output_standard[i] - output_fast[i]));
    }
    
    float speedup = standard_time / fast_time;
    
    std::cout << "Results:\n";
    std::cout << "  Standard MatMul: " << standard_time << " ms\n";
    std::cout << "  Fast MatMul:     " << fast_time << " ms\n";
    std::cout << "  Speedup:         " << speedup << "x\n";
    std::cout << "  Max diff:        " << max_diff << "\n\n";
    
    // Calculate throughput impact
    float standard_tok_per_sec = 1000.0f / standard_time;
    float fast_tok_per_sec = 1000.0f / fast_time;
    
    std::cout << "Throughput (single MatMul):\n";
    std::cout << "  Standard: " << standard_tok_per_sec << " ops/sec\n";
    std::cout << "  Fast:     " << fast_tok_per_sec << " ops/sec\n\n";
    
    std::cout << "Done!\n";
    return 0;
}
