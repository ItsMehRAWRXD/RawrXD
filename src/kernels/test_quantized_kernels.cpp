/*===========================================================================
 * test_quantized_kernels.cpp
 *
 * Validation harness for Fused Q4_0 Quantized Matrix Multiplication
 * RawrXD Fix #4
 *===========================================================================*/

#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <cstring>
#include "quantized_matmul.hpp"

using namespace RawrXD::Kernels;

/*===========================================================================
 * Test Configuration
 *===========================================================================*/
constexpr size_t WARMUP_ITERATIONS = 10;
constexpr size_t BENCHMARK_ITERATIONS = 100;

/*===========================================================================
 * Q4_0 Block Structure
 *===========================================================================*/
struct Q4_0_Block {
    float scale;
    uint8_t weights[16];  // 32 x 4-bit packed
};

/*===========================================================================
 * Generate Test Data
 *===========================================================================*/
void GenerateQ4_0Weights(std::vector<Q4_0_Block>& blocks, size_t numBlocks) {
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> scaleDist(0.01f, 0.1f);
    std::uniform_int_distribution<int> weightDist(0, 15);
    
    for (size_t i = 0; i < numBlocks; ++i) {
        blocks[i].scale = scaleDist(rng);
        for (int j = 0; j < 16; ++j) {
            uint8_t w0 = weightDist(rng);
            uint8_t w1 = weightDist(rng);
            blocks[i].weights[j] = (w1 << 4) | w0;
        }
    }
}

void GenerateActivation(std::vector<float>& activation) {
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 1.0f);
    
    for (auto& val : activation) {
        val = dist(rng);
    }
}

/*===========================================================================
 * Reference Implementation (for validation)
 *===========================================================================*/
void ReferenceMatMul(const std::vector<Q4_0_Block>& weights,
                     const std::vector<float>& activation,
                     std::vector<float>& output,
                     size_t N, size_t K) {
    size_t blocksPerRow = K / 32;
    
    for (size_t n = 0; n < N; ++n) {
        float sum = 0.0f;
        for (size_t k = 0; k < K; ++k) {
            size_t blockIdx = n * blocksPerRow + (k / 32);
            size_t weightIdx = k % 32;
            
            uint8_t packed = weights[blockIdx].weights[weightIdx / 2];
            uint8_t w = (weightIdx % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
            
            float dequant = (static_cast<float>(w) - 8.0f) * weights[blockIdx].scale;
            sum += dequant * activation[k];
        }
        output[n] = sum;
    }
}

/*===========================================================================
 * Benchmark Function
 *===========================================================================*/
template<typename KernelFunc>
double BenchmarkKernel(KernelFunc kernel,
                       const void* weights,
                       const float* activation,
                       float* output,
                       uint64_t N,
                       uint64_t K,
                       size_t iterations) {
    // Warmup
    for (size_t i = 0; i < WARMUP_ITERATIONS; ++i) {
        kernel(weights, activation, output, N, K);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < iterations; ++i) {
        kernel(weights, activation, output, N, K);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    std::chrono::duration<double> elapsed = end - start;
    return elapsed.count() / iterations * 1e6; // Return microseconds per call
}

/*===========================================================================
 * Validation Test
 *===========================================================================*/
bool Test4K() {
    std::cout << "\n=== Test: 4K Dimension ===\n";
    
    constexpr size_t N = 4096;
    constexpr size_t K = 4096;
    constexpr size_t numBlocks = (N * K) / 32;
    
    std::vector<Q4_0_Block> weights(numBlocks);
    std::vector<float> activation(K);
    std::vector<float> output(N);
    std::vector<float> reference(N);
    
    GenerateQ4_0Weights(weights, numBlocks);
    GenerateActivation(activation);
    
    // Run reference
    ReferenceMatMul(weights, activation, reference, N, K);
    
    // Run optimized kernel
    auto* kernel = KernelRegistry::Instance().Resolve(N, K);
    if (!kernel) {
        std::cout << "FAIL: Kernel not found\n";
        return false;
    }
    
    kernel->Execute(weights.data(), activation.data(), output.data(), N, K);
    
    // Compare (allow some tolerance for quantization)
    float maxError = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        float error = std::abs(output[i] - reference[i]);
        maxError = std::max(maxError, error);
    }
    
    std::cout << "Max error: " << maxError << "\n";
    
    if (maxError > 0.1f) {
        std::cout << "FAIL: Error too large\n";
        return false;
    }
    
    std::cout << "PASS\n";
    return true;
}

bool Test5K() {
    std::cout << "\n=== Test: 5K Dimension ===\n";
    
    constexpr size_t N = 5120;
    constexpr size_t K = 5120;
    constexpr size_t numBlocks = (N * K) / 32;
    
    std::vector<Q4_0_Block> weights(numBlocks);
    std::vector<float> activation(K);
    std::vector<float> output(N);
    std::vector<float> reference(N);
    
    GenerateQ4_0Weights(weights, numBlocks);
    GenerateActivation(activation);
    
    ReferenceMatMul(weights, activation, reference, N, K);
    
    auto* kernel = KernelRegistry::Instance().Resolve(N, K);
    if (!kernel) {
        std::cout << "FAIL: Kernel not found\n";
        return false;
    }
    
    kernel->Execute(weights.data(), activation.data(), output.data(), N, K);
    
    float maxError = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        float error = std::abs(output[i] - reference[i]);
        maxError = std::max(maxError, error);
    }
    
    std::cout << "Max error: " << maxError << "\n";
    
    if (maxError > 0.1f) {
        std::cout << "FAIL: Error too large\n";
        return false;
    }
    
    std::cout << "PASS\n";
    return true;
}

/*===========================================================================
 * Performance Benchmark
 *===========================================================================*/
void Benchmark4K() {
    std::cout << "\n=== Benchmark: 4K Dimension ===\n";
    
    constexpr size_t N = 4096;
    constexpr size_t K = 4096;
    constexpr size_t numBlocks = (N * K) / 32;
    
    std::vector<Q4_0_Block> weights(numBlocks);
    std::vector<float> activation(K);
    std::vector<float> output(N);
    
    GenerateQ4_0Weights(weights, numBlocks);
    GenerateActivation(activation);
    
    auto* kernel = KernelRegistry::Instance().Resolve(N, K);
    if (!kernel) {
        std::cout << "Kernel not found\n";
        return;
    }
    
    // Warmup and benchmark
    double avgTime = BenchmarkKernel(
        [&](const void* w, const float* a, float* o, uint64_t n, uint64_t k) {
            kernel->Execute(w, a, o, n, k);
        },
        weights.data(), activation.data(), output.data(), N, K,
        BENCHMARK_ITERATIONS
    );
    
    std::cout << "Average time: " << avgTime << " us\n";
    std::cout << "Throughput: " << (1e6 / avgTime) << " ops/sec\n";
    
    // Estimate TPS contribution
    // Assuming this is the matmul in a transformer layer
    double estimatedTPS = 540.0 * (61.0 / avgTime);  // Scale from baseline
    std::cout << "Estimated TPS contribution: " << estimatedTPS << " TPS\n";
}

/*===========================================================================
 * Main
 *===========================================================================*/
int main() {
    std::cout << "========================================================================\n";
    std::cout << "  RawrXD Quantized Kernel Test Harness\n";
    std::cout << "  Fix #4: Fused Q4_0 Dequant + MatMul\n";
    std::cout << "========================================================================\n";
    
    // Initialize registry
    if (!KernelRegistry::Instance().Initialize()) {
        std::cout << "ERROR: Failed to initialize kernel registry\n";
        std::cout << "AVX-512 may not be available on this CPU\n";
        return 1;
    }
    
    std::cout << "\nKernel registry initialized\n";
    std::cout << "AVX-512: Available\n";
    
    // Run tests
    bool allPassed = true;
    allPassed &= Test4K();
    allPassed &= Test5K();
    
    if (!allPassed) {
        std::cout << "\n=== SOME TESTS FAILED ===\n";
        return 1;
    }
    
    // Run benchmarks
    Benchmark4K();
    
    std::cout << "\n========================================================================\n";
    std::cout << "  All tests passed\n";
    std::cout << "========================================================================\n";
    
    return 0;
}
