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
    
    // Debug: print first few weights and activations
    std::cout << "First weight block scale: " << weights[0].scale << "\n";
    std::cout << "First weight block bytes: ";
    for (int i = 0; i < 4; ++i) {
        std::cout << (int)weights[0].weights[i] << " ";
    }
    std::cout << "\n";
    std::cout << "First activations: ";
    for (int i = 0; i < 4; ++i) {
        std::cout << activation[i] << " ";
    }
    std::cout << "\n";
    
    // Run optimized kernel
    auto* kernel = KernelRegistry::Instance().Resolve(N, K);
    if (!kernel) {
        std::cout << "FAIL: Kernel not found\n";
        return false;
    }
    
    kernel->Execute(weights.data(), activation.data(), output.data(), N, K);
    
    // Compare (allow some tolerance for quantization)
    float maxError = 0.0f;
    size_t errorIdx = 0;
    for (size_t i = 0; i < N; ++i) {
        float error = std::abs(output[i] - reference[i]);
        if (error > maxError) {
            maxError = error;
            errorIdx = i;
        }
    }
    
    std::cout << "Max error: " << maxError << " at index " << errorIdx << "\n";
    std::cout << "  Output: " << output[errorIdx] << "\n";
    std::cout << "  Reference: " << reference[errorIdx] << "\n";
    std::cout << "  First output: " << output[0] << "\n";
    std::cout << "  First reference: " << reference[0] << "\n";
    
    if (maxError > 0.1f) {
        std::cout << "FAIL: Error too large\n";
        return false;
    }
    
    std::cout << "PASS\n";
    return true;
}

bool Test4K_AVX512() {
    std::cout << "\n=== Test: 4K Dimension (AVX-512) ===\n";
    
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
    
    // Run AVX-512 kernel directly
    auto kernel = std::make_shared<QuantizedMatMul_4K_AVX512>();
    kernel->Execute(weights.data(), activation.data(), output.data(), N, K);
    
    // Compare
    float maxError = 0.0f;
    size_t errorIdx = 0;
    for (size_t i = 0; i < N; ++i) {
        float error = std::abs(output[i] - reference[i]);
        if (error > maxError) {
            maxError = error;
            errorIdx = i;
        }
    }
    
    std::cout << "Max error: " << maxError << " at index " << errorIdx << "\n";
    
    if (maxError > 0.1f) {
        std::cout << "FAIL: Error too large\n";
        return false;
    }
    
    std::cout << "PASS\n";
    return true;
}

bool Test4K_4Way() {
    std::cout << "\n=== Test: 4K Dimension (4-Way Accumulator) ===\n";

    constexpr size_t N = 4096;
    constexpr size_t K = 4096;
    constexpr size_t numBlocks = (N * K) / 32;

    std::vector<Q4_0_Block> weights(numBlocks);
    std::vector<float> activation(K);
    std::vector<float> output_4way(N);
    std::vector<float> output_scalar(N);
    std::vector<float> reference(N);

    GenerateQ4_0Weights(weights, numBlocks);
    GenerateActivation(activation);

    // Run reference
    ReferenceMatMul(weights, activation, reference, N, K);

    // Run scalar kernel (oracle)
    QuantizedMatMul_Fused_4K(weights.data(), activation.data(), output_scalar.data(), N, K);

    // Run 4-way kernel
    QuantizedMatMul_4Way_4K(weights.data(), activation.data(), output_4way.data(), N, K);

    // Compare 4-way vs scalar (oracle)
    double maxErrorVsScalar = 0.0;
    size_t errorIdxScalar = 0;
    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(output_4way[i] - output_scalar[i]);
        if (error > maxErrorVsScalar) {
            maxErrorVsScalar = error;
            errorIdxScalar = i;
        }
    }

    // Compare 4-way vs reference
    double maxErrorVsRef = 0.0;
    size_t errorIdxRef = 0;
    for (size_t i = 0; i < N; ++i) {
        double error = std::abs(output_4way[i] - reference[i]);
        if (error > maxErrorVsRef) {
            maxErrorVsRef = error;
            errorIdxRef = i;
        }
    }

    std::cout << "Max error (4-way vs scalar oracle): " << maxErrorVsScalar << " at index " << errorIdxScalar << "\n";
    std::cout << "  4-way output: " << output_4way[errorIdxScalar] << "\n";
    std::cout << "  Scalar output: " << output_scalar[errorIdxScalar] << "\n";
    std::cout << "Max error (4-way vs reference): " << maxErrorVsRef << " at index " << errorIdxRef << "\n";
    std::cout << "  4-way output: " << output_4way[errorIdxRef] << "\n";
    std::cout << "  Reference: " << reference[errorIdxRef] << "\n";

    // FP32 tolerance for different accumulation order
    // 4-way changes order: (a+b)+(c+d) vs (((a+b)+c)+d)
    // For typical values, this should be within 1e-4 relative
    const double FP32_TOLERANCE = 1e-3;  // Absolute tolerance for FP32 reordering

    if (maxErrorVsScalar > FP32_TOLERANCE) {
        std::cout << "FAIL: Error vs scalar exceeds FP32 tolerance (" << FP32_TOLERANCE << ")\n";
        return false;
    }

    std::cout << "PASS (within FP32 tolerance)\n";
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

void Benchmark4K_AVX512() {
    std::cout << "\n=== Benchmark: 4K Dimension (AVX-512) ===\n";
    
    constexpr size_t N = 4096;
    constexpr size_t K = 4096;
    constexpr size_t numBlocks = (N * K) / 32;
    
    std::vector<Q4_0_Block> weights(numBlocks);
    std::vector<float> activation(K);
    std::vector<float> output(N);
    
    GenerateQ4_0Weights(weights, numBlocks);
    GenerateActivation(activation);
    
    auto kernel = std::make_shared<QuantizedMatMul_4K_AVX512>();
    
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

void Benchmark4K_4Way() {
    std::cout << "\n=== Benchmark: 4K Dimension (4-Way Accumulator) ===\n";
    
    constexpr size_t N = 4096;
    constexpr size_t K = 4096;
    constexpr size_t numBlocks = (N * K) / 32;
    
    std::vector<Q4_0_Block> weights(numBlocks);
    std::vector<float> activation(K);
    std::vector<float> output(N);
    
    GenerateQ4_0Weights(weights, numBlocks);
    GenerateActivation(activation);
    
    auto kernel = std::make_shared<QuantizedMatMul_4K_4Way>();
    
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
    double estimatedTPS = 540.0 * (61.0 / avgTime);  // Scale from baseline
    std::cout << "Estimated TPS contribution: " << estimatedTPS << " TPS\n";
    
    // Calculate speedup vs scalar baseline
    std::cout << "\n--- Performance Comparison ---\n";
    std::cout << "Expected speedup from 4-way accumulators: 1.5-2.0x\n";
    std::cout << "(Actual speedup requires comparison with scalar baseline)\n";
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
    allPassed &= Test4K_AVX512();
    allPassed &= Test4K_4Way();  // VAL-Q4.2 correctness gate
    allPassed &= Test5K();

    if (!allPassed) {
        std::cout << "\n=== SOME TESTS FAILED ===\n";
        return 1;
    }

    // Run benchmarks
    Benchmark4K();
    Benchmark4K_AVX512();
    Benchmark4K_4Way();  // VAL-Q4.2 performance gate
    
    std::cout << "\n========================================================================\n";
    std::cout << "  All tests passed\n";
    std::cout << "========================================================================\n";
    
    return 0;
}
