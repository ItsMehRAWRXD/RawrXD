// ============================================================================
// q4_0_optimized_bench.cpp - Benchmark: Original vs Optimized Q4_0 Kernel
// ============================================================================

#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <cstring>
#include <random>

#include "kernels/masm_kernels.hpp"

// Q4_0 Block Structure (matches GGUF format)
#pragma pack(push, 1)
struct block_q4_0 {
    float d;           // scale (4 bytes)
    uint8_t qs[8];     // 16 nibbles packed into 8 bytes (8 bytes)
    uint8_t padding[6]; // Padding to match assembly's 18-byte stride
};
#pragma pack(pop)

static_assert(sizeof(block_q4_0) == 18, "block_q4_0 must be 18 bytes");

// Initialize blocks with random data
void init_random_blocks(block_q4_0* blocks, size_t num_blocks) {
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> scale_dist(0.001f, 0.1f);
    std::uniform_int_distribution<int> nibble_dist(0, 15);
    
    for (size_t i = 0; i < num_blocks; ++i) {
        blocks[i].d = scale_dist(rng);
        for (int j = 0; j < 8; ++j) {
            uint8_t low = nibble_dist(rng);
            uint8_t high = nibble_dist(rng);
            blocks[i].qs[j] = (high << 4) | low;
        }
    }
}

// Benchmark a kernel function
template<typename Func>
struct BenchmarkResult {
    double time_ms;
    double throughput_gbps;
    double elements_per_sec;
    bool success;
};

template<typename Func>
BenchmarkResult<Func> benchmark_kernel(Func kernel, const block_q4_0* input, 
                                        float* output, size_t num_blocks,
                                        int iterations = 100) {
    BenchmarkResult<Func> result = {};
    
    // Warmup
    for (int i = 0; i < 10; ++i) {
        kernel(input, output, num_blocks);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        int ret = kernel(input, output, num_blocks);
        if (ret != 0) {
            result.success = false;
            return result;
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    result.success = true;
    result.time_ms = std::chrono::duration<double, std::milli>(end - start).count() / iterations;
    
    // Calculate throughput
    size_t total_bytes = num_blocks * sizeof(block_q4_0);
    size_t total_output_bytes = num_blocks * 16 * sizeof(float);
    result.throughput_gbps = (total_bytes + total_output_bytes) / (result.time_ms * 1e6);
    
    // Calculate elements/sec
    size_t total_elements = num_blocks * 16;
    result.elements_per_sec = total_elements / (result.time_ms * 1e-3) / 1e6; // M elements/sec
    
    return result;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Q4_0 Kernel Optimization Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    const size_t num_blocks = 100000;  // 100K blocks
    const int iterations = 100;
    
    // Allocate memory
    std::vector<block_q4_0> input(num_blocks);
    std::vector<float> output_original(num_blocks * 16);
    std::vector<float> output_optimized(num_blocks * 16);
    
    // Initialize with random data
    init_random_blocks(input.data(), num_blocks);
    
    std::cout << "Test Configuration:" << std::endl;
    std::cout << "  Blocks: " << num_blocks << std::endl;
    std::cout << "  Iterations: " << iterations << std::endl;
    std::cout << "  Total elements: " << (num_blocks * 16) << std::endl;
    std::cout << std::endl;
    
    // Benchmark original kernel
    std::cout << "Running Original Kernel..." << std::endl;
    auto result_orig = benchmark_kernel(MASM_Q4_0_Dequantize, 
                                        input.data(), output_original.data(), 
                                        num_blocks, iterations);
    
    if (!result_orig.success) {
        std::cout << "  ❌ Original kernel failed!" << std::endl;
        return 1;
    }
    
    // Benchmark optimized kernel
    std::cout << "Running Optimized Kernel..." << std::endl;
    auto result_opt = benchmark_kernel(MASM_Q4_0_Dequantize_Optimized,
                                       input.data(), output_optimized.data(),
                                       num_blocks, iterations);
    
    if (!result_opt.success) {
        std::cout << "  ❌ Optimized kernel failed!" << std::endl;
        return 1;
    }
    
    // Verify correctness
    std::cout << "Verifying correctness..." << std::endl;
    bool match = true;
    double max_diff = 0.0;
    for (size_t i = 0; i < num_blocks * 16; ++i) {
        double diff = std::abs(output_original[i] - output_optimized[i]);
        max_diff = std::max(max_diff, diff);
        if (diff > 1e-5) {
            match = false;
            std::cout << "  Mismatch at index " << i << ": " 
                      << output_original[i] << " vs " << output_optimized[i] << std::endl;
            break;
        }
    }
    
    // Print results
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "| Metric | Original | Optimized | Speedup |" << std::endl;
    std::cout << "|--------|----------|-----------|---------|" << std::endl;
    std::cout << "| Time (ms) | " << result_orig.time_ms << " | " 
              << result_opt.time_ms << " | " 
              << (result_orig.time_ms / result_opt.time_ms) << "x |" << std::endl;
    std::cout << "| Throughput (GB/s) | " << result_orig.throughput_gbps 
              << " | " << result_opt.throughput_gbps << " | "
              << (result_opt.throughput_gbps / result_orig.throughput_gbps) << "x |" << std::endl;
    std::cout << "| Elements/sec (M) | " << result_orig.elements_per_sec
              << " | " << result_opt.elements_per_sec << " | "
              << (result_opt.elements_per_sec / result_orig.elements_per_sec) << "x |" << std::endl;
    
    std::cout << std::endl;
    std::cout << "Correctness: " << (match ? "✅ PASS" : "❌ FAIL") << std::endl;
    std::cout << "Max difference: " << std::scientific << max_diff << std::endl;
    
    // Target check
    std::cout << std::endl;
    std::cout << "Target: 10,000 M elements/sec" << std::endl;
    if (result_opt.elements_per_sec >= 10000.0) {
        std::cout << "  ✅ TARGET ACHIEVED!" << std::endl;
    } else {
        std::cout << "  ⚠️  Below target by " << (10000.0 - result_opt.elements_per_sec) 
                  << " M elements/sec" << std::endl;
    }
    
    return match ? 0 : 1;
}
