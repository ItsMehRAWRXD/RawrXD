// ============================================================================
// Test Quantization Kernels
// ============================================================================

#include "quantization_kernels.hpp"
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>

using namespace RawrXD::Quantization;

// Test Q4_K dequantization
bool TestQ4_K() {
    std::cout << "Testing Q4_K dequantization...\n";
    
    // Create a simple Q4_K block
    BlockQ4_K block;
    block.d = 0x3C00;  // 1.0 in half-precision
    block.dmin = 0x0000; // 0.0 in half-precision
    
    // Initialize scales (simplified)
    for (int i = 0; i < K_SCALE_SIZE; i++) {
        block.scales[i] = 0x11;  // Scale = 1 for all blocks
    }
    
    // Initialize quants
    for (int i = 0; i < QK_K/2; i++) {
        block.qs[i] = 0x88;  // All values = 8
    }
    
    float output[QK_K];
    size_t count = QuantizationKernels::DequantizeQ4_K(&block, output, QK_K);
    
    if (count != QK_K) {
        std::cout << "  ✗ Expected " << QK_K << " elements, got " << count << "\n";
        return false;
    }
    
    // Check values (should be around 8.0 with scale 1.0)
    for (int i = 0; i < QK_K; i++) {
        if (std::abs(output[i] - 8.0f) > 0.1f) {
            std::cout << "  ✗ Value " << i << " = " << output[i] << " (expected ~8.0)\n";
            return false;
        }
    }
    
    std::cout << "  ✓ Q4_K dequantization correct\n";
    return true;
}

// Test Q6_K dequantization
bool TestQ6_K() {
    std::cout << "Testing Q6_K dequantization...\n";
    
    // Create a simple Q6_K block
    BlockQ6_K block;
    block.d = 0x3C00;  // 1.0 in half-precision
    
    // Initialize scales
    for (int i = 0; i < QK_K/16; i++) {
        block.scales[i] = 1;
    }
    
    // Initialize quants (all zeros = -32 after offset)
    for (int i = 0; i < QK_K/2; i++) {
        block.ql[i] = 0;
    }
    for (int i = 0; i < QK_K/4; i++) {
        block.qh[i] = 0;
    }
    
    float output[QK_K];
    size_t count = QuantizationKernels::DequantizeQ6_K(&block, output, QK_K);
    
    if (count != QK_K) {
        std::cout << "  ✗ Expected " << QK_K << " elements, got " << count << "\n";
        return false;
    }
    
    // Check values (should be -32.0 with scale 1.0)
    for (int i = 0; i < QK_K; i++) {
        if (std::abs(output[i] - (-32.0f)) > 0.1f) {
            std::cout << "  ✗ Value " << i << " = " << output[i] << " (expected ~-32.0)\n";
            return false;
        }
    }
    
    std::cout << "  ✓ Q6_K dequantization correct\n";
    return true;
}

// Test Q8_K dequantization
bool TestQ8_K() {
    std::cout << "Testing Q8_K dequantization...\n";
    
    // Create a simple Q8_K block
    BlockQ8_K block;
    block.d = 1.0f;
    
    // Initialize quants (all 1s)
    for (int i = 0; i < QK_K; i++) {
        block.qs[i] = 1;
    }
    
    // Initialize bsums
    for (int i = 0; i < QK_K/16; i++) {
        block.bsums[i] = 16;
    }
    
    float output[QK_K];
    size_t count = QuantizationKernels::DequantizeQ8_K(&block, output, QK_K);
    
    if (count != QK_K) {
        std::cout << "  ✗ Expected " << QK_K << " elements, got " << count << "\n";
        return false;
    }
    
    // Check values (should be 1.0 with scale 1.0)
    for (int i = 0; i < QK_K; i++) {
        if (std::abs(output[i] - 1.0f) > 0.1f) {
            std::cout << "  ✗ Value " << i << " = " << output[i] << " (expected ~1.0)\n";
            return false;
        }
    }
    
    std::cout << "  ✓ Q8_K dequantization correct\n";
    return true;
}

// Benchmark dequantization
void BenchmarkDequantization() {
    std::cout << "\nBenchmarking dequantization...\n";
    
    const size_t num_elements = 256 * 1000;  // 1000 blocks
    
    // Allocate blocks
    std::vector<BlockQ4_K> q4_blocks(num_elements / QK_K);
    std::vector<BlockQ6_K> q6_blocks(num_elements / QK_K);
    std::vector<BlockQ8_K> q8_blocks(num_elements / QK_K);
    std::vector<float> output(num_elements);
    
    // Initialize blocks
    for (auto& block : q4_blocks) {
        block.d = 0x3C00;
        block.dmin = 0;
        for (int i = 0; i < K_SCALE_SIZE; i++) block.scales[i] = 0x11;
        for (int i = 0; i < QK_K/2; i++) block.qs[i] = 0x88;
    }
    
    for (auto& block : q6_blocks) {
        block.d = 0x3C00;
        for (int i = 0; i < QK_K/16; i++) block.scales[i] = 1;
        for (int i = 0; i < QK_K/2; i++) block.ql[i] = 0;
        for (int i = 0; i < QK_K/4; i++) block.qh[i] = 0;
    }
    
    for (auto& block : q8_blocks) {
        block.d = 1.0f;
        for (int i = 0; i < QK_K; i++) block.qs[i] = 1;
    }
    
    // Benchmark Q4_K
    auto start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < 10; iter++) {
        QuantizationKernels::DequantizeQ4_K(q4_blocks.data(), output.data(), num_elements);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    float q4_time = duration.count() / 10.0f / 1000.0f;  // ms
    float q4_throughput = (num_elements * sizeof(float)) / (q4_time / 1000.0f) / (1024.0f * 1024.0f);  // MB/s
    
    // Benchmark Q6_K
    start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < 10; iter++) {
        QuantizationKernels::DequantizeQ6_K(q6_blocks.data(), output.data(), num_elements);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    float q6_time = duration.count() / 10.0f / 1000.0f;
    float q6_throughput = (num_elements * sizeof(float)) / (q6_time / 1000.0f) / (1024.0f * 1024.0f);
    
    // Benchmark Q8_K
    start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < 10; iter++) {
        QuantizationKernels::DequantizeQ8_K(q8_blocks.data(), output.data(), num_elements);
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    float q8_time = duration.count() / 10.0f / 1000.0f;
    float q8_throughput = (num_elements * sizeof(float)) / (q8_time / 1000.0f) / (1024.0f * 1024.0f);
    
    std::cout << "  Q4_K: " << q4_time << " ms (" << q4_throughput << " MB/s)\n";
    std::cout << "  Q6_K: " << q6_time << " ms (" << q6_throughput << " MB/s)\n";
    std::cout << "  Q8_K: " << q8_time << " ms (" << q8_throughput << " MB/s)\n";
    
    // Check CPU features
    std::cout << "\nCPU Features:\n";
    std::cout << "  AVX-512: " << (QuantizationKernels::HasAVX512() ? "Yes" : "No") << "\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Quantization Kernels Test\n";
    std::cout << "========================================\n\n";
    
    // Initialize
    QuantizationKernels::Initialize();
    
    bool all_passed = true;
    
    // Run tests
    all_passed &= TestQ4_K();
    all_passed &= TestQ6_K();
    all_passed &= TestQ8_K();
    
    // Run benchmark
    BenchmarkDequantization();
    
    std::cout << "\n========================================\n";
    if (all_passed) {
        std::cout << "All tests passed!\n";
    } else {
        std::cout << "Some tests failed!\n";
    }
    std::cout << "========================================\n";
    
    return all_passed ? 0 : 1;
}
