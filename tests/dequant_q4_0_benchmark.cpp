// ============================================================================
// Q4_0 Dequantization Benchmark & Validation Suite
// ============================================================================
//
// Comprehensive test harness for Q4_0 AVX2 dequantization kernel:
// - Correctness validation against scalar reference
// - Throughput measurement (GB/s dequantization rate)
// - Latency analysis (cycles per block)
// - Memory bandwidth saturation verification
//
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <random>
#include <cmath>
#include <cstring>
#include <malloc.h>

// ============================================================================
// Q4_0 Block Structure (GGUF Format)
// ============================================================================

struct block_q4_0 {
    float scale;           // 4 bytes: shared scale for 32 weights
    uint8_t qs[16];        // 16 bytes: 32 nibbles packed (2 per byte)
}; // 20 bytes total = 5 bits/weight

static_assert(sizeof(block_q4_0) == 20, "Q4_0 block must be 20 bytes");

// ============================================================================
// Assembly Function Declaration
// ============================================================================

extern "C" {
    // AVX2 dequantization kernel
    // Parameters:
    //   RCX = const block_q4_0* blocks (32-byte aligned)
    //   RDX = float* output (32-byte aligned)
    //   R8  = size_t num_blocks
    // Returns: RAX = 0 on success, error code on failure
    int MASM_Dequant_Q4_0_AVX2(const block_q4_0* blocks, float* output, size_t num_blocks);
}

// ============================================================================
// Scalar Reference Implementation (Correctness Baseline)
// ============================================================================

void Dequant_Q4_0_Scalar(const block_q4_0* blocks, float* output, size_t num_blocks) {
    for (size_t b = 0; b < num_blocks; b++) {
        float scale = blocks[b].scale;
        const uint8_t* qs = blocks[b].qs;
        
        for (int i = 0; i < 32; i++) {
            // Extract nibble: high nibble for even indices, low for odd
            uint8_t byte = qs[i / 2];
            uint8_t nibble = (i % 2 == 0) ? (byte >> 4) : (byte & 0x0F);
            
            // Dequantize: (nibble - 8) * scale
            output[b * 32 + i] = (static_cast<float>(nibble) - 8.0f) * scale;
        }
    }
}

// ============================================================================
// Test Data Generation
// ============================================================================

void Generate_Test_Blocks(block_q4_0* blocks, size_t num_blocks, unsigned int seed = 42) {
    std::mt19937 gen(seed);
    std::uniform_real_distribution<float> scale_dist(0.001f, 0.1f);
    
    for (size_t b = 0; b < num_blocks; b++) {
        blocks[b].scale = scale_dist(gen);
        
        for (int i = 0; i < 16; i++) {
            // Use deterministic pattern: low=i, high=i+1
            uint8_t low_nibble = static_cast<uint8_t>(i % 16);
            uint8_t high_nibble = static_cast<uint8_t>((i + 1) % 16);
            blocks[b].qs[i] = (high_nibble << 4) | low_nibble;
        }
    }
}

// ============================================================================
// Validation Tests
// ============================================================================

bool Test_Correctness() {
    std::cout << "\n=== Test: Correctness ===\n";
    
    const size_t num_blocks = 100;
    
    // Allocate aligned memory
    block_q4_0* blocks = (block_q4_0*)_aligned_malloc(num_blocks * sizeof(block_q4_0), 32);
    float* output_scalar = (float*)_aligned_malloc(num_blocks * 32 * sizeof(float), 32);
    float* output_avx2 = (float*)_aligned_malloc(num_blocks * 32 * sizeof(float), 32);
    
    if (!blocks || !output_scalar || !output_avx2) {
        std::cout << "❌ Memory allocation failed\n";
        return false;
    }
    
    // Generate test data
    Generate_Test_Blocks(blocks, num_blocks);
    
    // Run scalar reference
    Dequant_Q4_0_Scalar(blocks, output_scalar, num_blocks);
    
    // Run AVX2 kernel
    int ret = MASM_Dequant_Q4_0_AVX2(blocks, output_avx2, num_blocks);
    
    if (ret != 0) {
        std::cout << "❌ AVX2 kernel returned error code: " << ret << "\n";
        _aligned_free(blocks);
        _aligned_free(output_scalar);
        _aligned_free(output_avx2);
        return false;
    }
    
    // Compare results
    bool match = true;
    int mismatch_count = 0;
    float max_error = 0.0f;
    
    for (size_t i = 0; i < num_blocks * 32; i++) {
        float error = std::abs(output_scalar[i] - output_avx2[i]);
        if (error > 0.01f) {
            match = false;
            mismatch_count++;
            max_error = std::max(max_error, error);
            
            if (mismatch_count <= 5) {
                std::cout << "  Mismatch at index " << i 
                          << ": scalar=" << output_scalar[i]
                          << " avx2=" << output_avx2[i]
                          << " error=" << error << "\n";
            }
        }
    }
    
    if (match) {
        std::cout << "✅ All " << num_blocks * 32 << " values match (max error < 0.01)\n";
    } else {
        std::cout << "❌ " << mismatch_count << " mismatches found (max error: " << max_error << ")\n";
    }
    
    _aligned_free(blocks);
    _aligned_free(output_scalar);
    _aligned_free(output_avx2);
    
    return match;
}

// ============================================================================
// Performance Benchmarks
// ============================================================================

struct BenchmarkResult {
    double throughput_gbps;      // GB/s dequantization rate
    double latency_ns;         // Nanoseconds per block
    double cycles_per_block;   // Estimated CPU cycles
    double speedup_vs_scalar;  // Relative to scalar implementation
};

BenchmarkResult Benchmark_Scalar(const block_q4_0* blocks, float* output, 
                                  size_t num_blocks, int iterations) {
    // Warmup
    for (int i = 0; i < 10; i++) {
        Dequant_Q4_0_Scalar(blocks, output, num_blocks);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        Dequant_Q4_0_Scalar(blocks, output, num_blocks);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double total_bytes = static_cast<double>(num_blocks * iterations * sizeof(block_q4_0));
    double total_output_bytes = static_cast<double>(num_blocks * iterations * 32 * sizeof(float));
    
    BenchmarkResult result;
    result.throughput_gbps = (total_bytes + total_output_bytes) / duration_ns;
    result.latency_ns = static_cast<double>(duration_ns) / (num_blocks * iterations);
    result.cycles_per_block = result.latency_ns * 3.6; // Assuming 3.6 GHz
    result.speedup_vs_scalar = 1.0; // Baseline
    
    return result;
}

BenchmarkResult Benchmark_AVX2(const block_q4_0* blocks, float* output, 
                                size_t num_blocks, int iterations) {
    // Warmup
    for (int i = 0; i < 10; i++) {
        MASM_Dequant_Q4_0_AVX2(blocks, output, num_blocks);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        MASM_Dequant_Q4_0_AVX2(blocks, output, num_blocks);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double total_bytes = static_cast<double>(num_blocks * iterations * sizeof(block_q4_0));
    double total_output_bytes = static_cast<double>(num_blocks * iterations * 32 * sizeof(float));
    
    BenchmarkResult result;
    result.throughput_gbps = (total_bytes + total_output_bytes) / duration_ns;
    result.latency_ns = static_cast<double>(duration_ns) / (num_blocks * iterations);
    result.cycles_per_block = result.latency_ns * 3.6; // Assuming 3.6 GHz
    result.speedup_vs_scalar = 1.0; // Will be calculated later
    
    return result;
}

void Test_Performance() {
    std::cout << "\n=== Test: Performance ===\n";
    
    const size_t num_blocks = 10000;  // Large enough to saturate cache
    const int iterations = 100;
    
    // Allocate aligned memory
    block_q4_0* blocks = (block_q4_0*)_aligned_malloc(num_blocks * sizeof(block_q4_0), 32);
    float* output_scalar = (float*)_aligned_malloc(num_blocks * 32 * sizeof(float), 32);
    float* output_avx2 = (float*)_aligned_malloc(num_blocks * 32 * sizeof(float), 32);
    
    if (!blocks || !output_scalar || !output_avx2) {
        std::cout << "❌ Memory allocation failed\n";
        return;
    }
    
    // Generate test data
    Generate_Test_Blocks(blocks, num_blocks);
    
    std::cout << "Testing with " << num_blocks << " blocks (" 
              << (num_blocks * 20 / 1024.0 / 1024.0) << " MB input)\n";
    std::cout << "Running " << iterations << " iterations...\n\n";
    
    // Benchmark scalar
    std::cout << "Scalar Implementation:\n";
    auto scalar_result = Benchmark_Scalar(blocks, output_scalar, num_blocks, iterations);
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Throughput: " << scalar_result.throughput_gbps << " GB/s\n";
    std::cout << "  Latency: " << scalar_result.latency_ns << " ns/block\n";
    std::cout << "  Cycles: " << scalar_result.cycles_per_block << " cycles/block\n\n";
    
    // Benchmark AVX2
    std::cout << "AVX2 Implementation:\n";
    auto avx2_result = Benchmark_AVX2(blocks, output_avx2, num_blocks, iterations);
    avx2_result.speedup_vs_scalar = scalar_result.latency_ns / avx2_result.latency_ns;
    std::cout << "  Throughput: " << avx2_result.throughput_gbps << " GB/s\n";
    std::cout << "  Latency: " << avx2_result.latency_ns << " ns/block\n";
    std::cout << "  Cycles: " << avx2_result.cycles_per_block << " cycles/block\n";
    std::cout << "  Speedup: " << avx2_result.speedup_vs_scalar << "x vs scalar\n\n";
    
    // Memory bandwidth analysis
    double theoretical_max_bw = 50.0; // DDR4-3200 theoretical ~50 GB/s
    double utilization = (avx2_result.throughput_gbps / theoretical_max_bw) * 100.0;
    std::cout << "Memory Bandwidth Analysis:\n";
    std::cout << "  Theoretical Max: " << theoretical_max_bw << " GB/s (DDR4-3200)\n";
    std::cout << "  Achieved: " << avx2_result.throughput_gbps << " GB/s\n";
    std::cout << "  Utilization: " << utilization << "%\n";
    
    if (utilization > 80.0) {
        std::cout << "  ✅ Memory bandwidth saturated!\n";
    } else if (utilization > 50.0) {
        std::cout << "  ⚠️  Good but could be optimized further\n";
    } else {
        std::cout << "  ❌ Not saturating memory bandwidth - optimization needed\n";
    }
    
    _aligned_free(blocks);
    _aligned_free(output_scalar);
    _aligned_free(output_avx2);
}

// ============================================================================
// Stress Test
// ============================================================================

void Test_Stress() {
    std::cout << "\n=== Test: Stress (Various Block Counts) ===\n";
    
    std::vector<size_t> block_counts = {1, 10, 100, 1000, 10000};
    
    for (size_t num_blocks : block_counts) {
        block_q4_0* blocks = (block_q4_0*)_aligned_malloc(num_blocks * sizeof(block_q4_0), 32);
        float* output = (float*)_aligned_malloc(num_blocks * 32 * sizeof(float), 32);
        
        if (!blocks || !output) continue;
        
        Generate_Test_Blocks(blocks, num_blocks);
        
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100; i++) {
            MASM_Dequant_Q4_0_AVX2(blocks, output, num_blocks);
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 100;
        
        std::cout << "  " << std::setw(6) << num_blocks << " blocks: " 
                  << us << " µs/iter ("
                  << (num_blocks * 32 * sizeof(float) / 1024.0 / 1024.0 / (us / 1000000.0)) 
                  << " MB/s output)\n";
        
        _aligned_free(blocks);
        _aligned_free(output);
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Q4_0 Dequantization Benchmark Suite\n";
    std::cout << "RawrXD Assembly Kernel Validation\n";
    std::cout << "========================================\n";
    
    // Run tests
    bool correctness_passed = Test_Correctness();
    
    if (correctness_passed) {
        Test_Performance();
        Test_Stress();
        
        std::cout << "\n========================================\n";
        std::cout << "✅ ALL TESTS PASSED\n";
        std::cout << "========================================\n";
        return 0;
    } else {
        std::cout << "\n========================================\n";
        std::cout << "❌ CORRECTNESS TEST FAILED - Fix before benchmarking\n";
        std::cout << "========================================\n";
        return 1;
    }
}
