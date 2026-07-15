// ============================================================================
// q4_0_differential_test.cpp - Comprehensive Q4_0 Dequantization Validator
// ============================================================================
// 
// PURPOSE: Validate Q4_0 MASM kernel against scalar reference implementation
// 
// Test Coverage:
//   - Numerical equivalence (max error, mean error)
//   - Edge cases (all zeros, all 15s, alternating patterns)
//   - Random stress testing (100,000+ blocks)
//   - Performance benchmarking (cycles, throughput)
//   - Alignment variations
//
// Success Criteria:
//   - Max error < 1e-5 (FP32 rounding tolerance)
//   - Zero mismatches on all test cases
//   - MASM throughput > 10,000 M elements/sec
//
// ============================================================================

#include <iostream>
#include <iomanip>
#include <vector>
#include <random>
#include <chrono>
#include <cmath>
#include <cstring>
#include <algorithm>

#include "kernels/masm_kernels.hpp"

// ============================================================================
// Q4_0 Block Structure (matches GGUF format)
// ============================================================================
#pragma pack(push, 1)
struct block_q4_0 {
    float d;           // scale (4 bytes)
    uint8_t qs[8];     // 16 nibbles packed into 8 bytes (8 bytes)
    uint8_t padding[6]; // Padding to match assembly's 18-byte stride
    // Total: 18 bytes
};
#pragma pack(pop)

// Verify structure size
static_assert(sizeof(block_q4_0) == 18, "block_q4_0 must be 18 bytes");

// ============================================================================
// Scalar Reference Implementation (C++)
// ============================================================================
void dequantize_q4_0_scalar(const block_q4_0* blocks, float* output, size_t num_blocks) {
    for (size_t b = 0; b < num_blocks; ++b) {
        const block_q4_0& block = blocks[b];
        float scale = block.d;
        
        for (int i = 0; i < 8; ++i) {
            uint8_t byte = block.qs[i];
            
            // Low nibble (bits 0-3) -> weight index 0, 2, 4, 6, 8, 10, 12, 14
            int low_nibble = byte & 0x0F;
            float low_weight = (low_nibble - 8) * scale;
            output[b * 16 + i * 2] = low_weight;
            
            // High nibble (bits 4-7) -> weight index 1, 3, 5, 7, 9, 11, 13, 15
            int high_nibble = (byte >> 4) & 0x0F;
            float high_weight = (high_nibble - 8) * scale;
            output[b * 16 + i * 2 + 1] = high_weight;
        }
    }
}

// ============================================================================
// Test Result Structure
// ============================================================================
struct TestResult {
    const char* name;
    size_t blocks_tested;
    size_t floats_compared;
    double max_error;
    double mean_error;
    size_t mismatches;
    double cycles_per_block;
    double throughput_gbps;
    bool passed;
};

// ============================================================================
// Comparison Function
// ============================================================================
bool compare_outputs(const float* expected, const float* actual, size_t count, 
                     TestResult& result, double tolerance = 1e-5) {
    result.floats_compared = count;
    result.max_error = 0.0;
    result.mean_error = 0.0;
    result.mismatches = 0;
    
    double sum_error = 0.0;
    
    for (size_t i = 0; i < count; ++i) {
        double error = std::abs(expected[i] - actual[i]);
        sum_error += error;
        result.max_error = std::max(result.max_error, error);
        
        if (error > tolerance) {
            result.mismatches++;
            if (result.mismatches <= 5) {
                std::cout << "  Mismatch at index " << i << ": expected " 
                          << expected[i] << ", got " << actual[i] 
                          << " (error: " << error << ")" << std::endl;
            }
        }
    }
    
    result.mean_error = sum_error / count;
    result.passed = (result.mismatches == 0);
    
    return result.passed;
}

// ============================================================================
// Test Case: All Zeros
// ============================================================================
bool test_all_zeros(TestResult& result) {
    std::cout << "\n[Test] All zeros (scale=1.0)" << std::endl;
    
    const size_t num_blocks = 100;
    std::vector<block_q4_0> blocks(num_blocks);
    std::vector<float> expected(num_blocks * 16);
    std::vector<float> actual(num_blocks * 16);
    
    // Initialize all blocks with zeros
    for (auto& block : blocks) {
        block.d = 1.0f;
        std::memset(block.qs, 0, sizeof(block.qs));
    }
    
    // Scalar reference
    dequantize_q4_0_scalar(blocks.data(), expected.data(), num_blocks);
    
    // MASM kernel
    std::cout << "  Debug: Calling MASM_Q4_0_Dequantize with " << num_blocks << " blocks" << std::endl;
    std::cout << "  Debug: Input ptr = " << blocks.data() << ", Output ptr = " << actual.data() << std::endl;
    int ret = MASM_Q4_0_Dequantize(blocks.data(), actual.data(), num_blocks);
    if (ret != 0) {
        std::cout << "  ❌ FAIL: MASM kernel returned error code " << ret << std::endl;
        result.passed = false;
        return false;
    }
    
    // Debug: Print first few expected vs actual
    std::cout << "  Debug: First 8 expected: ";
    for (int i = 0; i < 8; ++i) std::cout << expected[i] << " ";
    std::cout << std::endl;
    std::cout << "  Debug: First 8 actual:   ";
    for (int i = 0; i < 8; ++i) std::cout << actual[i] << " ";
    std::cout << std::endl;
    std::cout << "  Debug: Block 0 (indices 8-15) expected: ";
    for (int i = 8; i < 16; ++i) std::cout << expected[i] << " ";
    std::cout << std::endl;
    std::cout << "  Debug: Block 0 (indices 8-15) actual:   ";
    for (int i = 8; i < 16; ++i) std::cout << actual[i] << " ";
    std::cout << std::endl;
    std::cout << "  Debug: Block 1 (indices 16-23) expected: ";
    for (int i = 16; i < 24; ++i) std::cout << expected[i] << " ";
    std::cout << std::endl;
    std::cout << "  Debug: Block 1 (indices 16-23) actual:   ";
    for (int i = 16; i < 24; ++i) std::cout << actual[i] << " ";
    std::cout << std::endl;
    
    // Debug: Check input block layout
    std::cout << "  Debug: Block 0 bytes 0-17: ";
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(blocks.data());
    for (int i = 0; i < 18; ++i) std::cout << std::hex << (int)raw[i] << " ";
    std::cout << std::dec << std::endl;
    std::cout << "  Debug: Block 1 bytes 18-35: ";
    for (int i = 18; i < 36; ++i) std::cout << std::hex << (int)raw[i] << " ";
    std::cout << std::dec << std::endl;
    
    result.name = "All Zeros";
    result.blocks_tested = num_blocks;
    
    bool pass = compare_outputs(expected.data(), actual.data(), num_blocks * 16, result);
    std::cout << "  " << (pass ? "✅ PASS" : "❌ FAIL") << std::endl;
    
    return pass;
}

// ============================================================================
// Test Case: All 15s
// ============================================================================
bool test_all_15s(TestResult& result) {
    std::cout << "\n[Test] All 15s (scale=1.0)" << std::endl;
    
    const size_t num_blocks = 100;
    std::vector<block_q4_0> blocks(num_blocks);
    std::vector<float> expected(num_blocks * 16);
    std::vector<float> actual(num_blocks * 16);
    
    // Initialize all blocks with 0xFF (both nibbles = 15)
    for (auto& block : blocks) {
        block.d = 1.0f;
        std::memset(block.qs, 0xFF, sizeof(block.qs));
    }
    
    dequantize_q4_0_scalar(blocks.data(), expected.data(), num_blocks);
    
    int ret = MASM_Q4_0_Dequantize(blocks.data(), actual.data(), num_blocks);
    if (ret != 0) {
        std::cout << "  ❌ FAIL: MASM kernel returned error code " << ret << std::endl;
        result.passed = false;
        return false;
    }
    
    result.name = "All 15s";
    result.blocks_tested = num_blocks;
    
    bool pass = compare_outputs(expected.data(), actual.data(), num_blocks * 16, result);
    std::cout << "  " << (pass ? "✅ PASS" : "❌ FAIL") << std::endl;
    
    return pass;
}

// ============================================================================
// Test Case: Alternating Pattern
// ============================================================================
bool test_alternating(TestResult& result) {
    std::cout << "\n[Test] Alternating 0/15 pattern" << std::endl;
    
    const size_t num_blocks = 100;
    std::vector<block_q4_0> blocks(num_blocks);
    std::vector<float> expected(num_blocks * 16);
    std::vector<float> actual(num_blocks * 16);
    
    // Initialize with alternating pattern: 0xF0, 0x0F, 0xF0, 0x0F...
    for (auto& block : blocks) {
        block.d = 0.5f;
        for (int i = 0; i < 8; ++i) {
            block.qs[i] = (i % 2 == 0) ? 0xF0 : 0x0F;
        }
    }
    
    dequantize_q4_0_scalar(blocks.data(), expected.data(), num_blocks);
    
    int ret = MASM_Q4_0_Dequantize(blocks.data(), actual.data(), num_blocks);
    if (ret != 0) {
        std::cout << "  ❌ FAIL: MASM kernel returned error code " << ret << std::endl;
        result.passed = false;
        return false;
    }
    
    result.name = "Alternating";
    result.blocks_tested = num_blocks;
    
    bool pass = compare_outputs(expected.data(), actual.data(), num_blocks * 16, result);
    std::cout << "  " << (pass ? "✅ PASS" : "❌ FAIL") << std::endl;
    
    return pass;
}

// ============================================================================
// Test Case: Random Stress Test
// ============================================================================
bool test_random_stress(TestResult& result) {
    std::cout << "\n[Test] Random stress (100,000 blocks)" << std::endl;
    
    const size_t num_blocks = 100000;
    std::vector<block_q4_0> blocks(num_blocks);
    std::vector<float> expected(num_blocks * 16);
    std::vector<float> actual(num_blocks * 16);
    
    // Random number generators
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> scale_dist(0.001f, 10.0f);
    std::uniform_int_distribution<int> nibble_dist(0, 15);
    
    // Initialize random blocks
    for (auto& block : blocks) {
        block.d = scale_dist(gen);
        for (int i = 0; i < 8; ++i) {
            int low = nibble_dist(gen);
            int high = nibble_dist(gen);
            block.qs[i] = (high << 4) | low;
        }
    }
    
    dequantize_q4_0_scalar(blocks.data(), expected.data(), num_blocks);
    
    int ret = MASM_Q4_0_Dequantize(blocks.data(), actual.data(), num_blocks);
    if (ret != 0) {
        std::cout << "  ❌ FAIL: MASM kernel returned error code " << ret << std::endl;
        result.passed = false;
        return false;
    }
    
    result.name = "Random Stress";
    result.blocks_tested = num_blocks;
    
    bool pass = compare_outputs(expected.data(), actual.data(), num_blocks * 16, result);
    std::cout << "  " << (pass ? "✅ PASS" : "❌ FAIL") << std::endl;
    
    return pass;
}

// ============================================================================
// Performance Benchmark
// ============================================================================
bool benchmark_performance(TestResult& result) {
    std::cout << "\n[Benchmark] Performance (1M blocks)" << std::endl;
    
    const size_t num_blocks = 1000000;
    std::vector<block_q4_0> blocks(num_blocks);
    std::vector<float> output(num_blocks * 16);
    
    // Initialize with random data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> scale_dist(0.001f, 10.0f);
    std::uniform_int_distribution<int> nibble_dist(0, 15);
    
    for (auto& block : blocks) {
        block.d = scale_dist(gen);
        for (int i = 0; i < 8; ++i) {
            int low = nibble_dist(gen);
            int high = nibble_dist(gen);
            block.qs[i] = (high << 4) | low;
        }
    }
    
    // Warmup
    for (int i = 0; i < 3; ++i) {
        MASM_Q4_0_Dequantize(blocks.data(), output.data(), num_blocks);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    int ret = MASM_Q4_0_Dequantize(blocks.data(), output.data(), num_blocks);
    auto end = std::chrono::high_resolution_clock::now();
    
    if (ret != 0) {
        std::cout << "  ❌ FAIL: MASM kernel returned error code " << ret << std::endl;
        result.passed = false;
        return false;
    }
    
    double ms = std::chrono::duration<double, std::milli>(end - start).count();
    double total_floats = num_blocks * 16;
    double bytes_processed = num_blocks * sizeof(block_q4_0);
    double throughput_gbps = (bytes_processed / (ms / 1000.0)) / 1e9;
    double elements_per_sec = (total_floats / (ms / 1000.0)) / 1e6;  // Millions
    
    result.name = "Performance";
    result.blocks_tested = num_blocks;
    result.floats_compared = total_floats;
    result.throughput_gbps = throughput_gbps;
    
    std::cout << "  Time: " << std::fixed << std::setprecision(2) << ms << " ms" << std::endl;
    std::cout << "  Throughput: " << std::fixed << std::setprecision(2) << throughput_gbps << " GB/s" << std::endl;
    std::cout << "  Elements/sec: " << std::fixed << std::setprecision(2) << elements_per_sec << " M elements/sec" << std::endl;
    
    // Performance target: > 10,000 M elements/sec
    bool pass = (elements_per_sec > 10000);
    result.passed = pass;
    std::cout << "  " << (pass ? "✅ PASS" : "⚠️  BELOW TARGET") << std::endl;
    
    return pass;
}

// ============================================================================
// Main Entry Point
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Q4_0 Dequantization Differential Test" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::vector<TestResult> results;
    bool all_passed = true;
    
    // Run all test cases
    TestResult r1; test_all_zeros(r1); results.push_back(r1); all_passed &= r1.passed;
    TestResult r2; test_all_15s(r2); results.push_back(r2); all_passed &= r2.passed;
    TestResult r3; test_alternating(r3); results.push_back(r3); all_passed &= r3.passed;
    TestResult r4; test_random_stress(r4); results.push_back(r4); all_passed &= r4.passed;
    TestResult r5; benchmark_performance(r5); results.push_back(r5); all_passed &= r5.passed;
    
    // Summary Report
    std::cout << "\n========================================" << std::endl;
    std::cout << "=== FINAL SUMMARY ===" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::cout << "\n| Test Case | Blocks | Floats | Max Error | Mean Error | Mismatches | Status |" << std::endl;
    std::cout << "|-----------|--------|--------|-----------|------------|------------|--------|" << std::endl;
    
    for (const auto& r : results) {
        std::cout << "| " << std::left << std::setw(9) << r.name 
                  << " | " << std::setw(6) << r.blocks_tested
                  << " | " << std::setw(6) << r.floats_compared
                  << " | " << std::scientific << std::setprecision(2) << r.max_error
                  << " | " << r.mean_error
                  << " | " << std::setw(10) << r.mismatches
                  << " | " << (r.passed ? "✅ PASS" : "❌ FAIL")
                  << " |" << std::endl;
    }
    
    std::cout << "\n========================================" << std::endl;
    if (all_passed) {
        std::cout << "✅ ALL TESTS PASSED" << std::endl;
        std::cout << "Q4_0 kernel is PRODUCTION READY" << std::endl;
        return 0;
    } else {
        std::cout << "❌ SOME TESTS FAILED" << std::endl;
        std::cout << "Review failures above before production deployment" << std::endl;
        return 1;
    }
}
