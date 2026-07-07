// ============================================================================
// zero_assembly_test.cpp - Zero-Assembly Baseline Test
// ============================================================================
// 
// PURPOSE: Isolate timing wrapper corruption from assembly kernel corruption
// 
// STRATEGY:
//   1. Replace MASM kernel calls with simple C++ loops
//   2. If timing is STILL corrupt, bug is in timing wrapper
//   3. If timing is correct, bug is in assembly-to-C++ ABI boundary
// 
// CRITICAL: This test uses NO assembly code - pure C++ timing
// 
// ============================================================================

#include <iostream>
#include <cstdint>
#include <chrono>
#include <thread>
#include <immintrin.h>

#include "timing_wrapper_fixed.hpp"

using namespace RawrXD::Validation;

// ============================================================================
// Simple C++ Kernels (No Assembly)
// ============================================================================

void Simple_Sleep_Kernel(void* data, size_t size) {
    // Simple kernel that just sleeps for 1ms
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
}

void Simple_Loop_Kernel(void* data, size_t size) {
    // Simple kernel that performs basic math
    float* values = static_cast<float*>(data);
    size_t count = size / sizeof(float);
    
    // Simple loop: multiply each value by 2
    for (size_t i = 0; i < count; ++i) {
        values[i] = values[i] * 2.0f;
    }
}

void Simple_Vector_Kernel(void* data, size_t size) {
    // Simple kernel that uses AVX2 vector operations
    float* values = static_cast<float*>(data);
    size_t count = size / sizeof(float);
    
    // Process 8 floats at a time using AVX2
    size_t i = 0;
    for (; i + 8 <= count; i += 8) {
        __m256 vec = _mm256_load_ps(&values[i]);
        vec = _mm256_mul_ps(vec, _mm256_set1_ps(2.0f));
        _mm256_store_ps(&values[i], vec);
    }
    
    // Process remaining elements
    for (; i < count; ++i) {
        values[i] = values[i] * 2.0f;
    }
}

// ============================================================================
// Timing Wrapper Validation
// ============================================================================

bool Test_Timing_Wrapper_Basic() {
    std::cout << "\n=== Test 1: Basic Timing Wrapper ===" << std::endl;
    
    // Allocate aligned data
    alignas(32) float data[1024];
    for (int i = 0; i < 1024; ++i) {
        data[i] = static_cast<float>(i);
    }
    
    // Test with simple sleep kernel
    std::cout << "Testing with Sleep(1ms) kernel..." << std::endl;
    TimingResult result = measure_kernel_comprehensive(Simple_Sleep_Kernel, data, sizeof(data));
    
    if (!result.valid) {
        std::cout << "❌ FAIL: " << result.error_message << std::endl;
        return false;
    }
    
    std::cout << "✅ PASS: Timing wrapper works correctly" << std::endl;
    std::cout << "   Cycles: " << result.cycles << std::endl;
    std::cout << "   Time: " << result.time_ms << " ms" << std::endl;
    
    // Verify timing is reasonable (1ms sleep should be ~1-10ms in wall clock time)
    if (result.time_ms < 0.5 || result.time_ms > 100.0) {
        std::cout << "❌ FAIL: Timing is unreasonable (expected ~1ms, got " << result.time_ms << " ms)" << std::endl;
        return false;
    }
    
    std::cout << "✅ PASS: Timing is reasonable" << std::endl;
    return true;
}

bool Test_Timing_Wrapper_Loop() {
    std::cout << "\n=== Test 2: Loop Kernel Timing ===" << std::endl;
    
    // Allocate aligned data
    alignas(32) float data[1024];
    for (int i = 0; i < 1024; ++i) {
        data[i] = static_cast<float>(i);
    }
    
    // Test with simple loop kernel
    std::cout << "Testing with simple loop kernel..." << std::endl;
    TimingResult result = measure_kernel_comprehensive(Simple_Loop_Kernel, data, sizeof(data));
    
    if (!result.valid) {
        std::cout << "❌ FAIL: " << result.error_message << std::endl;
        return false;
    }
    
    std::cout << "✅ PASS: Timing wrapper works correctly" << std::endl;
    std::cout << "   Cycles: " << result.cycles << std::endl;
    std::cout << "   Time: " << result.time_ms << " ms" << std::endl;
    
    // Verify timing is reasonable (should be very fast, < 1ms)
    if (result.time_ms < 0.0 || result.time_ms > 10.0) {
        std::cout << "❌ FAIL: Timing is unreasonable (expected < 1ms, got " << result.time_ms << " ms)" << std::endl;
        return false;
    }
    
    // Verify cycles are reasonable (should be > 0 and < 1 billion)
    if (result.cycles == 0 || result.cycles > 1000000000ULL) {
        std::cout << "❌ FAIL: Cycle count is unreasonable (expected > 0 and < 1B, got " << result.cycles << ")" << std::endl;
        return false;
    }
    
    std::cout << "✅ PASS: Timing is reasonable" << std::endl;
    return true;
}

bool Test_Timing_Wrapper_Vector() {
    std::cout << "\n=== Test 3: Vector Kernel Timing ===" << std::endl;
    
    // Allocate aligned data
    alignas(32) float data[1024];
    for (int i = 0; i < 1024; ++i) {
        data[i] = static_cast<float>(i);
    }
    
    // Test with AVX2 vector kernel
    std::cout << "Testing with AVX2 vector kernel..." << std::endl;
    TimingResult result = measure_kernel_comprehensive(Simple_Vector_Kernel, data, sizeof(data));
    
    if (!result.valid) {
        std::cout << "❌ FAIL: " << result.error_message << std::endl;
        return false;
    }
    
    std::cout << "✅ PASS: Timing wrapper works correctly" << std::endl;
    std::cout << "   Cycles: " << result.cycles << std::endl;
    std::cout << "   Time: " << result.time_ms << " ms" << std::endl;
    
    // Verify timing is reasonable (should be very fast, < 1ms)
    if (result.time_ms < 0.0 || result.time_ms > 10.0) {
        std::cout << "❌ FAIL: Timing is unreasonable (expected < 1ms, got " << result.time_ms << " ms)" << std::endl;
        return false;
    }
    
    // Verify cycles are reasonable (should be > 0 and < 1 billion)
    if (result.cycles == 0 || result.cycles > 1000000000ULL) {
        std::cout << "❌ FAIL: Cycle count is unreasonable (expected > 0 and < 1B, got " << result.cycles << ")" << std::endl;
        return false;
    }
    
    std::cout << "✅ PASS: Timing is reasonable" << std::endl;
    return true;
}

bool Test_Timing_Wrapper_Multiple_Runs() {
    std::cout << "\n=== Test 4: Multiple Runs Consistency ===" << std::endl;
    
    // Allocate aligned data
    alignas(32) float data[1024];
    for (int i = 0; i < 1024; ++i) {
        data[i] = static_cast<float>(i);
    }
    
    // Run multiple times to check for consistency
    std::cout << "Running 10 iterations..." << std::endl;
    
    uint64_t min_cycles = UINT64_MAX;
    uint64_t max_cycles = 0;
    uint64_t total_cycles = 0;
    int valid_runs = 0;
    
    for (int i = 0; i < 10; ++i) {
        TimingResult result = measure_kernel_comprehensive(Simple_Loop_Kernel, data, sizeof(data));
        
        if (!result.valid) {
            std::cout << "❌ FAIL on iteration " << i << ": " << result.error_message << std::endl;
            continue;
        }
        
        valid_runs++;
        min_cycles = (std::min)(min_cycles, result.cycles);
        max_cycles = (std::max)(max_cycles, result.cycles);
        total_cycles += result.cycles;
        
        std::cout << "  Run " << i << ": " << result.cycles << " cycles, " << result.time_ms << " ms" << std::endl;
    }
    
    if (valid_runs < 10) {
        std::cout << "❌ FAIL: Only " << valid_runs << "/10 runs were valid" << std::endl;
        return false;
    }
    
    uint64_t avg_cycles = total_cycles / 10;
    
    std::cout << "✅ PASS: All 10 runs were valid" << std::endl;
    std::cout << "   Min cycles: " << min_cycles << std::endl;
    std::cout << "   Max cycles: " << max_cycles << std::endl;
    std::cout << "   Avg cycles: " << avg_cycles << std::endl;
    
    // Check for reasonable variance (max should not be > 10x min)
    if (max_cycles > min_cycles * 10) {
        std::cout << "❌ FAIL: Timing variance is too high (max > 10x min)" << std::endl;
        return false;
    }
    
    std::cout << "✅ PASS: Timing variance is reasonable" << std::endl;
    return true;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Zero-Assembly Baseline Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "\nThis test isolates the timing wrapper from assembly kernels." << std::endl;
    std::cout << "If this test FAILS, the bug is in the timing wrapper." << std::endl;
    std::cout << "If this test PASSES, the bug is in the assembly-to-C++ boundary." << std::endl;
    
    bool all_passed = true;
    
    // Run all tests
    all_passed &= Test_Timing_Wrapper_Basic();
    all_passed &= Test_Timing_Wrapper_Loop();
    all_passed &= Test_Timing_Wrapper_Vector();
    all_passed &= Test_Timing_Wrapper_Multiple_Runs();
    
    // Final result
    std::cout << "\n========================================" << std::endl;
    std::cout << "=== FINAL RESULT ===" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (all_passed) {
        std::cout << "✅ ALL TESTS PASSED" << std::endl;
        std::cout << "\n🎯 DIAGNOSIS: Timing wrapper is CORRECT." << std::endl;
        std::cout << "   The bug is in the ASSEMBLY-TO-C++ BOUNDARY." << std::endl;
        std::cout << "\nNext steps:" << std::endl;
        std::cout << "   1. Check XMM/YMM/ZMM register preservation in assembly" << std::endl;
        std::cout << "   2. Verify function calling convention matches" << std::endl;
        std::cout << "   3. Check for stack alignment issues" << std::endl;
        return 0;
    } else {
        std::cout << "❌ TESTS FAILED" << std::endl;
        std::cout << "\n🎯 DIAGNOSIS: Timing wrapper is CORRUPT." << std::endl;
        std::cout << "   The bug is in the TIMING WRAPPER itself." << std::endl;
        std::cout << "\nNext steps:" << std::endl;
        std::cout << "   1. Fix the timing wrapper implementation" << std::endl;
        std::cout << "   2. Check for integer type mismatches" << std::endl;
        std::cout << "   3. Verify stack alignment in timing wrapper" << std::endl;
        return 1;
    }
}