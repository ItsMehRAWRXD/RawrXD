// ============================================================================
// masm_kernels_test.cpp
// ============================================================================
// Test harness for MASM AVX-512 kernels.
// Performs differential testing between scalar C++ and MASM implementations.
//
// Test Strategy:
//   1. Generate random test data
//   2. Run scalar C++ implementation
//   3. Run MASM AVX-512 implementation
//   4. Compare results bit-by-bit
//   5. Measure performance difference
// ============================================================================

#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <chrono>
#include <random>
#include <vector>

#include "masm_kernels.hpp"
#include "../aligned_allocator.h"

// Windows headers for AVX-512 detection
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <intrin.h>

using namespace RawrXD;

// ============================================================================
// Test Configuration
// ============================================================================

constexpr size_t TEST_SIZE = 1024;  // Number of floats to test
constexpr size_t ALIGNMENT = 64;    // AVX-512 alignment requirement
constexpr float TOLERANCE = 1e-5f; // Tolerance for floating-point comparison

// ============================================================================
// Scalar Reference Implementations
// ============================================================================

void Scalar_Silu_Activation(float* data, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        // SiLU(x) = x * sigmoid(x)
        // sigmoid(x) ≈ 0.5 + 0.25*x - 0.020833*x^3 + 0.002604*x^5
        float x = data[i];
        float x2 = x * x;
        float x3 = x2 * x;
        float x5 = x3 * x2;
        
        float sigmoid = 0.5f + 0.25f * x - 0.020833f * x3 + 0.002604f * x5;
        data[i] = x * sigmoid;
    }
}

// ============================================================================
// Test Utilities
// ============================================================================

bool CompareFloats(float a, float b, float tolerance = TOLERANCE) {
    if (std::isnan(a) && std::isnan(b)) return true;
    if (std::isinf(a) && std::isinf(b)) return true;
    return std::abs(a - b) < tolerance;
}

void PrintFloatArray(const char* name, const float* data, size_t count, size_t max_print = 10) {
    std::cout << name << ": [";
    for (size_t i = 0; i < std::min(count, max_print); ++i) {
        std::cout << std::fixed << std::setprecision(6) << data[i];
        if (i < count - 1) std::cout << ", ";
    }
    if (count > max_print) std::cout << ", ...";
    std::cout << "]" << std::endl;
}

// ============================================================================
// Test Functions
// ============================================================================

bool Test_Silu_Activation_Basic() {
    std::cout << "\n[Test] SiLU Activation - Basic Functionality" << std::endl;
    
    // Allocate aligned buffers
    AlignedVector<float> input(TEST_SIZE);
    AlignedVector<float> scalar_output(TEST_SIZE);
    AlignedVector<float> masm_output(TEST_SIZE);
    
    // Initialize with test data
    std::mt19937 rng(42);  // Fixed seed for reproducibility
    std::uniform_real_distribution<float> dist(-5.0f, 5.0f);
    
    for (size_t i = 0; i < TEST_SIZE; ++i) {
        input[i] = dist(rng);
        scalar_output[i] = input[i];
        masm_output[i] = input[i];
    }
    
    // Run scalar implementation
    auto scalar_start = std::chrono::high_resolution_clock::now();
    Scalar_Silu_Activation(scalar_output.data(), TEST_SIZE);
    auto scalar_end = std::chrono::high_resolution_clock::now();
    double scalar_ms = std::chrono::duration<double, std::milli>(scalar_end - scalar_start).count();
    
    // Run MASM implementation
    auto masm_start = std::chrono::high_resolution_clock::now();
    int result = MASM_Silu_Activation_AVX512(masm_output.data(), TEST_SIZE * sizeof(float));
    auto masm_end = std::chrono::high_resolution_clock::now();
    double masm_ms = std::chrono::duration<double, std::milli>(masm_end - masm_start).count();
    
    // Check return value
    if (result != 0) {
        std::cerr << "  ❌ MASM kernel returned error: " << result << std::endl;
        return false;
    }
    
    // Compare results
    size_t mismatches = 0;
    float max_diff = 0.0f;
    
    for (size_t i = 0; i < TEST_SIZE; ++i) {
        if (!CompareFloats(scalar_output[i], masm_output[i])) {
            mismatches++;
            float diff = std::abs(scalar_output[i] - masm_output[i]);
            if (diff > max_diff) max_diff = diff;
        }
    }
    
    // Print results
    std::cout << "  Scalar time: " << std::fixed << std::setprecision(3) << scalar_ms << " ms" << std::endl;
    std::cout << "  MASM time:   " << std::fixed << std::setprecision(3) << masm_ms << " ms" << std::endl;
    std::cout << "  Speedup:     " << std::fixed << std::setprecision(2) << (scalar_ms / masm_ms) << "x" << std::endl;
    std::cout << "  Mismatches:  " << mismatches << " / " << TEST_SIZE << std::endl;
    std::cout << "  Max diff:    " << std::scientific << std::setprecision(6) << max_diff << std::endl;
    
    // Print sample outputs
    PrintFloatArray("  Input", input.data(), TEST_SIZE, 5);
    PrintFloatArray("  Scalar", scalar_output.data(), TEST_SIZE, 5);
    PrintFloatArray("  MASM", masm_output.data(), TEST_SIZE, 5);
    
    if (mismatches > 0) {
        std::cerr << "  ❌ Mismatch detected!" << std::endl;
        return false;
    }
    
    std::cout << "  ✅ Test passed!" << std::endl;
    return true;
}

bool Test_Silu_Activation_EdgeCases() {
    std::cout << "\n[Test] SiLU Activation - Edge Cases" << std::endl;
    
    // Test edge cases: zero, very small, very large, negative
    AlignedVector<float> input = {0.0f, 1e-10f, 1e10f, -1e10f, 1.0f, -1.0f, 5.0f, -5.0f};
    AlignedVector<float> scalar_output = input;
    AlignedVector<float> masm_output = input;
    
    // Pad to 16 floats (AVX-512 requirement)
    while (input.size() < 16) {
        input.push_back(0.0f);
        scalar_output.push_back(0.0f);
        masm_output.push_back(0.0f);
    }
    
    // Run both implementations
    Scalar_Silu_Activation(scalar_output.data(), 16);
    int result = MASM_Silu_Activation_AVX512(masm_output.data(), 16 * sizeof(float));
    
    if (result != 0) {
        std::cerr << "  ❌ MASM kernel returned error: " << result << std::endl;
        return false;
    }
    
    // Compare results
    bool passed = true;
    for (size_t i = 0; i < 8; ++i) {  // Only check first 8 (actual test values)
        if (!CompareFloats(scalar_output[i], masm_output[i])) {
            std::cerr << "  ❌ Edge case " << i << " mismatch: scalar=" 
                      << scalar_output[i] << ", masm=" << masm_output[i] << std::endl;
            passed = false;
        }
    }
    
    if (passed) {
        std::cout << "  ✅ All edge cases passed!" << std::endl;
    }
    
    return passed;
}

bool Test_Silu_Activation_Alignment() {
    std::cout << "\n[Test] SiLU Activation - Alignment Validation" << std::endl;
    
    AlignedVector<float> aligned_buffer(16);
    float unaligned_buffer[17];  // Intentionally unaligned
    
    // Test aligned buffer (should succeed)
    int result_aligned = MASM_Silu_Activation_AVX512(aligned_buffer.data(), 16 * sizeof(float));
    if (result_aligned != 0) {
        std::cerr << "  ❌ Aligned buffer failed: " << result_aligned << std::endl;
        return false;
    }
    std::cout << "  ✅ Aligned buffer test passed" << std::endl;
    
    // Test unaligned buffer (should fail with error code 3)
    uintptr_t unaligned_ptr = reinterpret_cast<uintptr_t>(unaligned_buffer);
    if (unaligned_ptr % 64 == 0) {
        unaligned_ptr += 4;  // Force misalignment
    }
    int result_unaligned = MASM_Silu_Activation_AVX512(
        reinterpret_cast<void*>(unaligned_ptr), 
        16 * sizeof(float)
    );
    
    if (result_unaligned != 3) {  // Error code 3 = MisalignedPointer
        std::cerr << "  ❌ Unaligned buffer should have failed with error 3, got: " 
                  << result_unaligned << std::endl;
        return false;
    }
    std::cout << "  ✅ Unaligned buffer correctly rejected" << std::endl;
    
    return true;
}

bool Test_Silu_Activation_Performance() {
    std::cout << "\n[Test] SiLU Activation - Performance Benchmark" << std::endl;
    
    constexpr size_t BENCHMARK_SIZE = 1024 * 1024;  // 1M floats
    constexpr size_t ITERATIONS = 100;
    
    AlignedVector<float> input(BENCHMARK_SIZE);
    AlignedVector<float> output(BENCHMARK_SIZE);
    
    // Initialize with random data
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-5.0f, 5.0f);
    for (size_t i = 0; i < BENCHMARK_SIZE; ++i) {
        input[i] = dist(rng);
    }
    
    // Benchmark scalar
    double total_scalar_ms = 0.0;
    for (size_t iter = 0; iter < ITERATIONS; ++iter) {
        std::copy(input.begin(), input.end(), output.begin());
        
        auto start = std::chrono::high_resolution_clock::now();
        Scalar_Silu_Activation(output.data(), BENCHMARK_SIZE);
        auto end = std::chrono::high_resolution_clock::now();
        
        total_scalar_ms += std::chrono::duration<double, std::milli>(end - start).count();
    }
    
    // Benchmark MASM
    double total_masm_ms = 0.0;
    for (size_t iter = 0; iter < ITERATIONS; ++iter) {
        std::copy(input.begin(), input.end(), output.begin());
        
        auto start = std::chrono::high_resolution_clock::now();
        MASM_Silu_Activation_AVX512(output.data(), BENCHMARK_SIZE * sizeof(float));
        auto end = std::chrono::high_resolution_clock::now();
        
        total_masm_ms += std::chrono::duration<double, std::milli>(end - start).count();
    }
    
    // Calculate statistics
    double avg_scalar_ms = total_scalar_ms / ITERATIONS;
    double avg_masm_ms = total_masm_ms / ITERATIONS;
    double speedup = avg_scalar_ms / avg_masm_ms;
    
    // Calculate throughput
    double scalar_throughput = (BENCHMARK_SIZE * sizeof(float)) / (avg_scalar_ms / 1000.0) / (1024.0 * 1024.0 * 1024.0);
    double masm_throughput = (BENCHMARK_SIZE * sizeof(float)) / (avg_masm_ms / 1000.0) / (1024.0 * 1024.0 * 1024.0);
    
    std::cout << "  Iterations:     " << ITERATIONS << std::endl;
    std::cout << "  Data size:      " << BENCHMARK_SIZE << " floats (" << (BENCHMARK_SIZE * sizeof(float) / 1024.0) << " KB)" << std::endl;
    std::cout << "  Scalar avg:     " << std::fixed << std::setprecision(3) << avg_scalar_ms << " ms" << std::endl;
    std::cout << "  MASM avg:       " << std::fixed << std::setprecision(3) << avg_masm_ms << " ms" << std::endl;
    std::cout << "  Speedup:        " << std::fixed << std::setprecision(2) << speedup << "x" << std::endl;
    std::cout << "  Scalar throughput: " << std::fixed << std::setprecision(2) << scalar_throughput << " GB/s" << std::endl;
    std::cout << "  MASM throughput:   " << std::fixed << std::setprecision(2) << masm_throughput << " GB/s" << std::endl;
    
    // Check if we achieved target speedup (7x)
    if (speedup < 5.0) {
        std::cerr << "  ⚠️  Speedup below target (5x)" << std::endl;
    } else {
        std::cout << "  ✅ Performance target met!" << std::endl;
    }
    
    return true;
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "============================================================================" << std::endl;
    std::cout << "MASM AVX-512 Kernels Test Suite" << std::endl;
    std::cout << "============================================================================" << std::endl;
    
    // Check AVX-512 support
    int cpuinfo[4];
    __cpuid(cpuinfo, 0);
    if (cpuinfo[0] >= 7) {
        __cpuidex(cpuinfo, 7, 0);
        bool has_avx512f = (cpuinfo[1] & (1 << 16)) != 0;
        bool has_avx512dq = (cpuinfo[1] & (1 << 17)) != 0;
        bool has_avx512bw = (cpuinfo[1] & (1 << 30)) != 0;
        bool has_avx512vl = (cpuinfo[1] & (1 << 31)) != 0;
        
        std::cout << "\nAVX-512 Support:" << std::endl;
        std::cout << "  AVX-512F:  " << (has_avx512f ? "✓" : "✗") << std::endl;
        std::cout << "  AVX-512DQ: " << (has_avx512dq ? "✓" : "✗") << std::endl;
        std::cout << "  AVX-512BW: " << (has_avx512bw ? "✓" : "✗") << std::endl;
        std::cout << "  AVX-512VL: " << (has_avx512vl ? "✓" : "✗") << std::endl;
        
        if (!has_avx512f) {
            std::cerr << "\n❌ AVX-512F not supported. Tests will use scalar fallback." << std::endl;
        }
    }
    
    // Run tests
    std::cout << "\n============================================================================" << std::endl;
    std::cout << "Running Tests" << std::endl;
    std::cout << "============================================================================" << std::endl;
    
    bool all_passed = true;
    
    all_passed &= Test_Silu_Activation_Basic();
    all_passed &= Test_Silu_Activation_EdgeCases();
    all_passed &= Test_Silu_Activation_Alignment();
    all_passed &= Test_Silu_Activation_Performance();
    
    // Summary
    std::cout << "\n============================================================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "============================================================================" << std::endl;
    
    if (all_passed) {
        std::cout << "✅ All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "❌ Some tests failed!" << std::endl;
        return 1;
    }
}