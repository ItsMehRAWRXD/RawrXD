// ============================================================================
// masm_benchmark_integration.cpp
// ============================================================================
// Integration of MASM kernels into telemetry_validation for performance benchmarking
// 
// This file demonstrates how to:
// 1. Load MASM kernels dynamically
// 2. Run differential testing (scalar C++ vs AVX2 MASM)
// 3. Measure cycle-accurate performance with __rdtsc
// 4. Calculate speedup ratios
// 5. Verify numerical accuracy
// ============================================================================

#include <cstdint>
#include <cmath>
#include <chrono>
#include <vector>
#include <iostream>
#include <iomanip>
#include <immintrin.h>  // For __rdtsc
#include "masm_kernels.hpp"

namespace RawrXD {
namespace Validation {

// ============================================================================
// Scalar C++ Reference Implementations
// ============================================================================

// Scalar SiLU for differential testing
void Silu_Scalar(float* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        // Sigmoid approximation: sigmoid(x) ≈ 0.5 + 0.25*x - 0.020833*x^3 + 0.002604*x^5
        float x = data[i];
        float x2 = x * x;
        float x3 = x2 * x;
        float x5 = x3 * x2;
        
        float sigmoid = 0.5f + 0.25f * x - 0.020833f * x3 + 0.002604f * x5;
        data[i] = x * sigmoid;
    }
}

// Scalar RMSNorm for differential testing
void RMSNorm_Scalar(float* input, float* output, float* weights, size_t size) {
    // Compute sum of squares
    float sum_sq = 0.0f;
    for (size_t i = 0; i < size; i++) {
        sum_sq += input[i] * input[i];
    }
    
    // Compute RMS
    float mean_sq = sum_sq / size;
    float rms = std::sqrt(mean_sq + 1e-5f);
    
    // Normalize and apply weights
    for (size_t i = 0; i < size; i++) {
        output[i] = (input[i] / rms) * weights[i];
    }
}

// ============================================================================
// Benchmark Harness
// ============================================================================

struct BenchmarkResult {
    double scalar_cycles;
    double masm_cycles;
    double speedup_ratio;
    double max_error;
    bool passed;
    std::string error_message;
};

class MASMBenchmarkHarness {
public:
    // Run SiLU benchmark with differential testing
    static BenchmarkResult BenchmarkSilu(size_t size, int iterations = 100) {
        BenchmarkResult result;
        result.passed = false;
        
        // Allocate aligned buffers
        float* buffer_scalar = (float*)_aligned_malloc(size * sizeof(float), 32);
        float* buffer_masm = (float*)_aligned_malloc(size * sizeof(float), 32);
        
        if (!buffer_scalar || !buffer_masm) {
            result.error_message = "Failed to allocate aligned memory";
            return result;
        }
        
        // Initialize with test data
        for (size_t i = 0; i < size; i++) {
            float val = (float)(i % 100) / 10.0f - 5.0f;  // Range: [-5, 5]
            buffer_scalar[i] = val;
            buffer_masm[i] = val;
        }
        
        // Warmup
        for (int i = 0; i < 10; i++) {
            Silu_Scalar(buffer_scalar, size);
            MASM_Silu_Activation_AVX512(buffer_masm, size * sizeof(float));
        }
        
        // Benchmark scalar C++
        uint64_t scalar_start = __rdtsc();
        for (int i = 0; i < iterations; i++) {
            // Restore original values
            for (size_t j = 0; j < size; j++) {
                buffer_scalar[j] = (float)(j % 100) / 10.0f - 5.0f;
            }
            Silu_Scalar(buffer_scalar, size);
        }
        uint64_t scalar_end = __rdtsc();
        result.scalar_cycles = (double)(scalar_end - scalar_start) / iterations;
        
        // Benchmark MASM AVX2
        uint64_t masm_start = __rdtsc();
        for (int i = 0; i < iterations; i++) {
            // Restore original values
            for (size_t j = 0; j < size; j++) {
                buffer_masm[j] = (float)(j % 100) / 10.0f - 5.0f;
            }
            int err = MASM_Silu_Activation_AVX512(buffer_masm, size * sizeof(float));
            if (err != 0) {
                result.error_message = "MASM kernel returned error: " + std::to_string(err);
                _aligned_free(buffer_scalar);
                _aligned_free(buffer_masm);
                return result;
            }
        }
        uint64_t masm_end = __rdtsc();
        result.masm_cycles = (double)(masm_end - masm_start) / iterations;
        
        // Calculate speedup
        result.speedup_ratio = result.scalar_cycles / result.masm_cycles;
        
        // Differential testing: compare results
        result.max_error = 0.0;
        for (size_t i = 0; i < size; i++) {
            float error = std::abs(buffer_scalar[i] - buffer_masm[i]);
            if (error > result.max_error) {
                result.max_error = error;
            }
        }
        
        // Check if results match within tolerance
        const float tolerance = 1e-5f;
        result.passed = (result.max_error < tolerance);
        
        if (!result.passed) {
            result.error_message = "Max error " + std::to_string(result.max_error) + 
                                   " exceeds tolerance " + std::to_string(tolerance);
        }
        
        // Cleanup
        _aligned_free(buffer_scalar);
        _aligned_free(buffer_masm);
        
        return result;
    }
    
    // Run RMSNorm benchmark with differential testing
    static BenchmarkResult BenchmarkRMSNorm(size_t size, int iterations = 100) {
        BenchmarkResult result;
        result.passed = false;
        
        // Allocate aligned buffers
        float* input_scalar = (float*)_aligned_malloc(size * sizeof(float), 32);
        float* input_masm = (float*)_aligned_malloc(size * sizeof(float), 32);
        float* output_scalar = (float*)_aligned_malloc(size * sizeof(float), 32);
        float* output_masm = (float*)_aligned_malloc(size * sizeof(float), 32);
        float* weights = (float*)_aligned_malloc(size * sizeof(float), 32);
        
        if (!input_scalar || !input_masm || !output_scalar || !output_masm || !weights) {
            result.error_message = "Failed to allocate aligned memory";
            return result;
        }
        
        // Initialize with test data
        for (size_t i = 0; i < size; i++) {
            float val = (float)(i % 100) / 10.0f - 5.0f;
            input_scalar[i] = val;
            input_masm[i] = val;
            weights[i] = 1.0f;  // Unit weights for simplicity
        }
        
        // Warmup
        for (int i = 0; i < 10; i++) {
            RMSNorm_Scalar(input_scalar, output_scalar, weights, size);
            MASM_RMSNorm_Forward_AVX2(input_masm, output_masm, weights, size);
        }
        
        // Benchmark scalar C++
        uint64_t scalar_start = __rdtsc();
        for (int i = 0; i < iterations; i++) {
            RMSNorm_Scalar(input_scalar, output_scalar, weights, size);
        }
        uint64_t scalar_end = __rdtsc();
        result.scalar_cycles = (double)(scalar_end - scalar_start) / iterations;
        
        // Benchmark MASM AVX2
        uint64_t masm_start = __rdtsc();
        for (int i = 0; i < iterations; i++) {
            int err = MASM_RMSNorm_Forward_AVX2(input_masm, output_masm, weights, size);
            if (err != 0) {
                result.error_message = "MASM kernel returned error: " + std::to_string(err);
                _aligned_free(input_scalar);
                _aligned_free(input_masm);
                _aligned_free(output_scalar);
                _aligned_free(output_masm);
                _aligned_free(weights);
                return result;
            }
        }
        uint64_t masm_end = __rdtsc();
        result.masm_cycles = (double)(masm_end - masm_start) / iterations;
        
        // Calculate speedup
        result.speedup_ratio = result.scalar_cycles / result.masm_cycles;
        
        // Differential testing
        result.max_error = 0.0;
        for (size_t i = 0; i < size; i++) {
            float error = std::abs(output_scalar[i] - output_masm[i]);
            if (error > result.max_error) {
                result.max_error = error;
            }
        }
        
        // Check tolerance
        const float tolerance = 1e-5f;
        result.passed = (result.max_error < tolerance);
        
        if (!result.passed) {
            result.error_message = "Max error " + std::to_string(result.max_error) + 
                                   " exceeds tolerance " + std::to_string(tolerance);
        }
        
        // Cleanup
        _aligned_free(input_scalar);
        _aligned_free(input_masm);
        _aligned_free(output_scalar);
        _aligned_free(output_masm);
        _aligned_free(weights);
        
        return result;
    }
    
    // Print benchmark results
    static void PrintResults(const std::string& kernel_name, const BenchmarkResult& result) {
        std::cout << "\n========================================\n";
        std::cout << kernel_name << " Benchmark Results\n";
        std::cout << "========================================\n";
        std::cout << "Scalar C++ Cycles: " << std::fixed << std::setprecision(0) << result.scalar_cycles << "\n";
        std::cout << "MASM AVX2 Cycles:   " << std::fixed << std::setprecision(0) << result.masm_cycles << "\n";
        std::cout << "Speedup Ratio:     " << std::fixed << std::setprecision(2) << result.speedup_ratio << "x\n";
        std::cout << "Max Error:         " << std::scientific << std::setprecision(6) << result.max_error << "\n";
        std::cout << "Status:            " << (result.passed ? "PASS ✅" : "FAIL ❌") << "\n";
        if (!result.passed) {
            std::cout << "Error:             " << result.error_message << "\n";
        }
        std::cout << "========================================\n";
    }
};

// ============================================================================
// Integration with Telemetry Layer
// ============================================================================

void RunMASMBenchmarks() {
    std::cout << "\n========================================\n";
    std::cout << "MASM Kernel Performance Benchmarks\n";
    std::cout << "========================================\n";
    
    // Test sizes: 256, 512, 1024, 2048, 4096
    const size_t test_sizes[] = {256, 512, 1024, 2048, 4096};
    
    for (size_t size : test_sizes) {
        std::cout << "\n--- Testing size: " << size << " floats ---\n";
        
        // SiLU benchmark
        auto silu_result = MASMBenchmarkHarness::BenchmarkSilu(size);
        MASMBenchmarkHarness::PrintResults("SiLU Activation", silu_result);
        
        // RMSNorm benchmark
        auto rms_result = MASMBenchmarkHarness::BenchmarkRMSNorm(size);
        MASMBenchmarkHarness::PrintResults("RMS Normalization", rms_result);
    }
    
    std::cout << "\n========================================\n";
    std::cout << "All benchmarks complete!\n";
    std::cout << "========================================\n";
}

} // namespace Validation
} // namespace RawrXD

// ============================================================================
// Main Entry Point
// ============================================================================

int main() {
    RawrXD::Validation::RunMASMBenchmarks();
    return 0;
}