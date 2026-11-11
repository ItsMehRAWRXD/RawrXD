// ============================================================================
// A/B Test Harness - Differential Testing for Scalar vs MASM Kernels
// Provides cache-warmed, aligned, bit-wise validated performance comparison
// ============================================================================

#pragma once

#include <chrono>
#include <iostream>
#include <iomanip>
#include <cmath>
#include <vector>
#include <string>
#include <functional>

// Include AlignedBuffer from model_validation_real
// Forward declaration - actual implementation in model_validation_real.cpp
template<typename T>
class AlignedBuffer;

namespace RawrXD {
namespace Validation {

// Benchmark result structure
struct BenchmarkResult {
    double scalar_ms;
    double titan_ms;
    double speedup;
    bool passed;
    std::string name;
    size_t iterations;
    
    void PrintSummary() const {
        std::cout << "\n=== Benchmark: " << name << " ===" << std::endl;
        std::cout << "  Scalar:   " << std::fixed << std::setprecision(4) << scalar_ms << " ms" << std::endl;
        std::cout << "  Titan:    " << std::fixed << std::setprecision(4) << titan_ms << " ms" << std::endl;
        std::cout << "  Speedup:  " << std::fixed << std::setprecision(2) << speedup << "x" << std::endl;
        std::cout << "  Status:   " << (passed ? "✅ PASS" : "❌ FAIL") << std::endl;
    }
};

// Differential testing harness
class DifferentialTester {
public:
    // Epsilon for floating point comparison
    static constexpr float DEFAULT_EPSILON = 1e-5f;
    
    // Number of warmup iterations
    static constexpr size_t WARMUP_ITERATIONS = 3;
    
    // Number of measurement iterations for statistical significance
    static constexpr size_t MEASUREMENT_ITERATIONS = 10;

    // Run differential test with raw function pointers
    template<typename T>
    static BenchmarkResult Run(
        const std::string& name,
        std::function<void(T*, size_t)> scalar_func,
        std::function<void(T*, size_t)> titan_func,
        const std::vector<T>& input,
        float epsilon = DEFAULT_EPSILON,
        size_t warmup_iters = WARMUP_ITERATIONS,
        size_t measure_iters = MEASUREMENT_ITERATIONS
    ) {
        BenchmarkResult result;
        result.name = name;
        result.iterations = measure_iters;
        
        const size_t size = input.size();
        
        // Prepare aligned buffers
        AlignedBuffer<T> buffer_scalar(size);
        AlignedBuffer<T> buffer_titan(size);
        
        // Verify alignment
        if (!buffer_scalar.is_aligned(64) || !buffer_titan.is_aligned(64)) {
            std::cerr << "[CRITICAL] Buffer alignment failed!" << std::endl;
            result.passed = false;
            return result;
        }
        
        // Copy input to both buffers
        buffer_scalar.copy_from(input);
        buffer_titan.copy_from(input);
        
        // Phase 1: Warmup (cache warming)
        std::cout << "\n[Warmup] " << warmup_iters << " iterations..." << std::endl;
        for (size_t i = 0; i < warmup_iters; ++i) {
            // Re-copy input to prevent drift
            buffer_scalar.copy_from(input);
            buffer_titan.copy_from(input);
            
            scalar_func(buffer_scalar.data(), size);
            titan_func(buffer_titan.data(), size);
        }
        std::cout << "✅ Warmup complete" << std::endl;
        
        // Phase 2: Scalar measurement
        std::cout << "\n[Measurement] Scalar (" << measure_iters << " iterations)..." << std::endl;
        double total_scalar_ms = 0.0;
        
        for (size_t i = 0; i < measure_iters; ++i) {
            buffer_scalar.copy_from(input);
            
            auto start = std::chrono::high_resolution_clock::now();
            scalar_func(buffer_scalar.data(), size);
            auto end = std::chrono::high_resolution_clock::now();
            
            double ms = std::chrono::duration<double, std::milli>(end - start).count();
            total_scalar_ms += ms;
        }
        result.scalar_ms = total_scalar_ms / measure_iters;
        
        // Phase 3: Titan/MASM measurement
        std::cout << "[Measurement] Titan/MASM (" << measure_iters << " iterations)..." << std::endl;
        double total_titan_ms = 0.0;
        
        for (size_t i = 0; i < measure_iters; ++i) {
            buffer_titan.copy_from(input);
            
            auto start = std::chrono::high_resolution_clock::now();
            titan_func(buffer_titan.data(), size);
            auto end = std::chrono::high_resolution_clock::now();
            
            double ms = std::chrono::duration<double, std::milli>(end - start).count();
            total_titan_ms += ms;
        }
        result.titan_ms = total_titan_ms / measure_iters;
        
        // Phase 4: Integrity validation (bit-wise comparison)
        std::cout << "\n[Validation] Bit-wise comparison..." << std::endl;
        
        // Final run to get outputs for comparison
        buffer_scalar.copy_from(input);
        buffer_titan.copy_from(input);
        scalar_func(buffer_scalar.data(), size);
        titan_func(buffer_titan.data(), size);
        
        bool passed = true;
        size_t mismatch_count = 0;
        
        for (size_t i = 0; i < size; ++i) {
            T diff = std::abs(buffer_scalar[i] - buffer_titan[i]);
            T threshold = static_cast<T>(epsilon);
            
            if (diff > threshold) {
                if (mismatch_count < 5) {  // Limit error output
                    std::cerr << "  [MISMATCH] Index " << i << ": "
                              << std::setprecision(8) << buffer_scalar[i] << " vs "
                              << buffer_titan[i] << " (diff: " << diff << ")" << std::endl;
                }
                passed = false;
                mismatch_count++;
            }
        }
        
        if (mismatch_count > 0) {
            std::cerr << "  Total mismatches: " << mismatch_count << "/" << size << std::endl;
        }
        
        result.passed = passed;
        result.speedup = result.titan_ms > 0 ? result.scalar_ms / result.titan_ms : 0.0;
        
        // Print results
        std::cout << "\n[" << (passed ? "PASS" : "FAIL") << "] " << name << std::endl;
        std::cout << "  Scalar:   " << std::fixed << std::setprecision(4) << result.scalar_ms << " ms" << std::endl;
        std::cout << "  Titan:    " << std::fixed << std::setprecision(4) << result.titan_ms << " ms" << std::endl;
        std::cout << "  Speedup:  " << std::fixed << std::setprecision(2) << result.speedup << "x" << std::endl;
        
        return result;
    }
    
    // Convenience overload for simple kernels
    template<typename T>
    static BenchmarkResult RunQuick(
        const std::string& name,
        void (*scalar_func)(T*, size_t),
        void (*titan_func)(T*, size_t),
        const std::vector<T>& input,
        float epsilon = DEFAULT_EPSILON
    ) {
        return Run(name, 
                   std::function<void(T*, size_t)>(scalar_func),
                   std::function<void(T*, size_t)>(titan_func),
                   input, epsilon, 1, 1);  // Minimal warmup/measurement for quick tests
    }
};

// Registry for tracking all benchmark results
class BenchmarkRegistry {
    std::vector<BenchmarkResult> results_;
    
public:
    void AddResult(const BenchmarkResult& result) {
        results_.push_back(result);
    }
    
    void PrintSummary() const {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "DIFFERENTIAL TEST SUMMARY" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        
        size_t passed = 0;
        size_t failed = 0;
        double total_speedup = 0.0;
        
        for (const auto& r : results_) {
            if (r.passed) passed++;
            else failed++;
            total_speedup += r.speedup;
            
            std::cout << "\n" << r.name << ": " << (r.passed ? "PASS" : "FAIL") << std::endl;
            std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << r.speedup << "x" << std::endl;
        }
        
        std::cout << "\n" << std::string(60, '-') << std::endl;
        std::cout << "Total: " << results_.size() << " | Passed: " << passed << " | Failed: " << failed << std::endl;
        if (!results_.empty()) {
            std::cout << "Average Speedup: " << std::fixed << std::setprecision(2) 
                      << (total_speedup / results_.size()) << "x" << std::endl;
        }
        std::cout << std::string(60, '=') << std::endl;
    }
    
    bool AllPassed() const {
        for (const auto& r : results_) {
            if (!r.passed) return false;
        }
        return true;
    }
    
    void Clear() {
        results_.clear();
    }
};

} // namespace Validation
} // namespace RawrXD
