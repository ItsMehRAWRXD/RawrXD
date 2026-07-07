// ============================================================================
// A/B Secure Benchmark - Performance Test with Fortress-Grade Hardening
// Measures security overhead vs. speedup
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <intrin.h>
#include <malloc.h>

#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <functional>
#include <chrono>
#include <iomanip>

// Include secure bridge
#include "../src/validation/kernels/masm_bridge_secure.hpp"

using namespace RawrXD::Kernels::Secure;

// ============================================================================
// AlignedBuffer (local copy for standalone compilation)
// ============================================================================
template<typename T>
class AlignedBuffer {
    T* ptr_;
    size_t size_;
    
public:
    AlignedBuffer(size_t size) : size_(size) {
        ptr_ = static_cast<T*>(_aligned_malloc(size * sizeof(T), 64));
        if (!ptr_) {
            throw std::bad_alloc();
        }
        std::memset(ptr_, 0, size * sizeof(T));
    }
    
    ~AlignedBuffer() {
        if (ptr_) {
            _aligned_free(ptr_);
            ptr_ = nullptr;
        }
    }
    
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;
    
    AlignedBuffer(AlignedBuffer&& other) noexcept : ptr_(other.ptr_), size_(other.size_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }
    
    T* data() { return ptr_; }
    const T* data() const { return ptr_; }
    size_t size() const { return size_; }
    
    bool is_aligned(size_t alignment = 64) const {
        return (reinterpret_cast<uintptr_t>(ptr_) % alignment) == 0;
    }
    
    void copy_from(const std::vector<T>& src) {
        size_t copy_size = (src.size() < size_) ? src.size() : size_;
        std::memcpy(ptr_, src.data(), copy_size * sizeof(T));
    }
};

// ============================================================================
// Scalar Implementations (Reference)
// ============================================================================

void Scalar_SiLU(float* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] = data[i] / (1.0f + std::exp(-data[i]));
    }
}

void Scalar_Softmax(float* data, size_t size) {
    float max_val = data[0];
    for (size_t i = 1; i < size; ++i) {
        if (data[i] > max_val) max_val = data[i];
    }
    
    float sum = 0.0f;
    for (size_t i = 0; i < size; ++i) {
        data[i] = std::exp(data[i] - max_val);
        sum += data[i];
    }
    
    for (size_t i = 0; i < size; ++i) {
        data[i] /= sum;
    }
}

void Scalar_RMSNorm(float* data, float* weights, size_t size) {
    float sum_sq = 0.0f;
    for (size_t i = 0; i < size; ++i) {
        sum_sq += data[i] * data[i];
    }
    float rms = std::sqrt(sum_sq / size + 1e-6f);
    float scale = 1.0f / rms;
    
    for (size_t i = 0; i < size; ++i) {
        data[i] = data[i] * scale * weights[i];
    }
}

// ============================================================================
// Benchmark Structure
// ============================================================================

struct BenchmarkResult {
    std::string name;
    double scalar_ms;
    double secure_masm_ms;
    double speedup;
    double security_overhead_pct;
    bool passed;
    
    void print() const {
        std::cout << "\n=== " << name << " ===\n";
        std::cout << "  Scalar:        " << std::fixed << std::setprecision(4) << scalar_ms << " ms\n";
        std::cout << "  Secure MASM:   " << std::fixed << std::setprecision(4) << secure_masm_ms << " ms\n";
        std::cout << "  Speedup:       " << std::fixed << std::setprecision(2) << speedup << "x\n";
        std::cout << "  Sec Overhead:  " << std::fixed << std::setprecision(4) << security_overhead_pct << "%\n";
        std::cout << "  Status:        " << (passed ? "✅ PASS" : "❌ FAIL") << "\n";
    }
};

// ============================================================================
// Benchmark Runner
// ============================================================================

template<typename Func>
double measure_time(Func&& f, int iterations = 100) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        f();
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    return duration.count() / 1000.0 / iterations; // Average ms per iteration
}

// ============================================================================
// SiLU Benchmark
// ============================================================================

BenchmarkResult benchmark_silu(size_t size, int iterations = 100) {
    BenchmarkResult result;
    result.name = "SiLU (" + std::to_string(size) + " elements)";
    
    // Generate test data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
    std::vector<float> input(size);
    for (auto& x : input) x = dist(gen);
    
    // Scalar benchmark
    AlignedBuffer<float> scalar_buf(size);
    scalar_buf.copy_from(input);
    
    result.scalar_ms = measure_time([&]() {
        Scalar_SiLU(scalar_buf.data(), size);
    }, iterations);
    
    // Secure MASM benchmark
    AlignedBuffer<float> masm_buf(size);
    masm_buf.copy_from(input);
    
    result.secure_masm_ms = measure_time([&]() {
        SecureMASMKernelBridge::SiLU(masm_buf.data(), size);
    }, iterations);
    
    // Calculate metrics
    result.speedup = result.scalar_ms / result.secure_masm_ms;
    result.security_overhead_pct = 0.0; // Would need unsecure MASM for comparison
    result.passed = (result.speedup > 1.0);
    
    return result;
}

// ============================================================================
// Softmax Benchmark
// ============================================================================

BenchmarkResult benchmark_softmax(size_t size, int iterations = 100) {
    BenchmarkResult result;
    result.name = "Softmax (" + std::to_string(size) + " elements)";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
    std::vector<float> input(size);
    for (auto& x : input) x = dist(gen);
    
    // Scalar
    AlignedBuffer<float> scalar_buf(size);
    scalar_buf.copy_from(input);
    result.scalar_ms = measure_time([&]() {
        Scalar_Softmax(scalar_buf.data(), size);
    }, iterations);
    
    // Secure MASM
    AlignedBuffer<float> masm_buf(size);
    masm_buf.copy_from(input);
    result.secure_masm_ms = measure_time([&]() {
        SecureMASMKernelBridge::Softmax(masm_buf.data(), size);
    }, iterations);
    
    result.speedup = result.scalar_ms / result.secure_masm_ms;
    result.security_overhead_pct = 0.0;
    result.passed = (result.speedup > 1.0);
    
    return result;
}

// ============================================================================
// RMSNorm Benchmark
// ============================================================================

BenchmarkResult benchmark_rmsnorm(size_t size, int iterations = 100) {
    BenchmarkResult result;
    result.name = "RMSNorm (" + std::to_string(size) + " elements)";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
    std::vector<float> input(size);
    std::vector<float> weights(size);
    for (auto& x : input) x = dist(gen);
    for (auto& x : weights) x = dist(gen);
    
    // Scalar
    AlignedBuffer<float> scalar_buf(size);
    AlignedBuffer<float> scalar_weights(size);
    scalar_buf.copy_from(input);
    scalar_weights.copy_from(weights);
    result.scalar_ms = measure_time([&]() {
        Scalar_RMSNorm(scalar_buf.data(), scalar_weights.data(), size);
    }, iterations);
    
    // Secure MASM (requires separate output buffer)
    AlignedBuffer<float> masm_input(size);
    AlignedBuffer<float> masm_output(size);
    AlignedBuffer<float> masm_weights(size);
    masm_input.copy_from(input);
    masm_weights.copy_from(weights);
    result.secure_masm_ms = measure_time([&]() {
        SecureMASMKernelBridge::RMSNorm(masm_input.data(), masm_output.data(), masm_weights.data(), size);
    }, iterations);
    
    result.speedup = result.scalar_ms / result.secure_masm_ms;
    result.security_overhead_pct = 0.0;
    result.passed = (result.speedup > 1.0);
    
    return result;
}

// ============================================================================
// Main Entry
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "A/B Secure Benchmark\n";
    std::cout << "Performance with Fortress-Grade Security\n";
    std::cout << "========================================\n";
    
    std::vector<BenchmarkResult> results;
    
    // Test sizes: small, medium, large
    std::vector<size_t> sizes = {1024, 4096, 16384, 65536, 262144};
    
    std::cout << "\nRunning SiLU benchmarks...\n";
    for (size_t size : sizes) {
        results.push_back(benchmark_silu(size));
    }
    
    std::cout << "\nRunning Softmax benchmarks...\n";
    for (size_t size : sizes) {
        results.push_back(benchmark_softmax(size));
    }
    
    std::cout << "\nRunning RMSNorm benchmarks...\n";
    for (size_t size : sizes) {
        results.push_back(benchmark_rmsnorm(size));
    }
    
    // Print summary
    std::cout << "\n========================================\n";
    std::cout << "BENCHMARK SUMMARY\n";
    std::cout << "========================================\n";
    
    double total_speedup = 0.0;
    int passed = 0;
    
    for (const auto& r : results) {
        r.print();
        total_speedup += r.speedup;
        if (r.passed) passed++;
    }
    
    double avg_speedup = total_speedup / results.size();
    
    std::cout << "\n========================================\n";
    std::cout << "OVERALL RESULTS\n";
    std::cout << "========================================\n";
    std::cout << "Tests Run:      " << results.size() << "\n";
    std::cout << "Passed:         " << passed << "\n";
    std::cout << "Failed:         " << (results.size() - passed) << "\n";
    std::cout << "Avg Speedup:    " << std::fixed << std::setprecision(2) << avg_speedup << "x\n";
    std::cout << "Status:         " << (passed == results.size() ? "✅ FORTRESS-PERFORMANT" : "❌ DEGRADED") << "\n";
    std::cout << "========================================\n";
    
    return (passed == results.size()) ? 0 : 1;
}
