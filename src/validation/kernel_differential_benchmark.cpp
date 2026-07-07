// ============================================================================
// Standalone Kernel Differential Benchmark
// Tests RMSNorm Fixed vs Tiled at 32K elements without full validation pipeline
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
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <vector>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <functional>

// MASM kernel function declarations
extern "C" int MASM_RMSNorm_Fixed(float* input, float* output, float* weights, size_t size);
extern "C" int MASM_RMSNorm_Tiled(float* input, float* output, float* weights, size_t size);

// AlignedBuffer - 64-byte aligned memory for AVX-512
template<typename T>
class AlignedBuffer {
    T* ptr_;
    size_t size_;

public:
    AlignedBuffer(size_t size) : size_(size) {
        ptr_ = (T*)_aligned_malloc(size * sizeof(T), 64);
        if (!ptr_) throw std::bad_alloc();
        std::memset(ptr_, 0, size * sizeof(T));
    }

    ~AlignedBuffer() {
        if (ptr_) _aligned_free(ptr_);
    }

    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;

    AlignedBuffer(AlignedBuffer&& other) noexcept : ptr_(other.ptr_), size_(other.size_) {
        other.ptr_ = nullptr;
        other.size_ = 0;
    }

    AlignedBuffer& operator=(AlignedBuffer&& other) noexcept {
        if (this != &other) {
            if (ptr_) _aligned_free(ptr_);
            ptr_ = other.ptr_;
            size_ = other.size_;
            other.ptr_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    T* data() { return ptr_; }
    const T* data() const { return ptr_; }
    size_t size() const { return size_; }
    T& operator[](size_t i) { return ptr_[i]; }
    const T& operator[](size_t i) const { return ptr_[i]; }
};

// Benchmark result structure
struct BenchmarkResult {
    std::string name;
    double avg_time_ms;
    double throughput_melems;
    int return_code;
    bool success;
};

// Run benchmark with multiple iterations
BenchmarkResult RunBenchmark(
    const std::string& name,
    std::function<int()> kernel_func,
    size_t element_count,
    int iterations = 10
) {
    BenchmarkResult result;
    result.name = name;

    // Warmup
    for (int i = 0; i < 3; ++i) {
        kernel_func();
    }

    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    int ret = 0;
    for (int i = 0; i < iterations; ++i) {
        ret = kernel_func();
    }
    auto end = std::chrono::high_resolution_clock::now();

    double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
    result.avg_time_ms = total_ms / iterations;
    result.throughput_melems = (element_count / (result.avg_time_ms / 1000.0)) / 1e6;
    result.return_code = ret;
    result.success = (ret == 0);

    return result;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RMSNorm KERNEL DIFFERENTIAL BENCHMARK" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Date: " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "Array size: 32768 elements (128KB)" << std::endl;
    std::cout << "Tile size: 4096 elements (16KB - L1 cache)" << std::endl;
    std::cout << std::endl;

    const size_t SIZE = 32768;
    const int ITERATIONS = 10;

    // Allocate aligned buffers
    AlignedBuffer<float> input(SIZE);
    AlignedBuffer<float> output_fixed(SIZE);
    AlignedBuffer<float> output_tiled(SIZE);
    AlignedBuffer<float> weights(SIZE);

    // Initialize with varied data
    std::cout << "[Setup] Initializing test data..." << std::endl;
    for (size_t i = 0; i < SIZE; ++i) {
        input[i] = 1.0f + (float)(i % 100) / 100.0f;
        weights[i] = 1.0f + (float)(i % 10) / 50.0f;
    }
    std::cout << "  ✅ Data initialized" << std::endl;

    // ============================================================================
    // Benchmark 1: Fixed RMSNorm
    // ============================================================================
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "[1/2] RMSNorm_Fixed (baseline)" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    auto result_fixed = RunBenchmark(
        "RMSNorm_Fixed_32K",
        [&]() { return MASM_RMSNorm_Fixed(input.data(), output_fixed.data(), weights.data(), SIZE); },
        SIZE,
        ITERATIONS
    );

    std::cout << "  Status: " << (result_fixed.success ? "✅ PASS" : "❌ FAIL") << std::endl;
    std::cout << "  Return code: " << result_fixed.return_code << std::endl;
    std::cout << "  Total time (" << ITERATIONS << " runs): " << std::fixed << std::setprecision(4)
              << result_fixed.avg_time_ms * ITERATIONS << " ms" << std::endl;
    std::cout << "  Avg time per run: " << std::fixed << std::setprecision(4)
              << result_fixed.avg_time_ms << " ms" << std::endl;
    std::cout << "  Throughput: " << std::fixed << std::setprecision(2)
              << result_fixed.throughput_melems << " M elements/sec" << std::endl;

    // ============================================================================
    // Benchmark 2: Tiled RMSNorm
    // ============================================================================
    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "[2/2] RMSNorm_Tiled (L1 cache optimized)" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    auto result_tiled = RunBenchmark(
        "RMSNorm_Tiled_32K",
        [&]() { return MASM_RMSNorm_Tiled(input.data(), output_tiled.data(), weights.data(), SIZE); },
        SIZE,
        ITERATIONS
    );

    std::cout << "  Status: " << (result_tiled.success ? "✅ PASS" : "❌ FAIL") << std::endl;
    std::cout << "  Return code: " << result_tiled.return_code << std::endl;
    std::cout << "  Total time (" << ITERATIONS << " runs): " << std::fixed << std::setprecision(4)
              << result_tiled.avg_time_ms * ITERATIONS << " ms" << std::endl;
    std::cout << "  Avg time per run: " << std::fixed << std::setprecision(4)
              << result_tiled.avg_time_ms << " ms" << std::endl;
    std::cout << "  Throughput: " << std::fixed << std::setprecision(2)
              << result_tiled.throughput_melems << " M elements/sec" << std::endl;

    // ============================================================================
    // Differential Analysis
    // ============================================================================
    std::cout << "\n========================================" << std::endl;
    std::cout << "DIFFERENTIAL ANALYSIS" << std::endl;
    std::cout << "========================================" << std::endl;

    if (result_fixed.success && result_tiled.success) {
        double speedup = result_fixed.avg_time_ms / result_tiled.avg_time_ms;
        double throughput_ratio = result_tiled.throughput_melems / result_fixed.throughput_melems;

        std::cout << "Fixed (baseline):   " << std::fixed << std::setprecision(4)
                  << result_fixed.avg_time_ms << " ms, "
                  << std::fixed << std::setprecision(2) << result_fixed.throughput_melems
                  << " M elems/sec" << std::endl;
        std::cout << "Tiled (optimized):  " << std::fixed << std::setprecision(4)
                  << result_tiled.avg_time_ms << " ms, "
                  << std::fixed << std::setprecision(2) << result_tiled.throughput_melems
                  << " M elems/sec" << std::endl;
        std::cout << "Speedup factor:     " << std::fixed << std::setprecision(2)
                  << speedup << "x" << std::endl;
        std::cout << "Throughput ratio:   " << std::fixed << std::setprecision(2)
                  << throughput_ratio << "x" << std::endl;

        std::cout << std::endl;
        if (speedup > 1.05) {
            std::cout << "✅ TILING SUCCESS: Cache optimization provides " << std::fixed << std::setprecision(2)
                      << (speedup - 1.0) * 100 << "% speedup" << std::endl;
            std::cout << "   The tiled implementation overcomes the memory bandwidth wall." << std::endl;
        } else if (speedup < 0.95) {
            std::cout << "⚠️  TILING REGRESSION: Fixed version is " << std::fixed << std::setprecision(2)
                      << (1.0 / speedup - 1.0) * 100 << "% faster" << std::endl;
            std::cout << "   Possible causes: tile overhead, small array, or cache already hot" << std::endl;
        } else {
            std::cout << "⚠️  NO SIGNIFICANT DIFFERENCE: Performance is equivalent" << std::endl;
            std::cout << "   The array may be small enough to fit in cache already." << std::endl;
        }
    } else {
        std::cout << "❌ Cannot compare: One or both kernels failed" << std::endl;
        if (!result_fixed.success) {
            std::cout << "   - Fixed kernel failed with code: " << result_fixed.return_code << std::endl;
        }
        if (!result_tiled.success) {
            std::cout << "   - Tiled kernel failed with code: " << result_tiled.return_code << std::endl;
        }
    }

    // ============================================================================
    // Correctness Check
    // ============================================================================
    if (result_fixed.success && result_tiled.success) {
        std::cout << "\n----------------------------------------" << std::endl;
        std::cout << "CORRECTNESS VERIFICATION" << std::endl;
        std::cout << "----------------------------------------" << std::endl;

        double max_diff = 0.0;
        double sum_diff = 0.0;
        size_t sample_size = std::min(SIZE, (size_t)1000);

        // Debug: Print first few values
        std::cout << "\n  Debug - First 10 output values:" << std::endl;
        std::cout << "    Index | Fixed      | Tiled      | Diff" << std::endl;
        std::cout << "    ------|------------|------------|------------" << std::endl;
        for (size_t i = 0; i < std::min(sample_size, (size_t)10); ++i) {
            double diff = std::abs(output_fixed[i] - output_tiled[i]);
            std::cout << "    " << std::setw(5) << i << " | "
                      << std::fixed << std::setprecision(6) << std::setw(10) << output_fixed[i] << " | "
                      << std::fixed << std::setprecision(6) << std::setw(10) << output_tiled[i] << " | "
                      << std::scientific << diff << std::endl;
            max_diff = std::max(max_diff, diff);
            sum_diff += diff;
        }
        double avg_diff = sum_diff / sample_size;

        std::cout << "  Sample size: " << sample_size << " elements" << std::endl;
        std::cout << "  Max difference: " << std::scientific << max_diff << std::endl;
        std::cout << "  Avg difference: " << std::scientific << avg_diff << std::endl;

        if (max_diff < 1e-4) {
            std::cout << "  ✅ Outputs match within tolerance (1e-4)" << std::endl;
        } else if (max_diff < 1e-3) {
            std::cout << "  ⚠️  Outputs differ slightly (within 1e-3)" << std::endl;
        } else {
            std::cout << "  ❌ Outputs differ significantly!" << std::endl;
        }
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << "BENCHMARK COMPLETE" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
