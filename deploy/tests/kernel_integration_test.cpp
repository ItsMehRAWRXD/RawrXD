// ============================================================================
// Kernel Integration Test
// Validates real AVX2/AVX-512 kernels work with Secure Kernel Dispatch
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <malloc.h>

#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>
#include <iomanip>
#include <cstring>

// Include secure bridge
#include "../src/validation/kernels/masm_bridge_secure.hpp"

using namespace RawrXD::Kernels::Secure;

// ============================================================================
// Test Framework
// ============================================================================

struct TestResult {
    int passed = 0;
    int failed = 0;
    
    void record(bool success, const char* name) {
        if (success) {
            passed++;
            std::cout << "[PASS] " << name << std::endl;
        } else {
            failed++;
            std::cout << "[FAIL] " << name << std::endl;
        }
    }
    
    void summary() const {
        std::cout << "\n========================================\n";
        std::cout << "Kernel Integration Test\n";
        std::cout << "Passed: " << passed << " | Failed: " << failed << "\n";
        std::cout << (failed == 0 ? "✅ KERNELS INTEGRATED" : "❌ INTEGRATION FAILED") << "\n";
        std::cout << "========================================\n";
    }
};

static TestResult g_results;

// ============================================================================
// AlignedBuffer
// ============================================================================

template<typename T>
class AlignedBuffer {
    T* ptr_;
    size_t size_;
    
public:
    AlignedBuffer(size_t size) : size_(size) {
        ptr_ = static_cast<T*>(_aligned_malloc(size * sizeof(T), 64));
        if (!ptr_) throw std::bad_alloc();
        std::memset(ptr_, 0, size * sizeof(T));
    }
    
    ~AlignedBuffer() {
        if (ptr_) _aligned_free(ptr_);
    }
    
    AlignedBuffer(const AlignedBuffer&) = delete;
    AlignedBuffer& operator=(const AlignedBuffer&) = delete;
    
    T* data() { return ptr_; }
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
// Reference Implementations
// ============================================================================

void Reference_SiLU(float* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] = data[i] / (1.0f + std::exp(-data[i]));
    }
}

void Reference_Softmax(float* data, size_t size) {
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

// ============================================================================
// Numerical Comparison
// ============================================================================

bool CompareFloats(float a, float b, float epsilon = 1e-4f) {
    if (std::isnan(a) || std::isnan(b)) return false;
    if (std::isinf(a) || std::isinf(b)) return false;
    return std::abs(a - b) < epsilon;
}

// ============================================================================
// Test 1: SiLU Integration
// ============================================================================
void testSiLUIntegration() {
    std::cout << "\n--- Test: SiLU Integration ---\n";
    
    const size_t size = 1024; // Must be multiple of 16 for AVX-512
    
    // Generate test data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
    std::vector<float> input(size);
    for (auto& x : input) x = dist(gen);
    
    // Reference output
    std::vector<float> reference = input;
    Reference_SiLU(reference.data(), size);
    
    // Secure MASM output
    AlignedBuffer<float> masm_buf(size);
    masm_buf.copy_from(input);
    
    try {
        SecureMASMKernelBridge::SiLU(masm_buf.data(), size);
        
        // Compare results
        bool match = true;
        for (size_t i = 0; i < size; ++i) {
            if (!CompareFloats(masm_buf.data()[i], reference[i])) {
                match = false;
                std::cout << "  Mismatch at index " << i << ": " 
                          << masm_buf.data()[i] << " vs " << reference[i] << std::endl;
                break;
            }
        }
        g_results.record(match, "SiLU_NumericalAccuracy");
        
    } catch (const std::exception& e) {
        std::cout << "  Exception: " << e.what() << std::endl;
        g_results.record(false, "SiLU_NoException");
    }
    
    // Test with various sizes
    for (size_t test_size : {16, 64, 256, 1024, 4096}) {
        std::vector<float> test_input(test_size);
        for (auto& x : test_input) x = dist(gen);
        
        AlignedBuffer<float> test_buf(test_size);
        test_buf.copy_from(test_input);
        
        try {
            SecureMASMKernelBridge::SiLU(test_buf.data(), test_size);
            g_results.record(true, ("SiLU_Size_" + std::to_string(test_size)).c_str());
        } catch (...) {
            g_results.record(false, ("SiLU_Size_" + std::to_string(test_size)).c_str());
        }
    }
}

// ============================================================================
// Test 2: Softmax Integration
// ============================================================================
void testSoftmaxIntegration() {
    std::cout << "\n--- Test: Softmax Integration ---\n";
    
    const size_t size = 1024; // Must be multiple of 8 for AVX2
    
    // Generate test data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
    std::vector<float> input(size);
    for (auto& x : input) x = dist(gen);
    
    // Reference output
    std::vector<float> reference = input;
    Reference_Softmax(reference.data(), size);
    
    // Secure MASM output
    AlignedBuffer<float> masm_buf(size);
    masm_buf.copy_from(input);
    
    try {
        SecureMASMKernelBridge::Softmax(masm_buf.data(), size);
        
        // Compare results
        bool match = true;
        for (size_t i = 0; i < size; ++i) {
            if (!CompareFloats(masm_buf.data()[i], reference[i], 1e-3f)) {
                match = false;
                std::cout << "  Mismatch at index " << i << ": " 
                          << masm_buf.data()[i] << " vs " << reference[i] << std::endl;
                break;
            }
        }
        g_results.record(match, "Softmax_NumericalAccuracy");
        
        // Verify softmax properties (sum = 1)
        float sum = 0.0f;
        for (size_t i = 0; i < size; ++i) {
            sum += masm_buf.data()[i];
        }
        bool valid_softmax = std::abs(sum - 1.0f) < 0.01f;
        g_results.record(valid_softmax, "Softmax_SumToOne");
        
    } catch (const std::exception& e) {
        std::cout << "  Exception: " << e.what() << std::endl;
        g_results.record(false, "Softmax_NoException");
    }
    
    // Test with various sizes
    for (size_t test_size : {8, 64, 256, 1024, 4096}) {
        std::vector<float> test_input(test_size);
        for (auto& x : test_input) x = dist(gen);
        
        AlignedBuffer<float> test_buf(test_size);
        test_buf.copy_from(test_input);
        
        try {
            SecureMASMKernelBridge::Softmax(test_buf.data(), test_size);
            g_results.record(true, ("Softmax_Size_" + std::to_string(test_size)).c_str());
        } catch (...) {
            g_results.record(false, ("Softmax_Size_" + std::to_string(test_size)).c_str());
        }
    }
}

// ============================================================================
// Test 3: Performance Benchmark
// ============================================================================
void testPerformance() {
    std::cout << "\n--- Test: Performance Benchmark ---\n";
    
    const size_t size = 65536;
    const int iterations = 100;
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
    std::vector<float> input(size);
    for (auto& x : input) x = dist(gen);
    
    // SiLU Performance
    {
        AlignedBuffer<float> buf(size);
        
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            buf.copy_from(input);
            SecureMASMKernelBridge::SiLU(buf.data(), size);
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double avg_ms = duration.count() / 1000.0 / iterations;
        
        std::cout << "  SiLU (" << size << " elements): " 
                  << std::fixed << std::setprecision(4) << avg_ms << " ms/iter\n";
        
        g_results.record(avg_ms < 1.0, "SiLU_Performance"); // Should be fast
    }
    
    // Softmax Performance
    {
        AlignedBuffer<float> buf(size);
        
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            buf.copy_from(input);
            SecureMASMKernelBridge::Softmax(buf.data(), size);
        }
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double avg_ms = duration.count() / 1000.0 / iterations;
        
        std::cout << "  Softmax (" << size << " elements): " 
                  << std::fixed << std::setprecision(4) << avg_ms << " ms/iter\n";
        
        g_results.record(avg_ms < 2.0, "Softmax_Performance"); // Should be reasonable
    }
}

// ============================================================================
// Main Entry
// ============================================================================
int main() {
    std::cout << "========================================\n";
    std::cout << "Kernel Integration Test\n";
    std::cout << "Real Kernels + Secure Dispatch\n";
    std::cout << "========================================\n";
    
    testSiLUIntegration();
    testSoftmaxIntegration();
    testPerformance();
    
    g_results.summary();
    
    return g_results.failed == 0 ? 0 : 1;
}
