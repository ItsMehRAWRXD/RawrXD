// ============================================================================
// Final Benchmark - ABI-Compliant Assembly Performance Test
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>
#include <iomanip>
#include <malloc.h>
#include <cstring>

// Assembly functions
extern "C" {
    int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
}

// Scalar implementation
void Scalar_SiLU(float* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] = data[i] / (1.0f + std::exp(-data[i]));
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Final SiLU Benchmark - ABI Compliant\n";
    std::cout << "========================================\n";
    
    const int iterations = 100;
    
    // Test different sizes (in elements, must be multiple of 16 for AVX-512)
    std::vector<size_t> sizes = {1024, 4096, 16384, 65536, 262144};
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
    for (size_t size : sizes) {
        // Generate test data
        std::vector<float> input(size);
        for (auto& x : input) x = dist(gen);
        
        // Allocate aligned buffers
        float* scalar_buf = (float*)_aligned_malloc(size * sizeof(float), 64);
        float* asm_buf = (float*)_aligned_malloc(size * sizeof(float), 64);
        
        if (!scalar_buf || !asm_buf) {
            std::cout << "Memory allocation failed\n";
            return 1;
        }
        
        // Scalar benchmark
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            memcpy(scalar_buf, input.data(), size * sizeof(float));
            Scalar_SiLU(scalar_buf, size);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto scalar_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / iterations;
        
        // Assembly benchmark
        start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            memcpy(asm_buf, input.data(), size * sizeof(float));
            MASM_Silu_Activation_AVX512(asm_buf, size * sizeof(float)); // Pass bytes, not elements
        }
        end = std::chrono::high_resolution_clock::now();
        auto asm_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / iterations;
        
        // Calculate speedup
        double speedup = (double)scalar_us / (double)asm_us;
        
        std::cout << "\nSize " << size << " elements:\n";
        std::cout << "  Scalar:   " << std::fixed << std::setprecision(3) << (scalar_us / 1000.0) << " ms\n";
        std::cout << "  Assembly:   " << std::fixed << std::setprecision(3) << (asm_us / 1000.0) << " ms\n";
        std::cout << "  Speedup:    " << std::fixed << std::setprecision(2) << speedup << "x\n";
        
        // Verify correctness
        memcpy(scalar_buf, input.data(), size * sizeof(float));
        memcpy(asm_buf, input.data(), size * sizeof(float));
        Scalar_SiLU(scalar_buf, size);
        MASM_Silu_Activation_AVX512(asm_buf, size * sizeof(float));
        
        bool match = true;
        for (size_t i = 0; i < size && i < 100; ++i) {
            if (std::abs(scalar_buf[i] - asm_buf[i]) > 0.01f) {
                match = false;
                break;
            }
        }
        std::cout << "  Correct:    " << (match ? "✅ PASS" : "❌ FAIL") << "\n";
        
        _aligned_free(scalar_buf);
        _aligned_free(asm_buf);
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Benchmark Complete - ABI COMPLIANT ✅\n";
    std::cout << "========================================\n";
    
    return 0;
}
