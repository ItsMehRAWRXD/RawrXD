// ============================================================================
// Direct Benchmark - Simple timing without lambdas or complex mechanisms
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <chrono>
#include <iomanip>
#include <malloc.h>

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
    std::cout << "Direct SiLU Benchmark\n";
    std::cout << "========================================\n";
    
    const size_t size = 65536;
    const int iterations = 100;
    
    // Generate test data
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<float> dist(-3.0f, 3.0f);
    
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
    std::cout << "\nRunning scalar benchmark...\n";
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        memcpy(scalar_buf, input.data(), size * sizeof(float));
        Scalar_SiLU(scalar_buf, size);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto scalar_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double scalar_ms = scalar_duration.count() / 1000.0 / iterations;
    
    std::cout << "Scalar: " << std::fixed << std::setprecision(4) << scalar_ms << " ms/iter\n";
    
    // Assembly benchmark
    std::cout << "\nRunning assembly benchmark...\n";
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        memcpy(asm_buf, input.data(), size * sizeof(float));
        MASM_Silu_Activation_AVX512(asm_buf, size * sizeof(float));
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto asm_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double asm_ms = asm_duration.count() / 1000.0 / iterations;
    
    std::cout << "Assembly: " << std::fixed << std::setprecision(4) << asm_ms << " ms/iter\n";
    
    // Calculate speedup
    double speedup = scalar_ms / asm_ms;
    std::cout << "Speedup: " << std::fixed << std::setprecision(2) << speedup << "x\n";
    
    // Verify correctness
    std::cout << "\nVerifying correctness...\n";
    memcpy(scalar_buf, input.data(), size * sizeof(float));
    memcpy(asm_buf, input.data(), size * sizeof(float));
    
    Scalar_SiLU(scalar_buf, size);
    MASM_Silu_Activation_AVX512(asm_buf, size * sizeof(float));
    
    bool match = true;
    for (size_t i = 0; i < 10; ++i) {
        if (std::abs(scalar_buf[i] - asm_buf[i]) > 0.01f) {
            match = false;
            std::cout << "Mismatch at index " << i << ": " << scalar_buf[i] << " vs " << asm_buf[i] << "\n";
        }
    }
    
    if (match) {
        std::cout << "✅ Results match!\n";
    } else {
        std::cout << "❌ Results differ!\n";
    }
    
    _aligned_free(scalar_buf);
    _aligned_free(asm_buf);
    
    std::cout << "\n========================================\n";
    std::cout << "Benchmark Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
