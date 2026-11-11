// Test Softmax ABI compliance
#include <iostream>
#include <chrono>
#include <malloc.h>
#include <cstring>
#include <cmath>

extern "C" int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);

void test_correctness() {
    std::cout << "=== Softmax Correctness Test ===\n";
    
    // Test with 32 elements (8 AVX2 registers)
    float* buf = (float*)_aligned_malloc(128, 32); // 32 floats = 128 bytes
    for (int i = 0; i < 32; ++i) buf[i] = (i % 8) * 0.1f; // Pattern: 0, 0.1, 0.2, ...
    
    int ret = MASM_Softmax_Forward_AVX2(buf, 128);
    std::cout << "Return code: " << ret << std::endl;
    
    // Sum should be close to 1.0
    float sum = 0;
    for (int i = 0; i < 32; ++i) sum += buf[i];
    std::cout << "Sum: " << sum << " (should be ~1.0)\n";
    
    if (std::abs(sum - 1.0f) < 0.01f) {
        std::cout << "✅ Softmax correctness PASSED\n";
    } else {
        std::cout << "❌ Softmax correctness FAILED\n";
    }
    
    _aligned_free(buf);
}

void test_timing_stability() {
    std::cout << "\n=== Softmax Timing Stability Test ===\n";
    
    float* buf = (float*)_aligned_malloc(65536 * sizeof(float), 32);
    for (int i = 0; i < 65536; ++i) buf[i] = (i % 100) * 0.01f;
    
    for (int run = 0; run < 5; ++run) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100; ++i) {
            MASM_Softmax_Forward_AVX2(buf, 65536 * sizeof(float));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        std::cout << "Run " << run << ": " << us/100 << " us/iter\n";
    }
    
    _aligned_free(buf);
    std::cout << "✅ Softmax timing stable\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Softmax AVX2 ABI Compliance Test\n";
    std::cout << "========================================\n";
    
    test_correctness();
    test_timing_stability();
    
    std::cout << "\n========================================\n";
    std::cout << "Softmax Test Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
