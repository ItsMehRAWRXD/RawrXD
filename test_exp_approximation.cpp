// Test FAST_EXP macro in isolation
#include <iostream>
#include <cmath>
#include <immintrin.h>

extern "C" int MASM_Softmax_Forward_AVX2(void* data, size_t data_size);

// Simple test for exp approximation
void test_exp_approximation() {
    std::cout << "Testing exp approximation..." << std::endl;
    
    // Test values
    float test_values[] = {-5.0f, -4.0f, -3.0f, -2.0f, -1.0f, 0.0f, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f};
    
    for (float x : test_values) {
        float true_exp = std::exp(x);
        std::cout << "exp(" << x << ") = " << true_exp << std::endl;
    }
}

int main() {
    test_exp_approximation();
    
    std::cout << "\nTesting Softmax kernel..." << std::endl;
    
    // Allocate aligned buffer
    const size_t count = 256;
    const size_t size = count * sizeof(float);
    float* data = static_cast<float*>(_aligned_malloc(size, 32));
    
    // Initialize with test data
    for (size_t i = 0; i < count; ++i) {
        data[i] = static_cast<float>(i % 100) / 10.0f - 5.0f;  // Range: [-5, 5]
    }
    
    std::cout << "Input data (first 10):" << std::endl;
    for (size_t i = 0; i < 10; ++i) {
        std::cout << "  data[" << i << "] = " << data[i] << std::endl;
    }
    
    std::cout << "Calling MASM_Softmax_Forward_AVX2..." << std::endl;
    int result = MASM_Softmax_Forward_AVX2(data, size);
    std::cout << "Result: " << result << std::endl;
    
    if (result != 0) {
        std::cerr << "Softmax kernel failed with error: " << result << std::endl;
        _aligned_free(data);
        return 1;
    }
    
    std::cout << "Output data (first 10):" << std::endl;
    for (size_t i = 0; i < 10; ++i) {
        std::cout << "  data[" << i << "] = " << data[i] << std::endl;
    }
    
    // Verify sum = 1.0
    float sum = 0.0f;
    for (size_t i = 0; i < count; ++i) {
        sum += data[i];
    }
    std::cout << "Sum: " << sum << std::endl;
    
    if (std::abs(sum - 1.0f) < 1e-5f) {
        std::cout << "✅ Softmax kernel passed!" << std::endl;
    } else {
        std::cerr << "❌ Softmax kernel failed: sum != 1.0" << std::endl;
    }
    
    _aligned_free(data);
    return 0;
}