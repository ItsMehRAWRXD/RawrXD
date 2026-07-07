// Minimal Softmax test
#include <iostream>
#include <cmath>
#include <immintrin.h>
#include <thread>
#include <chrono>

extern "C" int MASM_Softmax_Forward_AVX2(void* data, size_t data_size);

int main() {
    std::cout << "Testing Softmax kernel..." << std::endl;
    
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
    
    // Add timeout check
    volatile bool done = false;
    std::thread timeout_thread([&done]() {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (!done) {
            std::cerr << "❌ TIMEOUT: Kernel did not return within 5 seconds" << std::endl;
            std::exit(1);
        }
    });
    
    int result = MASM_Softmax_Forward_AVX2(data, size);
    done = true;
    
    timeout_thread.detach();
    
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