// Simple MASM kernel test
#include <iostream>
#include <cstring>
#include <malloc.h>

extern "C" int MASM_Silu_Activation_AVX512(float* data, size_t data_size);

int main() {
    std::cout << "Testing MASM SiLU kernel..." << std::endl;
    
    // Allocate aligned buffer
    float* data = (float*)_aligned_malloc(64, 64);
    if (!data) {
        std::cerr << "Failed to allocate aligned memory" << std::endl;
        return 1;
    }
    
    // Initialize with test data
    for (int i = 0; i < 8; i++) {
        data[i] = 1.0f;
    }
    
    std::cout << "Input: ";
    for (int i = 0; i < 8; i++) std::cout << data[i] << " ";
    std::cout << std::endl;
    
    std::cout << "Calling MASM kernel..." << std::endl;
    int result = MASM_Silu_Activation_AVX512(data, 32);  // 8 floats * 4 bytes
    std::cout << "Result code: " << result << std::endl;
    
    std::cout << "Output: ";
    for (int i = 0; i < 8; i++) std::cout << data[i] << " ";
    std::cout << std::endl;
    
    _aligned_free(data);
    return result;
}
