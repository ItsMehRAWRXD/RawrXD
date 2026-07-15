// Minimal test for SiLU assembly
#include <iostream>
#include <cmath>
#include <malloc.h>
#include <cstring>

extern "C" int MASM_Silu_Activation_AVX512(float* data, size_t data_size);

int main() {
    // Test with simple values
    float data[16] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f,
                      1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    
    std::cout << "Input:  " << data[0] << std::endl;
    
    int result = MASM_Silu_Activation_AVX512(data, 64); // 16 floats * 4 bytes
    
    std::cout << "Return: " << result << std::endl;
    std::cout << "Output: " << data[0] << std::endl;
    std::cout << "Expected: ~0.731 (sigmoid(1) * 1)" << std::endl;
    
    // Check all values
    bool all_same = true;
    for (int i = 1; i < 16; ++i) {
        if (data[i] != data[0]) {
            all_same = false;
            std::cout << "Index " << i << ": " << data[i] << std::endl;
        }
    }
    
    if (all_same) {
        std::cout << "All 16 values are the same: " << data[0] << std::endl;
    }
    
    return 0;
}
