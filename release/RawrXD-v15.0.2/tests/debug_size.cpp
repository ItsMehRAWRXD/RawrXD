// Debug specific sizes
#include <iostream>
#include <cmath>
#include <malloc.h>
#include <cstring>

extern "C" int MASM_Silu_Activation_AVX512(float* data, size_t data_size);

void Scalar_SiLU(float* data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        data[i] = data[i] / (1.0f + std::exp(-data[i]));
    }
}

void test_size(size_t size) {
    std::cout << "\n=== Testing size " << size << " elements ===\n";
    
    float* scalar_buf = (float*)_aligned_malloc(size * sizeof(float), 64);
    float* asm_buf = (float*)_aligned_malloc(size * sizeof(float), 64);
    
    // Fill with test data
    for (size_t i = 0; i < size; ++i) {
        scalar_buf[i] = asm_buf[i] = 1.0f + (i % 5) * 0.1f; // Simple pattern
    }
    
    // Run scalar
    Scalar_SiLU(scalar_buf, size);
    
    // Run assembly
    int ret = MASM_Silu_Activation_AVX512(asm_buf, size * sizeof(float));
    std::cout << "Return code: " << ret << std::endl;
    
    // Compare
    int mismatches = 0;
    for (size_t i = 0; i < size && mismatches < 5; ++i) {
        if (std::abs(scalar_buf[i] - asm_buf[i]) > 0.01f) {
            std::cout << "Mismatch at " << i << ": scalar=" << scalar_buf[i] 
                      << " asm=" << asm_buf[i] << std::endl;
            mismatches++;
        }
    }
    
    if (mismatches == 0) {
        std::cout << "✅ All values match!\n";
    }
    
    _aligned_free(scalar_buf);
    _aligned_free(asm_buf);
}

int main() {
    test_size(1024);
    test_size(4096);
    test_size(16384);
    test_size(65536);
    test_size(262144);
    return 0;
}
