// Verify assembly produces consistent results
#include <iostream>
#include <chrono>
#include <malloc.h>
#include <cstring>

extern "C" int MASM_Silu_Activation_AVX512(float* data, size_t data_size);

int main() {
    // Test with all 1.0f
    float* buf1 = (float*)_aligned_malloc(64, 64);
    float* buf2 = (float*)_aligned_malloc(64, 64);
    
    for (int i = 0; i < 16; ++i) {
        buf1[i] = buf2[i] = 1.0f;
    }
    
    MASM_Silu_Activation_AVX512(buf1, 64);
    MASM_Silu_Activation_AVX512(buf2, 64);
    
    bool match = true;
    for (int i = 0; i < 16; ++i) {
        if (buf1[i] != buf2[i]) {
            std::cout << "Inconsistent at " << i << ": " << buf1[i] << " vs " << buf2[i] << std::endl;
            match = false;
        }
    }
    
    if (match) {
        std::cout << "✅ Assembly produces consistent results!\n";
        std::cout << "Value for input 1.0f: " << buf1[0] << std::endl;
    }
    
    _aligned_free(buf1);
    _aligned_free(buf2);
    
    // Test timing stability
    std::cout << "\nTiming stability test:\n";
    float* buf = (float*)_aligned_malloc(65536 * sizeof(float), 64);
    for (int i = 0; i < 65536; ++i) buf[i] = 1.0f;
    
    for (int run = 0; run < 5; ++run) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100; ++i) {
            MASM_Silu_Activation_AVX512(buf, 65536 * sizeof(float));
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        std::cout << "Run " << run << ": " << us/100 << " us/iter\n";
    }
    
    _aligned_free(buf);
    
    return 0;
}
