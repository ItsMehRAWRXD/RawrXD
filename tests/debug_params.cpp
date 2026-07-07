// Debug parameter passing
#include <iostream>
#include <cmath>
#include <malloc.h>
#include <cstring>

extern "C" int MASM_Silu_Activation_AVX512(float* data, size_t data_size);

int main() {
    float data[16] = {1.0f};
    
    std::cout << "Pointer: " << data << std::endl;
    std::cout << "Size:    " << 64 << std::endl;
    std::cout << "Size_t:  " << sizeof(size_t) << " bytes" << std::endl;
    
    // Try different sizes
    for (size_t sz : {16, 32, 64, 128, 256}) {
        float* buf = (float*)_aligned_malloc(sz, 64);
        for (size_t i = 0; i < sz/4; ++i) buf[i] = 1.0f;
        
        int result = MASM_Silu_Activation_AVX512(buf, sz);
        std::cout << "Size " << sz << " bytes: return=" << result << ", data[0]=" << buf[0] << std::endl;
        
        _aligned_free(buf);
    }
    
    return 0;
}
