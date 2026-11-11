// Minimal Q4_0 test
#include <iostream>
#include <cstdint>
#include <malloc.h>

struct block_q4_0 {
    float scale;
    uint8_t qs[16];
};

extern "C" int MASM_Dequant_Q4_0_AVX2(const block_q4_0* blocks, float* output, size_t num_blocks);

int main() {
    std::cout << "Minimal Q4_0 Test\n";
    
    block_q4_0* blocks = (block_q4_0*)_aligned_malloc(sizeof(block_q4_0), 32);
    float* output = (float*)_aligned_malloc(64 * sizeof(float), 32);  // Allocate extra for safety
    
    if (!blocks || !output) {
        std::cout << "Memory allocation failed\n";
        return 1;
    }
    
    // Initialize test data with DIFFERENT nibbles
    blocks->scale = 0.1f;
    for (int i = 0; i < 16; i++) {
        uint8_t low = i;           // Low nibble = i
        uint8_t high = (i + 1) % 16;  // High nibble = i+1
        blocks->qs[i] = (high << 4) | low;
    }
    
    std::cout << "Calling kernel...\n";
    int ret = MASM_Dequant_Q4_0_AVX2(blocks, output, 1);
    std::cout << "Return code: " << ret << "\n";
    
    if (ret == 0) {
        std::cout << "First 8 outputs:\n";
        for (int i = 0; i < 8; i++) {
            std::cout << "  [" << i << "] = " << output[i] << "\n";
        }
    }
    
    _aligned_free(blocks);
    _aligned_free(output);
    
    return 0;
}
