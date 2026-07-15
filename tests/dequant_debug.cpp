// Debug test for Q4_0 dequantization
#include <iostream>
#include <cstdint>
#include <malloc.h>
#include <cstring>

struct block_q4_0 {
    float scale;
    uint8_t qs[16];
};

extern "C" int MASM_Dequant_Q4_0_AVX2(const block_q4_0* blocks, float* output, size_t num_blocks);

void Dequant_Q4_0_Scalar(const block_q4_0* blocks, float* output, size_t num_blocks) {
    for (size_t b = 0; b < num_blocks; b++) {
        float scale = blocks[b].scale;
        const uint8_t* qs = blocks[b].qs;
        
        for (int i = 0; i < 32; i++) {
            uint8_t byte = qs[i / 2];
            uint8_t nibble = (i % 2 == 0) ? (byte >> 4) : (byte & 0x0F);
            output[b * 32 + i] = (static_cast<float>(nibble) - 8.0f) * scale;
        }
    }
}

int main() {
    std::cout << "Q4_0 Debug Test\n\n";
    
    block_q4_0* blocks = (block_q4_0*)_aligned_malloc(sizeof(block_q4_0), 32);
    float* output_scalar = (float*)_aligned_malloc(32 * sizeof(float), 32);
    float* output_avx2 = (float*)_aligned_malloc(32 * sizeof(float), 32);
    
    // Initialize with pattern: qs[i] = ((i+1) << 4) | i
    blocks->scale = 0.1f;
    std::cout << "Input bytes (qs):\n";
    for (int i = 0; i < 16; i++) {
        uint8_t low = i;
        uint8_t high = (i + 1) % 16;
        blocks->qs[i] = (high << 4) | low;
        std::cout << "  qs[" << i << "] = 0x" << std::hex << (int)blocks->qs[i] 
                  << " (high=" << (int)high << ", low=" << (int)low << ")\n";
    }
    std::cout << std::dec << "\n";
    
    // Expected weights:
    std::cout << "Expected weights (scalar):\n";
    for (int i = 0; i < 32; i++) {
        uint8_t byte = blocks->qs[i / 2];
        uint8_t nibble = (i % 2 == 0) ? (byte >> 4) : (byte & 0x0F);
        float expected = (nibble - 8.0f) * 0.1f;
        std::cout << "  weight[" << i << "] = (" << (int)nibble << " - 8) * 0.1 = " << expected << "\n";
    }
    std::cout << "\n";
    
    // Run scalar
    Dequant_Q4_0_Scalar(blocks, output_scalar, 1);
    
    // Debug: print raw memory
    std::cout << "\nRaw memory at blocks+4 (qs):\n";
    uint8_t* raw = (uint8_t*)blocks;
    for (int i = 0; i < 20; i++) {
        std::cout << "  byte[" << i << "] = 0x" << std::hex << (int)raw[i] << std::dec << "\n";
    }
    std::cout << "\n";
    
    // Run AVX2
    int ret = MASM_Dequant_Q4_0_AVX2(blocks, output_avx2, 1);
    std::cout << "AVX2 return code: " << ret << "\n\n";
    
    // Compare
    std::cout << "Comparison:\n";
    for (int i = 0; i < 32; i++) {
        std::cout << "  [" << i << "] scalar=" << output_scalar[i] 
                  << " avx2=" << output_avx2[i];
        if (output_scalar[i] != output_avx2[i]) {
            std::cout << " MISMATCH!";
        }
        std::cout << "\n";
    }
    
    _aligned_free(blocks);
    _aligned_free(output_scalar);
    _aligned_free(output_avx2);
    
    return 0;
}
