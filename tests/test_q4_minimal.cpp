//=============================================================================
// Q4 Minimal Test - Exact reproduction of fused pipeline
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include "../src/memory/Q4WeightPreprocess.hpp"

using namespace RawrXD::Memory;

extern "C" {
    float q4_preprocessed_dot_avx512_asm(
        const PreprocessedQ4Block* block,
        const float* activations
    );
}

int main() {
    printf("Q4 Minimal Test\n");
    printf("===============\n\n");
    
    // Create a simple GGUF block
    alignas(64) uint8_t gguf_block[64];
    memset(gguf_block, 0, 64);
    
    // Scale = 1.0 in fp16 = 0x3C00
    gguf_block[0] = 0x00;
    gguf_block[1] = 0x3C;
    
    // All weights = 1 (nibble value = 9, so packed byte = 0x99)
    for (int i = 0; i < 32; i++) {
        gguf_block[2 + i] = 0x99;
    }
    
    // Preprocess
    alignas(64) PreprocessedQ4Block preproc;
    Q4WeightPreprocessor::PreprocessBlock(gguf_block, &preproc, 0, 1, 64);
    
    // Activations all = 1.0
    alignas(64) float activations[64];
    for (int i = 0; i < 64; i++) {
        activations[i] = 1.0f;
    }
    
    printf("After preprocessing:\n");
    printf("  scale: %f\n", preproc.scale);
    printf("  weights[0]: %d\n", preproc.weights[0]);
    printf("  weights[1]: %d\n", preproc.weights[1]);
    printf("  weights[63]: %d\n", preproc.weights[63]);
    printf("\n");
    
    // C++ reference
    float cpp_result = 0.0f;
    for (int i = 0; i < 64; i++) {
        cpp_result += preproc.scale * preproc.weights[i] * activations[i];
    }
    
    // ASM result
    float asm_result = q4_preprocessed_dot_avx512_asm(&preproc, activations);
    
    printf("Results:\n");
    printf("  Expected: 64.0\n");
    printf("  C++:      %f\n", cpp_result);
    printf("  ASM:      %f\n", asm_result);
    printf("\n");
    
    // Check raw memory
    printf("Raw memory check:\n");
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&preproc);
    printf("  Bytes 16-19 (scale): ");
    for (int i = 0; i < 4; i++) printf("%02x ", ptr[16 + i]);
    printf("\n");
    printf("  Bytes 20-35 (weights 0-15): ");
    for (int i = 0; i < 16; i++) printf("%02x ", ptr[20 + i]);
    printf("\n");
    
    return 0;
}
