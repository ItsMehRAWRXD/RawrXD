//=============================================================================
// Q4 Debug Test - Isolate ASM vs C++ mismatch
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include "../src/memory/Q4WeightPreprocess.hpp"

using namespace RawrXD::Memory;

// External ASM function
extern "C" {
    float q4_preprocessed_dot_avx512_asm(
        const PreprocessedQ4Block* block,
        const float* activations
    );
}

// C++ reference implementation (exact same algorithm as ASM)
float q4_cpp_dot(const PreprocessedQ4Block* block, const float* activations) {
    float sum = 0.0f;
    for (int i = 0; i < 64; i++) {
        float w = static_cast<float>(block->weights[i]) * block->scale;
        sum += w * activations[i];
    }
    return sum;
}

// Manual SIMD simulation (4 passes of 16)
float q4_simd_simulation(const PreprocessedQ4Block* block, const float* activations) {
    float acc[16] = {};
    
    // Pass 1: weights 0-15
    for (int i = 0; i < 16; i++) {
        float w = static_cast<float>(block->weights[i]) * block->scale;
        acc[i] += w * activations[i];
    }
    
    // Pass 2: weights 16-31
    for (int i = 0; i < 16; i++) {
        float w = static_cast<float>(block->weights[i + 16]) * block->scale;
        acc[i] += w * activations[i + 16];
    }
    
    // Pass 3: weights 32-47
    for (int i = 0; i < 16; i++) {
        float w = static_cast<float>(block->weights[i + 32]) * block->scale;
        acc[i] += w * activations[i + 32];
    }
    
    // Pass 4: weights 48-63
    for (int i = 0; i < 16; i++) {
        float w = static_cast<float>(block->weights[i + 48]) * block->scale;
        acc[i] += w * activations[i + 48];
    }
    
    // Horizontal sum
    float total = 0.0f;
    for (int i = 0; i < 16; i++) {
        total += acc[i];
    }
    return total;
}

int main() {
    printf("Q4 Debug Test\n");
    printf("=============\n\n");
    
    // Create a simple test block
    alignas(64) PreprocessedQ4Block block;
    memset(&block, 0, sizeof(block));
    
    // Initialize header
    block.init_header(1, 64);
    
    // Set scale to 1.0 for simplicity
    block.scale = 1.0f;
    
    // Set weights to simple pattern: 1, 2, 3, ..., 64
    for (int i = 0; i < 64; i++) {
        block.weights[i] = static_cast<int8_t>(i - 32);  // -32 to +31
    }
    
    // Set activations to 1.0 for simplicity
    alignas(64) float activations[64];
    for (int i = 0; i < 64; i++) {
        activations[i] = 1.0f;
    }
    
    printf("Block layout:\n");
    printf("  sizeof(PreprocessedQ4Block): %zu\n", sizeof(PreprocessedQ4Block));
    printf("  offsetof(header): %zu\n", offsetof(PreprocessedQ4Block, header));
    printf("  offsetof(scale): %zu\n", offsetof(PreprocessedQ4Block, scale));
    printf("  offsetof(weights): %zu\n", offsetof(PreprocessedQ4Block, weights));
    printf("\n");
    
    printf("First 16 weights: ");
    for (int i = 0; i < 16; i++) {
        printf("%d ", block.weights[i]);
    }
    printf("\n");
    
    printf("Scale: %f\n", block.scale);
    printf("\n");
    
    // Calculate expected result
    // Sum of weights -32 to +31 = -32
    float expected = 0.0f;
    for (int i = 0; i < 64; i++) {
        expected += block.weights[i] * activations[i] * block.scale;
    }
    printf("Expected (C++ loop): %f\n", expected);
    
    float simd_result = q4_simd_simulation(&block, activations);
    printf("SIMD simulation: %f\n", simd_result);
    
    float asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    printf("ASM result: %f\n", asm_result);
    
    printf("\n");
    printf("Errors:\n");
    printf("  SIMD vs Expected: %f\n", simd_result - expected);
    printf("  ASM vs Expected:  %f\n", asm_result - expected);
    printf("  ASM vs SIMD:      %f\n", asm_result - simd_result);
    
    // Now test with actual GGUF format
    printf("\n\n=== Testing with actual GGUF format ===\n\n");
    
    // Create a GGUF block: scale (fp16) + 32 packed nibbles
    alignas(64) uint8_t gguf_block[64];
    memset(gguf_block, 0, 64);
    
    // Scale = 1.0 in fp16
    // 1.0 = 0x3C00 in fp16
    gguf_block[0] = 0x00;
    gguf_block[1] = 0x3C;
    
    // Pack weights: each nibble is weight+8 (so -8 becomes 0, +7 becomes 15)
    // Let's use weight=1 for all (nibble value = 9)
    for (int i = 0; i < 32; i++) {
        gguf_block[2 + i] = 0x99;  // Both nibbles = 9 (weight = 1)
    }
    
    // Preprocess
    alignas(64) PreprocessedQ4Block preproc;
    Q4WeightPreprocessor::PreprocessBlock(gguf_block, &preproc, 0, 1, 64);
    
    printf("Preprocessed scale: %f\n", preproc.scale);
    printf("First 16 weights: ");
    for (int i = 0; i < 16; i++) {
        printf("%d ", preproc.weights[i]);
    }
    printf("\n");
    
    // Expected: 64 weights of 1.0 * scale 1.0 * activations 1.0 = 64
    float expected2 = 64.0f;
    float cpp_result2 = q4_cpp_dot(&preproc, activations);
    float simd_result2 = q4_simd_simulation(&preproc, activations);
    float asm_result2 = q4_preprocessed_dot_avx512_asm(&preproc, activations);
    
    printf("\nResults:\n");
    printf("  Expected: %f\n", expected2);
    printf("  C++:      %f (error: %f)\n", cpp_result2, cpp_result2 - expected2);
    printf("  SIMD:     %f (error: %f)\n", simd_result2, simd_result2 - expected2);
    printf("  ASM:      %f (error: %f)\n", asm_result2, asm_result2 - expected2);
    
    return 0;
}
