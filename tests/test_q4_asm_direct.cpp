//=============================================================================
// Q4_0 ASM Kernel Direct Debug Test
// Tests the ASM kernel directly with known values
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>

// Minimal PreprocessedQ4Block definition for testing
struct Q4BlockHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t block_count;
    uint32_t original_elements;
};

struct alignas(64) PreprocessedQ4Block {
    Q4BlockHeader header;
    float scale;
    int8_t weights[64];
    uint8_t padding[44];
};

// External ASM function
extern "C" {
    float q4_preprocessed_dot_avx512_asm(
        const PreprocessedQ4Block* block,
        const float* activations
    );
}

// Simple reference implementation
float reference_dot(
    const PreprocessedQ4Block* block,
    const float* activations
) {
    float sum = 0.0f;
    for (int i = 0; i < 64; i++) {
        sum += block->scale * static_cast<float>(block->weights[i]) * activations[i];
    }
    return sum;
}

int main() {
    printf("Q4_0 ASM Kernel Direct Debug Test\n");
    printf("=================================\n\n");
    
    alignas(64) PreprocessedQ4Block block;
    alignas(64) float activations[64];
    
    // Test 1: All ones
    block.header.magic = 0x51345030;
    block.header.version = 1;
    block.header.block_count = 1;
    block.header.original_elements = 64;
    block.scale = 1.0f;
    
    for (int i = 0; i < 64; i++) {
        block.weights[i] = 1;
        activations[i] = 1.0f;
    }
    
    printf("Test 1: All ones (scale=1.0, weights=1, activations=1.0)\n");
    printf("  Expected: 64.0\n");
    
    float ref = reference_dot(&block, activations);
    float asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  ASM:       %.8f\n", asm_result);
    printf("  Error:     %.8e\n\n", std::abs(ref - asm_result));
    
    // Test 2: Single weight
    memset(block.weights, 0, 64);
    block.weights[0] = 1;
    memset(activations, 0, sizeof(activations));
    activations[0] = 1.0f;
    
    printf("Test 2: Single weight (index 0 = 1, activation 0 = 1)\n");
    printf("  Expected: 1.0\n");
    
    ref = reference_dot(&block, activations);
    asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  ASM:       %.8f\n", asm_result);
    printf("  Error:     %.8e\n\n", std::abs(ref - asm_result));
    
    // Test 3: First 16 only
    for (int i = 0; i < 64; i++) {
        block.weights[i] = (i < 16) ? 1 : 0;
        activations[i] = 1.0f;
    }
    
    printf("Test 3: First 16 weights = 1, rest = 0\n");
    printf("  Expected: 16.0\n");
    
    ref = reference_dot(&block, activations);
    asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  ASM:       %.8f\n", asm_result);
    printf("  Error:     %.8e\n\n", std::abs(ref - asm_result));
    
    // Test 4: Check block memory layout
    printf("Block Layout:\n");
    printf("  sizeof(PreprocessedQ4Block): %zu\n", sizeof(PreprocessedQ4Block));
    printf("  offsetof(header): %zu\n", offsetof(PreprocessedQ4Block, header));
    printf("  offsetof(scale): %zu\n", offsetof(PreprocessedQ4Block, scale));
    printf("  offsetof(weights): %zu\n", offsetof(PreprocessedQ4Block, weights));
    printf("\n");
    
    // Test 5: Check scale loading
    block.scale = 2.0f;
    for (int i = 0; i < 64; i++) {
        block.weights[i] = 1;
        activations[i] = 1.0f;
    }
    
    printf("Test 5: Scale test (scale=2.0, all weights=1, all activations=1.0)\n");
    printf("  Expected: 128.0\n");
    
    ref = reference_dot(&block, activations);
    asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  ASM:       %.8f\n", asm_result);
    printf("  Error:     %.8e\n\n", std::abs(ref - asm_result));
    
    return 0;
}
