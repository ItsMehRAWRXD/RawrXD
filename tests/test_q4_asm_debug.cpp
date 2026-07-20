//=============================================================================
// Q4_0 ASM Kernel Debug Test
// Isolates the AVX-512 kernel for debugging
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

// Scalar reference - use output parameter to avoid return value issues
__declspec(noinline) void reference_dot(
    const PreprocessedQ4Block* block,
    const float* activations,
    float* result
) {
    float sum = 0.0f;
    for (int i = 0; i < 64; i++) {
        sum += block->scale * static_cast<float>(block->weights[i]) * activations[i];
    }
    *result = sum;
}

int main() {
    printf("Q4_0 ASM Kernel Debug Test\n");
    printf("==========================\n\n");
    
    // Create a simple test block
    alignas(64) PreprocessedQ4Block block;
    alignas(64) float activations[64];
    
    // Initialize header
    block.init_header(1, 64);
    
    // Set scale to 1.0 for simplicity
    block.scale = 1.0f;
    
    // Set all weights to 1
    for (int i = 0; i < 64; i++) {
        block.weights[i] = 1;
    }
    
    // Set all activations to 1
    for (int i = 0; i < 64; i++) {
        activations[i] = 1.0f;
    }
    
    // Expected result: sum = 1.0 * 1 * 1.0 * 64 = 64.0
    float expected = 64.0f;
    
    printf("Test 1: All ones\n");
    printf("  Scale: %.2f\n", block.scale);
    printf("  Weights: all %d\n", block.weights[0]);
    printf("  Activations: all %.2f\n", activations[0]);
    printf("  Expected: %.2f\n", expected);
    
    // Debug: print what reference sees
    printf("  Debug - block.scale: %f\n", block.scale);
    printf("  Debug - block.weights[0]: %d\n", block.weights[0]);
    printf("  Debug - activations[0]: %f\n", activations[0]);
    
    float ref_result;
    reference_dot(&block, activations, &ref_result);
    float asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    
    printf("  Reference: %.8f\n", ref_result);
    printf("  ASM:       %.8f\n", asm_result);
    printf("  Error:     %.8e\n", std::abs(ref_result - asm_result));
    printf("\n");
    
    // Test 2: Different weights
    for (int i = 0; i < 64; i++) {
        block.weights[i] = static_cast<int8_t>(i % 8);  // 0,1,2,3,4,5,6,7,0,1...
        activations[i] = 1.0f;
    }
    block.scale = 2.0f;
    
    // Expected: 2.0 * sum(0+1+2+3+4+5+6+7) * 8 = 2.0 * 28 * 8 = 448.0
    expected = 448.0f;
    
    printf("Test 2: Pattern weights (0-7 repeating), scale=2.0\n");
    printf("  Expected: %.2f\n", expected);
    
    reference_dot(&block, activations, &ref_result);
    asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    
    printf("  Reference: %.8f\n", ref_result);
    printf("  ASM:       %.8f\n", asm_result);
    printf("  Error:     %.8e\n", std::abs(ref_result - asm_result));
    printf("\n");
    
    // Test 3: Check block layout
    printf("Block Layout Check:\n");
    printf("  sizeof(PreprocessedQ4Block): %zu\n", sizeof(PreprocessedQ4Block));
    printf("  alignof(PreprocessedQ4Block): %zu\n", alignof(PreprocessedQ4Block));
    printf("  offsetof(header): %zu\n", offsetof(PreprocessedQ4Block, header));
    printf("  offsetof(scale): %zu\n", offsetof(PreprocessedQ4Block, scale));
    printf("  offsetof(weights): %zu\n", offsetof(PreprocessedQ4Block, weights));
    printf("\n");
    
    // Test 4: Single weight test
    memset(block.weights, 0, 64);
    block.weights[0] = 1;
    block.scale = 1.0f;
    memset(activations, 0, sizeof(activations));
    activations[0] = 1.0f;
    
    printf("Test 4: Single weight (index 0 = 1, activation 0 = 1)\n");
    printf("  Expected: 1.0\n");
    
    reference_dot(&block, activations, &ref_result);
    asm_result = q4_preprocessed_dot_avx512_asm(&block, activations);
    
    printf("  Reference: %.8f\n", ref_result);
    printf("  ASM:       %.8f\n", asm_result);
    printf("  Error:     %.8e\n", std::abs(ref_result - asm_result));
    printf("\n");
    
    return 0;
}
