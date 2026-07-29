//=============================================================================
// Q4_0 Scalar SIMD Simulation Test
// Simulates what the AVX-512 kernel should do using scalar operations
// This helps debug the ASM kernel by providing a reference implementation
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include "../src/memory/Q4WeightPreprocess.hpp"

using namespace RawrXD::Memory;

// Simulate AVX-512 operations with scalar code
float simulate_avx512_dot(
    const PreprocessedQ4Block* block,
    const float* activations
) {
    // zmm7 = broadcast scale
    float scale = block->scale;
    
    // zmm0 = accumulator (16 floats)
    float acc[16] = {0};
    
    // Process 4 chunks of 16 weights each
    for (int chunk = 0; chunk < 4; chunk++) {
        // Load 16 int8 weights and sign-extend to int32
        int32_t weights_i32[16];
        for (int i = 0; i < 16; i++) {
            weights_i32[i] = static_cast<int32_t>(block->weights[chunk * 16 + i]);
        }
        
        // Convert int32 to fp32
        float weights_f32[16];
        for (int i = 0; i < 16; i++) {
            weights_f32[i] = static_cast<float>(weights_i32[i]);
        }
        
        // Multiply by scale
        for (int i = 0; i < 16; i++) {
            weights_f32[i] *= scale;
        }
        
        // Load 16 activations
        float acts[16];
        for (int i = 0; i < 16; i++) {
            acts[i] = activations[chunk * 16 + i];
        }
        
        // FMA: acc += weight * activation
        for (int i = 0; i < 16; i++) {
            acc[i] += weights_f32[i] * acts[i];
        }
    }
    
    // Horizontal sum of 16 elements
    // Step 1: Extract high 8 and add to low 8
    float sum8[8];
    for (int i = 0; i < 8; i++) {
        sum8[i] = acc[i] + acc[i + 8];
    }
    
    // Step 2: Extract high 4 and add to low 4
    float sum4[4];
    for (int i = 0; i < 4; i++) {
        sum4[i] = sum8[i] + sum8[i + 4];
    }
    
    // Step 3: Shuffle and add [2,3,0,1]
    float sum4_shuffled[4];
    sum4_shuffled[0] = sum4[2];
    sum4_shuffled[1] = sum4[3];
    sum4_shuffled[2] = sum4[0];
    sum4_shuffled[3] = sum4[1];
    for (int i = 0; i < 4; i++) {
        sum4[i] += sum4_shuffled[i];
    }
    
    // Step 4: Shuffle and add [1,0,3,2]
    float sum4_shuffled2[4];
    sum4_shuffled2[0] = sum4[1];
    sum4_shuffled2[1] = sum4[0];
    sum4_shuffled2[2] = sum4[3];
    sum4_shuffled2[3] = sum4[2];
    
    // Final sum
    float result = sum4[0] + sum4_shuffled2[0];
    
    return result;
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
    printf("Q4_0 Scalar SIMD Simulation Test\n");
    printf("=================================\n\n");
    
    alignas(64) PreprocessedQ4Block block;
    alignas(64) float activations[64];
    
    // Test 1: All ones
    block.init_header(1, 64);
    block.scale = 1.0f;
    for (int i = 0; i < 64; i++) {
        block.weights[i] = 1;
        activations[i] = 1.0f;
    }
    
    printf("Test 1: All ones (scale=1.0, weights=1, activations=1.0)\n");
    printf("  Expected: 64.0\n");
    
    float ref = reference_dot(&block, activations);
    float simd = simulate_avx512_dot(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  SIMD Sim:  %.8f\n", simd);
    printf("  Error:     %.8e\n\n", std::abs(ref - simd));
    
    // Test 2: Pattern weights
    block.scale = 2.0f;
    for (int i = 0; i < 64; i++) {
        block.weights[i] = static_cast<int8_t>(i % 8);
        activations[i] = 1.0f;
    }
    
    printf("Test 2: Pattern weights (0-7 repeating), scale=2.0\n");
    printf("  Expected: 448.0 (2.0 * 28 * 8)\n");
    
    ref = reference_dot(&block, activations);
    simd = simulate_avx512_dot(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  SIMD Sim:  %.8f\n", simd);
    printf("  Error:     %.8e\n\n", std::abs(ref - simd));
    
    // Test 3: Random values
    block.scale = 0.5f;
    for (int i = 0; i < 64; i++) {
        block.weights[i] = static_cast<int8_t>((i * 3) % 16 - 8);
        activations[i] = static_cast<float>(i % 5) * 0.5f;
    }
    
    printf("Test 3: Random-like values\n");
    
    ref = reference_dot(&block, activations);
    simd = simulate_avx512_dot(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  SIMD Sim:  %.8f\n", simd);
    printf("  Error:     %.8e\n\n", std::abs(ref - simd));
    
    // Test 4: Debug the horizontal sum
    printf("Test 4: Debug horizontal sum\n");
    block.scale = 1.0f;
    for (int i = 0; i < 64; i++) {
        block.weights[i] = 1;
        activations[i] = 0.0f;
    }
    // Only set first element in each chunk
    activations[0] = 1.0f;
    activations[16] = 1.0f;
    activations[32] = 1.0f;
    activations[48] = 1.0f;
    
    printf("  Only activations[0,16,32,48] = 1.0\n");
    printf("  Expected: 4.0\n");
    
    ref = reference_dot(&block, activations);
    simd = simulate_avx512_dot(&block, activations);
    
    printf("  Reference: %.8f\n", ref);
    printf("  SIMD Sim:  %.8f\n", simd);
    printf("  Error:     %.8e\n\n", std::abs(ref - simd));
    
    return 0;
}
