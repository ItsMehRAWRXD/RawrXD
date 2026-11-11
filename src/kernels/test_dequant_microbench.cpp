// ============================================================================
// Q4_0 Dequantization Microbenchmark
// Validates vectorized nibble extraction before matmul integration
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cmath>
#include <cstring>

// Q4_0 block structure
struct Q4_0_Block {
    float scale;                    // 4 bytes
    uint8_t weights[16];           // 16 bytes (32 nibbles)
};

// External assembly functions
extern "C" {
    void Q4_0_Dequant_Scalar(const void* block, float* output);
    void Q4_0_Dequant_AVX512(const void* block, float* output);
}

// Reference scalar dequantization
void ReferenceDequant(const Q4_0_Block* block, float* output) {
    for (int i = 0; i < 16; i++) {
        uint8_t byte = block->weights[i];
        
        // Lower nibble (first weight)
        int low = (byte & 0x0F) - 8;
        output[i * 2] = low * block->scale;
        
        // Upper nibble (second weight)
        int high = ((byte >> 4) & 0x0F) - 8;
        output[i * 2 + 1] = high * block->scale;
    }
}

// ============================================================================
// Test A: Correctness Validation
// ============================================================================
bool TestCorrectness() {
    printf("\n=== Test A: Dequant Correctness ===\n");
    
    // Create test block
    Q4_0_Block block;
    block.scale = 0.5f;
    for (int i = 0; i < 16; i++) {
        block.weights[i] = static_cast<uint8_t>((i * 17) % 256); // Pseudo-random pattern
    }
    
    float ref_output[32];
    float avx_output[32];
    
    ReferenceDequant(&block, ref_output);
    Q4_0_Dequant_AVX512(&block, avx_output);
    
    // AVX-512 outputs: first 16 = lower nibbles [L0-L15], next 16 = upper nibbles [H0-H15]
    // Need to reorder to match scalar: interleaved [L0,H0,L1,H1,...]
    float avx_reordered[32];
    for (int i = 0; i < 16; i++) {
        avx_reordered[i * 2] = avx_output[i];      // Lower nibble
        avx_reordered[i * 2 + 1] = avx_output[i + 16]; // Upper nibble
    }
    
    // Compare
    float max_error = 0.0f;
    int error_idx = -1;
    for (int i = 0; i < 32; i++) {
        float error = std::abs(ref_output[i] - avx_reordered[i]);
        if (error > max_error) {
            max_error = error;
            error_idx = i;
        }
    }
    
    printf("  Scale: %.4f\n", block.scale);
    printf("  Max error: %.6f at index %d\n", max_error, error_idx);
    
    // Print first few values for debugging
    printf("  First 8 values:\n");
    for (int i = 0; i < 8; i++) {
        printf("    [%2d] Ref: %8.4f, AVX: %8.4f, Diff: %8.4f\n", 
               i, ref_output[i], avx_reordered[i], std::abs(ref_output[i] - avx_reordered[i]));
    }
    printf("  ...\n");
    printf("  Last 8 values:\n");
    for (int i = 24; i < 32; i++) {
        printf("    [%2d] Ref: %8.4f, AVX: %8.4f, Diff: %8.4f\n", 
               i, ref_output[i], avx_reordered[i], std::abs(ref_output[i] - avx_reordered[i]));
    }
    
    bool pass = (max_error < 0.001f);
    printf("  [%s] Correctness check\n", pass ? "PASS" : "FAIL");
    
    return pass;
}

// ============================================================================
// Test B: Performance Benchmark
// ============================================================================
bool TestPerformance() {
    printf("\n=== Test B: Dequant Performance ===\n");
    
    constexpr int NUM_BLOCKS = 10000;
    constexpr int ITERATIONS = 100;
    
    // Create test data
    std::vector<Q4_0_Block> blocks(NUM_BLOCKS);
    for (int i = 0; i < NUM_BLOCKS; i++) {
        blocks[i].scale = 0.01f + (i % 100) * 0.001f;
        for (int j = 0; j < 16; j++) {
            blocks[i].weights[j] = static_cast<uint8_t>((i + j) % 256);
        }
    }
    
    std::vector<float> output(NUM_BLOCKS * 32);
    
    // Benchmark scalar
    auto start_scalar = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < ITERATIONS; iter++) {
        for (int i = 0; i < NUM_BLOCKS; i++) {
            ReferenceDequant(&blocks[i], &output[i * 32]);
        }
    }
    auto end_scalar = std::chrono::high_resolution_clock::now();
    auto scalar_us = std::chrono::duration_cast<std::chrono::microseconds>(end_scalar - start_scalar).count();
    
    // Benchmark AVX-512
    auto start_avx = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < ITERATIONS; iter++) {
        for (int i = 0; i < NUM_BLOCKS; i++) {
            Q4_0_Dequant_AVX512(&blocks[i], &output[i * 32]);
        }
    }
    auto end_avx = std::chrono::high_resolution_clock::now();
    auto avx_us = std::chrono::duration_cast<std::chrono::microseconds>(end_avx - start_avx).count();
    
    float scalar_ms = scalar_us / 1000.0f;
    float avx_ms = avx_us / 1000.0f;
    float speedup = scalar_ms / avx_ms;
    float throughput_scalar = (NUM_BLOCKS * ITERATIONS * 32) / scalar_ms;
    float throughput_avx = (NUM_BLOCKS * ITERATIONS * 32) / avx_ms;
    
    printf("  Blocks: %d, Iterations: %d\n", NUM_BLOCKS, ITERATIONS);
    printf("  Scalar:   %.2f ms (%.2f weights/ms)\n", scalar_ms, throughput_scalar);
    printf("  AVX-512:  %.2f ms (%.2f weights/ms)\n", avx_ms, throughput_avx);
    printf("  Speedup:  %.2fx\n", speedup);
    
    bool pass = (speedup > 2.0f);  // Expect at least 2x speedup
    printf("  [%s] Performance check\n", pass ? "PASS" : "FAIL");
    
    return pass;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=============================================================================\n");
    printf("Q4_0 Dequantization Microbenchmark\n");
    printf("=============================================================================\n");
    printf("\nThis benchmark validates:\n");
    printf("  1. Correctness of AVX-512 nibble extraction\n");
    printf("  2. Performance gain over scalar\n");
    printf("\nTarget: 5-10x speedup for dequant stage\n");
    printf("=============================================================================\n");
    
    bool all_pass = true;
    all_pass &= TestCorrectness();
    all_pass &= TestPerformance();
    
    printf("\n=============================================================================\n");
    printf("SUMMARY: %s\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("=============================================================================\n");
    
    return all_pass ? 0 : 1;
}
