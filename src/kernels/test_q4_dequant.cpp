/*===========================================================================
 * test_q4_dequant.cpp - Q4_0 Dequantization Microbenchmark
 * Validates vectorized nibble extraction before full matmul integration
 *===========================================================================*/

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cmath>
#include <cstring>

// Q4_0 block structure
struct Q4_0_Block {
    float scale;
    uint8_t weights[16];  // 32 weights packed as 16 bytes
};

// Scalar dequantization (reference)
void DequantScalar(const Q4_0_Block* block, float* output) {
    for (int i = 0; i < 16; i++) {
        uint8_t byte = block->weights[i];
        // Lower nibble
        output[i * 2] = ((float)(byte & 0x0F) - 8.0f) * block->scale;
        // Upper nibble
        output[i * 2 + 1] = ((float)((byte >> 4) & 0x0F) - 8.0f) * block->scale;
    }
}

// AVX-512 dequantization (vectorized)
// This will be implemented in assembly - for now, C++ placeholder
void DequantAVX512(const Q4_0_Block* block, float* output);

// Generate test data
void GenerateBlock(Q4_0_Block* block, uint32_t seed) {
    block->scale = 0.05f + (seed % 100) / 1000.0f;
    for (int i = 0; i < 16; i++) {
        block->weights[i] = (uint8_t)(seed + i * 7);
    }
}

// Validate dequantization
bool TestDequant() {
    printf("\n=== Test: Q4_0 Dequantization ===\n");
    
    Q4_0_Block block;
    GenerateBlock(&block, 42);
    
    float scalar_output[32];
    float avx_output[32];
    
    DequantScalar(&block, scalar_output);
    DequantAVX512(&block, avx_output);
    
    // Compare
    float maxError = 0.0f;
    int errorIdx = 0;
    for (int i = 0; i < 32; i++) {
        float error = std::abs(scalar_output[i] - avx_output[i]);
        if (error > maxError) {
            maxError = error;
            errorIdx = i;
        }
    }
    
    printf("Max error: %.6f at index %d\n", maxError, errorIdx);
    printf("  Scalar: %.6f\n", scalar_output[errorIdx]);
    printf("  AVX512: %.6f\n", avx_output[errorIdx]);
    
    // Show first few values
    printf("\nFirst 8 weights:\n");
    for (int i = 0; i < 8; i++) {
        printf("  [%d] scalar=%.4f avx512=%.4f\n", i, scalar_output[i], avx_output[i]);
    }
    
    bool pass = (maxError < 0.001f);
    printf("[%s] Dequantization test\n", pass ? "PASS" : "FAIL");
    return pass;
}

// Benchmark dequantization
void BenchmarkDequant() {
    printf("\n=== Benchmark: Q4_0 Dequantization ===\n");
    
    constexpr int NUM_BLOCKS = 10000;
    constexpr int ITERATIONS = 100;
    
    std::vector<Q4_0_Block> blocks(NUM_BLOCKS);
    std::vector<float> output(NUM_BLOCKS * 32);
    
    // Generate test data
    for (int i = 0; i < NUM_BLOCKS; i++) {
        GenerateBlock(&blocks[i], i);
    }
    
    // Warmup
    for (int i = 0; i < NUM_BLOCKS; i++) {
        DequantScalar(&blocks[i], &output[i * 32]);
    }
    
    // Benchmark scalar
    auto start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < ITERATIONS; iter++) {
        for (int i = 0; i < NUM_BLOCKS; i++) {
            DequantScalar(&blocks[i], &output[i * 32]);
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto scalar_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    // Benchmark AVX-512
    start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < ITERATIONS; iter++) {
        for (int i = 0; i < NUM_BLOCKS; i++) {
            DequantAVX512(&blocks[i], &output[i * 32]);
        }
    }
    end = std::chrono::high_resolution_clock::now();
    auto avx_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    float scalar_ms = scalar_us / 1000.0f;
    float avx_ms = avx_us / 1000.0f;
    float speedup = scalar_ms / avx_ms;
    
    printf("Scalar: %.2f ms (%.2f blocks/ms)\n", scalar_ms, 
           (NUM_BLOCKS * ITERATIONS) / scalar_ms);
    printf("AVX512: %.2f ms (%.2f blocks/ms)\n", avx_ms,
           (NUM_BLOCKS * ITERATIONS) / avx_ms);
    printf("Speedup: %.2fx\n", speedup);
    
    if (speedup < 2.0f) {
        printf("WARNING: AVX-512 speedup below target (2x)\n");
    }
}

int main() {
    printf("========================================================================\n");
    printf("Q4_0 Dequantization Microbenchmark\n");
    printf("========================================================================\n");
    
    bool pass = TestDequant();
    BenchmarkDequant();
    
    printf("\n========================================================================\n");
    printf("Summary: %s\n", pass ? "PASS" : "FAIL");
    printf("========================================================================\n");
    
    return pass ? 0 : 1;
}
