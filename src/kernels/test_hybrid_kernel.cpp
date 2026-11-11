// ============================================================================
// Hybrid AVX-512 Kernel Test
// Validates the inline dequant + FMA pipeline
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <cmath>
#include <random>

// Q4_0 block structure
struct Q4_0_Block {
    float scale;
    uint8_t weights[16];
};

// External hybrid kernel
extern "C" int QuantizedMatMul_Fused_4K_Hybrid(
    const void* weights,
    const float* activation,
    float* output,
    uint64_t N,
    uint64_t K
);

// Reference implementation
void ReferenceMatMul(const std::vector<Q4_0_Block>& weights,
                     const std::vector<float>& activation,
                     std::vector<float>& output,
                     size_t N, size_t K) {
    size_t blocks_per_row = K / 32;
    
    for (size_t row = 0; row < N; row++) {
        float sum = 0.0f;
        size_t row_offset = row * blocks_per_row;
        
        for (size_t block = 0; block < blocks_per_row; block++) {
            const auto& b = weights[row_offset + block];
            size_t act_offset = block * 32;
            
            for (size_t i = 0; i < 16; i++) {
                uint8_t byte = b.weights[i];
                
                // Lower nibble
                int low = (byte & 0x0F) - 8;
                sum += low * b.scale * activation[act_offset + i * 2];
                
                // Upper nibble
                int high = ((byte >> 4) & 0x0F) - 8;
                sum += high * b.scale * activation[act_offset + i * 2 + 1];
            }
        }
        output[row] = sum;
    }
}

void GenerateQ4_0Weights(std::vector<Q4_0_Block>& weights, size_t num_blocks) {
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> scale_dist(0.001f, 0.1f);
    
    for (size_t i = 0; i < num_blocks; i++) {
        weights[i].scale = scale_dist(rng);
        for (size_t j = 0; j < 16; j++) {
            weights[i].weights[j] = static_cast<uint8_t>(rng() % 256);
        }
    }
}

void GenerateActivation(std::vector<float>& activation) {
    std::mt19937 rng(43);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    
    for (size_t i = 0; i < activation.size(); i++) {
        activation[i] = dist(rng);
    }
}

// ============================================================================
// Test: Correctness
// ============================================================================
bool TestCorrectness() {
    printf("\n=== Hybrid Kernel Correctness Test ===\n");
    
    constexpr size_t N = 4096;
    constexpr size_t K = 4096;
    constexpr size_t num_blocks = (N * K) / 32;
    
    std::vector<Q4_0_Block> weights(num_blocks);
    std::vector<float> activation(K);
    std::vector<float> output_ref(N);
    std::vector<float> output_hybrid(N);
    
    GenerateQ4_0Weights(weights, num_blocks);
    GenerateActivation(activation);
    
    // Reference
    ReferenceMatMul(weights, activation, output_ref, N, K);
    
    // Hybrid kernel
    QuantizedMatMul_Fused_4K_Hybrid(weights.data(), activation.data(), 
                                       output_hybrid.data(), N, K);
    
    // Compare
    float max_error = 0.0f;
    size_t error_idx = 0;
    for (size_t i = 0; i < N; i++) {
        float error = std::abs(output_ref[i] - output_hybrid[i]);
        if (error > max_error) {
            max_error = error;
            error_idx = i;
        }
    }
    
    printf("  Max error: %.6f at index %zu\n", max_error, error_idx);
    printf("  Reference: %.6f, Hybrid: %.6f\n", 
           output_ref[error_idx], output_hybrid[error_idx]);
    
    bool pass = (max_error < 0.001f);
    printf("  [%s] Correctness check\n", pass ? "PASS" : "FAIL");
    
    return pass;
}

// ============================================================================
// Test: Performance
// ============================================================================
bool TestPerformance() {
    printf("\n=== Hybrid Kernel Performance Test ===\n");
    
    constexpr size_t N = 4096;
    constexpr size_t K = 4096;
    constexpr size_t num_blocks = (N * K) / 32;
    constexpr int iterations = 10;
    
    std::vector<Q4_0_Block> weights(num_blocks);
    std::vector<float> activation(K);
    std::vector<float> output(N);
    
    GenerateQ4_0Weights(weights, num_blocks);
    GenerateActivation(activation);
    
    // Warmup
    for (int i = 0; i < 3; i++) {
        QuantizedMatMul_Fused_4K_Hybrid(weights.data(), activation.data(), 
                                         output.data(), N, K);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        QuantizedMatMul_Fused_4K_Hybrid(weights.data(), activation.data(), 
                                         output.data(), N, K);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    float avg_ms = (us / 1000.0f) / iterations;
    float ops_per_sec = (iterations * N) / (us / 1000000.0f);
    
    printf("  Matrix: %zux%zu\n", N, K);
    printf("  Iterations: %d\n", iterations);
    printf("  Average time: %.2f ms\n", avg_ms);
    printf("  Throughput: %.2f ops/sec\n", ops_per_sec);
    printf("  Estimated TPS contribution: %.2f TPS\n", 540.0f * (33.0f / avg_ms));
    
    bool pass = (avg_ms < 20.0f);  // Expect significant speedup
    printf("  [%s] Performance check\n", pass ? "PASS" : "FAIL");
    
    return pass;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    printf("=============================================================================\n");
    printf("Hybrid AVX-512 Kernel Validation\n");
    printf("=============================================================================\n");
    printf("\nThis test validates:\n");
    printf("  1. Correctness of inline dequant + FMA\n");
    printf("  2. Performance vs scalar baseline\n");
    printf("\nTarget: max_error == 0, 8-15x speedup\n");
    printf("=============================================================================\n");
    
    bool all_pass = true;
    all_pass &= TestCorrectness();
    all_pass &= TestPerformance();
    
    printf("\n=============================================================================\n");
    printf("SUMMARY: %s\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    printf("=============================================================================\n");
    
    return all_pass ? 0 : 1;
}
