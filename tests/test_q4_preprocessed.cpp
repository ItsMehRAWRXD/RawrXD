//=============================================================================
// Q4_0 Preprocessed Weight Test Suite
// Validates preprocessing correctness and benchmarks performance
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include <cmath>
#include <vector>
#include "../src/memory/Q4WeightPreprocess.hpp"

using namespace RawrXD::Memory;

// External ASM functions
extern "C" {
    float q4_preprocessed_dot_avx512_asm(
        const PreprocessedQ4Block* block,
        const float* activations
    );
}

// Reference scalar implementation
float q4_dot_scalar_ref(const PreprocessedQ4Block* block, const float* activations) {
    float scale = Q4WeightPreprocessor::ExtractScale(block);
    float sum = 0.0f;
    
    for (int i = 0; i < 64; i++) {
        float weight = static_cast<float>(block->weights[i]) * scale;
        sum += weight * activations[i];
    }
    
    return sum;
}

// Generate random test data
void generate_test_data(
    PreprocessedQ4Block* block,
    float* activations,
    std::mt19937& rng
) {
    std::uniform_int_distribution<int> weight_dist(-8, 7);
    std::uniform_real_distribution<float> act_dist(-3.0f, 3.0f);
    
    // Generate random weights
    for (int i = 0; i < 64; i++) {
        block->weights[i] = static_cast<int8_t>(weight_dist(rng));
    }
    
    // Set scale (fixed for simplicity)
    uint16_t scale_fp16 = 0x2E66;  // ~0.1 in fp16
    std::memcpy(&block->scale, &scale_fp16, 2);
    
    // Generate random activations
    for (int i = 0; i < 64; i++) {
        activations[i] = act_dist(rng);
    }
}

// Validation test
bool run_validation(uint64_t num_iterations = 1000000) {
    printf("=============================================================================\n");
    printf("Q4_0 Preprocessed Weight Validation\n");
    printf("=============================================================================\n");
    printf("Iterations: %llu\n\n", static_cast<unsigned long long>(num_iterations));
    
    std::mt19937 rng(42);
    PreprocessedQ4Block block;
    alignas(64) float activations[64];
    
    double max_error = 0.0;
    uint64_t error_count = 0;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint64_t i = 0; i < num_iterations; i++) {
        generate_test_data(&block, activations, rng);
        
        float ref = q4_dot_scalar_ref(&block, activations);
        float avx = q4_preprocessed_dot_avx512_asm(&block, activations);
        
        float error = std::abs(ref - avx);
        max_error = std::max(max_error, static_cast<double>(error));
        
        if (error > 1e-5f) {
            error_count++;
            if (error_count <= 3) {
                printf("Error at iter %llu: ref=%.8f avx=%.8f err=%.8e\n",
                       static_cast<unsigned long long>(i), ref, avx, error);
            }
        }
        
        if ((i + 1) % 100000 == 0) {
            printf("Progress: %lluK / %lluK...\n",
                   static_cast<unsigned long long>((i + 1) / 1000),
                   static_cast<unsigned long long>(num_iterations / 1000));
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    printf("\n=============================================================================\n");
    printf("Results:\n");
    printf("  Time: %.2f seconds\n", duration.count() / 1000.0);
    printf("  Max error: %.8e\n", max_error);
    printf("  Error count: %llu / %llu\n",
           static_cast<unsigned long long>(error_count),
           static_cast<unsigned long long>(num_iterations));
    printf("  Status: %s\n", error_count == 0 ? "PASS" : "FAIL");
    printf("=============================================================================\n\n");
    
    return error_count == 0;
}

// Performance benchmark
void benchmark_performance(uint64_t num_iterations = 1000000) {
    printf("=============================================================================\n");
    printf("Performance Benchmark\n");
    printf("=============================================================================\n");
    printf("Iterations: %llu\n\n", static_cast<unsigned long long>(num_iterations));
    
    std::mt19937 rng(42);
    PreprocessedQ4Block block;
    alignas(64) float activations[64];
    generate_test_data(&block, activations, rng);
    
    // Warmup
    for (int i = 0; i < 10000; i++) {
        volatile float r = q4_dot_scalar_ref(&block, activations);
        (void)r;
    }
    
    // Benchmark scalar
    auto start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < num_iterations; i++) {
        volatile float r = q4_dot_scalar_ref(&block, activations);
        (void)r;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto scalar_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("Scalar reference:\n");
    printf("  Time: %.2f ms\n", scalar_us / 1000.0);
    printf("  Per block: %.2f ns\n", scalar_us * 1000.0 / num_iterations);
    printf("  Throughput: %.2fM blocks/sec\n", num_iterations / static_cast<double>(scalar_us));
    printf("\n");
    
    // Warmup AVX-512
    for (int i = 0; i < 10000; i++) {
        volatile float r = q4_preprocessed_dot_avx512_asm(&block, activations);
        (void)r;
    }
    
    // Benchmark AVX-512
    start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < num_iterations; i++) {
        volatile float r = q4_preprocessed_dot_avx512_asm(&block, activations);
        (void)r;
    }
    end = std::chrono::high_resolution_clock::now();
    auto avx_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("AVX-512 (preprocessed):\n");
    printf("  Time: %.2f ms\n", avx_us / 1000.0);
    printf("  Per block: %.2f ns\n", avx_us * 1000.0 / num_iterations);
    printf("  Throughput: %.2fM blocks/sec\n", num_iterations / static_cast<double>(avx_us));
    printf("  Speedup: %.2fx\n", static_cast<double>(scalar_us) / avx_us);
    printf("\n");
    
    // Calculate estimated GEMM performance
    double blocks_per_sec = num_iterations / (avx_us / 1000000.0);
    double ops_per_block = 64 * 2;  // 64 mul-adds
    double gops = blocks_per_sec * ops_per_block / 1e9;
    
    printf("Estimated GEMM performance:\n");
    printf("  %.2f GOP/s per core\n", gops);
    printf("  ~%.0f tokens/sec for 4K dim matmul\n", blocks_per_sec / 64);
    printf("=============================================================================\n\n");
}

// Test preprocessing
void test_preprocessing() {
    printf("=============================================================================\n");
    printf("Preprocessing Test\n");
    printf("=============================================================================\n\n");
    
    // Create a GGUF-style block
    struct GGUFBlock {
        uint16_t scale;
        uint8_t weights[32];
    } gguf_block;
    
    // Fill with test data
    gguf_block.scale = 0x2E66;  // ~0.1
    for (int i = 0; i < 32; i++) {
        // Pack two weights per byte: low nibble = i*2, high nibble = i*2+1
        int8_t w0 = (i * 2) % 16 - 8;      // -8 to +7
        int8_t w1 = (i * 2 + 1) % 16 - 8;
        gguf_block.weights[i] = ((w1 + 8) << 4) | (w0 + 8);
    }
    
    // Preprocess
    PreprocessedQ4Block preproc;
    Q4WeightPreprocessor::PreprocessBlock(&gguf_block, &preproc);
    
    // Validate
    bool valid = Q4WeightPreprocessor::ValidateBlock(&gguf_block, &preproc);
    printf("Preprocessing validation: %s\n\n", valid ? "PASS" : "FAIL");
    
    // Print first few weights
    printf("First 8 unpacked weights:\n");
    for (int i = 0; i < 8; i++) {
        printf("  w[%d] = %d\n", i, preproc.weights[i]);
    }
    printf("\n");
    
    // Test scale extraction
    float scale = Q4WeightPreprocessor::ExtractScale(&preproc);
    printf("Extracted scale: %.6f\n", scale);
    printf("=============================================================================\n\n");
}

int main(int argc, char** argv) {
    printf("\n");
    printf("RawrXD Q4_0 Preprocessed Weight Test Suite\n");
    printf("=========================================\n\n");
    
    uint64_t iterations = 1000000;
    if (argc > 1) {
        iterations = std::stoull(argv[1]);
    }
    
    // Test preprocessing
    test_preprocessing();
    
    // Run validation
    bool passed = run_validation(iterations);
    
    // Run benchmark
    benchmark_performance(iterations / 10);
    
    return passed ? 0 : 1;
}
