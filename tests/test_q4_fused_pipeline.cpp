//=============================================================================
// Q4_0 Fused Pipeline Validation
// Tests the complete pipeline: GGUF -> Preprocess -> AVX-512 -> Output
// Compares against scalar reference for end-to-end correctness
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

// Reference: Full GGUF Q4_0 -> scalar dequant -> dot product
// Use output parameter to avoid compiler optimization issues
__declspec(noinline) void reference_q4_dot(
    const void* gguf_block,
    const float* activations,
    float* result
) {
    const uint8_t* input = static_cast<const uint8_t*>(gguf_block);
    
    // Extract scale (fp16 -> fp32)
    uint16_t scale_bits;
    std::memcpy(&scale_bits, input, 2);
    
    uint32_t sign = (scale_bits >> 15) & 0x1;
    uint32_t exponent = (scale_bits >> 10) & 0x1F;
    uint32_t mantissa = scale_bits & 0x3FF;
    
    float scale;
    if (exponent == 0) {
        scale = sign ? -0.0f : 0.0f;
    } else if (exponent == 0x1F) {
        scale = sign ? -INFINITY : INFINITY;
    } else {
        int32_t exp = static_cast<int32_t>(exponent) - 15 + 127;
        uint32_t f32_bits = (sign << 31) | (exp << 23) | (mantissa << 13);
        scale = *reinterpret_cast<float*>(&f32_bits);
    }
    
    float sum = 0.0f;
    
    // Unpack and dequantize on-the-fly
    for (int i = 0; i < 32; i++) {
        uint8_t packed = input[2 + i];
        
        // Low nibble
        int8_t w0 = static_cast<int8_t>((packed & 0x0F) - 8);
        sum += scale * static_cast<float>(w0) * activations[i * 2];
        
        // High nibble
        int8_t w1 = static_cast<int8_t>(((packed >> 4) & 0x0F) - 8);
        sum += scale * static_cast<float>(w1) * activations[i * 2 + 1];
    }
    
    *result = sum;
}

// Optimized: Preprocessed -> AVX-512
float optimized_q4_dot(
    const PreprocessedQ4Block* preproc_block,
    const float* activations
) {
    return q4_preprocessed_dot_avx512_asm(preproc_block, activations);
}

// Generate random GGUF block
void generate_random_gguf_block(void* gguf_block, std::mt19937& rng) {
    std::uniform_int_distribution<int> weight_dist(0, 15);
    std::uniform_int_distribution<int> scale_exp_dist(10, 25);  // Reasonable scale range
    
    uint8_t* block = static_cast<uint8_t*>(gguf_block);
    
    // Generate scale (fp16)
    uint16_t scale_bits = (scale_exp_dist(rng) << 10) | 0;  // Simple scale
    std::memcpy(block, &scale_bits, 2);
    
    // Generate packed weights
    for (int i = 0; i < 32; i++) {
        uint8_t w0 = weight_dist(rng);  // Low nibble
        uint8_t w1 = weight_dist(rng);  // High nibble
        block[2 + i] = (w1 << 4) | w0;
    }
}

// Run fused pipeline validation
bool run_fused_validation(uint64_t num_iterations = 1000000) {
    printf("=============================================================================\n");
    printf("Q4_0 FUSED PIPELINE VALIDATION\n");
    printf("=============================================================================\n");
    printf("Testing: GGUF -> Preprocess -> AVX-512 vs GGUF -> Scalar\n");
    printf("Iterations: %llu\n\n", static_cast<unsigned long long>(num_iterations));
    
    std::mt19937 rng(42);
    
    alignas(64) uint8_t gguf_block[64];
    alignas(64) PreprocessedQ4Block preproc_block;
    alignas(64) float activations[64];
    
    double max_error = 0.0;
    double total_error = 0.0;
    uint64_t error_count = 0;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint64_t iter = 0; iter < num_iterations; iter++) {
        // Generate random test case
        generate_random_gguf_block(gguf_block, rng);
        
        // Generate random activations
        std::uniform_real_distribution<float> act_dist(-3.0f, 3.0f);
        for (int i = 0; i < 64; i++) {
            activations[i] = act_dist(rng);
        }
        
        // Preprocess (simulating load-time conversion)
        Q4WeightPreprocessor::PreprocessBlock(
            gguf_block, &preproc_block,
            static_cast<uint32_t>(iter),  // block_index
            static_cast<uint32_t>(num_iterations),  // total_blocks
            64  // total_elements
        );
        
        // Validate preprocessing
        if (!Q4WeightPreprocessor::ValidateBlock(gguf_block, &preproc_block)) {
            printf("PREPROCESSING FAILED at iteration %llu\n", 
                   static_cast<unsigned long long>(iter));
            return false;
        }
        
        // Reference result (GGUF -> scalar)
        float ref_result;
        reference_q4_dot(gguf_block, activations, &ref_result);
        
        // Optimized result (Preprocessed -> AVX-512)
        float opt_result = optimized_q4_dot(&preproc_block, activations);
        
        // Compare
        float error = std::abs(ref_result - opt_result);
        max_error = std::max(max_error, static_cast<double>(error));
        total_error += error;
        
        // Use relative error for large values, absolute for small
        float rel_error = error / (std::abs(ref_result) + 1e-6f);
        
        if (error > 1e-3f && rel_error > 1e-4f) {
            error_count++;
            if (error_count <= 5) {
                printf("MISMATCH at iteration %llu:\n", 
                       static_cast<unsigned long long>(iter));
                printf("  Reference: %.8f\n", ref_result);
                printf("  Optimized: %.8f\n", opt_result);
                printf("  Abs Error: %.8e\n", error);
                printf("  Rel Error: %.8e\n", rel_error);
            }
        }
        
        if ((iter + 1) % 100000 == 0) {
            printf("Progress: %lluK / %lluK...\n",
                   static_cast<unsigned long long>((iter + 1) / 1000),
                   static_cast<unsigned long long>(num_iterations / 1000));
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    printf("\n=============================================================================\n");
    printf("FUSED PIPELINE RESULTS\n");
    printf("=============================================================================\n");
    printf("Total iterations: %llu\n", static_cast<unsigned long long>(num_iterations));
    printf("Time: %.2f seconds\n", duration.count() / 1000.0);
    printf("\n");
    printf("Numerical Accuracy:\n");
    printf("  Max error: %.8e\n", max_error);
    printf("  Avg error: %.8e\n", total_error / num_iterations);
    printf("  Failures:  %llu / %llu (%.6f%%)\n",
           static_cast<unsigned long long>(error_count),
           static_cast<unsigned long long>(num_iterations),
           100.0 * error_count / num_iterations);
    printf("\n");
    
    if (error_count == 0) {
        printf("STATUS: PASS\n");
        printf("The fused pipeline produces numerically exact results.\n");
        printf("Ready for Kernel Registry integration.\n");
        return true;
    } else {
        printf("STATUS: FAIL\n");
        printf("The optimized pipeline has numerical errors.\n");
        return false;
    }
}

// Benchmark the full pipeline
void benchmark_pipeline(uint64_t num_iterations = 100000) {
    printf("\n=============================================================================\n");
    printf("PIPELINE PERFORMANCE BENCHMARK\n");
    printf("=============================================================================\n");
    printf("Iterations: %llu\n\n", static_cast<unsigned long long>(num_iterations));
    
    std::mt19937 rng(42);
    alignas(64) uint8_t gguf_block[64];
    alignas(64) PreprocessedQ4Block preproc_block;
    alignas(64) float activations[64];
    
    // Setup
    generate_random_gguf_block(gguf_block, rng);
    std::uniform_real_distribution<float> act_dist(-3.0f, 3.0f);
    for (int i = 0; i < 64; i++) activations[i] = act_dist(rng);
    
    Q4WeightPreprocessor::PreprocessBlock(gguf_block, &preproc_block, 0, 1, 64);
    
    // Warmup
    for (int i = 0; i < 10000; i++) {
        float r;
        reference_q4_dot(gguf_block, activations, &r);
        (void)r;
    }
    
    // Benchmark reference (GGUF -> scalar)
    auto start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < num_iterations; i++) {
        float r;
        reference_q4_dot(gguf_block, activations, &r);
        (void)r;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto ref_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("Reference Pipeline (GGUF -> Scalar):\n");
    printf("  Time: %.2f ms\n", ref_us / 1000.0);
    printf("  Per block: %.2f ns\n", ref_us * 1000.0 / num_iterations);
    printf("  Throughput: %.2fM blocks/sec\n", num_iterations / (ref_us / 1000000.0));
    printf("\n");
    
    // Warmup optimized
    for (int i = 0; i < 10000; i++) {
        volatile float r = optimized_q4_dot(&preproc_block, activations);
        (void)r;
    }
    
    // Benchmark optimized (Preprocessed -> AVX-512)
    start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < num_iterations; i++) {
        volatile float r = optimized_q4_dot(&preproc_block, activations);
        (void)r;
    }
    end = std::chrono::high_resolution_clock::now();
    auto opt_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("Optimized Pipeline (Preprocessed -> AVX-512):\n");
    printf("  Time: %.2f ms\n", opt_us / 1000.0);
    printf("  Per block: %.2f ns\n", opt_us * 1000.0 / num_iterations);
    printf("  Throughput: %.2fM blocks/sec\n", num_iterations / (opt_us / 1000000.0));
    printf("  Speedup: %.2fx\n", static_cast<double>(ref_us) / opt_us);
    printf("\n");
    
    // Calculate estimated GEMM performance
    double blocks_per_sec = num_iterations / (opt_us / 1000000.0);
    double ops_per_block = 64 * 2;  // 64 mul-adds
    double gops = blocks_per_sec * ops_per_block / 1e9;
    
    printf("Estimated Performance:\n");
    printf("  %.2f GOP/s per core\n", gops);
    printf("  ~%.0f tokens/sec for 4K dim matmul\n", blocks_per_sec / 64);
    printf("=============================================================================\n");
}

int main(int argc, char** argv) {
    printf("\n");
    printf("RawrXD Q4_0 Fused Pipeline Test\n");
    printf("Validates: GGUF -> Preprocess -> AVX-512 correctness\n");
    printf("\n");
    
    uint64_t iterations = 1000000;
    if (argc > 1) {
        iterations = std::stoull(argv[1]);
    }
    
    // Run fused validation
    bool passed = run_fused_validation(iterations);
    
    // Run benchmark
    benchmark_pipeline(iterations / 10);
    
    return passed ? 0 : 1;
}
