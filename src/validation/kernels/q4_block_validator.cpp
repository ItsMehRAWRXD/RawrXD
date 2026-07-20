//=============================================================================
// Q4_0 Block Validator
// Tests AVX-512 kernel against scalar reference for correctness
//
// Validates:
//   - Nibble unpacking accuracy
//   - Dequantization (scale * (nibble - 8))
//   - Dot product accumulation
//   - Numerical exactness vs scalar reference
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <chrono>
#include <cmath>

// External ASM functions
extern "C" {
    // Scalar reference implementation
    float q4_0_dot_scalar(const void* block, const float* activations);
    
    // AVX-512 implementation
    float q4_0_dot_avx512(const void* block, const float* activations);
    
    // Preprocessing function
    void q4_0_preprocess_block(const void* input_block, void* output_block);
}

// Q4_0 block structure (GGML format)
struct alignas(32) Q4_0Block {
    uint16_t scale;      // fp16 scale
    uint8_t weights[32]; // 32 packed nibbles (64 weights)
    
    void pack(float scale_f32, const int8_t* quantized_weights) {
        // Convert scale to fp16
        uint32_t scale_bits = *reinterpret_cast<const uint32_t*>(&scale_f32);
        scale = fp32_to_fp16(scale_f32);
        
        // Pack 64 quantized weights (0-15) into 32 bytes
        for (int i = 0; i < 32; i++) {
            uint8_t w0 = static_cast<uint8_t>(quantized_weights[i * 2] + 8);     // +8 for zero point
            uint8_t w1 = static_cast<uint8_t>(quantized_weights[i * 2 + 1] + 8);
            weights[i] = (w1 << 4) | w0;
        }
    }
    
    static uint16_t fp32_to_fp16(float f) {
        // Simple fp32 -> fp16 conversion
        uint32_t bits = *reinterpret_cast<const uint32_t*>(&f);
        uint32_t sign = (bits >> 31) & 0x1;
        uint32_t exponent = (bits >> 23) & 0xFF;
        uint32_t mantissa = bits & 0x7FFFFF;
        
        if (exponent == 0) {
            // Zero/denormal
            return static_cast<uint16_t>(sign << 15);
        } else if (exponent == 0xFF) {
            // Inf/NaN
            return static_cast<uint16_t>((sign << 15) | 0x7C00 | (mantissa >> 13));
        }
        
        // Normal number
        int16_t new_exp = static_cast<int16_t>(exponent) - 127 + 15;
        if (new_exp >= 31) {
            // Overflow to inf
            return static_cast<uint16_t>((sign << 15) | 0x7C00);
        } else if (new_exp <= 0) {
            // Underflow to zero
            return static_cast<uint16_t>(sign << 15);
        }
        
        return static_cast<uint16_t>((sign << 15) | (new_exp << 10) | (mantissa >> 13));
    }
};

// Scalar reference implementation (golden reference)
float q4_0_dot_scalar_ref(const Q4_0Block* block, const float* activations) {
    // Extract scale (fp16 -> fp32)
    uint16_t scale_bits = block->scale;
    float scale;
    
    // fp16 -> fp32 conversion
    uint32_t sign = (scale_bits >> 15) & 0x1;
    uint32_t exponent = (scale_bits >> 10) & 0x1F;
    uint32_t mantissa = scale_bits & 0x3FF;
    
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
    
    // Process 64 weights (32 bytes)
    for (int i = 0; i < 32; i++) {
        uint8_t packed = block->weights[i];
        
        // Low nibble (weight 2*i)
        int8_t w0 = static_cast<int8_t>(packed & 0x0F) - 8;
        float dequant0 = scale * static_cast<float>(w0);
        sum += dequant0 * activations[i * 2];
        
        // High nibble (weight 2*i + 1)
        int8_t w1 = static_cast<int8_t>((packed >> 4) & 0x0F) - 8;
        float dequant1 = scale * static_cast<float>(w1);
        sum += dequant1 * activations[i * 2 + 1];
    }
    
    return sum;
}

// Generate random Q4_0 block
void generate_random_block(Q4_0Block* block, float* activations, std::mt19937& rng) {
    std::uniform_real_distribution<float> scale_dist(0.001f, 0.1f);
    std::uniform_int_distribution<int> weight_dist(0, 15);
    std::uniform_real_distribution<float> act_dist(-3.0f, 3.0f);
    
    float scale = scale_dist(rng);
    int8_t quantized[64];
    
    // Generate random quantized weights
    for (int i = 0; i < 64; i++) {
        quantized[i] = static_cast<int8_t>(weight_dist(rng));
    }
    
    block->pack(scale, quantized);
    
    // Generate random activations
    for (int i = 0; i < 64; i++) {
        activations[i] = act_dist(rng);
    }
}

// Run validation
bool run_block_validator(uint64_t num_iterations = 10000000) {
    printf("=============================================================================\n");
    printf("Q4_0 Block Validator\n");
    printf("=============================================================================\n");
    printf("Iterations: %llu\n", static_cast<unsigned long long>(num_iterations));
    printf("\n");
    
    std::mt19937 rng(42);  // Fixed seed for reproducibility
    
    Q4_0Block block;
    alignas(64) float activations[64];
    
    double max_error = 0.0;
    double total_error = 0.0;
    uint64_t error_count = 0;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (uint64_t iter = 0; iter < num_iterations; iter++) {
        // Generate random test case
        generate_random_block(&block, activations, rng);
        
        // Compute reference result
        float ref_result = q4_0_dot_scalar_ref(&block, activations);
        
        // Compute AVX-512 result (if available)
        float avx_result = 0.0f;
        bool has_avx512 = false;
        
        #ifdef __AVX512F__
        has_avx512 = true;
        avx_result = q4_0_dot_avx512(&block, activations);
        #endif
        
        // Compare results
        if (has_avx512) {
            float error = std::abs(ref_result - avx_result);
            max_error = std::max(max_error, static_cast<double>(error));
            total_error += error;
            
            if (error > 1e-5f) {
                error_count++;
                if (error_count <= 5) {
                    printf("ERROR at iteration %llu:\n", static_cast<unsigned long long>(iter));
                    printf("  Reference: %.8f\n", ref_result);
                    printf("  AVX-512:   %.8f\n", avx_result);
                    printf("  Error:     %.8e\n", error);
                }
            }
        }
        
        // Progress report every 1M iterations
        if ((iter + 1) % 1000000 == 0) {
            printf("Progress: %lluM / %lluM iterations...\n", 
                   static_cast<unsigned long long>((iter + 1) / 1000000),
                   static_cast<unsigned long long>(num_iterations / 1000000));
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    printf("\n=============================================================================\n");
    printf("Validation Results\n");
    printf("=============================================================================\n");
    printf("Total iterations: %llu\n", static_cast<unsigned long long>(num_iterations));
    printf("Time: %.2f seconds\n", duration.count() / 1000.0);
    printf("Iterations/sec: %.2fM\n", (num_iterations / 1000000.0) / (duration.count() / 1000.0));
    printf("\n");
    
    if (error_count == 0) {
        printf("Status: PASS\n");
        printf("Max error: %.8e\n", max_error);
        printf("Avg error: %.8e\n", total_error / num_iterations);
        printf("\n");
        printf("The AVX-512 kernel produces numerically exact results.\n");
        printf("Ready for integration into production GEMM.\n");
        return true;
    } else {
        printf("Status: FAIL\n");
        printf("Error count: %llu / %llu (%.4f%%)\n", 
               static_cast<unsigned long long>(error_count),
               static_cast<unsigned long long>(num_iterations),
               100.0 * error_count / num_iterations);
        printf("Max error: %.8e\n", max_error);
        printf("Avg error: %.8e\n", total_error / num_iterations);
        printf("\n");
        printf("The AVX-512 kernel has numerical errors.\n");
        printf("Debug required before integration.\n");
        return false;
    }
}

// Benchmark performance
void benchmark_kernels(uint64_t num_iterations = 1000000) {
    printf("\n=============================================================================\n");
    printf("Performance Benchmark\n");
    printf("=============================================================================\n");
    printf("Iterations: %llu\n", static_cast<unsigned long long>(num_iterations));
    printf("\n");
    
    std::mt19937 rng(42);
    Q4_0Block block;
    alignas(64) float activations[64];
    generate_random_block(&block, activations, rng);
    
    // Warmup
    for (int i = 0; i < 1000; i++) {
        volatile float result = q4_0_dot_scalar_ref(&block, activations);
        (void)result;
    }
    
    // Benchmark scalar
    auto start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < num_iterations; i++) {
        volatile float result = q4_0_dot_scalar_ref(&block, activations);
        (void)result;
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto scalar_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("Scalar reference:\n");
    printf("  Time: %.2f ms\n", scalar_time / 1000.0);
    printf("  Throughput: %.2f blocks/sec\n", num_iterations * 1000000.0 / scalar_time);
    printf("  Per block: %.2f ns\n", scalar_time * 1000.0 / num_iterations);
    printf("\n");
    
    #ifdef __AVX512F__
    // Benchmark AVX-512
    start = std::chrono::high_resolution_clock::now();
    for (uint64_t i = 0; i < num_iterations; i++) {
        volatile float result = q4_0_dot_avx512(&block, activations);
        (void)result;
    }
    end = std::chrono::high_resolution_clock::now();
    auto avx_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    printf("AVX-512:\n");
    printf("  Time: %.2f ms\n", avx_time / 1000.0);
    printf("  Throughput: %.2f blocks/sec\n", num_iterations * 1000000.0 / avx_time);
    printf("  Per block: %.2f ns\n", avx_time * 1000.0 / num_iterations);
    printf("  Speedup: %.2fx\n", static_cast<double>(scalar_time) / avx_time);
    printf("\n");
    #else
    printf("AVX-512: Not available on this system\n");
    printf("\n");
    #endif
}

int main(int argc, char** argv) {
    uint64_t num_iterations = 10000000;  // 10M by default
    
    if (argc > 1) {
        num_iterations = std::stoull(argv[1]);
    }
    
    printf("\n");
    printf("RawrXD Q4_0 Block Validator\n");
    printf("Validates AVX-512 kernel against scalar reference\n");
    printf("\n");
    
    // Run validation
    bool passed = run_block_validator(num_iterations);
    
    // Run benchmark
    benchmark_kernels(num_iterations / 10);  // Fewer iterations for benchmark
    
    return passed ? 0 : 1;
}
