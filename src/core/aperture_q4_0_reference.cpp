/**
 * @file aperture_q4_0_reference.cpp
 * @brief Q4_0 Dequantization - Scalar C++ Reference Implementation
 * @version 1.0.0
 * 
 * Reference implementation for Q4_0 dequantization.
 * Used to validate MASM AVX-512 implementation.
 * 
 * Q4_0 Format:
 *   - Block size: 32 weights
 *   - Each block: 2 bytes scale (float16) + 16 bytes weights (4-bit packed)
 *   - Total: 18 bytes per 32 weights
 *   - Weight layout: 4 bits per weight, packed as 2 weights per byte
 * 
 * Dequantization formula:
 *   weight = (q - 8) * scale
 *   where q is the 4-bit quantized value (0-15)
 *   and scale is the block scale factor
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <cstdio>

// ============================================================================
// Q4_0 FORMAT CONSTANTS
// ============================================================================

static constexpr size_t Q4_0_BLOCK_SIZE = 32;        // Weights per block
static constexpr size_t Q4_0_BLOCK_BYTES = 18;     // Bytes per block (2 scale + 16 weights)
static constexpr size_t Q4_0_SCALE_BYTES = 2;      // Scale is float16
static constexpr size_t Q4_0_WEIGHT_BYTES = 16;    // 32 weights * 4 bits / 8 bits per byte

// ============================================================================
// FLOAT16 CONVERSION
// ============================================================================

/**
 * @brief Convert float16 (half precision) to float32
 * 
 * Float16 format:
 *   - Sign: 1 bit (bit 15)
 *   - Exponent: 5 bits (bits 14-10), bias 15
 *   - Mantissa: 10 bits (bits 9-0)
 * 
 * @param h Float16 value
 * @return Float32 value
 */
static inline float float16_to_float32(uint16_t h) {
    // Extract components
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exponent = (h >> 10) & 0x1F;
    uint32_t mantissa = h & 0x3FF;
    
    // Handle special cases
    if (exponent == 0) {
        // Zero or denormal
        if (mantissa == 0) {
            // Zero
            return sign ? -0.0f : 0.0f;
        }
        // Denormal: value = (-1)^sign * 2^-14 * (mantissa / 1024)
        float value = static_cast<float>(mantissa) / 1024.0f;
        return sign ? -value * 0.00006103515625f : value * 0.00006103515625f;
    } else if (exponent == 31) {
        // Infinity or NaN
        if (mantissa == 0) {
            return sign ? -INFINITY : INFINITY;
        }
        return NAN;
    }
    
    // Normal number: value = (-1)^sign * 2^(exponent-15) * (1 + mantissa/1024)
    uint32_t f32_sign = sign << 31;
    uint32_t f32_exponent = (exponent + 112) << 23;  // 127 - 15 = 112
    uint32_t f32_mantissa = mantissa << 13;         // 23 - 10 = 13
    
    union {
        uint32_t u;
        float f;
    } converter;
    converter.u = f32_sign | f32_exponent | f32_mantissa;
    return converter.f;
}

/**
 * @brief Convert float32 to float16 (for testing/validation)
 * @param f Float32 value
 * @return Float16 value
 */
static inline uint16_t float32_to_float16(float f) {
    union {
        float f;
        uint32_t u;
    } converter;
    converter.f = f;
    
    uint32_t sign = (converter.u >> 31) & 0x1;
    uint32_t exponent = (converter.u >> 23) & 0xFF;
    uint32_t mantissa = converter.u & 0x7FFFFF;
    
    // Handle special cases
    if (exponent == 0) {
        // Zero or denormal
        return sign << 15;  // Signed zero
    } else if (exponent == 255) {
        // Infinity or NaN
        return (sign << 15) | 0x7C00 | (mantissa >> 13);
    }
    
    // Normal number
    int32_t new_exp = static_cast<int32_t>(exponent) - 127 + 15;
    
    if (new_exp >= 31) {
        // Overflow to infinity
        return (sign << 15) | 0x7C00;
    } else if (new_exp <= 0) {
        // Underflow to denormal or zero
        if (new_exp < -10) {
            return sign << 15;  // Too small, return zero
        }
        // Denormal
        mantissa = (mantissa | 0x800000) >> (1 - new_exp);
        return (sign << 15) | (mantissa >> 13);
    }
    
    // Normal number
    return (sign << 15) | (new_exp << 10) | (mantissa >> 13);
}

// ============================================================================
// Q4_0 DEQUANTIZATION - REFERENCE IMPLEMENTATION
// ============================================================================

/**
 * @brief Dequantize a single Q4_0 block
 * 
 * Q4_0 block layout:
 *   Bytes 0-1:   scale (float16)
 *   Bytes 2-17:  32 weights (4 bits each, packed)
 * 
 * Weight unpacking:
 *   Each byte contains 2 weights:
 *     - Low nibble (bits 0-3): first weight
 *     - High nibble (bits 4-7): second weight
 * 
 * Dequantization:
 *   weight = (q - 8) * scale
 *   where q is the 4-bit value (0-15)
 * 
 * @param src Source block (18 bytes)
 * @param dst Destination buffer (32 floats)
 */
static void dequantize_q4_0_block(const uint8_t* __restrict src, 
                                   float* __restrict dst) {
    // Read scale (float16)
    uint16_t scale_h = *reinterpret_cast<const uint16_t*>(src);
    float scale = float16_to_float32(scale_h);
    
    // Unpack and dequantize weights
    for (size_t i = 0; i < Q4_0_BLOCK_SIZE / 2; ++i) {
        uint8_t packed = src[2 + i];  // Skip scale bytes
        
        // Extract low nibble (first weight)
        uint8_t q_low = packed & 0x0F;
        dst[i * 2] = (static_cast<float>(q_low) - 8.0f) * scale;
        
        // Extract high nibble (second weight)
        uint8_t q_high = (packed >> 4) & 0x0F;
        dst[i * 2 + 1] = (static_cast<float>(q_high) - 8.0f) * scale;
    }
}

/**
 * @brief Dequantize Q4_0 tensor to float32
 * 
 * This is the reference implementation used to validate the AVX-512 version.
 * 
 * @param src Source tensor (Q4_0 quantized)
 * @param dst Destination buffer (float32)
 * @param num_blocks Number of Q4_0 blocks to dequantize
 * @return 0 on success, -1 on error
 */
extern "C" int Aperture_Q4_0_Dequant_Reference(const uint8_t* __restrict src,
                                                  float* __restrict dst,
                                                  size_t num_blocks) {
    // Validate inputs
    if (!src || !dst || num_blocks == 0) {
        return -1;
    }
    
    // Process each block
    for (size_t block = 0; block < num_blocks; ++block) {
        const uint8_t* block_src = src + block * Q4_0_BLOCK_BYTES;
        float* block_dst = dst + block * Q4_0_BLOCK_SIZE;
        
        dequantize_q4_0_block(block_src, block_dst);
    }
    
    return 0;
}

// ============================================================================
// VALIDATION AND TESTING
// ============================================================================

/**
 * @brief Validate dequantization against known values
 * 
 * Tests the reference implementation with known inputs.
 * 
 * @return 0 if all tests pass, -1 otherwise
 */
extern "C" int Aperture_Q4_0_ValidateReference(void) {
    printf("[Aperture] Validating Q4_0 reference implementation...\n");
    
    // Test 1: Zero weights
    {
        uint8_t block[Q4_0_BLOCK_BYTES] = {0};
        block[0] = 0x00;  // Scale = 0.0 (float16)
        block[1] = 0x00;
        
        float output[Q4_0_BLOCK_SIZE];
        dequantize_q4_0_block(block, output);
        
        for (size_t i = 0; i < Q4_0_BLOCK_SIZE; ++i) {
            if (output[i] != 0.0f) {
                printf("[Aperture] FAIL: Zero test at index %zu: expected 0.0, got %f\n", 
                       i, output[i]);
                return -1;
            }
        }
        printf("[Aperture] PASS: Zero weights test\n");
    }
    
    // Test 2: Midpoint weights (q = 8, should give 0.0)
    {
        uint8_t block[Q4_0_BLOCK_BYTES];
        // Scale = 1.0 (float16 = 0x3C00)
        block[0] = 0x00;
        block[1] = 0x3C;
        
        // All weights = 8 (0x88 in each byte)
        for (size_t i = 0; i < Q4_0_WEIGHT_BYTES; ++i) {
            block[2 + i] = 0x88;
        }
        
        float output[Q4_0_BLOCK_SIZE];
        dequantize_q4_0_block(block, output);
        
        for (size_t i = 0; i < Q4_0_BLOCK_SIZE; ++i) {
            if (fabsf(output[i]) > 1e-6f) {
                printf("[Aperture] FAIL: Midpoint test at index %zu: expected ~0.0, got %f\n", 
                       i, output[i]);
                return -1;
            }
        }
        printf("[Aperture] PASS: Midpoint weights test\n");
    }
    
    // Test 3: Maximum positive weight (q = 15)
    {
        uint8_t block[Q4_0_BLOCK_BYTES];
        // Scale = 1.0
        block[0] = 0x00;
        block[1] = 0x3C;
        
        // All weights = 15 (0xFF in each byte)
        for (size_t i = 0; i < Q4_0_WEIGHT_BYTES; ++i) {
            block[2 + i] = 0xFF;
        }
        
        float output[Q4_0_BLOCK_SIZE];
        dequantize_q4_0_block(block, output);
        
        float expected = (15.0f - 8.0f) * 1.0f;  // = 7.0
        for (size_t i = 0; i < Q4_0_BLOCK_SIZE; ++i) {
            if (fabsf(output[i] - expected) > 1e-6f) {
                printf("[Aperture] FAIL: Max positive test at index %zu: expected %f, got %f\n", 
                       i, expected, output[i]);
                return -1;
            }
        }
        printf("[Aperture] PASS: Maximum positive weight test\n");
    }
    
    // Test 4: Maximum negative weight (q = 0)
    {
        uint8_t block[Q4_0_BLOCK_BYTES];
        // Scale = 1.0
        block[0] = 0x00;
        block[1] = 0x3C;
        
        // All weights = 0 (0x00 in each byte)
        for (size_t i = 0; i < Q4_0_WEIGHT_BYTES; ++i) {
            block[2 + i] = 0x00;
        }
        
        float output[Q4_0_BLOCK_SIZE];
        dequantize_q4_0_block(block, output);
        
        float expected = (0.0f - 8.0f) * 1.0f;  // = -8.0
        for (size_t i = 0; i < Q4_0_BLOCK_SIZE; ++i) {
            if (fabsf(output[i] - expected) > 1e-6f) {
                printf("[Aperture] FAIL: Max negative test at index %zu: expected %f, got %f\n", 
                       i, expected, output[i]);
                return -1;
            }
        }
        printf("[Aperture] PASS: Maximum negative weight test\n");
    }
    
    // Test 5: Scale variation
    {
        uint8_t block[Q4_0_BLOCK_BYTES];
        // Scale = 0.5 (float16 = 0x3800)
        block[0] = 0x00;
        block[1] = 0x38;
        
        // All weights = 12 (0xCC in each byte)
        for (size_t i = 0; i < Q4_0_WEIGHT_BYTES; ++i) {
            block[2 + i] = 0xCC;
        }
        
        float output[Q4_0_BLOCK_SIZE];
        dequantize_q4_0_block(block, output);
        
        float expected = (12.0f - 8.0f) * 0.5f;  // = 2.0
        for (size_t i = 0; i < Q4_0_BLOCK_SIZE; ++i) {
            if (fabsf(output[i] - expected) > 1e-6f) {
                printf("[Aperture] FAIL: Scale variation test at index %zu: expected %f, got %f\n", 
                       i, expected, output[i]);
                return -1;
            }
        }
        printf("[Aperture] PASS: Scale variation test\n");
    }
    
    printf("[Aperture] All reference validation tests PASSED!\n");
    return 0;
}

// ============================================================================
// PERFORMANCE BENCHMARKING
// ============================================================================

#ifdef _WIN32
#include <windows.h>

static inline uint64_t get_cycles() {
    return __rdtsc();
}

static inline double cycles_to_ms(uint64_t cycles) {
    static double cycles_per_ms = 0.0;
    if (cycles_per_ms == 0.0) {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        cycles_per_ms = static_cast<double>(freq.QuadPart) / 1000.0;
    }
    return static_cast<double>(cycles) / cycles_per_ms;
}
#else
#include <x86intrin.h>
static inline uint64_t get_cycles() {
    return __rdtsc();
}
#endif

/**
 * @brief Benchmark the reference implementation
 * 
 * @param num_blocks Number of blocks to process
 * @param iterations Number of iterations
 */
extern "C" void Aperture_Q4_0_BenchmarkReference(size_t num_blocks, 
                                                  size_t iterations) {
    printf("[Aperture] Benchmarking Q4_0 reference implementation...\n");
    printf("[Aperture] Blocks: %zu, Iterations: %zu\n", num_blocks, iterations);
    
    // Allocate buffers
    size_t src_size = num_blocks * Q4_0_BLOCK_BYTES;
    size_t dst_size = num_blocks * Q4_0_BLOCK_SIZE * sizeof(float);
    
    uint8_t* src = new uint8_t[src_size];
    float* dst = new float[num_blocks * Q4_0_BLOCK_SIZE];
    
    // Initialize with test pattern
    for (size_t i = 0; i < src_size; ++i) {
        src[i] = static_cast<uint8_t>(i % 256);
    }
    
    // Warmup
    for (size_t i = 0; i < 10; ++i) {
        Aperture_Q4_0_Dequant_Reference(src, dst, num_blocks);
    }
    
    // Benchmark
    uint64_t start_cycles = get_cycles();
    
    for (size_t i = 0; i < iterations; ++i) {
        Aperture_Q4_0_Dequant_Reference(src, dst, num_blocks);
    }
    
    uint64_t end_cycles = get_cycles();
    uint64_t total_cycles = end_cycles - start_cycles;
    double total_ms = cycles_to_ms(total_cycles);
    
    // Calculate metrics
    size_t total_weights = num_blocks * Q4_0_BLOCK_SIZE * iterations;
    size_t total_bytes = num_blocks * Q4_0_BLOCK_BYTES * iterations;
    double weights_per_sec = total_weights / (total_ms / 1000.0);
    double throughput_gbps = (total_bytes / 1e9) / (total_ms / 1000.0);
    
    printf("[Aperture] Results:\n");
    printf("[Aperture]   Total cycles: %llu\n", total_cycles);
    printf("[Aperture]   Total time: %.2f ms\n", total_ms);
    printf("[Aperture]   Cycles/weight: %.2f\n", 
           static_cast<double>(total_cycles) / total_weights);
    printf("[Aperture]   Weights/sec: %.2e\n", weights_per_sec);
    printf("[Aperture]   Throughput: %.2f GB/s\n", throughput_gbps);
    
    delete[] src;
    delete[] dst;
}

// ============================================================================
// MAIN (for standalone testing)
// ============================================================================

#ifdef APERTURE_STANDALONE_TEST
int main() {
    printf("========================================\n");
    printf("Aperture Q4_0 Reference Implementation\n");
    printf("========================================\n\n");
    
    // Run validation
    if (Aperture_Q4_0_ValidateReference() != 0) {
        printf("\nValidation FAILED!\n");
        return 1;
    }
    
    printf("\n");
    
    // Run benchmark
    Aperture_Q4_0_BenchmarkReference(10000, 100);
    
    printf("\nDone!\n");
    return 0;
}
#endif
