// ============================================================================
// test_avx512_intrinsics.cpp — Test AVX-512 Intrinsics Kernel
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <chrono>

// Function under test
extern "C" {
    int64_t Aperture_Q4_0_Dequant_AVX512_Intrinsics(float* dest, const uint8_t* src, uint64_t blockCount);
}

// Reference implementation for validation
void Reference_Q4_0_Dequant(float* dest, const uint8_t* src, uint64_t blockCount) {
    for (uint64_t b = 0; b < blockCount; ++b) {
        const uint8_t* block = src + b * 18;
        float* out = dest + b * 32;
        
        // Read scale (float16)
        uint16_t scale_f16 = *(uint16_t*)block;
        
        // Convert float16 to float32
        uint32_t sign = (scale_f16 >> 15) & 0x1;
        uint32_t exponent = (scale_f16 >> 10) & 0x1F;
        uint32_t mantissa = scale_f16 & 0x3FF;
        
        float scale;
        if (exponent == 0) {
            scale = (sign ? -1.0f : 1.0f) * (mantissa / 1024.0f) * (1.0f / 16384.0f);
        } else if (exponent == 31) {
            scale = sign ? -INFINITY : INFINITY;
        } else {
            scale = (sign ? -1.0f : 1.0f) * (1.0f + mantissa / 1024.0f) * (1 << (exponent - 15));
        }
        
        // Dequantize 32 weights
        for (int i = 0; i < 16; ++i) {
            uint8_t packed = block[2 + i];
            int low = (packed & 0x0F) - 8;
            int high = ((packed >> 4) & 0x0F) - 8;
            out[i * 2] = low * scale;
            out[i * 2 + 1] = high * scale;
        }
    }
}

// Helper to create test data
void CreateTestData(uint8_t* src, uint64_t blockCount) {
    for (uint64_t b = 0; b < blockCount; ++b) {
        uint8_t* block = src + b * 18;
        
        // Scale = 1.0 (float16 = 0x3C00)
        block[0] = 0x00;
        block[1] = 0x3C;
        
        // Weights: alternating pattern for easy verification
        for (int i = 2; i < 18; ++i) {
            block[i] = static_cast<uint8_t>((i * 7 + b * 13) % 256);
        }
    }
}

// Validate results
bool ValidateResults(float* actual, float* expected, uint64_t weightCount, float tolerance = 0.01f) {
    int errors = 0;
    for (uint64_t i = 0; i < weightCount; ++i) {
        float diff = actual[i] - expected[i];
        if (diff < 0) diff = -diff;
        if (diff > tolerance) {
            if (errors < 5) {
                printf("  [ERROR] Index %llu: expected %f, got %f (diff %f)\n", 
                       i, expected[i], actual[i], diff);
            }
            errors++;
        }
    }
    if (errors > 0) {
        printf("  [FAIL] %d errors out of %llu weights\n", errors, weightCount);
        return false;
    }
    return true;
}

int main() {
    printf("========================================\n");
    printf("AVX-512 Intrinsics Kernel Test\n");
    printf("========================================\n\n");
    
    // Test configurations
    const uint64_t testBlocks[] = {1, 8, 64, 512, 4096, 32768};
    const int numTests = sizeof(testBlocks) / sizeof(testBlocks[0]);
    
    for (int t = 0; t < numTests; ++t) {
        uint64_t blockCount = testBlocks[t];
        uint64_t weightCount = blockCount * 32;
        size_t srcSize = blockCount * 18;
        size_t dstSize = weightCount * sizeof(float);
        
        printf("[TEST] %llu blocks (%llu weights)...\n", blockCount, weightCount);
        
        // Allocate buffers
        uint8_t* src = (uint8_t*)malloc(srcSize);
        float* dst_avx = (float*)malloc(dstSize);
        float* dst_ref = (float*)malloc(dstSize);
        
        if (!src || !dst_avx || !dst_ref) {
            printf("[FAIL] Memory allocation failed\n");
            return 1;
        }
        
        // Create test data
        CreateTestData(src, blockCount);
        
        // Run reference implementation
        Reference_Q4_0_Dequant(dst_ref, src, blockCount);
        
        // Run AVX-512 intrinsics implementation
        auto start = std::chrono::high_resolution_clock::now();
        int64_t result = Aperture_Q4_0_Dequant_AVX512_Intrinsics(dst_avx, src, blockCount);
        auto end = std::chrono::high_resolution_clock::now();
        
        if (result != 0) {
            printf("[FAIL] AVX-512 kernel returned error: %lld\n", result);
            free(src);
            free(dst_avx);
            free(dst_ref);
            return 1;
        }
        
        // Validate results
        if (!ValidateResults(dst_avx, dst_ref, weightCount)) {
            printf("[FAIL] Validation failed for %llu blocks\n", blockCount);
            free(src);
            free(dst_avx);
            free(dst_ref);
            return 1;
        }
        
        // Calculate performance
        std::chrono::duration<double> elapsed = end - start;
        double seconds = elapsed.count();
        double weightsPerSec = weightCount / seconds;
        
        printf("[PASS] Validation OK\n");
        printf("[PERF] %.3f ms (%.2fM weights/sec)\n", 
               seconds * 1000.0, weightsPerSec / 1000000.0);
        
        // Cleanup
        free(src);
        free(dst_avx);
        free(dst_ref);
    }
    
    printf("\n========================================\n");
    printf("All AVX-512 Intrinsics Tests PASSED\n");
    printf("========================================\n");
    
    return 0;
}
