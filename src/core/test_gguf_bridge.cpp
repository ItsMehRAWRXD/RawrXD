// ============================================================================
// test_gguf_bridge.cpp — Test Aperture GGUF Bridge Integration
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

// Aperture GGUF Bridge API
extern "C" {
    void Aperture_InitDispatch(void);
    int Aperture_IsAVX512Available(void);
    const char* Aperture_GetActiveKernelName(void);
    int64_t asm_dml_dequant_q4_0_to_fp32(float* dest, const uint8_t* src, uint64_t blockCount);
    int64_t asm_dml_dequant_q8_0_to_fp32(float* dest, const uint8_t* src, uint64_t blockCount);
    void Aperture_SetUseAVX512(bool enable);
}

// Q4_0 format: 32 weights per block, 18 bytes per block
// Bytes 0-1: scale (float16), Bytes 2-17: 32 nibbles (4-bit weights)

int main() {
    printf("========================================\n");
    printf("Aperture GGUF Bridge Integration Test\n");
    printf("========================================\n\n");
    
    // Initialize dispatch
    printf("[INFO] Initializing Aperture dispatch...\n");
    Aperture_InitDispatch();
    
    // Check AVX-512 availability
    int avx512_available = Aperture_IsAVX512Available();
    const char* kernel_name = Aperture_GetActiveKernelName();
    
    printf("[INFO] AVX-512 Available: %s\n", avx512_available ? "YES" : "NO");
    printf("[INFO] Active Kernel: %s\n\n", kernel_name);
    
    // Test Q4_0 dequantization
    printf("[TEST] Q4_0 Dequantization...\n");
    
    const size_t num_blocks = 100;
    const size_t src_size = num_blocks * 18;  // 18 bytes per Q4_0 block
    const size_t dst_size = num_blocks * 32;  // 32 floats per block
    
    // Allocate buffers
    uint8_t* src = (uint8_t*)malloc(src_size);
    float* dst = (float*)malloc(dst_size * sizeof(float));
    
    if (!src || !dst) {
        printf("[FAIL] Memory allocation failed\n");
        return 1;
    }
    
    // Initialize test data
    // Scale = 1.0 (float16 = 0x3C00), weights = alternating pattern
    for (size_t b = 0; b < num_blocks; ++b) {
        uint8_t* block = src + b * 18;
        block[0] = 0x00;  // Scale low byte
        block[1] = 0x3C;  // Scale high byte (1.0 in float16)
        
        // Fill weights with pattern
        for (size_t i = 2; i < 18; ++i) {
            block[i] = static_cast<uint8_t>((i * 7 + b * 13) % 256);
        }
    }
    
    // Run dequantization via GGUF bridge
    int64_t result = asm_dml_dequant_q4_0_to_fp32(dst, src, num_blocks);
    
    if (result != 0) {
        printf("[FAIL] Q4_0 dequantization failed with error: %lld\n", result);
        free(src);
        free(dst);
        return 1;
    }
    
    // Verify output
    int has_nonzero = 0;
    int has_nan = 0;
    for (size_t i = 0; i < dst_size; ++i) {
        if (dst[i] != 0.0f) has_nonzero = 1;
        if (dst[i] != dst[i]) has_nan = 1;  // NaN check
    }
    
    if (!has_nonzero) {
        printf("[FAIL] Output is all zeros\n");
        free(src);
        free(dst);
        return 1;
    }
    
    if (has_nan) {
        printf("[FAIL] Output contains NaN values\n");
        free(src);
        free(dst);
        return 1;
    }
    
    printf("[PASS] Q4_0 dequantization successful\n");
    printf("[INFO] Output sample: %f, %f, %f...\n", dst[0], dst[1], dst[2]);
    
    // Test with AVX-512 disabled (force reference)
    if (avx512_available) {
        printf("\n[TEST] Q4_0 with AVX-512 disabled (reference fallback)...\n");
        Aperture_SetUseAVX512(false);
        
        memset(dst, 0, dst_size * sizeof(float));
        result = asm_dml_dequant_q4_0_to_fp32(dst, src, num_blocks);
        
        if (result != 0) {
            printf("[FAIL] Reference fallback failed\n");
            free(src);
            free(dst);
            return 1;
        }
        
        printf("[PASS] Reference fallback successful\n");
        
        // Re-enable AVX-512
        Aperture_SetUseAVX512(true);
    }
    
    // Test Q8_0 dequantization
    printf("\n[TEST] Q8_0 Dequantization...\n");
    
    const size_t q8_num_blocks = 50;
    const size_t q8_src_size = q8_num_blocks * 34;  // 34 bytes per Q8_0 block
    const size_t q8_dst_size = q8_num_blocks * 32;  // 32 floats per block
    
    uint8_t* q8_src = (uint8_t*)malloc(q8_src_size);
    float* q8_dst = (float*)malloc(q8_dst_size * sizeof(float));
    
    if (!q8_src || !q8_dst) {
        printf("[FAIL] Q8_0 memory allocation failed\n");
        free(src);
        free(dst);
        return 1;
    }
    
    // Initialize Q8_0 test data
    for (size_t b = 0; b < q8_num_blocks; ++b) {
        uint8_t* block = q8_src + b * 34;
        block[0] = 0x00;  // Scale low byte
        block[1] = 0x3C;  // Scale high byte (1.0 in float16)
        
        // Fill weights
        for (size_t i = 2; i < 34; ++i) {
            block[i] = static_cast<int8_t>((i * 5 + b * 11) % 256 - 128);
        }
    }
    
    result = asm_dml_dequant_q8_0_to_fp32(q8_dst, q8_src, q8_num_blocks);
    
    if (result != 0) {
        printf("[FAIL] Q8_0 dequantization failed\n");
        free(src);
        free(dst);
        free(q8_src);
        free(q8_dst);
        return 1;
    }
    
    // Verify Q8_0 output
    has_nonzero = 0;
    has_nan = 0;
    for (size_t i = 0; i < q8_dst_size; ++i) {
        if (q8_dst[i] != 0.0f) has_nonzero = 1;
        if (q8_dst[i] != q8_dst[i]) has_nan = 1;
    }
    
    if (!has_nonzero || has_nan) {
        printf("[FAIL] Q8_0 output validation failed\n");
        free(src);
        free(dst);
        free(q8_src);
        free(q8_dst);
        return 1;
    }
    
    printf("[PASS] Q8_0 dequantization successful\n");
    printf("[INFO] Output sample: %f, %f, %f...\n", q8_dst[0], q8_dst[1], q8_dst[2]);
    
    // Cleanup
    free(src);
    free(dst);
    free(q8_src);
    free(q8_dst);
    
    printf("\n========================================\n");
    printf("All GGUF Bridge Tests PASSED\n");
    printf("========================================\n");
    
    return 0;
}
