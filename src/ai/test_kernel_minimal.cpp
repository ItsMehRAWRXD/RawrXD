// test_kernel_minimal.cpp
// Minimal standalone test for Sovereign_GEMM_Q4_F32 kernel
// Isolates the kernel from GGUF loading to verify basic functionality

#include "rawr_linear_allocator.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

extern "C" {
    void Sovereign_GEMM_Q4_F32(
        const void* pWeights,
        const float* pInput,
        float* pOutput,
        int nElementCount
    );
}

static float* aligned_alloc_f32(size_t count, size_t alignment) {
    void* ptr = _aligned_malloc(count * sizeof(float), alignment);
    memset(ptr, 0, count * sizeof(float));
    return (float*)ptr;
}

int main() {
    printf("=== Kernel Minimal Test ===\n");

    // Test 1: Single Q4_0 block (32 elements) with all nibbles = 0
    printf("[Test 1] Single block, nibbles=0 (expect -8*32=-256)...\n");
    {
        uint8_t block[18];
        block[0] = 0x00; block[1] = 0x3C; // scale = 1.0
        memset(block + 2, 0x00, 16);      // weights = 0x00 (nibbles = 0)

        float input[32];
        for (int i = 0; i < 32; ++i) input[i] = 1.0f;

        float output = 999.0f;
        Sovereign_GEMM_Q4_F32(block, input, &output, 32);
        printf("  Output: %.6f (expected -256.0)\n", output);
    }

    // Test 2: Single block with all nibbles = 15
    printf("[Test 2] Single block, nibbles=15 (expect 7*32=224)...\n");
    {
        uint8_t block[18];
        block[0] = 0x00; block[1] = 0x3C; // scale = 1.0
        memset(block + 2, 0xFF, 16);      // weights = 0xFF (nibbles = 15)

        float input[32];
        for (int i = 0; i < 32; ++i) input[i] = 1.0f;

        float output = 999.0f;
        Sovereign_GEMM_Q4_F32(block, input, &output, 32);
        printf("  Output: %.6f (expected 224.0)\n", output);
    }

    // Test 3: Single block with all nibbles = 8 (centered, expect 0)
    printf("[Test 3] Single block, nibbles=8 (expect 0)...\n");
    {
        uint8_t block[18];
        block[0] = 0x00; block[1] = 0x3C; // scale = 1.0
        memset(block + 2, 0x88, 16);      // weights = 0x88 (nibbles = 8)

        float input[32];
        for (int i = 0; i < 32; ++i) input[i] = 1.0f;

        float output = 999.0f;
        Sovereign_GEMM_Q4_F32(block, input, &output, 32);
        printf("  Output: %.6f (expected 0.0)\n", output);
    }

    // Test 4: Two blocks (64 elements) with nibbles = 8
    printf("[Test 4] Two blocks, nibbles=8 (expect 0)...\n");
    {
        uint8_t blocks[36];
        for (int b = 0; b < 2; ++b) {
            blocks[b*18+0] = 0x00; blocks[b*18+1] = 0x3C;
            memset(blocks + b*18 + 2, 0x88, 16);
        }

        float input[64];
        for (int i = 0; i < 64; ++i) input[i] = 1.0f;

        float output = 999.0f;
        Sovereign_GEMM_Q4_F32(blocks, input, &output, 64);
        printf("  Output: %.6f (expected 0.0)\n", output);
    }

    // Test 5: Full row (4096 elements) with nibbles = 8
    printf("[Test 5] Full row, nibbles=8 (expect 0)...\n");
    {
        const int n = 4096;
        const int blocks_per_row = n / 32;
        const int row_stride = blocks_per_row * 18;

        uint8_t* weights = (uint8_t*)_aligned_malloc(row_stride, 512);
        for (int b = 0; b < blocks_per_row; ++b) {
            uint8_t* block = weights + b * 18;
            block[0] = 0x00; block[1] = 0x3C;
            memset(block + 2, 0x88, 16);
        }

        float* input = aligned_alloc_f32(n, 512);
        for (int i = 0; i < n; ++i) input[i] = 1.0f;

        float output = 999.0f;
        Sovereign_GEMM_Q4_F32(weights, input, &output, n);
        printf("  Output: %.6f (expected 0.0)\n", output);

        _aligned_free(weights);
        _aligned_free(input);
    }

    printf("\n=== All tests completed ===\n");
    return 0;
}
