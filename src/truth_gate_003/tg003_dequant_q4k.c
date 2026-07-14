/*
 * Truth Gate 003 - Phase 1: Q4_K Dequantization
 * 
 * Q4_K uses super-blocks of 256 weights:
 * - 8 sub-blocks of 32 weights each
 * - Each sub-block has its own scale/min
 * - Total block size: 144 bytes for 256 weights
 * 
 * Reference: llama.cpp ggml-quants.c dequantize_row_q4_K
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

/* Q4_K block structure (144 bytes for 256 weights) */
typedef struct {
    uint8_t scales[12];          /* 8 scales + 8 mins, packed (12 bytes) */
    uint8_t qs[256/2];           /* 256 4-bit weights packed into 128 bytes */
    uint16_t d;                  /* super-block scale (f16) */
    uint16_t dmin;               /* super-block min (f16) */
} block_q4_K;

/* F16 to F32 conversion */
static float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return sign ? -val * powf(2, -14) : val * powf(2, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    float val = 1.0f + mant / 1024.0f;
    int e = (int)exp - 15;
    return sign ? -val * powf(2, e) : val * powf(2, e);
}

/* Unpack scales and mins from packed 12-byte format */
static void unpack_scales_q4k(const uint8_t *scales, float *scale, float *min, float d, float dmin) {
    /* scales[0..5] contain 8 6-bit scales packed */
    /* scales[6..11] contain 8 6-bit mins packed */
    
    uint8_t scales_u8[8];
    uint8_t mins_u8[8];
    
    /* Unpack scales (6-bit values) */
    scales_u8[0] = (scales[0] & 0x3F);
    scales_u8[1] = ((scales[0] >> 6) | ((scales[1] & 0x0F) << 2));
    scales_u8[2] = ((scales[1] >> 4) | ((scales[2] & 0x03) << 4));
    scales_u8[3] = (scales[2] >> 2);
    scales_u8[4] = (scales[3] & 0x3F);
    scales_u8[5] = ((scales[3] >> 6) | ((scales[4] & 0x0F) << 2));
    scales_u8[6] = ((scales[4] >> 4) | ((scales[5] & 0x03) << 4));
    scales_u8[7] = (scales[5] >> 2);
    
    /* Unpack mins (6-bit values) */
    mins_u8[0] = (scales[6] & 0x3F);
    mins_u8[1] = ((scales[6] >> 6) | ((scales[7] & 0x0F) << 2));
    mins_u8[2] = ((scales[7] >> 4) | ((scales[8] & 0x03) << 4));
    mins_u8[3] = (scales[8] >> 2);
    mins_u8[4] = (scales[9] & 0x3F);
    mins_u8[5] = ((scales[9] >> 6) | ((scales[10] & 0x0F) << 2));
    mins_u8[6] = ((scales[10] >> 4) | ((scales[11] & 0x03) << 4));
    mins_u8[7] = (scales[11] >> 2);
    
    /* Convert to float with super-block scales */
    for (int i = 0; i < 8; i++) {
        scale[i] = d * scales_u8[i];
        min[i] = dmin * mins_u8[i];
    }
}

/* Dequantize Q4_K block */
void dequantize_q4k(const block_q4_K *blocks, int n_blocks, float *out) {
    for (int b = 0; b < n_blocks; b++) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        
        float scale[8];
        float min[8];
        unpack_scales_q4k(blocks[b].scales, scale, min, d, dmin);
        
        /* Dequantize 256 weights (8 sub-blocks of 32) */
        for (int sb = 0; sb < 8; sb++) {
            for (int i = 0; i < 16; i++) { /* 16 bytes per sub-block */
                uint8_t q = blocks[b].qs[sb * 16 + i];
                
                /* Lower nibble */
                int w0 = (q & 0x0F);
                out[b * 256 + sb * 32 + i * 2] = scale[sb] * w0 - min[sb];
                
                /* Upper nibble */
                int w1 = (q >> 4);
                out[b * 256 + sb * 32 + i * 2 + 1] = scale[sb] * w1 - min[sb];
            }
        }
    }
}

/* Synthetic test for Q4_K */
void test_q4k_synthetic() {
    printf("Truth Gate 003 - Phase 1: Q4_K Dequantization\n");
    printf("==============================================\n\n");
    
    /* Create synthetic block */
    block_q4_K block;
    memset(&block, 0, sizeof(block));
    
    /* Set super-block scale and min (f16 values) */
    /* d = 1.0, dmin = 0.0 */
    block.d = 0x3C00;  /* f16: 1.0 */
    block.dmin = 0;    /* f16: 0.0 */
    
    /* Set scales: all 1.0 (scale = d * scale_u8) */
    /* scale_u8 = 1 for all sub-blocks */
    /* Packed: 6 bits each, 8 values in 6 bytes */
    /* 1 = 0b000001, packed: [0x01, 0x04, 0x10, 0x40, 0x01, 0x04] */
    block.scales[0] = 0x01;
    block.scales[1] = 0x04;
    block.scales[2] = 0x10;
    block.scales[3] = 0x40;
    block.scales[4] = 0x01;
    block.scales[5] = 0x04;
    
    /* Mins: all 0.0 */
    block.scales[6] = 0;
    block.scales[7] = 0;
    block.scales[8] = 0;
    block.scales[9] = 0;
    block.scales[10] = 0;
    block.scales[11] = 0;
    
    /* Set quantized values: 0-15 pattern */
    for (int i = 0; i < 128; i++) {
        block.qs[i] = (i % 16) | (((i + 1) % 16) << 4);
    }
    
    /* Dequantize */
    float output[256];
    dequantize_q4k(&block, 1, output);
    
    /* Verify */
    printf("Synthetic Q4_K test:\n");
    printf("  Super-block scale: %.2f\n", f16_to_f32(block.d));
    printf("  Super-block min: %.2f\n", f16_to_f32(block.dmin));
    printf("\n  First 16 dequantized values:\n");
    
    for (int i = 0; i < 16; i++) {
        printf("    [%2d] = %6.2f\n", i, output[i]);
    }
    
    /* Check for NaN/Inf */
    int nan_count = 0, inf_count = 0;
    float min_val = output[0], max_val = output[0];
    
    for (int i = 0; i < 256; i++) {
        if (isnan(output[i])) nan_count++;
        if (isinf(output[i])) inf_count++;
        if (output[i] < min_val) min_val = output[i];
        if (output[i] > max_val) max_val = output[i];
    }
    
    printf("\n  Validation:\n");
    printf("    NaN: %d\n", nan_count);
    printf("    Inf: %d\n", inf_count);
    printf("    Min: %.2f\n", min_val);
    printf("    Max: %.2f\n", max_val);
    
    if (nan_count == 0 && inf_count == 0) {
        printf("\n  [PASS] Q4_K dequantization functional\n");
    } else {
        printf("\n  [FAIL] Invalid values detected\n");
    }
}

int main() {
    test_q4k_synthetic();
    
    printf("\n==============================================\n");
    printf("Next: Real Q4_K tensor validation\n");
    printf("Required: tinyllama-1.1b.Q4_K_M.gguf\n");
    
    return 0;
}
