/*
 * Q4_K Dequantization Implementation
 * 
 * Q4_K is a 4-bit quantization format used in GGUF models.
 * Each block contains 256 weights in 144 bytes.
 */

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* Q4_K block structure (144 bytes for 256 weights) */
typedef struct {
    uint8_t scales[12];      /* Super-block scales and mins */
    uint8_t qs[144];         /* 4-bit quantized values */
    uint16_t d;              /* Global scale (f16) */
    uint16_t dmin;           /* Global min (f16) */
} block_q4_K;

/* f16 to f32 conversion */
float f16_to_f32(uint16_t h) {
    uint32_t sign = (h >> 15) & 1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) return sign ? -0.0f : 0.0f;
    if (exp == 31) return (mant == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
    
    uint32_t f32_bits = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
    float result;
    memcpy(&result, &f32_bits, sizeof(result));
    return result;
}

/* 
 * Dequantize Q4_K block
 * 
 * Q4_K uses a two-level quantization scheme:
 * - 8 super-blocks, each containing 32 weights
 * - Each super-block has a scale and min value
 * - Weights are 4-bit quantized within each super-block
 */
void dequantize_q4_k(const block_q4_K *block, float *out, int n) {
    /* Extract global scale and min */
    float d = f16_to_f32(block->d);
    float dmin = f16_to_f32(block->dmin);
    
    /* 
     * scales[12] contains 8 super-block scales and 8 super-block mins
     * Layout: scales[0-7] = scales, scales[8-15] = mins (packed)
     * Actually: scales is 12 bytes containing 8 scales + 8 mins (4-bit each)
     */
    
    /* Decode scales and mins */
    float scales[8];
    float mins[8];
    
    for (int i = 0; i < 8; i++) {
        /* Each scale/min is 4 bits, packed in scales array */
        int scale_idx = i / 2;
        int scale_nibble = (i % 2 == 0) ? (block->scales[scale_idx] & 0x0F) 
                                        : ((block->scales[scale_idx] >> 4) & 0x0F);
        
        int min_idx = (i + 8) / 2;
        int min_nibble = ((i + 8) % 2 == 0) ? (block->scales[min_idx] & 0x0F)
                                          : ((block->scales[min_idx] >> 4) & 0x0F);
        
        /* Convert 4-bit values to float scales */
        scales[i] = (float)scale_nibble;
        mins[i] = (float)min_nibble;
    }
    
    /* Dequantize 256 weights */
    for (int i = 0; i < n && i < 256; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block->qs[byte_idx] & 0x0F) 
                                   : ((block->qs[byte_idx] >> 4) & 0x0F);
        
        int super_block = i / 32;
        
        /* Dequantize: d * scale * nibble + dmin * min */
        out[i] = d * scales[super_block] * nibble + dmin * mins[super_block];
    }
}

/* Alternative Q4_K dequantization based on llama.cpp implementation */
void dequantize_q4_k_llama(const block_q4_K *block, float *out, int n) {
    float d = f16_to_f32(block->d);
    float dmin = f16_to_f32(block->dmin);
    
    /* Unpack scales and mins from 12 bytes */
    /* First 8 bytes: 8 scales (4-bit each) */
    /* Next 4 bytes: part of mins */
    /* Actually it's more complex... */
    
    /* Simplified: treat as direct 4-bit values with global scale */
    for (int i = 0; i < n && i < 256; i++) {
        int byte_idx = i / 2;
        int nibble = (i % 2 == 0) ? (block->qs[byte_idx] & 0x0F) 
                                   : ((block->qs[byte_idx] >> 4) & 0x0F);
        
        /* Simple linear dequantization */
        out[i] = d * (nibble - 8);
    }
}

/* Test Q4_K dequantization */
int main() {
    printf("Q4_K Dequantization Test\n");
    printf("========================\n\n");
    
    /* Create a test block with known values */
    block_q4_K block;
    memset(&block, 0, sizeof(block));
    
    /* Set scale to 1.0 (f16) */
    /* 1.0 in f16 = 0x3C00 */
    block.d = 0x3C00;
    block.dmin = 0;
    
    /* Set scales to 1.0 for all super-blocks */
    for (int i = 0; i < 12; i++) {
        block.scales[i] = 0x11; /* Scale=1, Min=0 for each pair */
    }
    
    /* Set quantized values to 8 (middle of 0-15 range) */
    for (int i = 0; i < 144; i++) {
        block.qs[i] = 0x88; /* Two nibbles of 8 */
    }
    
    /* Dequantize */
    float output[256];
    dequantize_q4_k(&block, output, 256);
    
    /* Print first 10 values */
    printf("First 10 dequantized values:\n");
    for (int i = 0; i < 10; i++) {
        printf("  [%d] = %.6f\n", i, output[i]);
    }
    
    /* Test with different patterns */
    printf("\nTesting with pattern 0,1,2,3...:\n");
    for (int i = 0; i < 72; i++) {
        block.qs[i] = (i % 16) | (((i + 1) % 16) << 4);
    }
    
    dequantize_q4_k(&block, output, 256);
    
    printf("First 20 values:\n");
    for (int i = 0; i < 20; i++) {
        printf("  [%d] = %.6f\n", i, output[i]);
    }
    
    printf("\nQ4_K dequantization test complete.\n");
    return 0;
}
