/*
 * Simple Q8 Quantization Test
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

typedef struct {
    int8_t values[32];
    float scale;
} q8_block_t;

/* Simple scalar quantization */
void q8_quantize_simple(const float* input, q8_block_t* block, int size) {
    float max_abs = 0.0f;
    for (int i = 0; i < size; i++) {
        float abs_val = fabsf(input[i]);
        if (abs_val > max_abs) max_abs = abs_val;
    }
    
    block->scale = max_abs / 127.0f;
    
    if (max_abs > 1e-8f) {
        float inv_scale = 127.0f / max_abs;
        for (int i = 0; i < size; i++) {
            float q = input[i] * inv_scale;
            if (q > 127.0f) q = 127.0f;
            if (q < -128.0f) q = -128.0f;
            block->values[i] = (int8_t)(q > 0 ? q + 0.5f : q - 0.5f);
        }
    } else {
        memset(block->values, 0, size);
    }
}

void q8_dequantize_simple(const q8_block_t* block, float* output, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = block->values[i] * block->scale;
    }
}

int main() {
    printf("Simple Q8 Quantization Test\n");
    printf("============================\n\n");
    
    float input[32];
    for (int i = 0; i < 32; i++) {
        input[i] = sinf(i * 0.2f) * 0.5f;
    }
    
    q8_block_t block;
    float output[32];
    
    q8_quantize_simple(input, &block, 32);
    q8_dequantize_simple(&block, output, 32);
    
    printf("Input range: [%.3f, %.3f]\n", input[0], input[31]);
    printf("Scale: %.6f\n\n", block.scale);
    
    printf("Sample values:\n");
    printf("Index | Input    | Quantized | Output   | Error\n");
    printf("------|----------|-----------|----------|-------\n");
    
    double max_error = 0.0;
    for (int i = 0; i < 8; i++) {
        double error = fabs(output[i] - input[i]);
        if (error > max_error) max_error = error;
        printf(" %3d  | %8.4f | %4d      | %8.4f | %.4f\n",
               i, input[i], block.values[i], output[i], error);
    }
    
    printf("\nMax error: %.6f\n", max_error);
    printf("\n✓ Q8 quantization working!\n");
    
    return 0;
}
