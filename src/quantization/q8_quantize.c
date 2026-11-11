/*
 * RawrXD Q8 Quantization Implementation
 * Scalar reference implementation
 */

#include "q8_quantize.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* Find max absolute value in array */
float q8_find_max_abs(const float* data, int size) {
    float max_abs = 0.0f;
    for (int i = 0; i < size; i++) {
        float abs_val = fabsf(data[i]);
        if (abs_val > max_abs) max_abs = abs_val;
    }
    return max_abs;
}

/* Calculate number of blocks needed */
int q8_calculate_num_blocks(int num_elements) {
    return (num_elements + Q8_BLOCK_SIZE - 1) / Q8_BLOCK_SIZE;
}

/* Quantize a block of floats to Q8 */
void q8_quantize_block(const float* input, q8_block_t* block, int size) {
    /* Find max absolute value */
    float max_abs = q8_find_max_abs(input, size);
    
    /* Compute scale */
    block->scale = q8_compute_scale(max_abs);
    
    /* Quantize values */
    if (block->scale > 1e-8f) {
        float inv_scale = Q8_MAX_ABS / max_abs;
        for (int i = 0; i < size; i++) {
            float quantized = roundf(input[i] * inv_scale);
            /* Clamp to int8 range */
            if (quantized > 127.0f) quantized = 127.0f;
            if (quantized < -128.0f) quantized = -128.0f;
            block->values[i] = (int8_t)quantized;
        }
    } else {
        /* All zeros */
        memset(block->values, 0, size * sizeof(int8_t));
    }
}

/* Dequantize a block from Q8 to float */
void q8_dequantize_block(const q8_block_t* block, float* output, int size) {
    for (int i = 0; i < size; i++) {
        output[i] = block->values[i] * block->scale;
    }
}

/* Quantize full tensor */
void q8_quantize_tensor(const float* input, q8_tensor_t* tensor, int num_elements) {
    tensor->total_elements = num_elements;
    tensor->num_blocks = q8_calculate_num_blocks(num_elements);
    tensor->blocks = (q8_block_t*)calloc(tensor->num_blocks, sizeof(q8_block_t));
    
    for (int b = 0; b < tensor->num_blocks; b++) {
        int offset = b * Q8_BLOCK_SIZE;
        int size = (offset + Q8_BLOCK_SIZE <= num_elements) ? 
                   Q8_BLOCK_SIZE : (num_elements - offset);
        q8_quantize_block(input + offset, &tensor->blocks[b], size);
    }
}

/* Dequantize full tensor */
void q8_dequantize_tensor(const q8_tensor_t* tensor, float* output) {
    for (int b = 0; b < tensor->num_blocks; b++) {
        int offset = b * Q8_BLOCK_SIZE;
        int size = (offset + Q8_BLOCK_SIZE <= tensor->total_elements) ?
                   Q8_BLOCK_SIZE : (tensor->total_elements - offset);
        q8_dequantize_block(&tensor->blocks[b], output + offset, size);
    }
}

/* Free tensor memory */
void q8_free_tensor(q8_tensor_t* tensor) {
    if (tensor->blocks) {
        free(tensor->blocks);
        tensor->blocks = NULL;
    }
    tensor->num_blocks = 0;
    tensor->total_elements = 0;
}
