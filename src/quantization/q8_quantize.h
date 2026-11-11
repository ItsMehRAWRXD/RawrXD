/*
 * RawrXD Q8 Quantization Interface
 * 8-bit symmetric quantization for inference optimization
 */

#ifndef Q8_QUANTIZE_H
#define Q8_QUANTIZE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Q8 quantization block - 32 elements per block (256 bits = 1 AVX2 register) */
#define Q8_BLOCK_SIZE 32
#define Q8_MAX_ABS 127.0f

typedef struct {
    int8_t values[Q8_BLOCK_SIZE];  /* Quantized values */
    float scale;                    /* Scale factor (dequant = values * scale) */
} q8_block_t;

typedef struct {
    q8_block_t* blocks;
    int num_blocks;
    int total_elements;
} q8_tensor_t;

/* Quantization functions */
void q8_quantize_block(const float* input, q8_block_t* block, int size);
void q8_dequantize_block(const q8_block_t* block, float* output, int size);
void q8_quantize_tensor(const float* input, q8_tensor_t* tensor, int num_elements);
void q8_dequantize_tensor(const q8_tensor_t* tensor, float* output);

/* AVX2 optimized quantization */
void q8_quantize_block_avx2(const float* input, q8_block_t* block, int size);
void q8_dequantize_block_avx2(const q8_block_t* block, float* output, int size);

/* Utility functions */
float q8_find_max_abs(const float* data, int size);
void q8_free_tensor(q8_tensor_t* tensor);
int q8_calculate_num_blocks(int num_elements);

/* Compute scale from max absolute value */
static inline float q8_compute_scale(float max_abs) {
    if (max_abs < 1e-8f) return 1.0f;
    return max_abs / Q8_MAX_ABS;
}

#ifdef __cplusplus
}
#endif

#endif /* Q8_QUANTIZE_H */
