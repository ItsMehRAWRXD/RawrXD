/*
 * RawrXD Q8 Quantization - AVX2 Optimized Implementation
 * High-performance 8-bit quantization using AVX2 intrinsics
 */

#include "q8_quantize.h"
#include <immintrin.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

/* AVX2 find max absolute value */
static float q8_find_max_abs_avx2(const float* data, int size) {
    __m256 max_vec = _mm256_setzero_ps();
    int i = 0;
    
    /* Process 8 floats at a time */
    for (; i <= size - 8; i += 8) {
        __m256 vec = _mm256_loadu_ps(&data[i]);
        __m256 abs_vec = _mm256_and_ps(vec, _mm256_castsi256_ps(_mm256_set1_epi32(0x7FFFFFFF)));
        max_vec = _mm256_max_ps(max_vec, abs_vec);
    }
    
    /* Reduce max_vec to scalar */
    float max_arr[8];
    _mm256_storeu_ps(max_arr, max_vec);
    float max_abs = 0.0f;
    for (int j = 0; j < 8; j++) {
        if (max_arr[j] > max_abs) max_abs = max_arr[j];
    }
    
    /* Handle remainder */
    for (; i < size; i++) {
        float abs_val = fabsf(data[i]);
        if (abs_val > max_abs) max_abs = abs_val;
    }
    
    return max_abs;
}

/* AVX2 quantize block - process 8 floats at a time */
void q8_quantize_block_avx2(const float* input, q8_block_t* block, int size) {
    /* Find max absolute value using AVX2 */
    float max_abs = q8_find_max_abs_avx2(input, size);
    
    /* Compute scale */
    block->scale = q8_compute_scale(max_abs);
    
    if (block->scale > 1e-8f) {
        float inv_scale = Q8_MAX_ABS / max_abs;
        __m256 inv_scale_vec = _mm256_set1_ps(inv_scale);
        __m256 max_val_vec = _mm256_set1_ps(127.0f);
        __m256 min_val_vec = _mm256_set1_ps(-128.0f);
        
        int i = 0;
        /* Process 8 floats at a time */
        for (; i <= size - 8; i += 8) {
            __m256 vec = _mm256_loadu_ps(&input[i]);
            __m256 scaled = _mm256_mul_ps(vec, inv_scale_vec);
            
            /* Round to nearest integer */
            __m256 rounded = _mm256_round_ps(scaled, _MM_FROUND_TO_NEAREST_INT);
            
            /* Clamp to int8 range */
            rounded = _mm256_min_ps(rounded, max_val_vec);
            rounded = _mm256_max_ps(rounded, min_val_vec);
            
            /* Convert to int32, then pack to int8 */
            __m256i int32_vals = _mm256_cvtps_epi32(rounded);
            
            /* Pack 32-bit integers to 16-bit */
            __m128i int16_low = _mm256_castsi256_si128(int32_vals);
            __m128i int16_high = _mm256_extracti128_si256(int32_vals, 1);
            __m128i int16_packed = _mm_packs_epi32(int16_low, int16_high);
            
            /* Pack 16-bit integers to 8-bit */
            __m128i int8_packed = _mm_packs_epi16(int16_packed, int16_packed);
            
            /* Store 8 int8 values */
            _mm_storel_epi64((__m128i*)(block->values + i), int8_packed);
        }
        
        /* Handle remainder */
        for (; i < size; i++) {
            float quantized = roundf(input[i] * inv_scale);
            if (quantized > 127.0f) quantized = 127.0f;
            if (quantized < -128.0f) quantized = -128.0f;
            block->values[i] = (int8_t)quantized;
        }
    } else {
        memset(block->values, 0, size * sizeof(int8_t));
    }
}

/* AVX2 dequantize block - process 8 values at a time */
void q8_dequantize_block_avx2(const q8_block_t* block, float* output, int size) {
    __m256 scale_vec = _mm256_set1_ps(block->scale);
    
    int i = 0;
    /* Process 8 values at a time */
    for (; i <= size - 8; i += 8) {
        /* Load 8 int8 values */
        __m128i int8_vals = _mm_loadl_epi64((__m128i*)(block->values + i));
        
        /* Unpack to 16-bit */
        __m128i int16_vals = _mm_cvtepi8_epi16(int8_vals);
        
        /* Unpack to 32-bit (low and high halves) */
        __m128i int32_low = _mm_cvtepi16_epi32(int16_vals);
        __m128i int16_high = _mm_srli_si128(int16_vals, 8);
        __m128i int32_high = _mm_cvtepi16_epi32(int16_high);
        
        /* Combine into 256-bit register */
        __m256i int32_vals = _mm256_castsi128_si256(int32_low);
        int32_vals = _mm256_inserti128_si256(int32_vals, int32_high, 1);
        
        /* Convert to float */
        __m256 float_vals = _mm256_cvtepi32_ps(int32_vals);
        
        /* Scale */
        __m256 result = _mm256_mul_ps(float_vals, scale_vec);
        
        _mm256_storeu_ps(&output[i], result);
    }
    
    /* Handle remainder */
    for (; i < size; i++) {
        output[i] = block->values[i] * block->scale;
    }
}
