/*
 * RawrXD Q8 Matrix Multiplication - AVX2 Optimized
 * High-performance quantized matrix multiplication
 */

#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#ifdef _WIN32
    #include <windows.h>
    #define aligned_malloc(size, align) _aligned_malloc(size, align)
    #define aligned_free(ptr) _aligned_free(ptr)
#else
    #define aligned_malloc(size, align) aligned_alloc(align, size)
    #define aligned_free(ptr) free(ptr)
#endif

/* Q8 block structure */
typedef struct {
    int8_t values[32];  /* 32 int8 values per block */
    float scale;
} q8_block_t;

/* Q8 matrix structure */
typedef struct {
    q8_block_t* blocks;
    int rows;
    int cols;
    int num_blocks;
} q8_matrix_t;

/* Dot product of Q8 block with float vector using AVX2 */
static inline float q8_dot_product_avx2(const q8_block_t* block, const float* vec) {
    __m256 sum_vec = _mm256_setzero_ps();
    __m256 scale_vec = _mm256_set1_ps(block->scale);
    
    /* Process 8 values at a time (4 iterations for 32 values) */
    for (int i = 0; i < 32; i += 8) {
        /* Load 8 int8 values */
        __m128i int8_vals = _mm_loadl_epi64((__m128i*)(block->values + i));
        
        /* Unpack to 16-bit */
        __m128i int16_vals = _mm_cvtepi8_epi16(int8_vals);
        
        /* Unpack to 32-bit */
        __m128i int32_low = _mm_cvtepi16_epi32(int16_vals);
        __m128i int16_high = _mm_srli_si128(int16_vals, 8);
        __m128i int32_high = _mm_cvtepi16_epi32(int16_high);
        
        /* Combine into 256-bit */
        __m256i int32_vals = _mm256_castsi128_si256(int32_low);
        int32_vals = _mm256_inserti128_si256(int32_vals, int32_high, 1);
        
        /* Convert to float */
        __m256 q_vals = _mm256_cvtepi32_ps(int32_vals);
        
        /* Load float vector */
        __m256 f_vals = _mm256_loadu_ps(&vec[i]);
        
        /* Multiply and accumulate: q * f * scale */
        __m256 prod = _mm256_mul_ps(q_vals, f_vals);
        prod = _mm256_mul_ps(prod, scale_vec);
        sum_vec = _mm256_add_ps(sum_vec, prod);
    }
    
    /* Horizontal sum */
    float sum_arr[8];
    _mm256_storeu_ps(sum_arr, sum_vec);
    float sum = 0.0f;
    for (int j = 0; j < 8; j++) sum += sum_arr[j];
    
    return sum;
}

/* Q8 matrix-vector multiplication */
void matmul_q8_avx2(const q8_matrix_t* matrix, const float* vec, float* output) {
    for (int row = 0; row < matrix->rows; row++) {
        float sum = 0.0f;
        int block_idx = row * (matrix->cols / 32);
        
        for (int col = 0; col < matrix->cols; col += 32) {
            sum += q8_dot_product_avx2(&matrix->blocks[block_idx], &vec[col]);
            block_idx++;
        }
        
        output[row] = sum;
    }
}

/* High-resolution timer */
#ifdef _WIN32
    static inline double get_time_ms() {
        LARGE_INTEGER freq, count;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&count);
        return (double)count.QuadPart * 1000.0 / (double)freq.QuadPart;
    }
#else
    static inline double get_time_ms() {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
    }
#endif

/* Create Q8 matrix from float matrix */
q8_matrix_t* create_q8_matrix(const float* data, int rows, int cols) {
    q8_matrix_t* matrix = (q8_matrix_t*)malloc(sizeof(q8_matrix_t));
    matrix->rows = rows;
    matrix->cols = cols;
    matrix->num_blocks = rows * (cols / 32);
    matrix->blocks = (q8_block_t*)aligned_malloc(
        matrix->num_blocks * sizeof(q8_block_t), 32);
    
    /* Quantize each row */
    for (int row = 0; row < rows; row++) {
        for (int col = 0; col < cols; col += 32) {
            int block_idx = row * (cols / 32) + (col / 32);
            
            /* Find max abs in block */
            float max_abs = 0.0f;
            for (int i = 0; i < 32; i++) {
                float abs_val = fabsf(data[row * cols + col + i]);
                if (abs_val > max_abs) max_abs = abs_val;
            }
            
            /* Compute scale */
            matrix->blocks[block_idx].scale = max_abs / 127.0f;
            
            /* Quantize */
            if (max_abs > 1e-8f) {
                float inv_scale = 127.0f / max_abs;
                for (int i = 0; i < 32; i++) {
                    float q = roundf(data[row * cols + col + i] * inv_scale);
                    if (q > 127.0f) q = 127.0f;
                    if (q < -128.0f) q = -128.0f;
                    matrix->blocks[block_idx].values[i] = (int8_t)q;
                }
            } else {
                memset(matrix->blocks[block_idx].values, 0, 32);
            }
        }
    }
    
    return matrix;
}

void free_q8_matrix(q8_matrix_t* matrix) {
    if (matrix) {
        aligned_free(matrix->blocks);
        free(matrix);
    }
}

/* Benchmark function */
double benchmark_matmul_q8_avx2(int rows, int cols, int iterations) {
    /* Create test data */
    float* matrix_data = (float*)aligned_malloc(rows * cols * sizeof(float), 32);
    float* vec = (float*)aligned_malloc(cols * sizeof(float), 32);
    float* output = (float*)aligned_malloc(rows * sizeof(float), 32);
    
    for (int i = 0; i < rows * cols; i++) {
        matrix_data[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
    }
    for (int i = 0; i < cols; i++) {
        vec[i] = ((float)rand() / RAND_MAX) * 2.0f - 1.0f;
    }
    
    /* Create Q8 matrix */
    q8_matrix_t* q8_mat = create_q8_matrix(matrix_data, rows, cols);
    
    /* Warmup */
    for (int i = 0; i < 100; i++) {
        matmul_q8_avx2(q8_mat, vec, output);
    }
    
    /* Benchmark */
    double start = get_time_ms();
    
    for (int iter = 0; iter < iterations; iter++) {
        matmul_q8_avx2(q8_mat, vec, output);
    }
    
    double end = get_time_ms();
    double time_ms = end - start;
    
    /* Calculate GOPS */
    double ops = 2.0 * rows * cols * iterations;  /* multiply-add per element */
    double gops = (ops / (time_ms / 1000.0)) / 1e9;
    
    /* Cleanup */
    free_q8_matrix(q8_mat);
    aligned_free(matrix_data);
    aligned_free(vec);
    aligned_free(output);
    
    return gops;
}

int main() {
    printf("RawrXD Q8 Matmul AVX2 Benchmark\n");
    printf("================================\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* Benchmark different sizes */
    int sizes[][2] = {{64, 64}, {128, 128}, {256, 256}, {512, 512}, {1024, 1024}};
    int iterations[] = {1000, 500, 250, 100, 50};
    
    printf("Rows    Cols    Iterations    GOPS        Time (ms)\n");
    printf("---------------------------------------------------\n");
    
    for (int i = 0; i < 5; i++) {
        int rows = sizes[i][0];
        int cols = sizes[i][1];
        int iter = iterations[i];
        
        double gops = benchmark_matmul_q8_avx2(rows, cols, iter);
        double ops = 2.0 * rows * cols * iter;
        double time_ms = (ops / (gops * 1e9)) * 1000.0;
        
        printf("%-7d %-7d %-13d %-11.2f %.2f\n", rows, cols, iter, gops, time_ms);
    }
    
    printf("\n✓ Q8 Matmul AVX2 benchmark complete\n");
    
    return 0;
}
