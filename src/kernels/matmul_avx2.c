/*
 * RawrXD AVX2 Optimized Matrix Multiplication
 * High-performance kernel using AVX2 intrinsics
 */

#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <intrin.h>
    #define aligned_malloc(size, align) _aligned_malloc(size, align)
    #define aligned_free(ptr) _aligned_free(ptr)
#else
    #include <cpuid.h>
    #define aligned_malloc(size, align) aligned_alloc(align, size)
    #define aligned_free(ptr) free(ptr)
#endif

/* AVX2 optimized matmul - blocked for cache efficiency */
void matmul_avx2_blocked(const float* A, const float* B, float* C, 
                         int M, int N, int K) {
    const int BLOCK_M = 32;
    const int BLOCK_N = 32;
    const int BLOCK_K = 64;
    
    /* Zero C */
    memset(C, 0, M * N * sizeof(float));
    
    for (int i0 = 0; i0 < M; i0 += BLOCK_M) {
        for (int j0 = 0; j0 < N; j0 += BLOCK_N) {
            for (int k0 = 0; k0 < K; k0 += BLOCK_K) {
                int i_max = (i0 + BLOCK_M < M) ? i0 + BLOCK_M : M;
                int j_max = (j0 + BLOCK_N < N) ? j0 + BLOCK_N : N;
                int k_max = (k0 + BLOCK_K < K) ? k0 + BLOCK_K : K;
                
                for (int i = i0; i < i_max; i++) {
                    for (int j = j0; j < j_max; j += 8) {
                        __m256 c_vec = _mm256_loadu_ps(&C[i * N + j]);
                        
                        for (int k = k0; k < k_max; k++) {
                            __m256 a_broadcast = _mm256_broadcast_ss(&A[i * K + k]);
                            __m256 b_vec = _mm256_loadu_ps(&B[k * N + j]);
                            c_vec = _mm256_fmadd_ps(a_broadcast, b_vec, c_vec);
                        }
                        
                        _mm256_storeu_ps(&C[i * N + j], c_vec);
                    }
                }
            }
        }
    }
}

/* Simple AVX2 matmul for smaller matrices */
void matmul_avx2_simple(const float* A, const float* B, float* C,
                        int M, int N, int K) {
    /* Zero C */
    memset(C, 0, M * N * sizeof(float));
    
    for (int i = 0; i < M; i++) {
        for (int k = 0; k < K; k++) {
            __m256 a_broadcast = _mm256_broadcast_ss(&A[i * K + k]);
            
            int j = 0;
            for (; j <= N - 8; j += 8) {
                __m256 c_vec = _mm256_loadu_ps(&C[i * N + j]);
                __m256 b_vec = _mm256_loadu_ps(&B[k * N + j]);
                c_vec = _mm256_fmadd_ps(a_broadcast, b_vec, c_vec);
                _mm256_storeu_ps(&C[i * N + j], c_vec);
            }
            
            /* Handle remainder */
            for (; j < N; j++) {
                C[i * N + j] += A[i * K + k] * B[k * N + j];
            }
        }
    }
}

/* Benchmark function */
double benchmark_matmul_avx2(int dim, int iterations) {
    float* A = (float*)aligned_malloc(dim * dim * sizeof(float), 32);
    float* B = (float*)aligned_malloc(dim * dim * sizeof(float), 32);
    float* C = (float*)aligned_malloc(dim * dim * sizeof(float), 32);
    
    if (!A || !B || !C) {
        aligned_free(A); aligned_free(B); aligned_free(C);
        return 0.0;
    }
    
    /* Initialize */
    for (int i = 0; i < dim * dim; i++) {
        A[i] = (float)rand() / RAND_MAX;
        B[i] = (float)rand() / RAND_MAX;
    }
    
    /* Warmup */
    for (int i = 0; i < 10; i++) {
        if (dim >= 64) {
            matmul_avx2_blocked(A, B, C, dim, dim, dim);
        } else {
            matmul_avx2_simple(A, B, C, dim, dim, dim);
        }
    }
    
    /* Benchmark */
    clock_t start = clock();
    
    for (int iter = 0; iter < iterations; iter++) {
        if (dim >= 64) {
            matmul_avx2_blocked(A, B, C, dim, dim, dim);
        } else {
            matmul_avx2_simple(A, B, C, dim, dim, dim);
        }
    }
    
    clock_t end = clock();
    double time_ms = ((double)(end - start)) / CLOCKS_PER_SEC * 1000.0;
    
    /* Calculate GOPS */
    double ops = 2.0 * dim * dim * dim * iterations;
    double gops = (ops / (time_ms / 1000.0)) / 1e9;
    
    aligned_free(A); aligned_free(B); aligned_free(C);
    
    return gops;
}

int main() {
    printf("RawrXD AVX2 Matmul Benchmark\n");
    printf("============================\n\n");
    
    srand((unsigned int)time(NULL));
    
    /* Check AVX2 support */
    int cpuInfo[4];
    #ifdef _WIN32
    __cpuid(cpuInfo, 1);
    #else
    __cpuid(1, cpuInfo[0], cpuInfo[1], cpuInfo[2], cpuInfo[3]);
    #endif
    int hasAVX2 = (cpuInfo[2] & (1 << 28)) != 0;
    
    if (!hasAVX2) {
        printf("ERROR: AVX2 not supported on this CPU\n");
        return 1;
    }
    
    printf("AVX2: Supported ✓\n\n");
    
    /* Benchmark different sizes */
    int sizes[] = {64, 128, 256, 512};
    int iterations[] = {100, 50, 10, 5};
    
    printf("Size    Iterations    GOPS        Time (ms)\n");
    printf("-------------------------------------------\n");
    
    for (int i = 0; i < 4; i++) {
        int dim = sizes[i];
        int iter = iterations[i];
        
        double gops = benchmark_matmul_avx2(dim, iter);
        double time_ms = (2.0 * dim * dim * dim * iter) / (gops * 1e9) * 1000.0;
        
        printf("%-7d %-13d %-11.2f %.2f\n", dim, iter, gops, time_ms);
    }
    
    printf("\n✓ AVX2 benchmark complete\n");
    
    return 0;
}
