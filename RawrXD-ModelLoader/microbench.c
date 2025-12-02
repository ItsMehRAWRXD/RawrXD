// Micro-benchmark for matmul performance
// Build: See benchmark-build.ps1

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#ifdef __AVX2__
#include <immintrin.h>
#define HAS_AVX2
#endif

void matmul_scalar(const float* A, const float* B, float* C, int N, int M, int K) {
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float s = 0.0f;
            for (int k = 0; k < M; ++k) {
                s += A[i * M + k] * B[k * K + j];
            }
            C[i * K + j] = s;
        }
    }
}

#ifdef HAS_AVX2
void matmul_avx2(const float* A, const float* B, float* C, int N, int M, int K) {
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            __m256 sum = _mm256_setzero_ps();
            int k = 0;
            
            for (; k + 7 < M; k += 8) {
                __m256 a = _mm256_loadu_ps(&A[i * M + k]);
                __m256 b = _mm256_set_ps(
                    B[(k+7) * K + j], B[(k+6) * K + j],
                    B[(k+5) * K + j], B[(k+4) * K + j],
                    B[(k+3) * K + j], B[(k+2) * K + j],
                    B[(k+1) * K + j], B[k * K + j]
                );
                sum = _mm256_fmadd_ps(a, b, sum);
            }
            
            float result[8];
            _mm256_storeu_ps(result, sum);
            float s = result[0] + result[1] + result[2] + result[3] +
                      result[4] + result[5] + result[6] + result[7];
            
            for (; k < M; ++k) {
                s += A[i * M + k] * B[k * K + j];
            }
            
            C[i * K + j] = s;
        }
    }
}
#endif

double get_time() {
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (double)counter.QuadPart / (double)freq.QuadPart;
}

int main() {
    const int N = 1, M = 4096, K = 4096;
    const int iterations = 10;
    
    float* A = (float*)malloc(N * M * sizeof(float));
    float* B = (float*)malloc(M * K * sizeof(float));
    float* C = (float*)malloc(N * K * sizeof(float));
    
    for (int i = 0; i < N * M; i++) A[i] = 0.5f + (i % 100) * 0.01f;
    for (int i = 0; i < M * K; i++) B[i] = 0.5f + (i % 100) * 0.01f;
    
    // Warm-up
    matmul_scalar(A, B, C, N, M, K);
    
    // Benchmark scalar
    double start = get_time();
    for (int i = 0; i < iterations; i++) {
        matmul_scalar(A, B, C, N, M, K);
    }
    double end = get_time();
    double scalar_time = (end - start) / iterations * 1000.0;
    
    printf("Scalar: %.2f ms\n", scalar_time);
    
#ifdef HAS_AVX2
    // Warm-up AVX2
    matmul_avx2(A, B, C, N, M, K);
    
    // Benchmark AVX2
    start = get_time();
    for (int i = 0; i < iterations; i++) {
        matmul_avx2(A, B, C, N, M, K);
    }
    end = get_time();
    double avx2_time = (end - start) / iterations * 1000.0;
    
    printf("AVX2:   %.2f ms\n", avx2_time);
    printf("Speedup: %.2fx\n", scalar_time / avx2_time);
#else
    printf("AVX2: Not compiled\n");
#endif
    
    free(A);
    free(B);
    free(C);
    
    return 0;
}
