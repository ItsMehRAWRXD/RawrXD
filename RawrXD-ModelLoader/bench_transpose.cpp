#include <iostream>
#include <chrono>
#include <vector>
#include <cstring>
#include <immintrin.h>

// Current production code: strided column access (SLOW)
void matmul_strided(const float* A, const float* B, float* C, int N, int M, int K) {
#ifdef __AVX2__
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            __m256 sum = _mm256_setzero_ps();
            int k = 0;
            
            for (; k + 7 < M; k += 8) {
                __m256 a = _mm256_loadu_ps(&A[i * M + k]);
                // BOTTLENECK: 8 scattered loads from column j
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
            
            for (; k < M; ++k) s += A[i * M + k] * B[k * K + j];
            
            C[i * K + j] = s;
        }
    }
#else
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float s = 0.0f;
            for (int k = 0; k < M; ++k) {
                s += A[i * M + k] * B[k * K + j];
            }
            C[i * K + j] = s;
        }
    }
#endif
}

// Optimized: transpose B first, then use contiguous loads
void matmul_optimized(const float* A, const float* B, float* C, int N, int M, int K) {
    // Allocate transposed B: B^T is K×M instead of M×K
    std::vector<float> BT(K * M);
    for (int k = 0; k < M; ++k) {
        for (int j = 0; j < K; ++j) {
            BT[j * M + k] = B[k * K + j];  // Transpose: BT[j][k] = B[k][j]
        }
    }
    
#ifdef __AVX2__
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            __m256 sum = _mm256_setzero_ps();
            int k = 0;
            
            // Now both A and BT can use contiguous vector loads
            for (; k + 7 < M; k += 8) {
                __m256 a = _mm256_loadu_ps(&A[i * M + k]);
                __m256 b = _mm256_loadu_ps(&BT[j * M + k]);  // Contiguous!
                sum = _mm256_fmadd_ps(a, b, sum);
            }
            
            float result[8];
            _mm256_storeu_ps(result, sum);
            float s = result[0] + result[1] + result[2] + result[3] +
                      result[4] + result[5] + result[6] + result[7];
            
            for (; k < M; ++k) s += A[i * M + k] * BT[j * M + k];
            
            C[i * K + j] = s;
        }
    }
#else
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float s = 0.0f;
            for (int k = 0; k < M; ++k) {
                s += A[i * M + k] * BT[j * M + k];
            }
            C[i * K + j] = s;
        }
    }
#endif
}

int main(int argc, char** argv) {
    const int N = 1024, M = 1024, K = 1024;
    
    std::vector<float> A(N * M, 0.5f);
    std::vector<float> B(M * K, 0.5f);
    std::vector<float> C(N * K);
    
    bool use_optimized = (argc > 1 && std::string(argv[1]) == "opt");
    
    auto t0 = std::chrono::high_resolution_clock::now();
    
    if (use_optimized) {
        matmul_optimized(A.data(), B.data(), C.data(), N, M, K);
    } else {
        matmul_strided(A.data(), B.data(), C.data(), N, M, K);
    }
    
    auto t1 = std::chrono::high_resolution_clock::now();
    
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    
    std::cout << (use_optimized ? "Optimized" : "Strided") << ": " << ms << " ms\n";
    
    return 0;
}
