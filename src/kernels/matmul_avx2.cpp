// Production implementation for matmul_avx2.cpp
// AVX2-optimized matrix multiplication for RawrXD inference
// C = A * B where A is MxK, B is KxN, C is MxN
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include <cstdint>
#include <immintrin.h>

namespace RawrXD { namespace Core {

// Scalar fallback for small matrices or when AVX2 is unavailable
static void MatMulScalar(const float* A, const float* B, float* C, 
                         int M, int N, int K) {
    for (int i = 0; i < M; ++i) {
        for (int j = 0; j < N; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < K; ++k) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

void MatMulAVX2(const float* A, const float* B, float* C, 
                int M, int N, int K) {
    if (!A || !B || !C || M <= 0 || N <= 0 || K <= 0) return;
    
#if defined(__AVX2__) || defined(_MSC_VER)
    // Use AVX2 for larger matrices
    if (M >= 8 && N >= 8 && K >= 8) {
        const int BLOCK_M = 64;
        const int BLOCK_N = 64;
        const int BLOCK_K = 256;
        
        // Blocked matrix multiplication for cache efficiency
        for (int i0 = 0; i0 < M; i0 += BLOCK_M) {
            int imax = (i0 + BLOCK_M < M) ? i0 + BLOCK_M : M;
            
            for (int j0 = 0; j0 < N; j0 += BLOCK_N) {
                int jmax = (j0 + BLOCK_N < N) ? j0 + BLOCK_N : N;
                
                // Initialize accumulator to zero
                for (int i = i0; i < imax; ++i) {
                    for (int j = j0; j < jmax; j += 8) {
                        if (j + 8 <= N) {
                            _mm256_storeu_ps(&C[i * N + j], _mm256_setzero_ps());
                        } else {
                            for (int jj = j; jj < jmax; ++jj) {
                                C[i * N + jj] = 0.0f;
                            }
                        }
                    }
                }
                
                for (int k0 = 0; k0 < K; k0 += BLOCK_K) {
                    int kmax = (k0 + BLOCK_K < K) ? k0 + BLOCK_K : K;
                    
                    // Compute block
                    for (int i = i0; i < imax; ++i) {
                        for (int k = k0; k < kmax; ++k) {
                            __m256 a_vec = _mm256_set1_ps(A[i * K + k]);
                            
                            for (int j = j0; j + 7 < jmax; j += 8) {
                                __m256 b_vec = _mm256_loadu_ps(&B[k * N + j]);
                                __m256 c_vec = _mm256_loadu_ps(&C[i * N + j]);
                                c_vec = _mm256_fmadd_ps(a_vec, b_vec, c_vec);
                                _mm256_storeu_ps(&C[i * N + j], c_vec);
                            }
                            
                            // Handle remaining columns
                            for (int j = j0 + ((jmax - j0) / 8) * 8; j < jmax; ++j) {
                                C[i * N + j] += A[i * K + k] * B[k * N + j];
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Use scalar for small matrices
        MatMulScalar(A, B, C, M, N, K);
    }
#else
    // Fallback to scalar implementation
    MatMulScalar(A, B, C, M, N, K);
#endif
}

// Transposed B version: C = A * B^T
// Useful when B is stored in column-major order
void MatMulAVX2_BTransposed(const float* A, const float* B, float* C,
                            int M, int N, int K) {
    if (!A || !B || !C || M <= 0 || N <= 0 || K <= 0) return;
    
#if defined(__AVX2__) || defined(_MSC_VER)
    if (M >= 8 && N >= 8 && K >= 8) {
        // B is N x K (stored as K x N in memory), we want B^T which is K x N
        // So B[j * K + k] is element (j, k) of B^T
        
        for (int i = 0; i < M; ++i) {
            for (int j = 0; j < N; j += 8) {
                if (j + 8 <= N) {
                    __m256 sum = _mm256_setzero_ps();
                    
                    for (int k = 0; k < K; ++k) {
                        __m256 a_vec = _mm256_set1_ps(A[i * K + k]);
                        __m256 b_vec = _mm256_loadu_ps(&B[j * K + k]);
                        sum = _mm256_fmadd_ps(a_vec, b_vec, sum);
                    }
                    
                    _mm256_storeu_ps(&C[i * N + j], sum);
                } else {
                    // Handle remaining columns
                    for (int jj = j; jj < N; ++jj) {
                        float sum = 0.0f;
                        for (int k = 0; k < K; ++k) {
                            sum += A[i * K + k] * B[jj * K + k];
                        }
                        C[i * N + jj] = sum;
                    }
                }
            }
        }
    } else {
        // Scalar fallback
        for (int i = 0; i < M; ++i) {
            for (int j = 0; j < N; ++j) {
                float sum = 0.0f;
                for (int k = 0; k < K; ++k) {
                    sum += A[i * K + k] * B[j * K + k];
                }
                C[i * N + j] = sum;
            }
        }
    }
#else
    // Scalar fallback
    for (int i = 0; i < M; ++i) {
        for (int j = 0; j < N; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < K; ++k) {
                sum += A[i * K + k] * B[j * K + k];
            }
            C[i * N + j] = sum;
        }
    }
#endif
}

}} // namespace RawrXD::Core
