// Production implementation for matmul_avx512.cpp
// AVX-512-optimized matrix multiplication for RawrXD inference
// C = A * B where A is MxK, B is KxN, C is MxN
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include <cstdint>
#include <immintrin.h>

namespace RawrXD { namespace Core {

// Check if AVX-512 is available at runtime
static bool HasAVX512() {
#if defined(__AVX512F__) || defined(_MSC_VER)
    // Check CPUID for AVX-512 Foundation
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    if (cpuInfo[0] >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        if ((cpuInfo[1] & (1 << 16)) != 0) {
            // Check OS support via XCR0
            unsigned __int64 xcr0 = _xgetbv(0);
            const unsigned __int64 avx512Mask = (1ULL << 1) | (1ULL << 2) | 
                                                (1ULL << 5) | (1ULL << 6) | (1ULL << 7);
            return (xcr0 & avx512Mask) == avx512Mask;
        }
    }
#endif
    return false;
}

// Scalar fallback for small matrices
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

void MatMulAVX512(const float* A, const float* B, float* C, 
                  int M, int N, int K) {
    if (!A || !B || !C || M <= 0 || N <= 0 || K <= 0) return;
    
#if defined(__AVX512F__) || defined(_MSC_VER)
    static bool hasAVX512 = HasAVX512();
    
    if (hasAVX512 && M >= 16 && N >= 16 && K >= 16) {
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
                    for (int j = j0; j < jmax; j += 16) {
                        if (j + 16 <= N) {
                            _mm512_storeu_ps(&C[i * N + j], _mm512_setzero_ps());
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
                            __m512 a_vec = _mm512_set1_ps(A[i * K + k]);
                            
                            for (int j = j0; j + 15 < jmax; j += 16) {
                                __m512 b_vec = _mm512_loadu_ps(&B[k * N + j]);
                                __m512 c_vec = _mm512_loadu_ps(&C[i * N + j]);
                                c_vec = _mm512_fmadd_ps(a_vec, b_vec, c_vec);
                                _mm512_storeu_ps(&C[i * N + j], c_vec);
                            }
                            
                            // Handle remaining columns
                            for (int j = j0 + ((jmax - j0) / 16) * 16; j < jmax; ++j) {
                                C[i * N + j] += A[i * K + k] * B[k * N + j];
                            }
                        }
                    }
                }
            }
        }
    } else {
        // Use scalar for small matrices or when AVX-512 unavailable
        MatMulScalar(A, B, C, M, N, K);
    }
#else
    // Fallback to scalar implementation
    MatMulScalar(A, B, C, M, N, K);
#endif
}

// Transposed B version: C = A * B^T with AVX-512
void MatMulAVX512_BTransposed(const float* A, const float* B, float* C,
                              int M, int N, int K) {
    if (!A || !B || !C || M <= 0 || N <= 0 || K <= 0) return;
    
#if defined(__AVX512F__) || defined(_MSC_VER)
    static bool hasAVX512 = HasAVX512();
    
    if (hasAVX512 && M >= 16 && N >= 16 && K >= 16) {
        for (int i = 0; i < M; ++i) {
            for (int j = 0; j < N; j += 16) {
                if (j + 16 <= N) {
                    __m512 sum = _mm512_setzero_ps();
                    
                    for (int k = 0; k < K; ++k) {
                        __m512 a_vec = _mm512_set1_ps(A[i * K + k]);
                        __m512 b_vec = _mm512_loadu_ps(&B[j * K + k]);
                        sum = _mm512_fmadd_ps(a_vec, b_vec, sum);
                    }
                    
                    _mm512_storeu_ps(&C[i * N + j], sum);
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
