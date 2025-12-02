#include <iostream>
#include <chrono>
#include <vector>
#include <algorithm>
#include <immintrin.h>

constexpr int BLOCK_SIZE = 64;  // 64×64 fits nicely in L1 cache

// Scalar blocked GEMM
void gemm_scalar_blocked(int M, int N, int K, const float* A, const float* B, float* C) {
    // Zero output
    for (int i = 0; i < M * N; ++i) C[i] = 0.0f;
    
    // Blocked loops
    for (int ii = 0; ii < M; ii += BLOCK_SIZE) {
        for (int jj = 0; jj < N; jj += BLOCK_SIZE) {
            for (int kk = 0; kk < K; kk += BLOCK_SIZE) {
                // Compute block bounds
                int i_max = std::min(ii + BLOCK_SIZE, M);
                int j_max = std::min(jj + BLOCK_SIZE, N);
                int k_max = std::min(kk + BLOCK_SIZE, K);
                
                // Micro-kernel: standard triple loop within block
                for (int i = ii; i < i_max; ++i) {
                    for (int k = kk; k < k_max; ++k) {
                        float a_val = A[i * K + k];
                        for (int j = jj; j < j_max; ++j) {
                            C[i * N + j] += a_val * B[k * N + j];
                        }
                    }
                }
            }
        }
    }
}

#ifdef __AVX2__
// AVX2 blocked GEMM with vectorized inner loop
void gemm_avx2_blocked(int M, int N, int K, const float* A, const float* B, float* C) {
    // Zero output
    for (int i = 0; i < M * N; ++i) C[i] = 0.0f;
    
    // Blocked loops
    for (int ii = 0; ii < M; ii += BLOCK_SIZE) {
        for (int jj = 0; jj < N; jj += BLOCK_SIZE) {
            for (int kk = 0; kk < K; kk += BLOCK_SIZE) {
                int i_max = std::min(ii + BLOCK_SIZE, M);
                int j_max = std::min(jj + BLOCK_SIZE, N);
                int k_max = std::min(kk + BLOCK_SIZE, K);
                
                // Micro-kernel with AVX2
                for (int i = ii; i < i_max; ++i) {
                    for (int k = kk; k < k_max; ++k) {
                        __m256 a_vec = _mm256_set1_ps(A[i * K + k]);
                        
                        int j = jj;
                        // Process 8 elements at a time
                        for (; j + 8 <= j_max; j += 8) {
                            __m256 b_vec = _mm256_loadu_ps(&B[k * N + j]);
                            __m256 c_vec = _mm256_loadu_ps(&C[i * N + j]);
                            c_vec = _mm256_fmadd_ps(a_vec, b_vec, c_vec);
                            _mm256_storeu_ps(&C[i * N + j], c_vec);
                        }
                        
                        // Handle remaining elements
                        float a_val = A[i * K + k];
                        for (; j < j_max; ++j) {
                            C[i * N + j] += a_val * B[k * N + j];
                        }
                    }
                }
            }
        }
    }
}
#endif

int main() {
    const int M = 4096, N = 4096, K = 4096;
    
    std::vector<float> A(M * K, 0.5f);
    std::vector<float> B(K * N, 0.5f);
    std::vector<float> C(M * N);
    
    auto t0 = std::chrono::high_resolution_clock::now();
    
#ifdef __AVX2__
    gemm_avx2_blocked(M, N, K, A.data(), B.data(), C.data());
#else
    gemm_scalar_blocked(M, N, K, A.data(), B.data(), C.data());
#endif
    
    auto t1 = std::chrono::high_resolution_clock::now();
    
    double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    std::cout << ms << "\n";
    
    // Sanity check
    std::cout << "C[0]=" << C[0] << " (expect ~2048)\n";
    
    return 0;
}
