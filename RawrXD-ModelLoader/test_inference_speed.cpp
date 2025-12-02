#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>

#ifdef __AVX2__
#include <immintrin.h>
#endif

// Check if CPU supports AVX2
bool hasAVX2() {
#if defined(_MSC_VER)
    int cpuInfo[4];
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 5)) != 0;
#elif defined(__GNUC__)
    return __builtin_cpu_supports("avx2");
#else
    return false;
#endif
}

// Scalar matmul (baseline)
void matmul_scalar(const float* A, const float* B, float* C, int M, int N, int K) {
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

#ifdef __AVX2__
// AVX2 matmul (optimized)
void matmul_avx2(const float* A, const float* B, float* C, int M, int N, int K) {
    constexpr int BLOCK = 64;
    
    // Zero output
    for (int i = 0; i < M * N; ++i) C[i] = 0.0f;
    
    // Blocked loops
    for (int ii = 0; ii < M; ii += BLOCK) {
        for (int jj = 0; jj < N; jj += BLOCK) {
            for (int kk = 0; kk < K; kk += BLOCK) {
                int i_max = std::min(ii + BLOCK, M);
                int j_max = std::min(jj + BLOCK, N);
                int k_max = std::min(kk + BLOCK, K);
                
                // Micro-kernel with AVX2
                for (int i = ii; i < i_max; ++i) {
                    for (int k = kk; k < k_max; ++k) {
                        __m256 a_vec = _mm256_set1_ps(A[i * K + k]);
                        
                        int j = jj;
                        for (; j + 8 <= j_max; j += 8) {
                            __m256 b_vec = _mm256_loadu_ps(&B[k * N + j]);
                            __m256 c_vec = _mm256_loadu_ps(&C[i * N + j]);
                            c_vec = _mm256_fmadd_ps(a_vec, b_vec, c_vec);
                            _mm256_storeu_ps(&C[i * N + j], c_vec);
                        }
                        
                        // Tail
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

// Simple LLaMA-style benchmark: M=1 (batch), N=8192 (vocab), K=4096 (hidden)
int main() {
    const int M = 1, N = 8192, K = 4096;
    const int warmup = 2, iters = 10;
    
    std::cout << "RawrXD Inference Benchmark\n";
    std::cout << "==========================\n";
    std::cout << "Matrix size: " << M << "×" << K << " × " << K << "×" << N << "\n";
    std::cout << "AVX2 support: " << (hasAVX2() ? "YES" : "NO") << "\n\n";
    
    std::vector<float> A(M * K, 0.5f);
    std::vector<float> B(K * N, 0.5f);
    std::vector<float> C(M * N);
    
    // Warmup + benchmark scalar
    for (int i = 0; i < warmup; ++i) {
        matmul_scalar(A.data(), B.data(), C.data(), M, N, K);
    }
    
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        matmul_scalar(A.data(), B.data(), C.data(), M, N, K);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double scalar_ms = std::chrono::duration<double, std::milli>(t1 - t0).count() / iters;
    double scalar_toks = 1000.0 / scalar_ms;  // 1 token per forward pass
    
    std::cout << "SCALAR:\n";
    std::cout << "  Time:   " << scalar_ms << " ms/token\n";
    std::cout << "  Speed:  " << scalar_toks << " tok/s\n";
    std::cout << "  Check:  C[0]=" << C[0] << " (expect ~2048)\n\n";
    
#ifdef __AVX2__
    if (hasAVX2()) {
        // Warmup + benchmark AVX2
        for (int i = 0; i < warmup; ++i) {
            matmul_avx2(A.data(), B.data(), C.data(), M, N, K);
        }
        
        t0 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < iters; ++i) {
            matmul_avx2(A.data(), B.data(), C.data(), M, N, K);
        }
        t1 = std::chrono::high_resolution_clock::now();
        double avx2_ms = std::chrono::duration<double, std::milli>(t1 - t0).count() / iters;
        double avx2_toks = 1000.0 / avx2_ms;
        
        std::cout << "AVX2:\n";
        std::cout << "  Time:   " << avx2_ms << " ms/token\n";
        std::cout << "  Speed:  " << avx2_toks << " tok/s\n";
        std::cout << "  Check:  C[0]=" << C[0] << " (expect ~2048)\n\n";
        
        double speedup = scalar_toks / avx2_toks;  // Note: inverted because lower ms is faster
        speedup = scalar_ms / avx2_ms;  // Correct version
        
        std::cout << "SPEEDUP: " << speedup << "×\n";
        
        if (speedup >= 2.5) {
            std::cout << "✅ SUCCESS: AVX2 provides significant real-world acceleration!\n";
            return 0;
        } else if (speedup >= 1.5) {
            std::cout << "⚠️  PARTIAL: Speedup is good but below expected 3×\n";
            return 1;
        } else {
            std::cout << "❌ FAILED: AVX2 not providing expected acceleration\n";
            return 2;
        }
    } else {
        std::cout << "⚠️  CPU does not support AVX2, skipping optimized test\n";
        return 1;
    }
#else
    std::cout << "⚠️  Binary compiled without AVX2 support\n";
    return 1;
#endif
}
