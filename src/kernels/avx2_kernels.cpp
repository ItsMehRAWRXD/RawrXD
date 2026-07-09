/**
 * @file avx2_kernels.cpp
 * @brief RawrXD AVX2 Optimized Kernels Implementation
 *
 * High-performance matrix operations using AVX2 intrinsics.
 *
 * @copyright RawrXD 2026
 */

#include "avx2_kernels.hpp"

#include <immintrin.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cstring>
#include <algorithm>

namespace rawrxd {
namespace kernels {

// ============================================================================
// CPU Feature Detection
// ============================================================================

#ifdef _WIN32
#include <intrin.h>

static void cpuid(int info[4], int function_id) {
    __cpuid(info, function_id);
}

static void cpuidex(int info[4], int function_id, int subfunction_id) {
    __cpuidex(info, function_id, subfunction_id);
}

#else

static void cpuid(int info[4], int function_id) {
    __asm__ __volatile__ (
        "cpuid"
        : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3])
        : "a"(function_id)
    );
}

static void cpuidex(int info[4], int function_id, int subfunction_id) {
    __asm__ __volatile__ (
        "cpuid"
        : "=a"(info[0]), "=b"(info[1]), "=c"(info[2]), "=d"(info[3])
        : "a"(function_id), "c"(subfunction_id)
    );
}

#endif

CPUFeatures CPUFeatures::Detect() {
    CPUFeatures features;
    
    int info[4];
    
    // Get vendor string
    cpuid(info, 0);
    
    // Get feature bits
    cpuid(info, 1);
    features.has_sse4_2 = (info[2] & (1 << 20)) != 0;
    features.has_avx2 = (info[2] & (1 << 28)) != 0;  // AVX
    
    // Check for AVX2
    cpuidex(info, 7, 0);
    features.has_avx2 = (info[1] & (1 << 5)) != 0;
    features.has_avx512f = (info[1] & (1 << 16)) != 0;
    features.has_avx512dq = (info[1] & (1 << 17)) != 0;
    
    // Check for FMA
    cpuid(info, 1);
    features.has_fma = (info[2] & (1 << 12)) != 0;
    
    return features;
}

void CPUFeatures::Print() {
    CPUFeatures features = Detect();
    
    std::cout << "CPU Features:\n";
    std::cout << "  SSE4.2: " << (features.has_sse4_2 ? "Yes" : "No") << "\n";
    std::cout << "  AVX2:   " << (features.has_avx2 ? "Yes" : "No") << "\n";
    std::cout << "  AVX512F:" << (features.has_avx512f ? "Yes" : "No") << "\n";
    std::cout << "  AVX512DQ:" << (features.has_avx512dq ? "Yes" : "No") << "\n";
    std::cout << "  FMA:    " << (features.has_fma ? "Yes" : "No") << "\n";
}

// ============================================================================
// Matrix Multiplication - AVX2
// ============================================================================

void MatMulAccumulateF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    // Simple implementation first - optimize later
    for (size_t m = 0; m < M; ++m) {
        for (size_t n = 0; n < N; ++n) {
            float sum = C[m * N + n];  // Start with existing value (accumulate)
            for (size_t k = 0; k < K; ++k) {
                sum += A[m * K + k] * B[k * N + n];
            }
            C[m * N + n] = sum;
        }
    }
}

void MatMulF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    // Initialize C to zero
    std::memset(C, 0, M * N * sizeof(float));
    
    // Call accumulate version
    MatMulAccumulateF32(A, B, C, M, N, K);
}

// ============================================================================
// Vector Operations - AVX2
// ============================================================================

void VecAddF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N) {
    
    size_t i = 0;
    
    // Process 8 elements at a time
    for (; i + 8 <= N; i += 8) {
        __m256 a = _mm256_loadu_ps(&A[i]);
        __m256 b = _mm256_loadu_ps(&B[i]);
        __m256 c = _mm256_add_ps(a, b);
        _mm256_storeu_ps(&C[i], c);
    }
    
    // Process remaining elements
    for (; i < N; ++i) {
        C[i] = A[i] + B[i];
    }
}

void VecMulF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N) {
    
    size_t i = 0;
    
    for (; i + 8 <= N; i += 8) {
        __m256 a = _mm256_loadu_ps(&A[i]);
        __m256 b = _mm256_loadu_ps(&B[i]);
        __m256 c = _mm256_mul_ps(a, b);
        _mm256_storeu_ps(&C[i], c);
    }
    
    for (; i < N; ++i) {
        C[i] = A[i] * B[i];
    }
}

void VecScaleF32(
    const float* __restrict X,
    float scale,
    float* __restrict Y,
    size_t N) {
    
    __m256 scale_vec = _mm256_set1_ps(scale);
    size_t i = 0;
    
    for (; i + 8 <= N; i += 8) {
        __m256 x = _mm256_loadu_ps(&X[i]);
        __m256 y = _mm256_mul_ps(x, scale_vec);
        _mm256_storeu_ps(&Y[i], y);
    }
    
    for (; i < N; ++i) {
        Y[i] = X[i] * scale;
    }
}

float VecDotF32(
    const float* __restrict A,
    const float* __restrict B,
    size_t N) {
    
    __m256 sum_vec = _mm256_setzero_ps();
    size_t i = 0;
    
    for (; i + 8 <= N; i += 8) {
        __m256 a = _mm256_loadu_ps(&A[i]);
        __m256 b = _mm256_loadu_ps(&B[i]);
        sum_vec = _mm256_fmadd_ps(a, b, sum_vec);
    }
    
    // Horizontal sum
    __m256 sum1 = _mm256_hadd_ps(sum_vec, sum_vec);
    __m256 sum2 = _mm256_hadd_ps(sum1, sum1);
    float sum = _mm_cvtss_f32(_mm256_castps256_ps128(sum2)) +
                _mm_cvtss_f32(_mm256_extractf128_ps(sum2, 1));
    
    // Process remaining elements
    for (; i < N; ++i) {
        sum += A[i] * B[i];
    }
    
    return sum;
}

// ============================================================================
// Activation Functions - AVX2
// ============================================================================

void SiLUF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    // AVX2 doesn't have exp, use scalar implementation
    for (size_t i = 0; i < N; ++i) {
        float sigmoid = 1.0f / (1.0f + std::exp(-X[i]));
        Y[i] = X[i] * sigmoid;
    }
}

void GELUF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    const float sqrt_2_over_pi = 0.7978845608f;
    const float coeff = 0.044715f;
    
    size_t i = 0;
    
    for (; i < N; ++i) {
        float x = X[i];
        float x3 = x * x * x;
        Y[i] = 0.5f * x * (1.0f + std::tanh(sqrt_2_over_pi * (x + coeff * x3)));
    }
}

void SoftmaxF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    // Find max for numerical stability
    float max_val = X[0];
    for (size_t i = 1; i < N; ++i) {
        max_val = std::max(max_val, X[i]);
    }
    
    // Compute exp(x - max) and sum
    float sum = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        Y[i] = std::exp(X[i] - max_val);
        sum += Y[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    for (size_t i = 0; i < N; ++i) {
        Y[i] *= inv_sum;
    }
}

void RMSNormF32(
    const float* __restrict X,
    const float* __restrict weight,
    float eps,
    float* __restrict Y,
    size_t N) {
    
    // Compute mean of squares
    float sum_sq = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        sum_sq += X[i] * X[i];
    }
    float mean_sq = sum_sq / N;
    float rms = std::sqrt(mean_sq + eps);
    float inv_rms = 1.0f / rms;
    
    // Normalize and scale
    for (size_t i = 0; i < N; ++i) {
        Y[i] = X[i] * inv_rms * weight[i];
    }
}

void LayerNormF32(
    const float* __restrict X,
    const float* __restrict gamma,
    const float* __restrict beta,
    float eps,
    float* __restrict Y,
    size_t N) {
    
    // Compute mean
    float mean = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        mean += X[i];
    }
    mean /= N;
    
    // Compute variance
    float var = 0.0f;
    for (size_t i = 0; i < N; ++i) {
        float diff = X[i] - mean;
        var += diff * diff;
    }
    var /= N;
    
    float inv_std = 1.0f / std::sqrt(var + eps);
    
    // Normalize, scale, and shift
    for (size_t i = 0; i < N; ++i) {
        float normalized = (X[i] - mean) * inv_std;
        Y[i] = normalized * gamma[i] + beta[i];
    }
}

// ============================================================================
// Attention Operations - AVX2
// ============================================================================

void AttentionQKF32(
    const float* __restrict Q,
    const float* __restrict K,
    float* __restrict scores,
    size_t seq_len,
    size_t head_dim,
    float scale) {
    
    // scores[b, i, j] = sum_k(Q[b, i, k] * K[b, j, k]) * scale
    for (size_t i = 0; i < seq_len; ++i) {
        for (size_t j = 0; j < seq_len; ++j) {
            float dot = 0.0f;
            for (size_t k = 0; k < head_dim; ++k) {
                dot += Q[i * head_dim + k] * K[j * head_dim + k];
            }
            scores[i * seq_len + j] = dot * scale;
        }
    }
}

void AttentionSoftmaxVF32(
    const float* __restrict scores,
    const float* __restrict V,
    float* __restrict output,
    size_t seq_len,
    size_t head_dim) {
    
    // output[b, i, k] = sum_j(softmax(scores[b, i, j]) * V[b, j, k])
    for (size_t i = 0; i < seq_len; ++i) {
        // Softmax for this row
        float max_val = scores[i * seq_len];
        for (size_t j = 1; j < seq_len; ++j) {
            max_val = std::max(max_val, scores[i * seq_len + j]);
        }
        
        float sum = 0.0f;
        for (size_t j = 0; j < seq_len; ++j) {
            sum += std::exp(scores[i * seq_len + j] - max_val);
        }
        
        // Weighted sum of V
        for (size_t k = 0; k < head_dim; ++k) {
            float weighted_sum = 0.0f;
            for (size_t j = 0; j < seq_len; ++j) {
                float prob = std::exp(scores[i * seq_len + j] - max_val) / sum;
                weighted_sum += prob * V[j * head_dim + k];
            }
            output[i * head_dim + k] = weighted_sum;
        }
    }
}

// ============================================================================
// Quantized Operations
// ============================================================================

void DequantizeQ4_0Block(
    const void* __restrict src,
    float* __restrict dst) {
    
    const uint8_t* src_u8 = static_cast<const uint8_t*>(src);
    
    // Read scale (F16)
    uint16_t scale_h;
    std::memcpy(&scale_h, src_u8, sizeof(uint16_t));
    
    // Convert F16 to F32
    float scale;
    uint32_t exp = ((scale_h & 0x7C00) + 0x1C000) << 13;
    uint32_t mant = (scale_h & 0x03FF) << 13;
    uint32_t s = (scale_h & 0x8000) << 16;
    uint32_t f32 = s | exp | mant;
    std::memcpy(&scale, &f32, sizeof(float));
    
    // Dequantize 32 weights
    for (size_t i = 0; i < 32; ++i) {
        uint8_t byte = src_u8[2 + i / 2];
        int8_t val = (i % 2 == 0) ? (byte & 0x0F) : ((byte >> 4) & 0x0F);
        if (val & 0x08) val |= 0xF0;  // Sign extend
        dst[i] = scale * static_cast<float>(val);
    }
}

void DequantizeQ8_0Block(
    const void* __restrict src,
    float* __restrict dst) {
    
    const uint8_t* src_u8 = static_cast<const uint8_t*>(src);
    
    // Read scale (F16)
    uint16_t scale_h;
    std::memcpy(&scale_h, src_u8, sizeof(uint16_t));
    
    // Convert F16 to F32
    float scale;
    uint32_t exp = ((scale_h & 0x7C00) + 0x1C000) << 13;
    uint32_t mant = (scale_h & 0x03FF) << 13;
    uint32_t s = (scale_h & 0x8000) << 16;
    uint32_t f32 = s | exp | mant;
    std::memcpy(&scale, &f32, sizeof(float));
    
    // Dequantize 32 weights
    for (size_t i = 0; i < 32; ++i) {
        int8_t val = static_cast<int8_t>(src_u8[2 + i]);
        dst[i] = scale * static_cast<float>(val);
    }
}

void MatMulQ4_0(
    const float* __restrict A,
    const void* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    // Temporary buffer for dequantized weights
    alignas(32) float dequantized[32];
    
    for (size_t m = 0; m < M; ++m) {
        for (size_t n = 0; n < N; ++n) {
            float sum = 0.0f;
            
            for (size_t k = 0; k < K; k += 32) {
                // Dequantize block
                const uint8_t* block = static_cast<const uint8_t*>(B) + 
                    (n * K + k) / 32 * 18;  // 18 bytes per block
                DequantizeQ4_0Block(block, dequantized);
                
                // Compute dot product
                for (size_t i = 0; i < 32 && k + i < K; ++i) {
                    sum += A[m * K + k + i] * dequantized[i];
                }
            }
            
            C[m * N + n] = sum;
        }
    }
}

void MatMulQ8_0(
    const float* __restrict A,
    const void* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    alignas(32) float dequantized[32];
    
    for (size_t m = 0; m < M; ++m) {
        for (size_t n = 0; n < N; ++n) {
            float sum = 0.0f;
            
            for (size_t k = 0; k < K; k += 32) {
                const uint8_t* block = static_cast<const uint8_t*>(B) +
                    (n * K + k) / 32 * 34;  // 34 bytes per block
                DequantizeQ8_0Block(block, dequantized);
                
                for (size_t i = 0; i < 32 && k + i < K; ++i) {
                    sum += A[m * K + k + i] * dequantized[i];
                }
            }
            
            C[m * N + n] = sum;
        }
    }
}

// ============================================================================
// Benchmark
// ============================================================================

void BenchmarkKernels(KernelBenchmark* results, size_t max_results) {
    size_t result_idx = 0;
    
    // Benchmark MatMul
    if (result_idx < max_results) {
        constexpr size_t M = 512, N = 512, K = 512;
        std::vector<float> A(M * K, 1.0f);
        std::vector<float> B(K * N, 1.0f);
        std::vector<float> C(M * N, 0.0f);
        
        auto start = std::chrono::high_resolution_clock::now();
        MatMulF32(A.data(), B.data(), C.data(), M, N, K);
        auto end = std::chrono::high_resolution_clock::now();
        
        double time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double flops = 2.0 * M * N * K;
        double gflops = flops / (time_ms * 1e6);
        
        results[result_idx] = {"MatMulF32", gflops, 0.0, time_ms, M * N};
        result_idx++;
    }
    
    // Benchmark VecDot
    if (result_idx < max_results) {
        constexpr size_t N = 1000000;
        std::vector<float> A(N, 1.0f);
        std::vector<float> B(N, 1.0f);
        
        auto start = std::chrono::high_resolution_clock::now();
        volatile float result = VecDotF32(A.data(), B.data(), N);
        (void)result;
        auto end = std::chrono::high_resolution_clock::now();
        
        double time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double flops = 2.0 * N;
        double gflops = flops / (time_ms * 1e6);
        
        results[result_idx] = {"VecDotF32", gflops, 0.0, time_ms, N};
        result_idx++;
    }
}

void PrintBenchmarkResults(const KernelBenchmark* results, size_t count) {
    std::cout << "\nKernel Benchmark Results:\n";
    std::cout << "=========================\n";
    std::cout << std::left << std::setw(20) << "Kernel"
              << std::right << std::setw(12) << "GFLOPS"
              << std::setw(12) << "Time (ms)"
              << std::setw(15) << "Elements"
              << "\n";
    std::cout << std::string(59, '-') << "\n";
    
    for (size_t i = 0; i < count; ++i) {
        std::cout << std::left << std::setw(20) << results[i].name
                  << std::right << std::setw(12) << std::fixed << std::setprecision(2) << results[i].gflops
                  << std::setw(12) << std::fixed << std::setprecision(3) << results[i].time_ms
                  << std::setw(15) << results[i].elements_processed
                  << "\n";
    }
}

} // namespace kernels
} // namespace rawrxd
