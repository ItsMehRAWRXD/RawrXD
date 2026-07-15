/**
 * @file avx512_kernels.cpp
 * @brief RawrXD AVX512 Optimized Kernels Implementation
 *
 * High-performance matrix operations using AVX512 intrinsics.
 * Requires AVX512F support.
 *
 * @copyright RawrXD 2026
 */

#include "avx512_kernels.hpp"
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
// Matrix Multiplication - AVX512
// ============================================================================

void MatMulAccumulateF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    // Simple implementation first - optimize later
    for (size_t i = 0; i < M; ++i) {
        for (size_t j = 0; j < N; ++j) {
            float sum = C[i * N + j];  // Start with existing value (accumulate)
            for (size_t k = 0; k < K; ++k) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

void MatMulF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    // Initialize C to zero
    std::memset(C, 0, M * N * sizeof(float));
    
    // Call accumulate version
    MatMulAccumulateF32_AVX512(A, B, C, M, N, K);
}

// ============================================================================
// Vector Operations - AVX512
// ============================================================================

float VecDotF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    size_t N) {
    
    __m512 sum_vec = _mm512_setzero_ps();
    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= N; i += 16) {
        __m512 a = _mm512_loadu_ps(&A[i]);
        __m512 b = _mm512_loadu_ps(&B[i]);
        sum_vec = _mm512_fmadd_ps(a, b, sum_vec);
    }
    
    // Horizontal sum using _mm512_reduce_add_ps (AVX512VL)
    float sum = _mm512_reduce_add_ps(sum_vec);
    
    // Process remaining elements
    for (; i < N; ++i) {
        sum += A[i] * B[i];
    }
    
    return sum;
}

void VecAddF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N) {
    
    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= N; i += 16) {
        __m512 a = _mm512_loadu_ps(&A[i]);
        __m512 b = _mm512_loadu_ps(&B[i]);
        __m512 c = _mm512_add_ps(a, b);
        _mm512_storeu_ps(&C[i], c);
    }
    
    // Process remaining elements
    for (; i < N; ++i) {
        C[i] = A[i] + B[i];
    }
}

void VecScaleF32_AVX512(
    const float* __restrict X,
    float scale,
    float* __restrict Y,
    size_t N) {
    
    __m512 scale_vec = _mm512_set1_ps(scale);
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        __m512 y = _mm512_mul_ps(x, scale_vec);
        _mm512_storeu_ps(&Y[i], y);
    }
    
    for (; i < N; ++i) {
        Y[i] = X[i] * scale;
    }
}

void VecMulF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N) {
    
    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= N; i += 16) {
        __m512 a = _mm512_loadu_ps(&A[i]);
        __m512 b = _mm512_loadu_ps(&B[i]);
        __m512 c = _mm512_mul_ps(a, b);
        _mm512_storeu_ps(&C[i], c);
    }
    
    // Process remaining elements
    for (; i < N; ++i) {
        C[i] = A[i] * B[i];
    }
}

// ============================================================================
// LayerNorm - AVX512
// ============================================================================

void LayerNormF32_AVX512(
    const float* __restrict X,
    const float* __restrict gamma,
    const float* __restrict beta,
    float eps,
    float* __restrict Y,
    size_t N) {
    
    // Compute mean using AVX512
    __m512 sum_vec = _mm512_setzero_ps();
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        sum_vec = _mm512_add_ps(sum_vec, x);
    }
    
    float sum = _mm512_reduce_add_ps(sum_vec);
    
    // Process remaining elements
    for (; i < N; ++i) {
        sum += X[i];
    }
    
    float mean = sum / N;
    __m512 mean_vec = _mm512_set1_ps(mean);
    
    // Compute variance using AVX512
    __m512 var_sum_vec = _mm512_setzero_ps();
    i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        __m512 diff = _mm512_sub_ps(x, mean_vec);
        var_sum_vec = _mm512_fmadd_ps(diff, diff, var_sum_vec);
    }
    
    float var_sum = _mm512_reduce_add_ps(var_sum_vec);
    
    // Process remaining elements
    for (; i < N; ++i) {
        float diff = X[i] - mean;
        var_sum += diff * diff;
    }
    
    float var = var_sum / N;
    float inv_std = 1.0f / std::sqrt(var + eps);
    __m512 inv_std_vec = _mm512_set1_ps(inv_std);
    
    // Normalize, scale, and shift using AVX512
    i = 0;
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        __m512 g = _mm512_loadu_ps(&gamma[i]);
        __m512 b = _mm512_loadu_ps(&beta[i]);
        
        __m512 normalized = _mm512_mul_ps(_mm512_sub_ps(x, mean_vec), inv_std_vec);
        __m512 scaled = _mm512_fmadd_ps(normalized, g, b);
        
        _mm512_storeu_ps(&Y[i], scaled);
    }
    
    // Process remaining elements
    for (; i < N; ++i) {
        float normalized = (X[i] - mean) * inv_std;
        Y[i] = normalized * gamma[i] + beta[i];
    }
}

// ============================================================================
// Attention Operations - AVX512
// ============================================================================

void AttentionQKF32_AVX512(
    const float* __restrict Q,
    const float* __restrict K,
    float* __restrict scores,
    size_t seq_len,
    size_t head_dim,
    float scale) {
    
    __m512 scale_vec = _mm512_set1_ps(scale);
    
    // scores[i, j] = sum_k(Q[i, k] * K[j, k]) * scale
    for (size_t i = 0; i < seq_len; ++i) {
        for (size_t j = 0; j < seq_len; ++j) {
            __m512 sum_vec = _mm512_setzero_ps();
            size_t k = 0;
            
            // Process 16 elements at a time
            for (; k + 16 <= head_dim; k += 16) {
                __m512 q = _mm512_loadu_ps(&Q[i * head_dim + k]);
                __m512 k_vec = _mm512_loadu_ps(&K[j * head_dim + k]);
                sum_vec = _mm512_fmadd_ps(q, k_vec, sum_vec);
            }
            
            float dot = _mm512_reduce_add_ps(sum_vec);
            
            // Process remaining elements
            for (; k < head_dim; ++k) {
                dot += Q[i * head_dim + k] * K[j * head_dim + k];
            }
            
            scores[i * seq_len + j] = dot * scale;
        }
    }
}

void AttentionSoftmaxVF32_AVX512(
    const float* __restrict scores,
    const float* __restrict V,
    float* __restrict output,
    size_t seq_len,
    size_t head_dim) {
    
    // output[i, k] = sum_j(softmax(scores[i, j]) * V[j, k])
    // V is stored as [seq_len, head_dim] row-major (strided access)
    // For simplicity, use scalar implementation (AVX512 gather would be needed for efficiency)
    // TODO: Implement with _mm512_i32gather_ps for strided access
    
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
// Activation Functions - AVX512
// ============================================================================

void SoftmaxF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    // Find max for numerical stability
    float max_val = X[0];
    for (size_t i = 1; i < N; ++i) {
        max_val = std::max(max_val, X[i]);
    }
    
    __m512 max_vec = _mm512_set1_ps(max_val);
    
    // Compute exp(x - max) and sum
    float sum = 0.0f;
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        __m512 shifted = _mm512_sub_ps(x, max_vec);
        
        // exp using scalar fallback (AVX512 doesn't have exp)
        alignas(64) float temp[16];
        _mm512_storeu_ps(temp, shifted);
        for (int j = 0; j < 16; ++j) {
            temp[j] = std::exp(temp[j]);
            sum += temp[j];
        }
        _mm512_storeu_ps(&Y[i], _mm512_loadu_ps(temp));
    }
    
    // Process remaining elements
    for (; i < N; ++i) {
        Y[i] = std::exp(X[i] - max_val);
        sum += Y[i];
    }
    
    // Normalize
    float inv_sum = 1.0f / sum;
    __m512 inv_sum_vec = _mm512_set1_ps(inv_sum);
    
    i = 0;
    for (; i + 16 <= N; i += 16) {
        __m512 y = _mm512_loadu_ps(&Y[i]);
        y = _mm512_mul_ps(y, inv_sum_vec);
        _mm512_storeu_ps(&Y[i], y);
    }
    
    for (; i < N; ++i) {
        Y[i] *= inv_sum;
    }
}

void RMSNormF32_AVX512(
    const float* __restrict X,
    const float* __restrict weight,
    float eps,
    float* __restrict Y,
    size_t N) {
    
    // Compute sum of squares
    __m512 sum_sq_vec = _mm512_setzero_ps();
    size_t i = 0;
    
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        sum_sq_vec = _mm512_fmadd_ps(x, x, sum_sq_vec);
    }
    
    float sum_sq = _mm512_reduce_add_ps(sum_sq_vec);
    
    // Process remaining elements
    for (; i < N; ++i) {
        sum_sq += X[i] * X[i];
    }
    
    float mean_sq = sum_sq / N;
    float rms = std::sqrt(mean_sq + eps);
    float inv_rms = 1.0f / rms;
    
    __m512 inv_rms_vec = _mm512_set1_ps(inv_rms);
    
    // Normalize and scale
    i = 0;
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        __m512 w = _mm512_loadu_ps(&weight[i]);
        __m512 y = _mm512_mul_ps(x, inv_rms_vec);
        y = _mm512_mul_ps(y, w);
        _mm512_storeu_ps(&Y[i], y);
    }
    
    for (; i < N; ++i) {
        Y[i] = X[i] * inv_rms * weight[i];
    }
}

// ============================================================================
// Activation Functions - AVX512 (SiLU, GELU)
// ============================================================================

// Fast polynomial approximation of sigmoid for SiLU
// Using rational approximation: sigmoid(x) ≈ 0.5 + 0.5 * tanh(x * 0.5)
// For better accuracy, we use a piecewise approach
static inline __m512 fast_sigmoid_ps(__m512 x) {
    // Clamp x to [-10, 10] to avoid overflow
    __m512 min_val = _mm512_set1_ps(-10.0f);
    __m512 max_val = _mm512_set1_ps(10.0f);
    x = _mm512_max_ps(x, min_val);
    x = _mm512_min_ps(x, max_val);
    
    // Approximate sigmoid using tanh: sigmoid(x) = 0.5 + 0.5 * tanh(x/2)
    // tanh(x) ≈ x * (1 - x^2/3) for small x, but we use a more accurate approximation
    __m512 half = _mm512_set1_ps(0.5f);
    __m512 x_half = _mm512_mul_ps(x, half);
    
    // For now, use scalar fallback stored in temp buffer
    // AVX512 doesn't have exp, so we process in chunks
    alignas(64) float temp[16];
    _mm512_storeu_ps(temp, x);
    for (int i = 0; i < 16; ++i) {
        temp[i] = 1.0f / (1.0f + std::exp(-temp[i]));
    }
    return _mm512_loadu_ps(temp);
}

void SiLUF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        
        // SiLU(x) = x * sigmoid(x)
        // Since AVX512 doesn't have exp, we use scalar fallback for sigmoid
        alignas(64) float x_vals[16];
        alignas(64) float y_vals[16];
        _mm512_storeu_ps(x_vals, x);
        
        for (int j = 0; j < 16; ++j) {
            float sigmoid = 1.0f / (1.0f + std::exp(-x_vals[j]));
            y_vals[j] = x_vals[j] * sigmoid;
        }
        
        _mm512_storeu_ps(&Y[i], _mm512_loadu_ps(y_vals));
    }
    
    // Process remaining elements
    for (; i < N; ++i) {
        float sigmoid = 1.0f / (1.0f + std::exp(-X[i]));
        Y[i] = X[i] * sigmoid;
    }
}

void GELUF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    const float sqrt_2_over_pi = 0.7978845608f;
    const float coeff = 0.044715f;
    
    size_t i = 0;
    
    // Process 16 elements at a time
    for (; i + 16 <= N; i += 16) {
        __m512 x = _mm512_loadu_ps(&X[i]);
        
        // GELU(x) = 0.5 * x * (1 + tanh(sqrt(2/π) * (x + 0.044715 * x^3)))
        // Since AVX512 doesn't have tanh, use scalar fallback
        alignas(64) float x_vals[16];
        alignas(64) float y_vals[16];
        _mm512_storeu_ps(x_vals, x);
        
        for (int j = 0; j < 16; ++j) {
            float xv = x_vals[j];
            float x3 = xv * xv * xv;
            y_vals[j] = 0.5f * xv * (1.0f + std::tanh(sqrt_2_over_pi * (xv + coeff * x3)));
        }
        
        _mm512_storeu_ps(&Y[i], _mm512_loadu_ps(y_vals));
    }
    
    // Process remaining elements
    for (; i < N; ++i) {
        float x = X[i];
        float x3 = x * x * x;
        Y[i] = 0.5f * x * (1.0f + std::tanh(sqrt_2_over_pi * (x + coeff * x3)));
    }
}

// ============================================================================
// Quantized Operations - AVX512
// ============================================================================

void DequantizeQ4_0Block_AVX512(
    const void* __restrict src,
    float* __restrict dst) {
    
    // For now, use AVX2 version (same algorithm, just process more at once)
    DequantizeQ4_0Block(src, dst);
}

void DequantizeQ8_0Block_AVX512(
    const void* __restrict src,
    float* __restrict dst) {
    
    // For now, use AVX2 version
    DequantizeQ8_0Block(src, dst);
}

void MatMulQ4_0_AVX512(
    const float* __restrict A,
    const void* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    // Temporary buffer for dequantized weights
    alignas(64) float dequantized[32];
    
    for (size_t m = 0; m < M; ++m) {
        for (size_t n = 0; n < N; ++n) {
            float sum = 0.0f;
            
            for (size_t k = 0; k < K; k += 32) {
                // Dequantize block
                const uint8_t* block = static_cast<const uint8_t*>(B) + 
                    (n * K + k) / 32 * 18;
                DequantizeQ4_0Block_AVX512(block, dequantized);
                
                // Compute dot product using AVX512
                __m512 sum_vec = _mm512_setzero_ps();
                for (size_t j = 0; j < 32 && k + j < K; j += 16) {
                    __m512 a = _mm512_loadu_ps(&A[m * K + k + j]);
                    __m512 b = _mm512_loadu_ps(&dequantized[j]);
                    sum_vec = _mm512_fmadd_ps(a, b, sum_vec);
                }
                sum += _mm512_reduce_add_ps(sum_vec);
            }
            
            C[m * N + n] = sum;
        }
    }
}

// ============================================================================
// Dispatch Functions
// ============================================================================

static bool g_avx512_initialized = false;
static bool g_has_avx512 = false;

static void InitDispatch() {
    if (!g_avx512_initialized) {
        g_has_avx512 = CPUFeatures::Detect().has_avx512f;
        g_avx512_initialized = true;
    }
}

void KernelDispatch::MatMulF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        MatMulF32_AVX512(A, B, C, M, N, K);
    } else {
        MatMulF32(A, B, C, M, N, K);
    }
}

float KernelDispatch::VecDotF32(
    const float* __restrict A,
    const float* __restrict B,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        return VecDotF32_AVX512(A, B, N);
    } else {
        return VecDotF32(A, B, N);
    }
}

void KernelDispatch::SoftmaxF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        SoftmaxF32_AVX512(X, Y, N);
    } else {
        SoftmaxF32(X, Y, N);
    }
}

void KernelDispatch::RMSNormF32(
    const float* __restrict X,
    const float* __restrict weight,
    float eps,
    float* __restrict Y,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        RMSNormF32_AVX512(X, weight, eps, Y, N);
    } else {
        RMSNormF32(X, weight, eps, Y, N);
    }
}

void KernelDispatch::SiLUF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        SiLUF32_AVX512(X, Y, N);
    } else {
        SiLUF32(X, Y, N);
    }
}

void KernelDispatch::GELUF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        GELUF32_AVX512(X, Y, N);
    } else {
        GELUF32(X, Y, N);
    }
}

void KernelDispatch::VecAddF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        VecAddF32_AVX512(A, B, C, N);
    } else {
        VecAddF32(A, B, C, N);
    }
}

void KernelDispatch::VecMulF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        VecMulF32_AVX512(A, B, C, N);
    } else {
        VecMulF32(A, B, C, N);
    }
}

void KernelDispatch::VecScaleF32(
    const float* __restrict X,
    float scale,
    float* __restrict Y,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        VecScaleF32_AVX512(X, scale, Y, N);
    } else {
        VecScaleF32(X, scale, Y, N);
    }
}

void KernelDispatch::AttentionQKF32(
    const float* __restrict Q,
    const float* __restrict K,
    float* __restrict scores,
    size_t seq_len,
    size_t head_dim,
    float scale) {
    
    InitDispatch();
    
    if (g_has_avx512 && head_dim >= 16) {
        AttentionQKF32_AVX512(Q, K, scores, seq_len, head_dim, scale);
    } else {
        AttentionQKF32(Q, K, scores, seq_len, head_dim, scale);
    }
}

void KernelDispatch::AttentionSoftmaxVF32(
    const float* __restrict scores,
    const float* __restrict V,
    float* __restrict output,
    size_t seq_len,
    size_t head_dim) {
    
    InitDispatch();
    
    if (g_has_avx512 && seq_len >= 16) {
        AttentionSoftmaxVF32_AVX512(scores, V, output, seq_len, head_dim);
    } else {
        AttentionSoftmaxVF32(scores, V, output, seq_len, head_dim);
    }
}

void KernelDispatch::LayerNormF32(
    const float* __restrict X,
    const float* __restrict gamma,
    const float* __restrict beta,
    float eps,
    float* __restrict Y,
    size_t N) {
    
    InitDispatch();
    
    if (g_has_avx512 && N >= 16) {
        LayerNormF32_AVX512(X, gamma, beta, eps, Y, N);
    } else {
        LayerNormF32(X, gamma, beta, eps, Y, N);
    }
}

// ============================================================================
// Benchmark - AVX512
// ============================================================================

void BenchmarkAVX512(KernelBenchmarkAVX512* results, size_t max_results) {
    size_t result_idx = 0;
    
    // Benchmark MatMul
    if (result_idx < max_results) {
        constexpr size_t M = 512, N = 512, K = 512;
        std::vector<float> A(M * K, 1.0f);
        std::vector<float> B(K * N, 1.0f);
        std::vector<float> C_avx2(M * N, 0.0f);
        std::vector<float> C_avx512(M * N, 0.0f);
        
        // AVX2 benchmark
        auto start = std::chrono::high_resolution_clock::now();
        MatMulF32(A.data(), B.data(), C_avx2.data(), M, N, K);
        auto end = std::chrono::high_resolution_clock::now();
        double time_avx2_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double flops = 2.0 * M * N * K;
        double gflops_avx2 = flops / (time_avx2_ms * 1e6);
        
        // AVX512 benchmark
        start = std::chrono::high_resolution_clock::now();
        MatMulF32_AVX512(A.data(), B.data(), C_avx512.data(), M, N, K);
        end = std::chrono::high_resolution_clock::now();
        double time_avx512_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double gflops_avx512 = flops / (time_avx512_ms * 1e6);
        
        results[result_idx] = {"MatMulF32", gflops_avx2, gflops_avx512, 
                              gflops_avx512 / gflops_avx2, M * N};
        result_idx++;
    }
    
    // Benchmark VecDot
    if (result_idx < max_results) {
        constexpr size_t N = 1000000;
        std::vector<float> A(N, 1.0f);
        std::vector<float> B(N, 1.0f);
        
        // AVX2 benchmark
        auto start = std::chrono::high_resolution_clock::now();
        volatile float result_avx2 = VecDotF32(A.data(), B.data(), N);
        (void)result_avx2;
        auto end = std::chrono::high_resolution_clock::now();
        double time_avx2_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double flops = 2.0 * N;
        double gflops_avx2 = flops / (time_avx2_ms * 1e6);
        
        // AVX512 benchmark
        start = std::chrono::high_resolution_clock::now();
        volatile float result_avx512 = VecDotF32_AVX512(A.data(), B.data(), N);
        (void)result_avx512;
        end = std::chrono::high_resolution_clock::now();
        double time_avx512_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double gflops_avx512 = flops / (time_avx512_ms * 1e6);
        
        results[result_idx] = {"VecDotF32", gflops_avx2, gflops_avx512,
                              gflops_avx512 / gflops_avx2, N};
        result_idx++;
    }
}

void PrintBenchmarkComparison(const KernelBenchmarkAVX512* results, size_t count) {
    std::cout << "\nAVX512 vs AVX2 Benchmark Comparison:\n";
    std::cout << "====================================\n";
    std::cout << std::left << std::setw(20) << "Kernel"
              << std::right << std::setw(12) << "AVX2 GFLOPS"
              << std::setw(14) << "AVX512 GFLOPS"
              << std::setw(12) << "Speedup"
              << std::setw(15) << "Elements"
              << "\n";
    std::cout << std::string(73, '-') << "\n";
    
    for (size_t i = 0; i < count; ++i) {
        std::cout << std::left << std::setw(20) << results[i].name
                  << std::right << std::setw(12) << std::fixed << std::setprecision(2) << results[i].gflops_avx2
                  << std::setw(14) << std::fixed << std::setprecision(2) << results[i].gflops_avx512
                  << std::setw(11) << std::fixed << std::setprecision(2) << results[i].speedup << "x"
                  << std::setw(15) << results[i].elements_processed
                  << "\n";
    }
}

} // namespace kernels
} // namespace rawrxd
