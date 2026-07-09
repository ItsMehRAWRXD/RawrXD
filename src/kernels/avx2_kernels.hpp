/**
 * @file avx2_kernels.hpp
 * @brief RawrXD AVX2 Optimized Kernels
 *
 * High-performance matrix operations using AVX2 intrinsics.
 * Targets: FMA, 256-bit vectors, cache-friendly access patterns.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstdint>
#include <cstddef>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Feature Detection
// ============================================================================

struct CPUFeatures {
    bool has_avx2 = false;
    bool has_avx512f = false;
    bool has_avx512dq = false;
    bool has_fma = false;
    bool has_sse4_2 = false;
    
    static CPUFeatures Detect();
    static void Print();
};

// ============================================================================
// Matrix Multiplication
// ============================================================================

/**
 * C = A @ B + C (accumulate)
 * A: [M, K], B: [K, N], C: [M, N]
 */
void MatMulAccumulateF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

/**
 * C = A @ B (no accumulate)
 * A: [M, K], B: [K, N], C: [M, N]
 */
void MatMulF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

// ============================================================================
// Vector Operations
// ============================================================================

/**
 * Vector addition: C[i] = A[i] + B[i]
 */
void VecAddF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N
);

/**
 * Vector multiplication: C[i] = A[i] * B[i]
 */
void VecMulF32(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N
);

/**
 * Vector scaling: Y[i] = X[i] * scale
 */
void VecScaleF32(
    const float* __restrict X,
    float scale,
    float* __restrict Y,
    size_t N
);

/**
 * Vector dot product: sum(A[i] * B[i])
 */
float VecDotF32(
    const float* __restrict A,
    const float* __restrict B,
    size_t N
);

// ============================================================================
// Activation Functions
// ============================================================================

/**
 * SiLU (Swish): Y[i] = X[i] * sigmoid(X[i])
 */
void SiLUF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

/**
 * GELU: Y[i] = X[i] * Phi(X[i])
 */
void GELUF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

/**
 * Softmax: Y[i] = exp(X[i]) / sum(exp(X))
 */
void SoftmaxF32(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

/**
 * RMSNorm: Y[i] = X[i] / sqrt(mean(X^2) + eps) * weight
 */
void RMSNormF32(
    const float* __restrict X,
    const float* __restrict weight,
    float eps,
    float* __restrict Y,
    size_t N
);

/**
 * LayerNorm: Y[i] = (X[i] - mean) / sqrt(var + eps) * gamma + beta
 */
void LayerNormF32(
    const float* __restrict X,
    const float* __restrict gamma,
    const float* __restrict beta,
    float eps,
    float* __restrict Y,
    size_t N
);

// ============================================================================
// Attention Operations
// ============================================================================

/**
 * Q @ K^T for attention scores
 * Q: [seq_len, head_dim], K: [seq_len, head_dim]
 * Output: [seq_len, seq_len]
 */
void AttentionQKF32(
    const float* __restrict Q,
    const float* __restrict K,
    float* __restrict scores,
    size_t seq_len,
    size_t head_dim,
    float scale
);

/**
 * Softmax @ V for attention output
 * scores: [seq_len, seq_len], V: [seq_len, head_dim]
 * Output: [seq_len, head_dim]
 */
void AttentionSoftmaxVF32(
    const float* __restrict scores,
    const float* __restrict V,
    float* __restrict output,
    size_t seq_len,
    size_t head_dim
);

// ============================================================================
// Quantized Operations
// ============================================================================

/**
 * Dequantize Q4_0 block to F32
 * src: 18 bytes (2 byte scale + 16 byte weights)
 * dst: 32 floats
 */
void DequantizeQ4_0Block(
    const void* __restrict src,
    float* __restrict dst
);

/**
 * Dequantize Q8_0 block to F32
 * src: 34 bytes (2 byte scale + 32 byte weights)
 * dst: 32 floats
 */
void DequantizeQ8_0Block(
    const void* __restrict src,
    float* __restrict dst
);

/**
 * Matrix multiply with Q4_0 quantized weights
 * A: [M, K] F32, B: [K, N] Q4_0, C: [M, N] F32
 */
void MatMulQ4_0(
    const float* __restrict A,
    const void* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

/**
 * Matrix multiply with Q8_0 quantized weights
 * A: [M, K] F32, B: [K, N] Q8_0, C: [M, N] F32
 */
void MatMulQ8_0(
    const float* __restrict A,
    const void* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

// ============================================================================
// Benchmark
// ============================================================================

struct KernelBenchmark {
    const char* name;
    double gflops;
    double bandwidth_gb_s;
    double time_ms;
    size_t elements_processed;
};

void BenchmarkKernels(KernelBenchmark* results, size_t max_results);
void PrintBenchmarkResults(const KernelBenchmark* results, size_t count);

} // namespace kernels
} // namespace rawrxd
