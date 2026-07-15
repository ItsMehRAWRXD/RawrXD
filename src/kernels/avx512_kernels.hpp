/**
 * @file avx512_kernels.hpp
 * @brief RawrXD AVX512 Optimized Kernels
 *
 * High-performance matrix operations using AVX512 intrinsics.
 * Targets: 512-bit vectors (16x float32), FMA, cache-friendly access.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <cstdint>
#include <cstddef>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Matrix Multiplication - AVX512
// ============================================================================

/**
 * C = A @ B + C (accumulate) - AVX512 version
 * A: [M, K], B: [K, N], C: [M, N]
 * Requires AVX512F support
 */
void MatMulAccumulateF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

/**
 * C = A @ B (no accumulate) - AVX512 version
 * A: [M, K], B: [K, N], C: [M, N]
 */
void MatMulF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

// ============================================================================
// Vector Operations - AVX512
// ============================================================================

/**
 * Vector dot product: sum(A[i] * B[i]) - AVX512
 * Processes 16 elements at a time
 */
float VecDotF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    size_t N
);

/**
 * Vector addition: C[i] = A[i] + B[i] - AVX512
 */
void VecAddF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N
);

/**
 * Vector scaling: Y[i] = X[i] * scale - AVX512
 */
void VecScaleF32_AVX512(
    const float* __restrict X,
    float scale,
    float* __restrict Y,
    size_t N
);

/**
 * Vector multiplication: C[i] = A[i] * B[i] - AVX512
 */
void VecMulF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N
);

// ============================================================================
// Activation Functions - AVX512
// ============================================================================

/**
 * Softmax: Y[i] = exp(X[i]) / sum(exp(X)) - AVX512
 * Uses AVX512 for vectorized exp and sum
 */
void SoftmaxF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

/**
 * RMSNorm: Y[i] = X[i] / sqrt(mean(X^2) + eps) * weight - AVX512
 */
void RMSNormF32_AVX512(
    const float* __restrict X,
    const float* __restrict weight,
    float eps,
    float* __restrict Y,
    size_t N
);

/**
 * SiLU (Swish): Y[i] = X[i] * sigmoid(X[i]) - AVX512
 */
void SiLUF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

/**
 * GELU: Y[i] = X[i] * Phi(X[i]) - AVX512
 */
void GELUF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

/**
 * LayerNorm: Y[i] = (X[i] - mean) / sqrt(var + eps) * gamma + beta - AVX512
 */
void LayerNormF32_AVX512(
    const float* __restrict X,
    const float* __restrict gamma,
    const float* __restrict beta,
    float eps,
    float* __restrict Y,
    size_t N
);

// ============================================================================
// Attention Operations - AVX512
// ============================================================================

/**
 * Q @ K^T for attention scores - AVX512
 * Q: [seq_len, head_dim], K: [seq_len, head_dim]
 * Output: [seq_len, seq_len]
 */
void AttentionQKF32_AVX512(
    const float* __restrict Q,
    const float* __restrict K,
    float* __restrict scores,
    size_t seq_len,
    size_t head_dim,
    float scale
);

/**
 * Softmax @ V for attention output - AVX512
 * scores: [seq_len, seq_len], V: [seq_len, head_dim]
 * Output: [seq_len, head_dim]
 */
void AttentionSoftmaxVF32_AVX512(
    const float* __restrict scores,
    const float* __restrict V,
    float* __restrict output,
    size_t seq_len,
    size_t head_dim
);

// ============================================================================
// Quantized Operations - AVX512
// ============================================================================

/**
 * Dequantize Q4_0 block to F32 - AVX512
 * src: 18 bytes (2 byte scale + 16 byte weights)
 * dst: 32 floats
 */
void DequantizeQ4_0Block_AVX512(
    const void* __restrict src,
    float* __restrict dst
);

/**
 * Dequantize Q8_0 block to F32 - AVX512
 * src: 34 bytes (2 byte scale + 32 byte weights)
 * dst: 32 floats
 */
void DequantizeQ8_0Block_AVX512(
    const void* __restrict src,
    float* __restrict dst
);

/**
 * Matrix multiply with Q4_0 quantized weights - AVX512
 * A: [M, K] F32, B: [K, N] Q4_0, C: [M, N] F32
 */
void MatMulQ4_0_AVX512(
    const float* __restrict A,
    const void* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

// ============================================================================
// Dispatch Functions
// ============================================================================

/**
 * Dispatch to best available implementation
 * Automatically selects AVX512, AVX2, or scalar based on CPU features
 */
struct KernelDispatch {
    // Matrix multiplication
    static void MatMulF32(
        const float* __restrict A,
        const float* __restrict B,
        float* __restrict C,
        size_t M, size_t N, size_t K
    );
    
    // Vector dot product
    static float VecDotF32(
        const float* __restrict A,
        const float* __restrict B,
        size_t N
    );
    
    // Softmax
    static void SoftmaxF32(
        const float* __restrict X,
        float* __restrict Y,
        size_t N
    );
    
    // RMSNorm
    static void RMSNormF32(
        const float* __restrict X,
        const float* __restrict weight,
        float eps,
        float* __restrict Y,
        size_t N
    );
    
    // SiLU
    static void SiLUF32(
        const float* __restrict X,
        float* __restrict Y,
        size_t N
    );
    
    // GELU
    static void GELUF32(
        const float* __restrict X,
        float* __restrict Y,
        size_t N
    );
    
    // Vector addition
    static void VecAddF32(
        const float* __restrict A,
        const float* __restrict B,
        float* __restrict C,
        size_t N
    );
    
    // Vector multiplication
    static void VecMulF32(
        const float* __restrict A,
        const float* __restrict B,
        float* __restrict C,
        size_t N
    );
    
    // Vector scaling
    static void VecScaleF32(
        const float* __restrict X,
        float scale,
        float* __restrict Y,
        size_t N
    );
    
    // Attention Q @ K^T
    static void AttentionQKF32(
        const float* __restrict Q,
        const float* __restrict K,
        float* __restrict scores,
        size_t seq_len,
        size_t head_dim,
        float scale
    );
    
    // Attention Softmax @ V
    static void AttentionSoftmaxVF32(
        const float* __restrict scores,
        const float* __restrict V,
        float* __restrict output,
        size_t seq_len,
        size_t head_dim
    );
    
    // LayerNorm
    static void LayerNormF32(
        const float* __restrict X,
        const float* __restrict gamma,
        const float* __restrict beta,
        float eps,
        float* __restrict Y,
        size_t N
    );
};

// ============================================================================
// Benchmark - AVX512
// ============================================================================

struct KernelBenchmarkAVX512 {
    const char* name;
    double gflops_avx2;
    double gflops_avx512;
    double speedup;
    size_t elements_processed;
};

void BenchmarkAVX512(KernelBenchmarkAVX512* results, size_t max_results);
void PrintBenchmarkComparison(const KernelBenchmarkAVX512* results, size_t count);

} // namespace kernels
} // namespace rawrxd
