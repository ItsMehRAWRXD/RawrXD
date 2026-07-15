#pragma once
// ============================================================================
// AVX-512 Optimized Kernels
// ============================================================================
// 16-wide vector operations for FFN and Attention
// ============================================================================

#include <cstddef>
#include <cstdint>

namespace SEG {

// ============================================================================
// CPU Feature Detection
// ============================================================================

struct CPUFeatures {
    bool hasAVX512F = false;
    bool hasAVX512DQ = false;
    bool hasAVX512VL = false;
    bool hasFMA = false;
    bool hasAVX2 = false;
    
    static CPUFeatures Detect();
    static const CPUFeatures& Get();
};

// ============================================================================
// Matrix Multiplication - AVX-512
// ============================================================================

// C = A @ B (no accumulate)
// A: [M, K], B: [K, N], C: [M, N]
void MatMulF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

// C = A @ B + C (accumulate)
void MatMulAccumulateF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

// C = A @ B^T (B transposed)
void MatMulBT_F32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t M, size_t N, size_t K
);

// ============================================================================
// Vector Operations - AVX-512
// ============================================================================

// Vector dot product: sum(A[i] * B[i])
float VecDotF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    size_t N
);

// Vector addition: C[i] = A[i] + B[i]
void VecAddF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N
);

// Vector scaling: Y[i] = X[i] * scale
void VecScaleF32_AVX512(
    const float* __restrict X,
    float scale,
    float* __restrict Y,
    size_t N
);

// Vector multiplication: C[i] = A[i] * B[i]
void VecMulF32_AVX512(
    const float* __restrict A,
    const float* __restrict B,
    float* __restrict C,
    size_t N
);

// ============================================================================
// Activation Functions - AVX-512
// ============================================================================

// SiLU: Y[i] = X[i] * sigmoid(X[i])
void SiLUF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

// GELU: Y[i] = X[i] * Phi(X[i])
void GELUF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

// RMSNorm: Y[i] = X[i] / sqrt(mean(X^2) + eps) * weight
void RMSNormF32_AVX512(
    const float* __restrict X,
    const float* __restrict weight,
    float eps,
    float* __restrict Y,
    size_t N
);

// Softmax: Y[i] = exp(X[i]) / sum(exp(X))
void SoftmaxF32_AVX512(
    const float* __restrict X,
    float* __restrict Y,
    size_t N
);

// ============================================================================
// Attention Operations - AVX-512
// ============================================================================

// Q @ K^T for attention scores
void AttentionQKF32_AVX512(
    const float* __restrict Q,
    const float* __restrict K,
    float* __restrict scores,
    size_t seq_len,
    size_t head_dim,
    float scale
);

// Softmax(QK^T) @ V
void AttentionSoftmaxVF32_AVX512(
    const float* __restrict scores,
    const float* __restrict V,
    float* __restrict output,
    size_t seq_len,
    size_t head_dim
);

// ============================================================================
// Dispatch Layer
// ============================================================================

class KernelDispatch {
public:
    // Initialize and detect CPU features
    static void Initialize();
    
    // Check capabilities
    static bool HasAVX512() { return CPUFeatures::Get().hasAVX512F; }
    static bool HasAVX2() { return CPUFeatures::Get().hasAVX2; }
    
    // Matrix multiplication with automatic dispatch
    static void MatMulF32(
        const float* A, const float* B, float* C,
        size_t M, size_t N, size_t K
    );
    
    static void MatMulAccumulateF32(
        const float* A, const float* B, float* C,
        size_t M, size_t N, size_t K
    );
    
    // Vector operations
    static float VecDotF32(const float* A, const float* B, size_t N);
    static void VecAddF32(const float* A, const float* B, float* C, size_t N);
    static void VecScaleF32(const float* X, float scale, float* Y, size_t N);
    static void VecMulF32(const float* A, const float* B, float* C, size_t N);
    
    // Activations
    static void SiLUF32(const float* X, float* Y, size_t N);
    static void GELUF32(const float* X, float* Y, size_t N);
    static void RMSNormF32(const float* X, const float* weight, float eps, float* Y, size_t N);
    static void SoftmaxF32(const float* X, float* Y, size_t N);
    
    // Attention
    static void AttentionQKF32(const float* Q, const float* K, float* scores,
                               size_t seq_len, size_t head_dim, float scale);
    static void AttentionSoftmaxVF32(const float* scores, const float* V,
                                      float* output, size_t seq_len, size_t head_dim);
};

} // namespace SEG
