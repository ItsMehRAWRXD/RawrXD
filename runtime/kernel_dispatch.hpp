#pragma once
// ============================================================================
// Kernel Dispatch Layer - Bridges SEG to Optimized Kernels
// ============================================================================
// Provides automatic dispatch to AVX512/AVX2/Scalar implementations
// ============================================================================

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Runtime {

// Kernel capability detection
struct KernelCapabilities {
    bool hasAVX512F = false;
    bool hasAVX512DQ = false;
    bool hasAVX512VL = false;
    bool hasFMA = false;
    bool hasAVX2 = false;
    
    static KernelCapabilities Detect();
    static const KernelCapabilities& Get();
};

// ============================================================================
// Dispatch Interface
// ============================================================================

class KernelDispatch {
public:
    // Matrix multiplication: C = A @ B
    static void MatMulF32(
        const float* A, const float* B, float* C,
        size_t M, size_t N, size_t K);
    
    // Vector dot product
    static float VecDotF32(
        const float* A, const float* B, size_t N);
    
    // Vector addition: C = A + B
    static void VecAddF32(
        const float* A, const float* B, float* C, size_t N);
    
    // Vector scaling: Y = X * scale
    static void VecScaleF32(
        const float* X, float scale, float* Y, size_t N);
    
    // Vector multiplication: C = A * B (element-wise)
    static void VecMulF32(
        const float* A, const float* B, float* C, size_t N);
    
    // Softmax
    static void SoftmaxF32(
        const float* X, float* Y, size_t N);
    
    // RMSNorm
    static void RMSNormF32(
        const float* X, const float* weight, float eps,
        float* Y, size_t N);
    
    // SiLU activation
    static void SiLUF32(
        const float* X, float* Y, size_t N);
    
    // GELU activation
    static void GELUF32(
        const float* X, float* Y, size_t N);
    
    // Attention Q @ K^T
    static void AttentionQKF32(
        const float* Q, const float* K, float* scores,
        size_t seq_len, size_t head_dim, float scale);
    
    // Attention Softmax @ V
    static void AttentionSoftmaxVF32(
        const float* scores, const float* V, float* output,
        size_t seq_len, size_t head_dim);
};

} // namespace Runtime
} // namespace RawrXD
