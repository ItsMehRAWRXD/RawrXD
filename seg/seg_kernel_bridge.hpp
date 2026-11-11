#pragma once
// ============================================================================
// SEG Kernel Bridge - Integrates RawrXD Optimized Kernels into SEG
// ============================================================================
// Provides clean interface between SEG execution graph and AVX512 kernels
// ============================================================================

#include "seg_core.hpp"
#include <cstdint>
#include <cstddef>

namespace SEG {

// Forward declarations
struct KernelConfig {
    bool use_avx512 = true;
    bool use_avx2 = true;
    bool use_fma = true;
    bool use_scalar_fallback = true;
    size_t block_size = 64;  // For tiled operations
};

// Kernel bridge interface
class KernelBridge {
public:
    // Initialize kernel capabilities detection
    static void Initialize();
    
    // Check if AVX512 is available
    static bool HasAVX512();
    
    // Check if AVX2 is available
    static bool HasAVX2();
    
    // Get optimal block size for attention
    static size_t GetOptimalBlockSize(size_t head_dim);
    
    // =========================================================================
    // Matrix Operations
    // =========================================================================
    
    // C = A @ B (matrix multiply)
    static void MatMul(const float* A, const float* B, float* C,
                       size_t M, size_t N, size_t K);
    
    // C = A @ B + C (accumulating)
    static void MatMulAccumulate(const float* A, const float* B, float* C,
                                  size_t M, size_t N, size_t K);
    
    // =========================================================================
    // Vector Operations
    // =========================================================================
    
    // dot = sum(A[i] * B[i])
    static float VecDot(const float* A, const float* B, size_t N);
    
    // C = A + B
    static void VecAdd(const float* A, const float* B, float* C, size_t N);
    
    // Y = X * scale
    static void VecScale(const float* X, float scale, float* Y, size_t N);
    
    // C = A * B (element-wise)
    static void VecMul(const float* A, const float* B, float* C, size_t N);
    
    // =========================================================================
    // Activation Functions
    // =========================================================================
    
    // Softmax: Y = softmax(X)
    static void Softmax(const float* X, float* Y, size_t N);
    
    // RMSNorm: Y = X / sqrt(mean(X^2) + eps) * weight
    static void RMSNorm(const float* X, const float* weight, float eps,
                        float* Y, size_t N);
    
    // SiLU: Y = X * sigmoid(X)
    static void SiLU(const float* X, float* Y, size_t N);
    
    // GELU: Y = GELU(X)
    static void GELU(const float* X, float* Y, size_t N);
    
    // =========================================================================
    // Attention Operations
    // =========================================================================
    
    // Check if kernel bridge is available (AVX512 or AVX2 detected)
    static bool IsAvailable();
    
    // Q @ K^T with scaling (FlashAttention compatible)
    static void AttentionQK(const float* Q, const float* K, float* scores,
                            size_t m, size_t n, size_t k, float scale);
    
    // Softmax(QK^T) @ V with online softmax (FlashAttention compatible)
    static void AttentionSoftmaxV(const float* S, const float* V_block,
                                   float* acc, float* m, float* l,
                                   size_t q_len, size_t kv_len, size_t head_dim);
    
    // Full attention forward pass (tiled)
    static void AttentionForward(const float* Q, const float* K, const float* V,
                                  float* O, size_t batch_size, size_t num_heads,
                                  size_t seq_len, size_t head_dim);
    
    // =========================================================================
    // Quantization Operations
    // =========================================================================
    
    // Dequantize Q4_0 block to float
    static void DequantizeQ4_0(const void* quantized, float* output,
                                  size_t num_elements);
    
    // Dequantize Q4_K block to float (K-quants)
    static void DequantizeQ4_K(const void* quantized, float* output,
                                  size_t num_elements);
    
    // Dequantize Q6_K block to float (K-quants)
    static void DequantizeQ6_K(const void* quantized, float* output,
                                  size_t num_elements);
    
    // Dequantize Q8_0 block to float
    static void DequantizeQ8_0(const void* quantized, float* output,
                                  size_t num_elements);
    
    // Dequantize Q8_K block to float (K-quants)
    static void DequantizeQ8_K(const void* quantized, float* output,
                                  size_t num_elements);
    
private:
    static KernelConfig config_;
    static bool initialized_;
};

} // namespace SEG
