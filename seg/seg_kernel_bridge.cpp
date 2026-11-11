#include "seg_kernel_bridge.hpp"
#include "../../rawrxd/src/kernels/avx2_kernels.hpp"
#include "../../rawrxd/src/kernels/avx512_kernels.hpp"
#include "quantization_kernels.hpp"
#include <cstring>
#include <cmath>
#include <algorithm>
#include <vector>

namespace SEG {

KernelConfig KernelBridge::config_;
bool KernelBridge::initialized_ = false;

void KernelBridge::Initialize() {
    if (initialized_) return;
    
    // Detect CPU capabilities
    auto features = rawrxd::kernels::CPUFeatures::Detect();
    config_.use_avx512 = features.has_avx512f;
    config_.use_avx2 = features.has_avx2;
    config_.use_fma = features.has_fma;
    
    initialized_ = true;
}

bool KernelBridge::IsAvailable() {
    if (!initialized_) Initialize();
    return config_.use_avx512 || config_.use_avx2;
}

bool KernelBridge::HasAVX512() {
    if (!initialized_) Initialize();
    return config_.use_avx512;
}

bool KernelBridge::HasAVX2() {
    if (!initialized_) Initialize();
    return config_.use_avx2;
}

size_t KernelBridge::GetOptimalBlockSize(size_t head_dim) {
    // For AVX512, process 16 floats at a time
    // For AVX2, process 8 floats at a time
    // Choose block size that aligns well with cache lines (64 bytes = 16 floats)
    
    if (HasAVX512()) {
        // 64x64 blocks work well for AVX512 attention
        return 64;
    } else if (HasAVX2()) {
        // 32x32 or 64x64 for AVX2
        return 32;
    }
    return 16;  // Scalar fallback
}

// ============================================================================
// Matrix Operations
// ============================================================================

void KernelBridge::MatMul(const float* A, const float* B, float* C,
                           size_t M, size_t N, size_t K) {
    if (!initialized_) Initialize();
    
    // Clear output first
    std::memset(C, 0, M * N * sizeof(float));
    
    // Use dispatch layer
    rawrxd::kernels::KernelDispatch::MatMulF32(A, B, C, M, N, K);
}

void KernelBridge::MatMulAccumulate(const float* A, const float* B, float* C,
                                     size_t M, size_t N, size_t K) {
    if (!initialized_) Initialize();
    
    // Dispatch layer already accumulates
    rawrxd::kernels::KernelDispatch::MatMulF32(A, B, C, M, N, K);
}

// ============================================================================
// Vector Operations
// ============================================================================

float KernelBridge::VecDot(const float* A, const float* B, size_t N) {
    if (!initialized_) Initialize();
    return rawrxd::kernels::KernelDispatch::VecDotF32(A, B, N);
}

void KernelBridge::VecAdd(const float* A, const float* B, float* C, size_t N) {
    if (!initialized_) Initialize();
    rawrxd::kernels::KernelDispatch::VecAddF32(A, B, C, N);
}

void KernelBridge::VecScale(const float* X, float scale, float* Y, size_t N) {
    if (!initialized_) Initialize();
    rawrxd::kernels::KernelDispatch::VecScaleF32(X, scale, Y, N);
}

void KernelBridge::VecMul(const float* A, const float* B, float* C, size_t N) {
    if (!initialized_) Initialize();
    rawrxd::kernels::KernelDispatch::VecMulF32(A, B, C, N);
}

// ============================================================================
// Activation Functions
// ============================================================================

void KernelBridge::Softmax(const float* X, float* Y, size_t N) {
    if (!initialized_) Initialize();
    rawrxd::kernels::KernelDispatch::SoftmaxF32(X, Y, N);
}

void KernelBridge::RMSNorm(const float* X, const float* weight, float eps,
                            float* Y, size_t N) {
    if (!initialized_) Initialize();
    rawrxd::kernels::KernelDispatch::RMSNormF32(X, weight, eps, Y, N);
}

void KernelBridge::SiLU(const float* X, float* Y, size_t N) {
    if (!initialized_) Initialize();
    rawrxd::kernels::KernelDispatch::SiLUF32(X, Y, N);
}

void KernelBridge::GELU(const float* X, float* Y, size_t N) {
    if (!initialized_) Initialize();
    rawrxd::kernels::KernelDispatch::GELUF32(X, Y, N);
}

// ============================================================================
// Attention Operations
// ============================================================================

void KernelBridge::AttentionQK(const float* Q, const float* K, float* scores,
                                size_t m, size_t n, size_t k, float scale) {
    if (!initialized_) Initialize();
    // The kernel expects: Q, K, scores, seq_len, head_dim, scale
    // where seq_len = m, head_dim = k
    // Note: n is the KV sequence length (not used in this simplified version)
    (void)n; // Suppress unused warning
    rawrxd::kernels::KernelDispatch::AttentionQKF32(Q, K, scores, m, k, scale);
}

void KernelBridge::AttentionSoftmaxV(const float* S, const float* V_block,
                                     float* acc, float* m, float* l,
                                     size_t q_len, size_t kv_len, size_t head_dim) {
    if (!initialized_) Initialize();
    // For now, use the basic kernel dispatch - FlashAttention-specific online softmax
    // would need a specialized kernel
    rawrxd::kernels::KernelDispatch::AttentionSoftmaxVF32(S, V_block, acc, q_len, head_dim);
    
    // Update m and l for FlashAttention compatibility (simplified)
    for (size_t i = 0; i < q_len; ++i) {
        float max_val = S[i * kv_len];
        for (size_t j = 1; j < kv_len; ++j) {
            max_val = std::max(max_val, S[i * kv_len + j]);
        }
        m[i] = max_val;
        
        float sum = 0.0f;
        for (size_t j = 0; j < kv_len; ++j) {
            sum += std::exp(S[i * kv_len + j] - max_val);
        }
        l[i] = sum;
    }
}

void KernelBridge::AttentionForward(const float* Q, const float* K, const float* V,
                                     float* O, size_t batch_size, size_t num_heads,
                                     size_t seq_len, size_t head_dim) {
    if (!initialized_) Initialize();
    
    const float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    const size_t head_size = seq_len * head_dim;
    const size_t qk_size = seq_len * seq_len;
    
    // Allocate temporary buffer for QK^T scores
    float* scores = new float[qk_size];
    float* softmax_scores = new float[qk_size];
    
    for (size_t b = 0; b < batch_size; ++b) {
        for (size_t h = 0; h < num_heads; ++h) {
            const float* Q_bh = Q + (b * num_heads + h) * head_size;
            const float* K_bh = K + (b * num_heads + h) * head_size;
            const float* V_bh = V + (b * num_heads + h) * head_size;
            float* O_bh = O + (b * num_heads + h) * head_size;
            
            // Step 1: Q @ K^T
            AttentionQK(Q_bh, K_bh, scores, seq_len, seq_len, head_dim, scale);
            
            // Step 2: Softmax over rows
            for (size_t i = 0; i < seq_len; ++i) {
                Softmax(scores + i * seq_len, softmax_scores + i * seq_len, seq_len);
            }
            
            // Step 3: Softmax(QK^T) @ V - need dummy m, l arrays for interface compatibility
            std::vector<float> m_vec(seq_len);
            std::vector<float> l_vec(seq_len);
            AttentionSoftmaxV(softmax_scores, V_bh, O_bh, m_vec.data(), l_vec.data(), seq_len, seq_len, head_dim);
        }
    }
    
    delete[] scores;
    delete[] softmax_scores;
}

// ============================================================================
// Quantization Operations
// ============================================================================

// Q4_0: 4-bit quantized with 16-value blocks
// Each block: 16-bit scale (float16) + 16x 4-bit values packed into 8 bytes
// Total: 2 + 8 = 10 bytes per 16 values = 0.625 bytes/value

struct Q4_0_Block {
    uint16_t scale;  // float16
    uint8_t values[8];  // 16 x 4-bit packed
};

static float HalfToFloat(uint16_t h) {
    // Simple half-to-float conversion
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        // Denormal
        float val = mant / 1024.0f;
        return sign ? -val * 1.0e-38f : val * 1.0e-38f;
    }
    if (exp == 31) {
        return mant ? std::numeric_limits<float>::quiet_NaN() :
               (sign ? -std::numeric_limits<float>::infinity() :
                       std::numeric_limits<float>::infinity());
    }
    
    float f = std::pow(2.0f, static_cast<float>(exp - 15)) * (1.0f + mant / 1024.0f);
    return sign ? -f : f;
}

void KernelBridge::DequantizeQ4_0(const void* quantized, float* output,
                                     size_t num_elements) {
    const Q4_0_Block* blocks = static_cast<const Q4_0_Block*>(quantized);
    const size_t num_blocks = (num_elements + 15) / 16;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        float scale = HalfToFloat(blocks[b].scale);
        
        for (size_t i = 0; i < 16; ++i) {
            size_t idx = b * 16 + i;
            if (idx >= num_elements) break;
            
            // Extract 4-bit value
            uint8_t packed = blocks[b].values[i / 2];
            uint8_t nibble = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
            
            // Dequantize: value = (nibble - 8) * scale
            output[idx] = (static_cast<float>(nibble) - 8.0f) * scale;
        }
    }
}

// Q4_K: 4-bit K-quantization
// Implemented in quantization_kernels.hpp/cpp
void KernelBridge::DequantizeQ4_K(const void* quantized, float* output,
                                     size_t num_elements) {
    Quantization::QuantizationKernels::DequantizeQ4_K(quantized, output, num_elements);
}

// Q6_K: 6-bit quantized (K-quants)
// Now implemented in quantization_kernels.hpp/cpp
void KernelBridge::DequantizeQ6_K(const void* quantized, float* output,
                                     size_t num_elements) {
    // Delegate to the optimized implementation
    Quantization::QuantizationKernels::DequantizeQ6_K(quantized, output, num_elements);
}

// Q8_K: 8-bit K-quantization
// Implemented in quantization_kernels.hpp/cpp
void KernelBridge::DequantizeQ8_K(const void* quantized, float* output,
                                     size_t num_elements) {
    Quantization::QuantizationKernels::DequantizeQ8_K(quantized, output, num_elements);
}

// Q8_0: 8-bit quantized with 32-value blocks
// Each block: 16-bit scale (float16) + 32x 8-bit values
// Total: 2 + 32 = 34 bytes per 32 values = 1.0625 bytes/value

struct Q8_0_Block {
    uint16_t scale;  // float16
    int8_t values[32];
};

void KernelBridge::DequantizeQ8_0(const void* quantized, float* output,
                                     size_t num_elements) {
    const Q8_0_Block* blocks = static_cast<const Q8_0_Block*>(quantized);
    const size_t num_blocks = (num_elements + 31) / 32;
    
    for (size_t b = 0; b < num_blocks; ++b) {
        float scale = HalfToFloat(blocks[b].scale);
        
        for (size_t i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= num_elements) break;
            
            output[idx] = static_cast<float>(blocks[b].values[i]) * scale;
        }
    }
}

} // namespace SEG
