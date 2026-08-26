// ============================================================================
// asm_stubs.cpp — Real implementations for inference kernels (was stubs)
// Replaces no-ops with reference implementations that actually compute.
// These are superseded by real MASM when linked; this file ensures
// the benchmark always has working fallbacks.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <vector>
#include <algorithm>

extern "C" {

// ============================================================================
// RMSNorm — Root Mean Square Layer Normalization
//   output[i] = input[i] / sqrt(mean(input^2) + eps)
// ============================================================================
void Deep2_RMSNorm_AVX2(const float* input, float* output, size_t dim, float eps) {
    float sumSq = 0.0f;
    for (size_t i = 0; i < dim; ++i) sumSq += input[i] * input[i];
    float rms = 1.0f / std::sqrt(sumSq / static_cast<float>(dim) + eps);
    for (size_t i = 0; i < dim; ++i) output[i] = input[i] * rms;
}

void rmsnorm_forward_avx2(const float* input, float* output, size_t dim, float eps) {
    Deep2_RMSNorm_AVX2(input, output, dim, eps);
}

// ============================================================================
// Softmax — Numerically stable softmax
// ============================================================================
void softmax_forward_avx2(const float* input, float* output, size_t dim) {
    float maxVal = input[0];
    for (size_t i = 1; i < dim; ++i) if (input[i] > maxVal) maxVal = input[i];
    float sum = 0.0f;
    for (size_t i = 0; i < dim; ++i) {
        output[i] = std::exp(input[i] - maxVal);
        sum += output[i];
    }
    float invSum = 1.0f / (sum + 1e-6f);
    for (size_t i = 0; i < dim; ++i) output[i] *= invSum;
}

// ============================================================================
// SiLU — Sigmoid Linear Unit: x * sigmoid(x)
// ============================================================================
void silu_activation_avx512(const float* input, float* output, size_t dim) {
    for (size_t i = 0; i < dim; ++i) {
        output[i] = input[i] * (1.0f / (1.0f + std::exp(-input[i])));
    }
}

// ============================================================================
// Q4_0 Dequantization — Dequantize 4-bit weights to FP32
// Block layout: 4 bytes scale + 16 bytes quants (32 x 4-bit)
// ============================================================================
void Dequant_Q4_0_AVX2(const uint8_t* weights, const float* input, float* output,
                       size_t outDim, size_t inDim) {
    (void)input; // GEMV uses weights directly; this is a dequant stub
    const size_t blockSize = 32;
    const size_t numBlocks = inDim / blockSize;
    
    for (size_t o = 0; o < outDim; ++o) {
        float sum = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            size_t blockOffset = o * numBlocks * 20 + b * 20; // 20 = 4 scale + 16 quants
            float scale = *reinterpret_cast<const float*>(weights + blockOffset);
            const uint8_t* quants = weights + blockOffset + 4;
            
            for (size_t i = 0; i < blockSize; ++i) {
                uint8_t q = (i % 2 == 0) ? (quants[i/2] & 0x0F) : (quants[i/2] >> 4);
                float val = (q - 8.0f) * scale;
                sum += val * input[b * blockSize + i];
            }
        }
        output[o] = sum;
    }
}

// ============================================================================
// Flash Attention — Scaled dot-product attention with causal mask
//   O = softmax((QK^T)/sqrt(d_k))V
// ============================================================================
void flash_attn_asm_avx2(const float* Q, const float* K, const float* V,
                         float* O, uint32_t seqLen, uint32_t headDim, float scale) {
    std::vector<float> scores(seqLen);
    std::vector<float> attnWeights(seqLen);
    
    for (uint32_t qPos = 0; qPos < seqLen; ++qPos) {
        // Compute attention scores with causal mask (kPos <= qPos)
        float maxScore = -1e30f;
        for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
            float dot = 0.0f;
            for (uint32_t d = 0; d < headDim; ++d) {
                dot += Q[qPos * headDim + d] * K[kPos * headDim + d];
            }
            scores[kPos] = dot * scale;
            if (scores[kPos] > maxScore) maxScore = scores[kPos];
        }
        
        // Softmax
        float sumExp = 0.0f;
        for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
            attnWeights[kPos] = std::exp(scores[kPos] - maxScore);
            sumExp += attnWeights[kPos];
        }
        float invSum = 1.0f / (sumExp + 1e-6f);
        for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
            attnWeights[kPos] *= invSum;
        }
        
        // Weighted sum of values
        for (uint32_t d = 0; d < headDim; ++d) {
            float sum = 0.0f;
            for (uint32_t kPos = 0; kPos <= qPos; ++kPos) {
                sum += attnWeights[kPos] * V[kPos * headDim + d];
            }
            O[qPos * headDim + d] = sum;
        }
    }
}

} // extern "C"

namespace Deep2 {
// ============================================================================
// IQ Kernel Registration — Register Imatrix-quantized kernels
// ============================================================================
void RegisterIQKernels() {
    // IQ2_XXS, IQ3_XXS, IQ4_NL kernels are registered here
    // These use importance matrix (imatrix) quantization for higher quality
    // at extreme compression ratios.
    // For now, the kernels are handled by the main registry.
}
}
