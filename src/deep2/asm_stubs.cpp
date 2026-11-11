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

// ============================================================================
// IQ2_XXS Dequantization — uses GGML's authoritative implementation
// Defined in ggml-quants.c and declared in ggml-quants.h; NOT redefined here
// to avoid duplicate symbol conflicts at link time.
// ============================================================================

// ============================================================================
// IQ Kernel Registration — Register Imatrix-quantized kernels
// ============================================================================
namespace Deep2 {
void RegisterIQKernels() {
    // Register IQ2_XXS (type 16) - uses GGML's dequantization
    // GEMV will use dequant + fp32 fallback via QuantKernelRegistry's scalar path
    // The actual GEMV for IQ types is handled by the generic LinearW path
    // which calls the registered dequant kernel then does fp32 GEMV
    
    // Note: IQ2_XXS dequant is already registered in QuantKernelRegistry::RegisterBuiltins
    // via RegisterDequant(GGML_TYPE_IQ2_XXS, dequant_iq2_xxs)
    // where dequant_iq2_xxs calls GGML's dequantize_row_iq2_xxs
}
}

// ============================================================================
// ============================================================================
// NVFP4 Dequantization — NVIDIA 4-bit floating point (E2M1)
// Block layout: 4 bytes FP32 scale + 32 bytes packed data (64 x 4-bit elements)
// Value = (-1)^sign * 2^(exp-1) * (1 + mantissa * 0.5) * block_scale
//   where exp is 2-bit biased by 1, mantissa is 1 bit
// ============================================================================
static void Dequant_NVFP4_AVX2(const uint8_t* weights, const float* scales,
                               float* output, size_t rows, size_t cols) {
    const size_t blockElems = 64;
    const size_t numBlocks = (cols + blockElems - 1) / blockElems;

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* rowWeights = weights + r * numBlocks * 36; // 36 bytes per block
        for (size_t b = 0; b < numBlocks; ++b) {
            float blockScale;
            memcpy(&blockScale, rowWeights + b * 36, 4);
            const uint8_t* packed = rowWeights + b * 36 + 4;
            size_t elemStart = b * blockElems;
            size_t elemsInBlock = (b == numBlocks - 1) ? (cols - elemStart) : blockElems;

            for (size_t i = 0; i < elemsInBlock; ++i) {
                size_t byteIdx = i / 2;
                uint8_t byte = packed[byteIdx];
                uint8_t nibble = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);

                uint8_t sign = (nibble >> 3) & 0x1;
                uint8_t exp  = (nibble >> 1) & 0x3;
                uint8_t mant = nibble & 0x1;

                // NVFP4 E2M1: value = (-1)^sign * 2^(exp-1) * (1 + mant * 0.5)
                float mantissa = 1.0f + static_cast<float>(mant) * 0.5f;
                float exponent = (exp == 0) ? 0.5f : ldexpf(1.0f, exp - 1);
                float val = exponent * mantissa;
                if (sign) val = -val;
                output[r * cols + elemStart + i] = val * blockScale;
            }
        }
    }
}

// ============================================================================
// NVFP4 GEMV — output[rows] = dequant(weights[rows, cols]) * input[cols]
// ============================================================================
static void NVFP4_GEMV_AVX2(const uint8_t* weights, const float* scales,
                            const float* input, float* output,
                            size_t rows, size_t cols) {
    const size_t blockElems = 64;
    const size_t numBlocks = (cols + blockElems - 1) / blockElems;

    for (size_t r = 0; r < rows; ++r) {
        const uint8_t* rowWeights = weights + r * numBlocks * 36;
        float acc = 0.0f;
        for (size_t b = 0; b < numBlocks; ++b) {
            float blockScale;
            memcpy(&blockScale, rowWeights + b * 36, 4);
            const uint8_t* packed = rowWeights + b * 36 + 4;
            size_t elemStart = b * blockElems;
            size_t elemsInBlock = (b == numBlocks - 1) ? (cols - elemStart) : blockElems;

            for (size_t i = 0; i < elemsInBlock; ++i) {
                size_t byteIdx = i / 2;
                uint8_t byte = packed[byteIdx];
                uint8_t nibble = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);

                uint8_t sign = (nibble >> 3) & 0x1;
                uint8_t exp  = (nibble >> 1) & 0x3;
                uint8_t mant = nibble & 0x1;

                float mantissa = 1.0f + static_cast<float>(mant) * 0.5f;
                float exponent = (exp == 0) ? 0.5f : ldexpf(1.0f, exp - 1);
                float val = exponent * mantissa;
                if (sign) val = -val;

                acc += val * blockScale * input[elemStart + i];
            }
        }
        output[r] = acc;
    }
}

// FP16 GEMV Fallback — Used when MASM implementation is not available
// ============================================================================
#if !defined(RAWRXD_TOOL_OWNS_FP16_GEMV)
extern "C" void Deep2_FP16_GEMV(const void* weights, const float* input, float* output, unsigned int rows, unsigned int cols) {
    const uint16_t* w = static_cast<const uint16_t*>(weights);
    for (unsigned int r = 0; r < rows; ++r) {
        float sum = 0.0f;
        for (unsigned int c = 0; c < cols; ++c) {
            // Convert FP16 to FP32
            uint16_t h = w[r * cols + c];
            uint32_t bits = (static_cast<uint32_t>(h & 0x8000) << 16) |
                           (((h >> 10) & 0x1F) == 0 ? 0 : (((h >> 10) & 0x1F) + 112) << 23) |
                           (static_cast<uint32_t>(h & 0x3FF) << 13);
            float fw;
            std::memcpy(&fw, &bits, sizeof(float));
            sum += fw * input[c];
        }
        output[r] = sum;
    }
}
#endif
