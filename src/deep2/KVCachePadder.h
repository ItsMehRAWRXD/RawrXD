// ============================================================================
// Blocker #23: KV Cache Head Dimension Padding
// Pads KV cache head dimensions to alignment boundaries for Q2_K/Q4_K
// quantized models where head_dim may not be a multiple of 32.
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

namespace Deep2 {

class KVCachePadder {
public:
    // Calculate padded head dimension for cache alignment
    // Ensures head_dim is padded to at least 32 elements (AVX2 width)
    static int PadHeadDim(int headDim, int alignment = 32) {
        if (headDim <= 0) return alignment;
        return ((headDim + alignment - 1) / alignment) * alignment;
    }

    // Calculate the actual bytes needed for KV cache with padding
    static size_t CalculatePaddedKVBytes(int numLayers, int numKVHeads, int headDim,
                                          int maxSeqLen, int alignment = 32) {
        int paddedHeadDim = PadHeadDim(headDim, alignment);
        return static_cast<size_t>(numLayers) * numKVHeads * paddedHeadDim * maxSeqLen * sizeof(float);
    }

    // Copy KV data with padding (scatter/gather)
    static void CopyWithPadding(float* dst, const float* src, int headDim, int paddedHeadDim,
                                 size_t numElements) {
        if (headDim == paddedHeadDim) {
            std::memcpy(dst, src, numElements * headDim * sizeof(float));
            return;
        }
        
        for (size_t i = 0; i < numElements; ++i) {
            // Copy actual data
            std::memcpy(dst + i * paddedHeadDim, src + i * headDim, headDim * sizeof(float));
            // Zero pad the remainder
            std::memset(dst + i * paddedHeadDim + headDim, 0,
                       (paddedHeadDim - headDim) * sizeof(float));
        }
    }

    // Extract unpadded KV data from padded cache
    static void ExtractWithoutPadding(float* dst, const float* src, int headDim,
                                       int paddedHeadDim, size_t numElements) {
        if (headDim == paddedHeadDim) {
            std::memcpy(dst, src, numElements * headDim * sizeof(float));
            return;
        }
        
        for (size_t i = 0; i < numElements; ++i) {
            std::memcpy(dst + i * headDim, src + i * paddedHeadDim, headDim * sizeof(float));
        }
    }

    // Get optimal alignment for a given quantization type
    static int GetAlignmentForQuant(int quantType) {
        // Q2_K, Q3_K, Q4_K, Q5_K, Q6_K typically use 32-element blocks
        // FP16/FP32 can use 8-element alignment (AVX2)
        switch (quantType) {
            case 2:  // Q4_0
            case 3:  // Q4_1
                return 32;
            case 10: // Q2_K
            case 11: // Q3_K
            case 12: // Q4_K
            case 13: // Q5_K
            case 14: // Q6_K
                return 64; // K-quants use larger blocks
            default:
                return 32;
        }
    }
};

} // namespace Deep2
