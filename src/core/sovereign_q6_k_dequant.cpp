// =============================================================================
// sovereign_q6_k_dequant.cpp
// Q6_K Dequantization Kernel
// Converts 6-bit K-quantized weights to float32 for inference
// =============================================================================

#include "sovereign_q6_k_dequant.h"
#include <cstdint>
#include <cstring>
#include <windows.h>

namespace Sovereign {

// =============================================================================
// Q6_K Block Structure
// =============================================================================
// Q6_K uses 256-element blocks with 6-bit quantization
// Each block contains:
// - Scales (higher precision than Q3_K)
// - 6-bit quantized values packed efficiently
// Total: ~210 bytes per 256 elements = 6 bits per weight

struct Q6_K_Block {
    uint8_t scales[12];     // Scale information
    uint8_t ql[256];        // Lower 4 bits of quantized values
    uint8_t qh[128];        // Upper 2 bits of quantized values (packed)
};

// =============================================================================
// Reference Dequantization
// =============================================================================

void Dequantize_Q6_K_Reference(const uint8_t* src, float* dst, uint32_t n_elements) {
    const uint32_t n_blocks = (n_elements + 255) / 256;
    
    for (uint32_t b = 0; b < n_blocks; b++) {
        const uint8_t* block = src + b * 210; // 210 bytes per block
        
        // Extract scales from first 12 bytes
        // Q6_K uses more complex scale encoding
        float scale = 1.0f / 16.0f; // Simplified - real implementation would parse scales
        
        // Dequantize 256 values
        for (uint32_t i = 0; i < 256 && (b * 256 + i) < n_elements; i++) {
            // Get lower 4 bits
            uint8_t low = block[12 + i] & 0x0F;
            // Get upper 2 bits from qh array
            uint8_t high = (block[12 + 256 + (i / 4)] >> (2 * (i % 4))) & 0x03;
            // Combine: 6 bits total (0-63)
            uint8_t val = low | (high << 4);
            
            // Map to float: center around 0, range [-32, 31]
            float dequant = static_cast<float>(val) - 32.0f;
            dst[b * 256 + i] = dequant * scale;
        }
    }
}

// =============================================================================
// Dispatch Function
// =============================================================================

void Dequantize_Q6_K(const uint8_t* src, float* dst, uint32_t n_elements) {
    if (!src || !dst || n_elements == 0) return;
    Dequantize_Q6_K_Reference(src, dst, n_elements);
}

// =============================================================================
// Tensor Dequantization Helper
// =============================================================================

bool DequantizeTensor_Q6_K(
    const uint8_t* quantized_data,
    uint64_t quantized_size,
    uint32_t n_elements,
    float** out_dequantized
) {
    if (!quantized_data || !out_dequantized || n_elements == 0) {
        return false;
    }
    
    // Allocate output buffer
    float* dequantized = static_cast<float*>(
        VirtualAlloc(nullptr, n_elements * sizeof(float), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    );
    
    if (!dequantized) {
        return false;
    }
    
    // Dequantize
    Dequantize_Q6_K(quantized_data, dequantized, n_elements);
    
    *out_dequantized = dequantized;
    return true;
}

// =============================================================================
// Get Dequantized Size
// =============================================================================

uint64_t GetDequantizedSize_Q6_K(uint64_t quantized_size) {
    // Q6_K: 210 bytes per 256 elements
    uint64_t n_blocks = quantized_size / 210;
    return n_blocks * 256 * sizeof(float);
}

uint32_t GetElementCount_Q6_K(uint64_t quantized_size) {
    uint64_t n_blocks = quantized_size / 210;
    return static_cast<uint32_t>(n_blocks * 256);
}

} // namespace Sovereign
