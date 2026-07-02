// =============================================================================
// sovereign_q6_k_dequant.h
// Q6_K Dequantization Kernel Header
// Converts 6-bit K-quantized weights to float32 for inference
// =============================================================================

#ifndef SOVEREIGN_Q6_K_DEQUANT_H
#define SOVEREIGN_Q6_K_DEQUANT_H

#include <cstdint>

namespace Sovereign {

// =============================================================================
// Q6_K Dequantization Functions
// =============================================================================

// Main dequantization function
void Dequantize_Q6_K(const uint8_t* src, float* dst, uint32_t n_elements);

// Reference C++ implementation
void Dequantize_Q6_K_Reference(const uint8_t* src, float* dst, uint32_t n_elements);

// =============================================================================
// Tensor Dequantization Helper
// =============================================================================
bool DequantizeTensor_Q6_K(
    const uint8_t* quantized_data,
    uint64_t quantized_size,
    uint32_t n_elements,
    float** out_dequantized
);

// =============================================================================
// Size Calculations
// =============================================================================

// Calculate dequantized size from quantized size
uint64_t GetDequantizedSize_Q6_K(uint64_t quantized_size);

// Calculate element count from quantized size
uint32_t GetElementCount_Q6_K(uint64_t quantized_size);

} // namespace Sovereign

#endif // SOVEREIGN_Q6_K_DEQUANT_H
