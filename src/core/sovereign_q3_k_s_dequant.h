// =============================================================================
// sovereign_q3_k_s_dequant.h
// Q3_K_S Dequantization Kernel Header
// Converts 3-bit K-quantized weights to float32 for inference
// =============================================================================

#ifndef SOVEREIGN_Q3_K_S_DEQUANT_H
#define SOVEREIGN_Q3_K_S_DEQUANT_H

#include <cstdint>

namespace Sovereign {

// =============================================================================
// Q3_K_S Dequantization Functions
// =============================================================================

// Main dequantization function - dispatches to best available implementation
void Dequantize_Q3_K_S(const uint8_t* src, float* dst, uint32_t n_elements);

// Reference C++ implementation (always available)
void Dequantize_Q3_K_S_Reference(const uint8_t* src, float* dst, uint32_t n_elements);

// AVX2-optimized implementation (if available)
#ifdef __AVX2__
void Dequantize_Q3_K_S_AVX2(const uint8_t* src, float* dst, uint32_t n_elements);
#endif

// =============================================================================
// Tensor Dequantization Helper
// =============================================================================

// Dequantize an entire tensor
// Parameters:
//   quantized_data    - Pointer to Q3_K_S quantized data
//   quantized_size    - Size of quantized data in bytes
//   n_elements        - Number of elements to dequantize
//   out_dequantized   - Output pointer (allocated with VirtualAlloc)
// Returns:
//   true on success, false on failure
bool DequantizeTensor_Q3_K_S(
    const uint8_t* quantized_data,
    uint64_t quantized_size,
    uint32_t n_elements,
    float** out_dequantized
);

// =============================================================================
// Size Calculations
// =============================================================================

// Calculate dequantized size from quantized size
uint64_t GetDequantizedSize_Q3_K_S(uint64_t quantized_size);

// Calculate element count from quantized size
uint32_t GetElementCount_Q3_K_S(uint64_t quantized_size);

} // namespace Sovereign

#endif // SOVEREIGN_Q3_K_S_DEQUANT_H
