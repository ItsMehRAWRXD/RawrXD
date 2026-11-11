/*===========================================================================
 * Deep2Bridge_Quantized.hpp
 * 
 * Integration layer connecting Q4_K_M kernels to Deep2Bridge
 * 
 * This is the production path for quantized inference:
 *   GGUF Q4_K_M tensor -> Deep2Linear_Q4KM -> AVX2/AVX-512 kernels
 * 
 * Replaces the scalar dequantization path with optimized MASM kernels
 *===========================================================================*/

#pragma once

#include "Deep2_Q4KM.hpp"
#include <cstdint>
#include <cstddef>

// Forward declarations from Deep2Bridge
struct Deep2Config;
struct Deep2Context;

namespace RawrXD {
namespace Bridge {

/*===========================================================================
 * Quantized Layer Types
 *===========================================================================*/
enum class QuantizedLayerType {
    Q4_K_M,     // Primary target - best speed/compression ratio
    Q5_K_M,     // Higher quality option
    Q6_K,       // Maximum quality quantized
    Q8_0,       // 8-bit quantization
    FP16,       // Half precision
    FP32        // Full precision (fallback)
};

/*===========================================================================
 * Quantized Weight Handle
 * Opaque handle to quantized weights in GGUF-mapped memory
 *===========================================================================*/
struct QuantizedWeightHandle {
    const uint8_t* data = nullptr;      // GGUF-mapped data pointer
    size_t num_blocks = 0;               // Number of quantization blocks
    size_t rows = 0;                     // Output dimension
    size_t cols = 0;                     // Input dimension
    QuantizedLayerType type = QuantizedLayerType::FP32;
    bool valid = false;
    
    bool IsValid() const { return valid && data != nullptr; }
};

/*===========================================================================
 * Deep2 Quantized Linear Layer
 * High-level interface for quantized matrix operations
 *===========================================================================*/
class Deep2QuantizedLinear {
public:
    Deep2QuantizedLinear() = default;
    ~Deep2QuantizedLinear() = default;
    
    // Non-copyable (holds memory-mapped pointers)
    Deep2QuantizedLinear(const Deep2QuantizedLinear&) = delete;
    Deep2QuantizedLinear& operator=(const Deep2QuantizedLinear&) = delete;
    
    // Movable
    Deep2QuantizedLinear(Deep2QuantizedLinear&& other) noexcept;
    Deep2QuantizedLinear& operator=(Deep2QuantizedLinear&& other) noexcept;
    
    /**
     * Initialize from GGUF-mapped quantized weights
     * @param handle Quantized weight handle from GGUF loader
     * @return true on success
     */
    bool Initialize(const QuantizedWeightHandle& handle);
    
    /**
     * Matrix-vector multiplication: y = weights * x
     * Automatically selects best kernel (Q4_K_M, Q5_K_M, etc.)
     * @param x Input vector (cols elements)
     * @param y Output vector (rows elements)
     * @return true on success
     */
    bool Forward(const float* x, float* y);
    
    // Dimensions
    size_t Rows() const { return rows_; }
    size_t Cols() const { return cols_; }
    QuantizedLayerType Type() const { return type_; }
    bool IsInitialized() const { return initialized_; }
    
    // Performance stats
    struct Stats {
        uint64_t forward_calls = 0;
        uint64_t total_cycles = 0;
        double avg_cycles_per_call = 0.0;
        uint64_t dequant_time_ns = 0;
        uint64_t gemv_time_ns = 0;
    };
    Stats GetStats() const { return stats_; }
    void ResetStats() { stats_ = Stats{}; }

private:
    QuantizedWeightHandle weights_;
    size_t rows_ = 0;
    size_t cols_ = 0;
    QuantizedLayerType type_ = QuantizedLayerType::FP32;
    bool initialized_ = false;
    
    // Implementation-specific data
    union {
        Deep2::Q4KMLinear* q4km_impl;
        // Add other quantized types here
    } impl_ = {nullptr};
    
    Stats stats_ = {};
    
    // Forward implementations by type
    bool Forward_Q4KM(const float* x, float* y);
    bool Forward_FP32(const float* x, float* y);
};

/*===========================================================================
 * Deep2Bridge Quantized API
 * C-compatible functions for MASM/C++ interop
 *===========================================================================*/
extern "C" {

/**
 * Deep2Bridge_CreateQuantizedLinear
 * Create a quantized linear layer from GGUF-mapped weights
 * 
 * @param weight_data GGUF-mapped quantized weight data
 * @param num_blocks Number of quantization blocks
 * @param rows Output dimension
 * @param cols Input dimension
 * @param quant_type Quantization type (4=Q4_K_M, 5=Q5_K_M, etc.)
 * @return Opaque handle to quantized layer (nullptr on failure)
 */
__declspec(dllexport)
void* Deep2Bridge_CreateQuantizedLinear(
    const uint8_t* weight_data,
    size_t num_blocks,
    size_t rows,
    size_t cols,
    int quant_type
);

/**
 * Deep2Bridge_QuantizedLinear_Forward
 * Execute quantized matrix-vector multiplication
 * 
 * @param layer Layer handle from CreateQuantizedLinear
 * @param input Input vector (cols elements)
 * @param output Output vector (rows elements)
 * @return true on success
 */
__declspec(dllexport)
bool Deep2Bridge_QuantizedLinear_Forward(
    void* layer,
    const float* input,
    float* output
);

/**
 * Deep2Bridge_DestroyQuantizedLinear
 * Destroy quantized linear layer
 * 
 * @param layer Layer handle
 */
__declspec(dllexport)
void Deep2Bridge_DestroyQuantizedLinear(void* layer);

/**
 * Deep2Bridge_HasQuantizedKernels
 * Check if quantized kernels are available
 * 
 * @return true if Q4_K_M and other quantized kernels are available
 */
__declspec(dllexport)
bool Deep2Bridge_HasQuantizedKernels(void);

/**
 * Deep2Bridge_GetQuantizedKernelVersion
 * Get version string of quantized kernel implementation
 * 
 * @return Version string (e.g., "Q4KM-AVX512-v1.0")
 */
__declspec(dllexport)
const char* Deep2Bridge_GetQuantizedKernelVersion(void);

} // extern "C"

/*===========================================================================
 * Integration Helpers
 *===========================================================================*/

/**
 * Convert GGUF quantization type to internal enum
 */
inline QuantizedLayerType GGUFQuantToInternal(int gguf_quant_type) {
    // GGUF file_type values:
    // 0=F32, 1=F16, 2=Q4_0, 3=Q4_1, 7=Q8_0, 8=Q5_0, 9=Q5_1
    // 10=Q2_K, 11=Q3_K_S, 12=Q3_K_M, 13=Q3_K_L
    // 14=Q4_K_S, 15=Q4_K_M, 16=Q5_K_S, 17=Q5_K_M, 18=Q6_K
    switch (gguf_quant_type) {
        case 15: return QuantizedLayerType::Q4_K_M;
        case 17: return QuantizedLayerType::Q5_K_M;
        case 18: return QuantizedLayerType::Q6_K;
        case 7:  return QuantizedLayerType::Q8_0;
        case 1:  return QuantizedLayerType::FP16;
        case 0:  return QuantizedLayerType::FP32;
        default: return QuantizedLayerType::FP32;  // Fallback
    }
}

/**
 * Check if quantization type is supported by Deep2 kernels
 */
inline bool IsQuantizationSupported(int gguf_quant_type) {
    switch (gguf_quant_type) {
        case 15:  // Q4_K_M
        case 1:   // F16
        case 0:   // F32
            return true;
        default:
            return false;  // Others not yet implemented
    }
}

} // namespace Bridge
} // namespace RawrXD
