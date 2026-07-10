//==============================================================================
// SovereignKernelTypes.hpp
// Common type definitions for Sovereign kernel dispatch
//
// Shared between CPU MASM and GPU Titan paths
//
// Date: July 10, 2026
//==============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace sovereign {

//==============================================================================
// Tensor Descriptor
// Describes memory layout for kernel I/O
//==============================================================================
struct TensorDesc {
    void*    data{nullptr};          // Pointer to tensor data
    size_t   sizeBytes{0};           // Total size in bytes
    
    // Shape information (up to 4D for transformers)
    uint32_t dims[4]{0, 0, 0, 0};   // [batch, seq/heads, heads/seq, features]
    uint32_t numDims{0};             // Actual number of dimensions
    
    // Data type
    enum class DataType : uint8_t {
        F32 = 0,
        F16,
        BF16,
        Q4_0,   // 4-bit quantized, type 0
        Q4_1,   // 4-bit quantized, type 1
        Q8_0,   // 8-bit quantized, type 0
        Q8_1,   // 8-bit quantized, type 1
        I32,
        I64,
        Unknown = 255
    } dtype{DataType::F32};
    
    // Strides for each dimension (0 = contiguous)
    size_t strides[4]{0, 0, 0, 0};
    
    // Validation
    bool IsValid() const {
        return data != nullptr && sizeBytes > 0 && numDims > 0;
    }
    
    // Calculate linear index from multi-dimensional indices
    size_t LinearIndex(uint32_t i0, uint32_t i1 = 0, uint32_t i2 = 0, uint32_t i3 = 0) const {
        if (strides[0] != 0) {
            return i0 * strides[0] + i1 * strides[1] + i2 * strides[2] + i3 * strides[3];
        }
        // Contiguous layout
        return ((i0 * dims[1] + i1) * dims[2] + i2) * dims[3] + i3;
    }
    
    // Total number of elements
    size_t NumElements() const {
        if (numDims == 0) return 0;
        size_t n = 1;
        for (uint32_t i = 0; i < numDims; ++i) {
            n *= dims[i];
        }
        return n;
    }
    
    // Element size in bytes
    size_t ElementSize() const {
        switch (dtype) {
            case DataType::F32:  return 4;
            case DataType::F16:  return 2;
            case DataType::BF16: return 2;
            case DataType::Q4_0: return 0;  // Special packing
            case DataType::Q4_1: return 0;
            case DataType::Q8_0: return 1;
            case DataType::Q8_1: return 1;
            case DataType::I32:  return 4;
            case DataType::I64:  return 8;
            default:             return 0;
        }
    }
};

//==============================================================================
// Kernel Parameters
// Flexible parameter passing for kernel dispatch
//==============================================================================
struct KernelParams {
    // Scalar parameters (up to 8)
    union ScalarParam {
        float    f32;
        int32_t  i32;
        uint32_t u32;
        int64_t  i64;
        uint64_t u64;
    } scalars[8];
    
    uint32_t numScalars{0};
    
    // Pointer parameters (up to 4)
    void* pointers[4];
    uint32_t numPointers{0};
    
    // Helper to add float
    void AddFloat(float v) {
        if (numScalars < 8) {
            scalars[numScalars++].f32 = v;
        }
    }
    
    // Helper to add int
    void AddInt(int32_t v) {
        if (numScalars < 8) {
            scalars[numScalars++].i32 = v;
        }
    }
    
    // Helper to add pointer
    void AddPointer(void* p) {
        if (numPointers < 4) {
            pointers[numPointers++] = p;
        }
    }
};

//==============================================================================
// Quantization Parameters
// For Q4/Q8 quantized operations
//==============================================================================
struct QuantParams {
    float scale{1.0f};       // Quantization scale
    float zeroPoint{0.0f};   // Zero point offset
    uint32_t blockSize{32};  // Block size for grouped quantization
    
    // Dequantize: (q - zeroPoint) * scale
    // Quantize:   round(x / scale) + zeroPoint
};

//==============================================================================
// Attention Parameters
// For attention kernel variants
//==============================================================================
struct AttentionParams {
    float scale{1.0f};           // Attention scale (typically 1/sqrt(head_dim))
    float softCap{0.0f};         // Soft capping value (0 = disabled)
    uint32_t seqLen{0};          // Sequence length
    uint32_t headDim{0};         // Head dimension
    uint32_t numHeads{0};        // Number of attention heads
    bool causal{true};           // Causal masking
    bool useAlibi{false};        // ALiBi position bias
    bool useFlash{true};         // Use FlashAttention algorithm
};

//==============================================================================
// MatMul Parameters
// For matrix multiplication variants
//==============================================================================
struct MatMulParams {
    uint32_t M{0};               // Output rows
    uint32_t N{0};               // Output columns
    uint32_t K{0};               // Inner dimension
    bool transposeA{false};      // Transpose first matrix
    bool transposeB{false};      // Transpose second matrix
    float alpha{1.0f};           // Output scale
    float beta{0.0f};            // Accumulation scale
};

} // namespace sovereign
