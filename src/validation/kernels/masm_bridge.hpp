// ============================================================================
// MASM Kernel Bridge - C++ to Assembly Interface
// Provides clean extern "C" linkage for telemetry harness
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <cstring>

// Forward declare AlignedBuffer
template<typename T>
class AlignedBuffer;

// ============================================================================
// External Assembly Functions
// ============================================================================

extern "C" {
    // SiLU Activation - AVX2 (256-bit) implementation
    // Parameters:
    //   RCX = float* data (32-byte aligned)
    //   RDX = size_t data_size (in bytes, multiple of 32)
    // Returns: RAX = 0 on success, non-zero on error
    int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
    
    // RMSNorm Forward - AVX2 implementation
    // Parameters:
    //   RCX = float* input (32-byte aligned)
    //   RDX = float* output (32-byte aligned)
    //   R8  = float* weights (32-byte aligned)
    //   R9  = size_t size (number of elements, multiple of 8)
    // Returns: RAX = 0 on success, non-zero on error
    int MASM_RMSNorm_Forward_AVX2(float* input, float* output, float* weights, size_t size);
    
    // Softmax Forward - AVX2 implementation
    // Parameters:
    //   RCX = float* data (32-byte aligned, in-place)
    //   RDX = size_t data_size (in bytes, multiple of 32)
    // Returns: RAX = 0 on success, non-zero on error
    int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);
}

namespace RawrXD {
namespace Kernels {

// ============================================================================
// Error Handling
// ============================================================================

enum class MASMError : int {
    Success = 0,
    NullPointer = 1,
    ZeroSize = 2,
    Misaligned = 3,
    InvalidSize = 4,
    Unknown = -1
};

inline const char* GetMASMErrorString(int error_code) {
    switch (error_code) {
        case 0: return "Success";
        case 1: return "Null pointer";
        case 2: return "Zero size";
        case 3: return "Misaligned pointer";
        case 4: return "Invalid size (not multiple of 8)";
        default: return "Unknown error";
    }
}

inline void CheckMASMResult(int result, const char* operation) {
    if (result != 0) {
        throw std::runtime_error(
            std::string("MASM kernel failed: ") + operation + 
            " - " + GetMASMErrorString(result)
        );
    }
}

// ============================================================================
// Kernel Dispatch Layer
// ============================================================================

class MASMKernelBridge {
public:
    // SiLU Activation - in-place
    // data: 32-byte aligned float array
    // count: number of floats (will be converted to bytes for assembly)
    static void SiLU(float* data, size_t count) {
        // Ensure count is multiple of 8 (AVX2 processes 8 floats)
        if (count % 8 != 0) {
            // Pad with zeros or handle remainder
            size_t padded_count = ((count + 7) / 8) * 8;
            // For now, just process what we can
            count = (count / 8) * 8;
        }
        
        size_t bytes = count * sizeof(float);
        int result = MASM_Silu_Activation_AVX512(data, bytes);
        CheckMASMResult(result, "SiLU");
    }
    
    // RMSNorm - requires separate input/output buffers and weights
    // input/output/weights: 32-byte aligned
    // count: number of elements (must be multiple of 8)
    static void RMSNorm(float* input, float* output, float* weights, size_t count) {
        if (count % 8 != 0) {
            count = (count / 8) * 8;  // Round down to multiple of 8
        }
        
        int result = MASM_RMSNorm_Forward_AVX2(input, output, weights, count);
        CheckMASMResult(result, "RMSNorm");
    }
    
    // RMSNorm wrapper for in-place operation (creates temp output)
    // Note: Implementation moved to .cpp file to avoid AlignedBuffer dependency in header
    static void RMSNorm_InPlace(float* data, float* weights, size_t count);
    
    // Softmax - in-place
    // data: 32-byte aligned float array
    // count: number of floats
    static void Softmax(float* data, size_t count) {
        if (count % 8 != 0) {
            count = (count / 8) * 8;
        }
        
        size_t bytes = count * sizeof(float);
        int result = MASM_Softmax_Forward_AVX2(data, bytes);
        CheckMASMResult(result, "Softmax");
    }
};

// ============================================================================
// C-compatible wrapper functions for function pointer compatibility
// ============================================================================

extern "C" {
    // C-compatible wrappers that match the expected signature: void func(float*, size_t)
    // These wrap the MASM kernels and handle the parameter translation
    
    inline void MASM_SiLU_Wrapper(float* data, size_t count) {
        MASMKernelBridge::SiLU(data, count);
    }
    
    inline void MASM_Softmax_Wrapper(float* data, size_t count) {
        MASMKernelBridge::Softmax(data, count);
    }
}

} // namespace Kernels
} // namespace RawrXD
