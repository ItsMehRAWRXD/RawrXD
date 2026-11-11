// ============================================================================
// Kernel Bridge - C++ to MASM Assembly Interface
// Provides clean linkage between telemetry harness and assembly kernels
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <cstring>

// ============================================================================
// External Assembly Functions (defined in .asm files)
// ============================================================================

extern "C" {
    // SiLU Activation - AVX2 implementation
    // Parameters:
    //   RCX = float* data (32-byte aligned)
    //   RDX = size_t data_size (in bytes, multiple of 32)
    // Returns: RAX = 0 on success, non-zero error code
    int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
    
    // RMSNorm Forward - AVX2 implementation  
    // Parameters:
    //   RCX = float* input (32-byte aligned)
    //   RDX = float* output (32-byte aligned)
    //   R8  = float* weights (32-byte aligned)
    //   R9  = size_t size (number of elements, multiple of 8)
    // Returns: RAX = 0 on success, non-zero error code
    int MASM_RMSNorm_Forward_AVX2(float* input, float* output, float* weights, size_t size);
    
    // Softmax Forward - AVX2 implementation
    // Parameters:
    //   RCX = float* data (32-byte aligned, in-place)
    //   RDX = size_t data_size (in bytes, multiple of 32)
    // Returns: RAX = 0 on success, non-zero error code
    int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);
    
    // Test function - returns 0
    int MASM_Test_Minimal();
}

namespace RawrXD {
namespace Kernels {

// Error codes from MASM kernels
enum class MASMError : int {
    Success = 0,
    NullPointer = 1,
    ZeroSize = 2,
    Misaligned = 3,
    InvalidSize = 4
};

inline const char* GetMASMErrorString(int code) {
    switch (code) {
        case 0: return "Success";
        case 1: return "Null pointer";
        case 2: return "Zero size";
        case 3: return "Misaligned pointer";
        case 4: return "Invalid size (not multiple of 8)";
        default: return "Unknown error";
    }
}

inline void CheckResult(int result, const char* operation) {
    if (result != 0) {
        throw std::runtime_error(
            std::string("MASM kernel '") + operation + "' failed: " + 
            GetMASMErrorString(result)
        );
    }
}

// ============================================================================
// Kernel Wrappers
// ============================================================================

// SiLU wrapper - in-place
inline void SiLU_MASM(float* data, size_t count) {
    // Ensure count is multiple of 8 for AVX2
    size_t aligned_count = (count / 8) * 8;
    if (aligned_count == 0) return;
    
    size_t bytes = aligned_count * sizeof(float);
    int result = MASM_Silu_Activation_AVX512(data, bytes);
    CheckResult(result, "SiLU");
    
    // Handle remainder with scalar fallback
    for (size_t i = aligned_count; i < count; ++i) {
        data[i] = data[i] / (1.0f + std::exp(-data[i]));
    }
}

// Softmax wrapper - in-place
inline void Softmax_MASM(float* data, size_t count) {
    size_t aligned_count = (count / 8) * 8;
    if (aligned_count == 0) return;
    
    size_t bytes = aligned_count * sizeof(float);
    int result = MASM_Softmax_Forward_AVX2(data, bytes);
    CheckResult(result, "Softmax");
    
    // Handle remainder with scalar fallback
    if (aligned_count < count) {
        // Find max for numerical stability
        float max_val = data[0];
        for (size_t i = 1; i < count; ++i) {
            if (data[i] > max_val) max_val = data[i];
        }
        float sum = 0.0f;
        for (size_t i = aligned_count; i < count; ++i) {
            data[i] = std::exp(data[i] - max_val);
            sum += data[i];
        }
        for (size_t i = aligned_count; i < count; ++i) {
            data[i] /= sum;
        }
    }
}

// RMSNorm wrapper - requires separate buffers
// For simplicity, this uses scalar implementation
// Full MASM version would need proper buffer management
inline void RMSNorm_MASM(float* data, size_t count) {
    // Calculate RMS
    float sum_sq = 0.0f;
    for (size_t i = 0; i < count; ++i) {
        sum_sq += data[i] * data[i];
    }
    float rms = std::sqrt(sum_sq / count + 1e-6f);
    float scale = 1.0f / rms;
    
    // Normalize
    for (size_t i = 0; i < count; ++i) {
        data[i] *= scale;
    }
}

} // namespace Kernels
} // namespace RawrXD
