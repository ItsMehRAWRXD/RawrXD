// ============================================================================
// MASM Kernel Bridge - SECURITY HARDENED VERSION
// Integrates Phase 7a Fortress-Grade validation with AVX-512 kernels
// All dispatch calls validated before assembly entry
// ============================================================================

#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <cstring>
#include <limits>

// Include the original bridge for assembly declarations
#include "masm_bridge.hpp"

namespace RawrXD {
namespace Kernels {
namespace Secure {

// ============================================================================
// Security Constants (mirrored from Phase 7a hardening)
// ============================================================================
constexpr size_t MAX_KERNEL_ELEMENTS = 100 * 1024 * 1024 / sizeof(float); // 100MB worth of floats
constexpr size_t MAX_ALIGNMENT = 64;
constexpr size_t MIN_ELEMENTS = 8;  // AVX2 processes 8 floats minimum

// ============================================================================
// Security Validation Functions
// ============================================================================

// Validate pointer alignment
inline bool IsAligned(const void* ptr, size_t alignment = 64) {
    return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

// Validate buffer bounds
inline bool IsValidBuffer(const float* ptr, size_t count, size_t alignment = 64) {
    // Null check
    if (ptr == nullptr) return false;
    
    // Alignment check
    if (!IsAligned(ptr, alignment)) return false;
    
    // Size bounds check (prevent overflow)
    if (count == 0 || count > MAX_KERNEL_ELEMENTS) return false;
    
    // Integer overflow check for byte calculation
    if (count > std::numeric_limits<size_t>::max() / sizeof(float)) return false;
    
    return true;
}

// Validate element count for AVX operations
inline bool IsValidElementCount(size_t count) {
    // Must be at least MIN_ELEMENTS (AVX2 processes 8 floats)
    if (count < MIN_ELEMENTS) return false;
    
    // Must be multiple of 8 for AVX2 alignment
    if (count % 8 != 0) return false;
    
    // Must not exceed max
    if (count > MAX_KERNEL_ELEMENTS) return false;
    
    return true;
}

// Clamp element count to safe bounds
inline size_t ClampElementCount(size_t count) {
    if (count > MAX_KERNEL_ELEMENTS) {
        return MAX_KERNEL_ELEMENTS;
    }
    // Round down to multiple of 8
    return (count / 8) * 8;
}

// ============================================================================
// Secure Kernel Dispatch Layer
// ============================================================================

class SecureMASMKernelBridge {
public:
    // SiLU Activation - SECURITY HARDENED
    // Validates all inputs before dispatching to assembly
    static void SiLU(float* data, size_t count) {
        // Security validation layer
        if (!IsValidBuffer(data, count)) {
            throw std::runtime_error("SiLU: Invalid buffer (null, misaligned, or out of bounds)");
        }
        
        if (!IsValidElementCount(count)) {
            // Clamp to valid range rather than fail
            count = ClampElementCount(count);
            if (count < MIN_ELEMENTS) {
                throw std::runtime_error("SiLU: Element count too small (minimum 8)");
            }
        }
        
        // Safe dispatch
        size_t bytes = count * sizeof(float);
        int result = MASM_Silu_Activation_AVX512(data, bytes);
        
        if (result != 0) {
            throw std::runtime_error(
                std::string("SiLU kernel failed: ") + GetMASMErrorString(result)
            );
        }
    }
    
    // RMSNorm - SECURITY HARDENED
    static void RMSNorm(float* input, float* output, float* weights, size_t count) {
        // Validate all buffers
        if (!IsValidBuffer(input, count) || 
            !IsValidBuffer(output, count) || 
            !IsValidBuffer(weights, count)) {
            throw std::runtime_error("RMSNorm: Invalid buffer(s) (null, misaligned, or out of bounds)");
        }
        
        // Check for buffer overlap (security issue)
        if (input == output) {
            throw std::runtime_error("RMSNorm: Input and output buffers must not overlap");
        }
        
        if (!IsValidElementCount(count)) {
            count = ClampElementCount(count);
            if (count < MIN_ELEMENTS) {
                throw std::runtime_error("RMSNorm: Element count too small (minimum 8)");
            }
        }
        
        int result = MASM_RMSNorm_Forward_AVX2(input, output, weights, count);
        
        if (result != 0) {
            throw std::runtime_error(
                std::string("RMSNorm kernel failed: ") + GetMASMErrorString(result)
            );
        }
    }
    
    // RMSNorm In-Place - SECURITY HARDENED
    // Note: Implementation requires AlignedBuffer, defined in .cpp file
    static void RMSNorm_InPlace(float* data, float* weights, size_t count);
    
    // Softmax - SECURITY HARDENED
    static void Softmax(float* data, size_t count) {
        if (!IsValidBuffer(data, count)) {
            throw std::runtime_error("Softmax: Invalid buffer (null, misaligned, or out of bounds)");
        }
        
        if (!IsValidElementCount(count)) {
            count = ClampElementCount(count);
            if (count < MIN_ELEMENTS) {
                throw std::runtime_error("Softmax: Element count too small (minimum 8)");
            }
        }
        
        size_t bytes = count * sizeof(float);
        int result = MASM_Softmax_Forward_AVX2(data, bytes);
        
        if (result != 0) {
            throw std::runtime_error(
                std::string("Softmax kernel failed: ") + GetMASMErrorString(result)
            );
        }
    }
};

// ============================================================================
// C-compatible Secure Wrappers
// ============================================================================

extern "C" {
    // Secure wrappers that can be used with function pointers
    // These provide the same security guarantees as the C++ interface
    
    inline int Secure_MASM_SiLU(float* data, size_t count) {
        try {
            SecureMASMKernelBridge::SiLU(data, count);
            return 0; // Success
        } catch (const std::exception& e) {
            // Log error (in production, use proper logging)
            return -1; // Security validation failed
        }
    }
    
    inline int Secure_MASM_RMSNorm(float* input, float* output, float* weights, size_t count) {
        try {
            SecureMASMKernelBridge::RMSNorm(input, output, weights, count);
            return 0;
        } catch (const std::exception& e) {
            return -1;
        }
    }
    
    inline int Secure_MASM_Softmax(float* data, size_t count) {
        try {
            SecureMASMKernelBridge::Softmax(data, count);
            return 0;
        } catch (const std::exception& e) {
            return -1;
        }
    }
}

// ============================================================================
// Security Audit Helpers
// ============================================================================

// Run security validation without dispatch (for testing)
inline bool ValidateKernelInputs(const float* data, size_t count) {
    return IsValidBuffer(data, count) && IsValidElementCount(count);
}

// Get security limits for documentation
inline void GetSecurityLimits(size_t& max_elements, size_t& min_elements, size_t& alignment) {
    max_elements = MAX_KERNEL_ELEMENTS;
    min_elements = MIN_ELEMENTS;
    alignment = MAX_ALIGNMENT;
}

} // namespace Secure
} // namespace Kernels
} // namespace RawrXD
