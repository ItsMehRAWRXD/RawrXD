// ============================================================================
// masm_kernels.hpp
// ============================================================================
// MASM Assembly Kernel Declarations for AVX-512 Optimized Operations
// 
// This header provides C++ declarations for hand-optimized assembly kernels
// that implement critical inference operations using AVX-512 instructions.
//
// All functions follow the x64 Windows __fastcall calling convention:
//   - First 4 arguments in RCX, RDX, R8, R9
//   - Return value in RAX
//   - Non-volatile registers preserved: RBX, RBP, RDI, RSI, R12-R15
//   - Volatile registers: RAX, RCX, RDX, R8-R11, XMM0-XMM5
//
// Safety Guarantees:
//   - All functions are thread-safe (no global state)
//   - All functions operate in-place (no memory allocation)
//   - All functions validate alignment (64-byte boundary)
//   - All functions return error codes for invalid inputs
//
// Performance Targets:
//   - SiLU Activation: <50,000 cycles for 1024 floats (7x speedup)
//   - RMS Normalization: <40,000 cycles for 1024 floats (8x speedup)
//   - Q4_0 Dequantize: <30,000 cycles for 1024 floats (10x speedup)
//   - Q8_0 Dequantize: <25,000 cycles for 1024 floats (12x speedup)
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// ============================================================================
// Error Codes
// ============================================================================

enum class MASMError : int {
    Success = 0,
    NullPointer = 1,
    ZeroSize = 2,
    MisalignedPointer = 3,
    InvalidSize = 4,
    NumericalOverflow = 5
};

// ============================================================================
// SiLU Activation Kernels
// ============================================================================

extern "C" {

// ============================================================================
// MASM_Silu_Activation_AVX512
// ============================================================================
// Computes SiLU activation: y = x * sigmoid(x)
//
// Mathematical Definition:
//   sigmoid(x) ≈ 0.5 + 0.25*x - 0.020833*x^3 + 0.002604*x^5
//   SiLU(x) = x * sigmoid(x)
//
// Parameters:
//   data      - Pointer to float array (must be 64-byte aligned)
//   data_size - Number of bytes to process (must be multiple of 64)
//
// Returns:
//   0 on success, non-zero on error (see MASMError enum)
//
// Performance:
//   - Processes 16 floats per iteration using ZMM registers
//   - Target: <50,000 cycles for 1024 floats
//   - Memory bandwidth: 0.03 GB/s (scalar baseline)
//
// Safety:
//   - Validates pointer alignment
//   - Validates size is multiple of 64
//   - No external function calls
//   - All ZMM registers are volatile
//
// Example:
//   float* buffer = aligned_alloc(1024 * sizeof(float), 64);
//   int result = MASM_Silu_Activation_AVX512(buffer, 1024 * sizeof(float));
//   if (result != 0) { /* handle error */ }
// ============================================================================

int MASM_Silu_Activation_AVX512(void* data, size_t data_size);

// ============================================================================
// MASM_Silu_Activation_AVX512_Fast
// ============================================================================
// Optimized version without parameter validation.
// Use only when you're certain inputs are valid.
//
// WARNING: This function assumes:
//   - data is 64-byte aligned
//   - data_size is multiple of 64
//   - data is not null
//   - data_size is not zero
//
// If these assumptions are violated, behavior is undefined.
// ============================================================================

int MASM_Silu_Activation_AVX512_Fast(void* data, size_t data_size);

// ============================================================================
// MASM_Silu_Activation_AVX512_Bounded
// ============================================================================
// Version with explicit bounds checking and numerical stability.
// Clamps output to [-10, 10] to prevent overflow in subsequent layers.
//
// This is the safest version for production use.
// ============================================================================

int MASM_Silu_Activation_AVX512_Bounded(void* data, size_t data_size);

// ============================================================================
// MASM_Silu_Activation_AVX512_Fixed
// ============================================================================
// ABI-compliant version that properly preserves non-volatile YMM registers.
// 
// CRITICAL FIX: This version saves/restores YMM6-YMM15 according to Windows x64 ABI.
// 
// Windows x64 ABI requires:
//   - YMM0-YMM5: Volatile (caller-saved)
//   - YMM6-YMM15: Non-volatile (callee-saved)
// 
// This version is safe for production use and will not corrupt caller's state.
// ============================================================================

int MASM_Silu_Activation_AVX512_Fixed(void* data, size_t data_size);

// ============================================================================
// MASM_SiLU_Clamped
// ============================================================================
// SiLU with input clamping to [-4, 4] for numerical stability.
// Uses polynomial approximation for exp(-x).
// Parameters:
//   data      - Pointer to float array (must be 32-byte aligned)
//   data_size - Number of bytes to process (must be multiple of 32)
// Returns:
//   0 on success, non-zero on error
// ============================================================================
int MASM_SiLU_Clamped(void* data, size_t data_size);

// ============================================================================
// RMS Normalization Kernels
// ============================================================================

int MASM_RMSNorm_Forward_AVX2(void* input, void* output, void* weights, size_t size);
int MASM_RMSNorm_Forward_AVX2_Fast(void* input, void* output, void* weights, size_t size);

// ============================================================================
// Q4_0 Dequantization Kernels (Placeholder)
// ============================================================================

int MASM_Q4_0_Dequantize_AVX512(void* data, size_t data_size);
int MASM_Q4_0_Dequantize_AVX512_Fast(void* data, size_t data_size);

// ============================================================================
// Q8_0 Dequantization Kernels (Placeholder)
// ============================================================================

int MASM_Q8_0_Dequantize_AVX512(void* data, size_t data_size);
int MASM_Q8_0_Dequantize_AVX512_Fast(void* data, size_t data_size);

// ============================================================================
// Attention Softmax Kernels
// ============================================================================

int MASM_Softmax_Forward_AVX2(void* data, size_t data_size);
int MASM_Softmax_Forward_AVX2_Fast(void* data, size_t data_size);

// ============================================================================
// ABI Integrity Test Functions
// ============================================================================
// These functions test MASM kernels for ABI compliance by checking register preservation.
// They are for development/debugging only and should not be used in production.

int TestABIIntegrity_Silu_Clamped(void* data, size_t data_size);
int TestABIIntegrity_Simple(void* data, size_t data_size);

} // extern "C"

// ============================================================================
// C++ Wrapper Functions
// ============================================================================

namespace RawrXD {
namespace Kernels {

// ============================================================================
// SiLU Activation
// ============================================================================

inline bool SiluActivation_AVX512(float* data, size_t count) {
    if (!data || count == 0) return false;
    if (reinterpret_cast<uintptr_t>(data) % 64 != 0) return false;
    if (count % 16 != 0) return false;  // Must be multiple of 16 floats
    
    int result = MASM_Silu_Activation_AVX512(data, count * sizeof(float));
    return result == 0;
}

inline bool SiluActivation_AVX512_Fast(float* data, size_t count) {
    int result = MASM_Silu_Activation_AVX512_Fast(data, count * sizeof(float));
    return result == 0;
}

inline bool SiluActivation_AVX512_Bounded(float* data, size_t count) {
    if (!data || count == 0) return false;
    if (reinterpret_cast<uintptr_t>(data) % 64 != 0) return false;
    if (count % 16 != 0) return false;
    
    int result = MASM_Silu_Activation_AVX512_Bounded(data, count * sizeof(float));
    return result == 0;
}

// ============================================================================
// RMS Normalization
// ============================================================================

inline bool RMSNorm_Forward_AVX512(float* data, size_t count) {
    if (!data || count == 0) return false;
    if (reinterpret_cast<uintptr_t>(data) % 64 != 0) return false;
    if (count % 16 != 0) return false;
    
    // Note: MASM_RMSNorm_Forward_AVX2 is the actual implementation
    // For now, return false as it's not yet implemented
    return false;
}

// ============================================================================
// Q4_0 Dequantization
// ============================================================================

inline bool Q4_0_Dequantize_AVX512(float* data, size_t count) {
    if (!data || count == 0) return false;
    if (reinterpret_cast<uintptr_t>(data) % 64 != 0) return false;
    if (count % 16 != 0) return false;
    
    int result = MASM_Q4_0_Dequantize_AVX512(data, count * sizeof(float));
    return result == 0;
}

// ============================================================================
// Q8_0 Dequantization
// ============================================================================

inline bool Q8_0_Dequantize_AVX512(float* data, size_t count) {
    if (!data || count == 0) return false;
    if (reinterpret_cast<uintptr_t>(data) % 64 != 0) return false;
    if (count % 16 != 0) return false;
    
    int result = MASM_Q8_0_Dequantize_AVX512(data, count * sizeof(float));
    return result == 0;
}

// ============================================================================
// Attention Softmax
// ============================================================================

inline bool Softmax_Forward_AVX2(float* data, size_t count) {
    if (!data || count == 0) return false;
    if (reinterpret_cast<uintptr_t>(data) % 32 != 0) return false;  // 32-byte alignment for AVX2
    if (count % 8 != 0) return false;  // Must be multiple of 8 floats
    
    int result = MASM_Softmax_Forward_AVX2(data, count * sizeof(float));
    return result == 0;
}

inline bool Softmax_Forward_AVX2_Fast(float* data, size_t count) {
    int result = MASM_Softmax_Forward_AVX2_Fast(data, count * sizeof(float));
    return result == 0;
}

} // namespace Kernels
} // namespace RawrXD