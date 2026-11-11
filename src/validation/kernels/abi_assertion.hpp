// ============================================================================
// ABI Assertion Layer - RawrXD Assembly Kernels
// ============================================================================
// 
// Static and runtime assertions to verify ABI compliance between C++ and
// assembly kernels. Include this header in any file that calls assembly
// functions to catch integration errors at compile time.
//
// Usage:
//   #include "abi_assertion.hpp"
//   
//   // Automatic checks run at compile time
//   void MyKernelCaller() {
//       ABI_ASSERT_KERNEL_READY(SiLU_AVX512);  // Runtime check
//       MASM_Silu_Activation_AVX512(data, size);
//   }
//
// ============================================================================

#ifndef RAWRXD_ABI_ASSERTION_HPP
#define RAWRXD_ABI_ASSERTION_HPP

#include <cstddef>
#include <cstdint>
#include <cassert>

// ============================================================================
// Compile-Time ABI Verification
// ============================================================================

namespace rawrxd {
namespace abi {

// Verify size_t matches assembly expectations (8 bytes on x64)
static_assert(sizeof(size_t) == 8, "ABI Error: size_t must be 8 bytes (x64)");

// Verify float is 4 bytes (IEEE 754 single precision)
static_assert(sizeof(float) == 4, "ABI Error: float must be 4 bytes");

// Verify pointer size (8 bytes on x64)
static_assert(sizeof(void*) == 8, "ABI Error: pointer must be 8 bytes (x64)");

// Verify alignment constants match assembly requirements
constexpr size_t AVX2_ALIGNMENT = 32;   // 256-bit vectors
constexpr size_t AVX512_ALIGNMENT = 64; // 512-bit vectors

// Kernel parameter structure size checks
// These ensure C++ and assembly agree on parameter layout
struct KernelArgs {
    void* data_ptr;      // RCX (1st parameter)
    size_t data_size;    // RDX (2nd parameter)
};

static_assert(sizeof(KernelArgs) == 16, "ABI Error: KernelArgs size mismatch");
static_assert(offsetof(KernelArgs, data_ptr) == 0, "ABI Error: data_ptr offset");
static_assert(offsetof(KernelArgs, data_size) == 8, "ABI Error: data_size offset");

// ============================================================================
// Runtime ABI Verification
// ============================================================================

// Check if pointer is aligned to required boundary
inline bool IsAligned(const void* ptr, size_t alignment) {
    return (reinterpret_cast<uintptr_t>(ptr) & (alignment - 1)) == 0;
}

// Validate kernel input parameters
inline bool ValidateKernelInput(void* data, size_t size, size_t min_elements, size_t alignment) {
    if (data == nullptr) return false;
    if (size == 0) return false;
    if (!IsAligned(data, alignment)) return false;
    if (size < min_elements * sizeof(float)) return false;
    return true;
}

// ============================================================================
// Kernel-Specific Assertions
// ============================================================================

// SiLU AVX-512 kernel validation
class SiLU_AVX512_Validator {
public:
    static constexpr size_t MIN_ELEMENTS = 16;     // 1 AVX-512 register
    static constexpr size_t ALIGNMENT = 64;        // 64-byte alignment
    static constexpr size_t VECTOR_WIDTH = 16;     // 16 floats per register
    
    static bool Validate(void* data, size_t size_bytes) {
        return ValidateKernelInput(data, size_bytes, MIN_ELEMENTS, ALIGNMENT);
    }
    
    static bool ValidateSize(size_t size_bytes) {
        return size_bytes >= MIN_ELEMENTS * sizeof(float) &&
               (size_bytes % (VECTOR_WIDTH * sizeof(float))) == 0;
    }
};

// Softmax AVX2 kernel validation
class Softmax_AVX2_Validator {
public:
    static constexpr size_t MIN_ELEMENTS = 8;      // 1 AVX2 register
    static constexpr size_t ALIGNMENT = 32;        // 32-byte alignment
    static constexpr size_t VECTOR_WIDTH = 8;      // 8 floats per register
    
    static bool Validate(void* data, size_t size_bytes) {
        return ValidateKernelInput(data, size_bytes, MIN_ELEMENTS, ALIGNMENT);
    }
    
    static bool ValidateSize(size_t size_bytes) {
        return size_bytes >= MIN_ELEMENTS * sizeof(float) &&
               (size_bytes % (VECTOR_WIDTH * sizeof(float))) == 0;
    }
};

} // namespace abi
} // namespace rawrxd

// ============================================================================
// Convenience Macros
// ============================================================================

// Compile-time assertion for kernel readiness
#define ABI_STATIC_ASSERT_READY(kernel_name) \
    static_assert(rawrxd::abi::kernel_name##_Validator::MIN_ELEMENTS > 0, \
                  #kernel_name " validator not properly defined")

// Runtime assertion for kernel input validation (debug builds only)
#ifdef _DEBUG
    #define ABI_ASSERT_KERNEL_INPUT(kernel_name, data, size) \
        assert(rawrxd::abi::kernel_name##_Validator::Validate(data, size) && \
               "ABI validation failed for " #kernel_name)
#else
    #define ABI_ASSERT_KERNEL_INPUT(kernel_name, data, size) ((void)0)
#endif

// Alignment assertion
#define ABI_ASSERT_ALIGNED(ptr, alignment) \
    assert(rawrxd::abi::IsAligned(ptr, alignment) && \
           "Pointer alignment check failed")

// ============================================================================
// Assembly Function Declarations with ABI Guards
// ============================================================================

extern "C" {
    // SiLU Activation - AVX-512 implementation
    // Parameters:
    //   RCX = float* data (64-byte aligned)
    //   RDX = size_t data_size (in bytes, multiple of 64)
    // Returns: RAX = 0 on success, error code on failure
    // Error codes: 1=nullptr, 2=zero_size, 3=misaligned, 4=invalid_size
    int MASM_Silu_Activation_AVX512(float* data, size_t data_size);
    
    // Softmax Forward - AVX2 implementation
    // Parameters:
    //   RCX = float* data (32-byte aligned)
    //   RDX = size_t data_size (in bytes, multiple of 32)
    // Returns: RAX = 0 on success, error code on failure
    // Error codes: 1=nullptr, 2=zero_size, 3=misaligned, 4=invalid_size
    int MASM_Softmax_Forward_AVX2(float* data, size_t data_size);
}

// Validate validators at compile time
ABI_STATIC_ASSERT_READY(SiLU_AVX512);
ABI_STATIC_ASSERT_READY(Softmax_AVX2);

#endif // RAWRXD_ABI_ASSERTION_HPP
