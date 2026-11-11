// LoRA_Kernel_Interface.h
// Phase 21: Formalized C++/ASM Interface with Compile-Time Verification
// ============================================================================
// This header defines the LoRAContext structure and verifies alignment
// between C++ and MASM (ApplyLoRA_Fixed.asm) at compile time.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <static_assert>

// ============================================================================
// ASM Offsets (must match ApplyLoRA_Fixed.asm)
// ============================================================================
// These are the offsets used in the MASM kernel. Any change here requires
// a corresponding change in ApplyLoRA_Fixed.asm.

namespace LoRAOffsets {
    constexpr std::size_t MAGIC       = 0;   // 0x00: uint64_t magic
    constexpr std::size_t RANK        = 8;   // 0x08: uint32_t rank
    constexpr std::size_t HIDDEN_DIM  = 12;  // 0x0C: uint32_t hidden_dim
    constexpr std::size_t INPUT_DIM   = 16;  // 0x10: uint32_t input_dim
    constexpr std::size_t RESERVED    = 20;  // 0x14: uint32_t reserved
    constexpr std::size_t PTR_A       = 24;  // 0x18: float* matrix_A
    constexpr std::size_t PTR_B       = 32;  // 0x20: float* matrix_B
    constexpr std::size_t ALPHA       = 40;  // 0x28: float alpha
    constexpr std::size_t SCALE       = 44;  // 0x2C: float scale
    constexpr std::size_t STATUS      = 48;  // 0x30: uint64_t status_flags
    constexpr std::size_t TOTAL_SIZE   = 64; // 0x40: cache-line aligned
}

// ============================================================================
// LoRAContext Structure (64-byte aligned for cache efficiency)
// ============================================================================
// This structure is shared between C++ and MASM. The layout must EXACTLY match
// the offsets defined in LoRAOffsets above.

#pragma pack(push, 1)
struct alignas(64) LoRAContext {
    // Offset 0x00: Magic number for validation
    uint64_t magic = 0x4141524F4C;  // "LORAA" in ASCII
    
    // Offset 0x08: LoRA rank (typically 4, 8, or 16)
    uint32_t rank = 8;
    
    // Offset 0x0C: Hidden dimension size
    uint32_t hidden_dim = 768;
    
    // Offset 0x10: Input dimension size
    uint32_t input_dim = 768;
    
    // Offset 0x14: Reserved for future use
    uint32_t reserved = 0;
    
    // Offset 0x18: Pointer to A matrix (rank x input_dim)
    float* matrix_A = nullptr;
    
    // Offset 0x20: Pointer to B matrix (hidden_dim x rank)
    float* matrix_B = nullptr;
    
    // Offset 0x28: Scaling factor alpha
    float alpha = 1.0f;
    
    // Offset 0x2C: Additional scaling factor
    float scale = 1.0f;
    
    // Offset 0x30: Status flags for kernel communication
    uint64_t status_flags = 0;
    
    // Padding to ensure 64-byte alignment
    uint8_t _padding[64 - 48] = {};
};
#pragma pack(pop)

// ============================================================================
// Compile-Time Alignment Verification
// ============================================================================
// These static_assert statements verify that the C++ struct layout matches
// the ASM offsets. If any assertion fails, the build will fail with a clear
// error message indicating which offset is misaligned.

static_assert(offsetof(LoRAContext, magic) == LoRAOffsets::MAGIC,
    "LoRAContext::magic offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, rank) == LoRAOffsets::RANK,
    "LoRAContext::rank offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, hidden_dim) == LoRAOffsets::HIDDEN_DIM,
    "LoRAContext::hidden_dim offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, input_dim) == LoRAOffsets::INPUT_DIM,
    "LoRAContext::input_dim offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, reserved) == LoRAOffsets::RESERVED,
    "LoRAContext::reserved offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, matrix_A) == LoRAOffsets::PTR_A,
    "LoRAContext::matrix_A offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, matrix_B) == LoRAOffsets::PTR_B,
    "LoRAContext::matrix_B offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, alpha) == LoRAOffsets::ALPHA,
    "LoRAContext::alpha offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, scale) == LoRAOffsets::SCALE,
    "LoRAContext::scale offset mismatch! C++ and ASM are out of sync.");

static_assert(offsetof(LoRAContext, status_flags) == LoRAOffsets::STATUS,
    "LoRAContext::status_flags offset mismatch! C++ and ASM are out of sync.");

static_assert(sizeof(LoRAContext) == LoRAOffsets::TOTAL_SIZE,
    "LoRAContext size mismatch! Expected 64 bytes for cache-line alignment.");

static_assert(alignof(LoRAContext) == 64,
    "LoRAContext alignment mismatch! Must be 64-byte aligned for AVX-512.");

// ============================================================================
// External ASM Function Declaration
// ============================================================================
// This is the entry point to the MASM kernel. The implementation is in
// ApplyLoRA_Fixed.asm.

extern "C" {
    // ApplyLoRA_Optimized
    // Parameters (x64 calling convention):
    //   RCX = base_output pointer (float*)
    //   RDX = input pointer (float*)
    //   R8  = result pointer (float*)
    //   R9  = LoRAContext pointer
    //   R10 = token_count (uint32_t)
    // Returns:
    //   RAX = 0 on success, non-zero on error
    int ApplyLoRA_Optimized(
        float* base_output,
        float* input,
        float* result,
        LoRAContext* context,
        uint32_t token_count
    );
}

// ============================================================================
// C++ Wrapper Class (Optional Convenience)
// ============================================================================
// Provides a more C++-friendly interface while maintaining zero overhead.

class LoRAKernel {
public:
    explicit LoRAKernel(LoRAContext* ctx) : context_(ctx) {}
    
    // Apply LoRA transformation
    // Returns true on success, false on failure
    bool Apply(float* base_output, float* input, float* result, uint32_t tokens = 1) {
        if (!context_ || !base_output || !input || !result) {
            return false;
        }
        return ApplyLoRA_Optimized(base_output, input, result, context_, tokens) == 0;
    }
    
    // Validate context integrity
    bool IsValid() const {
        if (!context_) return false;
        return context_->magic == 0x4141524F4C &&
               context_->rank > 0 &&
               context_->hidden_dim > 0 &&
               context_->matrix_A != nullptr &&
               context_->matrix_B != nullptr;
    }
    
private:
    LoRAContext* context_;
};

// ============================================================================
// Version Information
// ============================================================================

constexpr uint32_t LORA_KERNEL_VERSION_MAJOR = 1;
constexpr uint32_t LORA_KERNEL_VERSION_MINOR = 0;
constexpr uint32_t LORA_KERNEL_VERSION_PATCH = 0;
constexpr const char* LORA_KERNEL_VERSION_STRING = "1.0.0-Phase21";
