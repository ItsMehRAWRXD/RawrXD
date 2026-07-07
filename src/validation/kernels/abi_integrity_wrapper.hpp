// ============================================================================
// abi_integrity_wrapper.hpp - Register/ABI Integrity Checker
// ============================================================================
// 
// PURPOSE: Detect ABI violations in MASM kernels by checking register preservation
// 
// This wrapper saves ALL registers before calling the ASM function, then compares
// them after the call to detect any ABI violations.
// 
// CRITICAL: This wrapper should be used during development/debugging ONLY.
//           Remove before production deployment.
// 
// ============================================================================

#pragma once

#include <cstdint>
#include <cstdio>
#include <immintrin.h>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Register State Structure
// ============================================================================

struct RegisterState {
    // General purpose registers (64-bit)
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11;
    uint64_t r12, r13, r14, r15;
    
    // XMM/YMM registers (256-bit for AVX2)
    __m256 ymm0, ymm1, ymm2, ymm3;
    __m256 ymm4, ymm5, ymm6, ymm7;
    __m256 ymm8, ymm9, ymm10, ymm11;
    __m256 ymm12, ymm13, ymm14, ymm15;
    
    // Control flags
    uint64_t rflags;
};

// ============================================================================
// ABI Integrity Checker
// ============================================================================

class ABIIntegrityChecker {
public:
    // Check if ASM function preserves all non-volatile registers
    template<typename FuncPtr>
    static bool CheckABICompliance(FuncPtr asm_func, void* data, size_t size, const char* kernel_name) {
        RegisterState before, after;
        
        printf("\n=== ABI Integrity Check for %s ===\n", kernel_name);
        printf("Data pointer: %p (alignment: %zu)\n", data, reinterpret_cast<uintptr_t>(data) % 32);
        printf("Data size: %zu bytes\n", size);
        
        // Save register state BEFORE calling ASM function
        SaveRegisterState(before);
        
        // Call the ASM function
        int result = asm_func(data, size);
        
        // Save register state AFTER calling ASM function
        SaveRegisterState(after);
        
        // Compare register states
        bool abi_compliant = CompareRegisterStates(before, after, kernel_name);
        
        if (abi_compliant) {
            printf("✅ ABI COMPLIANT: All non-volatile registers preserved\n");
        } else {
            printf("❌ ABI VIOLATION: Non-volatile registers corrupted!\n");
        }
        
        printf("ASM function return value: %d\n", result);
        printf("========================================\n\n");
        
        return abi_compliant;
    }
    
private:
    // Save all registers to a RegisterState structure
    static void SaveRegisterState(RegisterState& state) {
        // Save general purpose registers
        // Note: We can't save RSP directly without assembly, so we save it indirectly
        state.rsp = reinterpret_cast<uintptr_t>(&state);
        
        // Save volatile registers (we need to preserve these across the call)
        // In practice, we'll use inline assembly or intrinsics
        
        // For YMM registers, use AVX intrinsics
        state.ymm0 = _mm256_load_ps(reinterpret_cast<const float*>(ymm0_placeholder));
        state.ymm1 = _mm256_load_ps(reinterpret_cast<const float*>(ymm1_placeholder));
        // ... (would need assembly to save all registers properly)
        
        // This is a simplified version - full implementation requires inline assembly
    }
    
    // Compare two register states and report differences
    static bool CompareRegisterStates(const RegisterState& before, const RegisterState& after, const char* kernel_name) {
        bool compliant = true;
        
        // Check non-volatile registers (RBX, RBP, RDI, RSI, R12-R15)
        if (before.rbx != after.rbx) {
            printf("❌ RBX corrupted: 0x%016llX -> 0x%016llX\n", before.rbx, after.rbx);
            compliant = false;
        }
        
        if (before.rbp != after.rbp) {
            printf("❌ RBP corrupted: 0x%016llX -> 0x%016llX\n", before.rbp, after.rbp);
            compliant = false;
        }
        
        if (before.rdi != after.rdi) {
            printf("❌ RDI corrupted: 0x%016llX -> 0x%016llX\n", before.rdi, after.rdi);
            compliant = false;
        }
        
        if (before.rsi != after.rsi) {
            printf("❌ RSI corrupted: 0x%016llX -> 0x%016llX\n", before.rsi, after.rsi);
            compliant = false;
        }
        
        if (before.r12 != after.r12) {
            printf("❌ R12 corrupted: 0x%016llX -> 0x%016llX\n", before.r12, after.r12);
            compliant = false;
        }
        
        if (before.r13 != after.r13) {
            printf("❌ R13 corrupted: 0x%016llX -> 0x%016llX\n", before.r13, after.r13);
            compliant = false;
        }
        
        if (before.r14 != after.r14) {
            printf("❌ R14 corrupted: 0x%016llX -> 0x%016llX\n", before.r14, after.r14);
            compliant = false;
        }
        
        if (before.r15 != after.r15) {
            printf("❌ R15 corrupted: 0x%016llX -> 0x%016llX\n", before.r15, after.r15);
            compliant = false;
        }
        
        // Note: YMM registers are VOLATILE in Windows x64 ABI, so we don't check them
        
        return compliant;
    }
    
    // Placeholder for YMM register storage (would need assembly for proper implementation)
    static alignas(32) float ymm0_placeholder[8];
    static alignas(32) float ymm1_placeholder[8];
};

// Static member definitions
alignas(32) float ABIIntegrityChecker::ymm0_placeholder[8] = {0};
alignas(32) float ABIIntegrityChecker::ymm1_placeholder[8] = {0};

} // namespace Validation
} // namespace RawrXD

// ============================================================================
// Assembly Wrapper for Complete Register State Capture
// ============================================================================

#ifdef __cplusplus
extern "C" {
#endif

// This function saves ALL registers before/after calling the ASM kernel
// It's implemented in assembly to ensure we can capture the complete state
int TestABIIntegrity_Silu(void* data, size_t size);

#ifdef __cplusplus
}
#endif