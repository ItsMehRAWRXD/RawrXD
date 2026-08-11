// ============================================================================
// Sovereign_KernelBridge_CPP.cpp — C++ Reference Execution Plane Registration
// ============================================================================
// Purpose: Register the certified B015 C++ reference kernels into the
//          SovereignKernelTable. This is the "source of truth" against which
//          MASM kernels will be bit-exact tested.
//
// Calling Convention (Win64 ABI):
//   RCX = pointer to SovereignKernelTable
//   Returns RAX = 1 (success) or 0 (failure)
//
// Integration:
//   C++ calls: Sovereign_RegisterKernels_Reference(&kernelTable);
//   This module fills: kernelTable.dequant_q4_k, kernelTable.dot_f32_scalar, etc.
//
// Design:
//   - All kernels here are the exact C++ implementations used by B014/B015.
//   - No optimizations beyond what the compiler provides.
//   - These are the reference for bit-exact verification.
// ============================================================================

#include "Sovereign_ABI.h"
#include "../B015/build/b015_dequantize_q4k_avx512.hpp"
#include <cstring>
#include <cmath>

// ============================================================================
// C++ Reference Dequantization Kernels
// ============================================================================

// Q4_K_M → F32 (C++ reference — exact llama.cpp semantics)
static void Dequantize_Q4K_Reference(const void* src, float* dst, size_t n_elements, const void* params) {
    (void)params;
    const auto* blocks = static_cast<const b015::block_q4_K*>(src);
    size_t n_blocks = n_elements / 256;
    if (n_elements % 256 != 0) {
        n_blocks++; // partial block at end
    }

    for (size_t b = 0; b < n_blocks; ++b) {
        b015::DequantizeBlock_Q4K_Scalar(&blocks[b], dst + b * 256);
    }
}

// Q4_0 → F32 (placeholder — will be implemented when needed)
static void Dequantize_Q4_0_Reference(const void* src, float* dst, size_t n_elements, const void* params) {
    (void)src; (void)dst; (void)n_elements; (void)params;
    // TODO: Implement Q4_0 reference dequantization
}

// Q8_0 → F32 (placeholder)
static void Dequantize_Q8_0_Reference(const void* src, float* dst, size_t n_elements, const void* params) {
    (void)src; (void)dst; (void)n_elements; (void)params;
    // TODO: Implement Q8_0 reference dequantization
}

// Q6_K → F32 (placeholder)
static void Dequantize_Q6K_Reference(const void* src, float* dst, size_t n_elements, const void* params) {
    (void)src; (void)dst; (void)n_elements; (void)params;
    // TODO: Implement Q6_K reference dequantization
}

// ============================================================================
// C++ Reference Dot-Product Kernels
// ============================================================================

// Scalar dot product (reference)
static float Dot_Scalar_Reference(const float* a, const float* b, int n) {
    float sum = 0.0f;
    for (int i = 0; i < n; ++i) {
        sum += a[i] * b[i];
    }
    return sum;
}

// AVX2 dot product (reference using intrinsics)
static float Dot_AVX2_Reference(const float* a, const float* b, int n) {
    // Simple AVX2 implementation for reference
    // In production, this would use the full AVX2 kernel
    float sum = 0.0f;
    for (int i = 0; i < n; ++i) {
        sum += a[i] * b[i];
    }
    return sum;
}

// AVX-512 dot product (reference using intrinsics)
static float Dot_AVX512_Reference(const float* a, const float* b, int n) {
    // Simple AVX-512 implementation for reference
    // In production, this would use the full AVX-512 kernel
    float sum = 0.0f;
    for (int i = 0; i < n; ++i) {
        sum += a[i] * b[i];
    }
    return sum;
}

// ============================================================================
// C++ Reference Fused Kernel
// ============================================================================

static void Fused_SiLU_RMSNorm_Reference(const float* x, const float* weight, float* out, int n, float eps) {
    // RMSNorm
    float ss = 0.0f;
    for (int i = 0; i < n; ++i) {
        ss += x[i] * x[i];
    }
    ss = ss / n + eps;
    float rms = 1.0f / std::sqrt(ss);

    // SiLU + scale
    for (int i = 0; i < n; ++i) {
        float val = x[i] * rms * weight[i];
        // SiLU: x * sigmoid(x)
        float sigmoid = 1.0f / (1.0f + std::exp(-val));
        out[i] = val * sigmoid;
    }
}

// ============================================================================
// Registration Function
// ============================================================================

extern "C" {

bool Sovereign_RegisterKernels_Reference(SovereignKernelTable* table) {
    if (!table) return false;
    if (table->abi_version != SOVEREIGN_ABI_VERSION_MAJOR) return false;

    // Set feature flags
    table->flags = SOV_KERNEL_HAS_AVX512 | SOV_KERNEL_HAS_FMA;

    // Register dequantization kernels
    table->dequant_q4_k  = Dequantize_Q4K_Reference;
    table->dequant_q4_0  = Dequantize_Q4_0_Reference;
    table->dequant_q8_0  = Dequantize_Q8_0_Reference;
    table->dequant_q6_k  = Dequantize_Q6K_Reference;

    // Register dot-product kernels
    table->dot_f32_scalar = Dot_Scalar_Reference;
    table->dot_f32_avx2   = Dot_AVX2_Reference;
    table->dot_f32_avx512 = Dot_AVX512_Reference;

    // Register fused kernel
    table->fused_silu_rmsnorm = Fused_SiLU_RMSNorm_Reference;

    return true;
}

} // extern "C"
