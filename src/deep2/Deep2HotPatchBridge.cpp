// ============================================================================
// Deep2HotPatchBridge.cpp - Runtime Hotpatch Integration
// Injects Deep2 MASM kernels into the IDE's inference pipeline
// ============================================================================

#include "../hot_patcher.h"
#include "Deep2.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <cstring>

namespace Deep2 {
namespace HotPatch {

// ============================================================================
// Function Pointer Types for Original Functions to Patch
// ============================================================================
typedef void (*VecDotProductFn)(const float* a, const float* b, float* out, size_t n);
typedef void (*SwiGLUFn)(const float* x, const float* y, float* out, size_t n);
typedef void (*RMSNormFn)(const float* x, float* out, size_t n, float eps);

// ============================================================================
// Patch State
// ============================================================================
struct PatchState {
    bool initialized = false;
    bool vecDotPatched = false;
    bool swiGLUPatched = false;
    bool rmsNormPatched = false;
    
    // Original function pointers (for restoration)
    void* originalVecDot = nullptr;
    void* originalSwiGLU = nullptr;
    void* originalRMSNorm = nullptr;
};

static PatchState g_patchState;
static HotPatcher g_deep2Patcher;

// ============================================================================
// Stub Functions (Placeholders to be patched)
// These represent the original slow/scalar implementations
// ============================================================================
extern "C" {
    // Original scalar implementations that Deep2 will replace
    void __declspec(noinline) OriginalVecDotProduct(const float* a, const float* b, float* out, size_t n) {
        float sum = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            sum += a[i] * b[i];
        }
        *out = sum;
    }
    
    void __declspec(noinline) OriginalSwiGLU(const float* x, const float* y, float* out, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            // Sigmoid: 1 / (1 + exp(-x))
            float sigmoid = 1.0f / (1.0f + expf(-x[i]));
            // SwiGLU: (x * sigmoid(x)) * y
            out[i] = (x[i] * sigmoid) * y[i];
        }
    }
    
    void __declspec(noinline) OriginalRMSNorm(const float* x, float* out, size_t n, float eps) {
        float sum = 0.0f;
        for (size_t i = 0; i < n; ++i) {
            sum += x[i] * x[i];
        }
        float rms = sqrtf(sum / n + eps);
        float scale = 1.0f / rms;
        for (size_t i = 0; i < n; ++i) {
            out[i] = x[i] * scale;
        }
    }
}

// ============================================================================
// Trampoline/Jump Functions
// These are small stubs that jump to the actual Deep2 implementations
// ============================================================================
#pragma code_seg(push, ".text")
__declspec(naked) void Trampoline_VecDotProduct(void) {
    __asm {
        jmp Deep2_VecDotProduct
    }
}

__declspec(naked) void Trampoline_SwiGLU(void) {
    __asm {
        jmp Deep2_SwiGLU
    }
}

__declspec(naked) void Trampoline_RMSNorm(void) {
    __asm {
        jmp Deep2_RMSNorm
    }
}
#pragma code_seg(pop)

// ============================================================================
// Patch Application
// ============================================================================

bool ApplyVecDotPatch() {
    if (g_patchState.vecDotPatched) {
        std::cout << "[Deep2Patch] VecDot already patched\n";
        return true;
    }
    
    void* target = (void*)&OriginalVecDotProduct;
    void* replacement = (void*)&Trampoline_VecDotProduct;
    
    // Create a jump instruction: jmp rel32
    // 5 bytes: 0xE9 + 32-bit relative offset
    int32_t relOffset = (int32_t)((uintptr_t)replacement - ((uintptr_t)target + 5));
    
    std::vector<unsigned char> patchBytes = { 0xE9 };
    patchBytes.push_back((relOffset >> 0) & 0xFF);
    patchBytes.push_back((relOffset >> 8) & 0xFF);
    patchBytes.push_back((relOffset >> 16) & 0xFF);
    patchBytes.push_back((relOffset >> 24) & 0xFF);
    
    // NOP padding to align (optional, for 8-byte alignment)
    patchBytes.push_back(0x90); // NOP
    patchBytes.push_back(0x90); // NOP
    patchBytes.push_back(0x90); // NOP
    
    if (g_deep2Patcher.ApplyPatch("Deep2_VecDotProduct", target, patchBytes)) {
        g_patchState.vecDotPatched = true;
        g_patchState.originalVecDot = target;
        std::cout << "[Deep2Patch] VecDotProduct patched -> AVX2 kernel\n";
        return true;
    }
    
    return false;
}

bool ApplySwiGLUPatch() {
    if (g_patchState.swiGLUPatched) {
        std::cout << "[Deep2Patch] SwiGLU already patched\n";
        return true;
    }
    
    void* target = (void*)&OriginalSwiGLU;
    void* replacement = (void*)&Trampoline_SwiGLU;
    
    int32_t relOffset = (int32_t)((uintptr_t)replacement - ((uintptr_t)target + 5));
    
    std::vector<unsigned char> patchBytes = { 0xE9 };
    patchBytes.push_back((relOffset >> 0) & 0xFF);
    patchBytes.push_back((relOffset >> 8) & 0xFF);
    patchBytes.push_back((relOffset >> 16) & 0xFF);
    patchBytes.push_back((relOffset >> 24) & 0xFF);
    patchBytes.push_back(0x90); // NOP padding
    patchBytes.push_back(0x90);
    patchBytes.push_back(0x90);
    
    if (g_deep2Patcher.ApplyPatch("Deep2_SwiGLU", target, patchBytes)) {
        g_patchState.swiGLUPatched = true;
        g_patchState.originalSwiGLU = target;
        std::cout << "[Deep2Patch] SwiGLU patched -> AVX2 kernel\n";
        return true;
    }
    
    return false;
}

bool ApplyRMSNormPatch() {
    if (g_patchState.rmsNormPatched) {
        std::cout << "[Deep2Patch] RMSNorm already patched\n";
        return true;
    }
    
    void* target = (void*)&OriginalRMSNorm;
    void* replacement = (void*)&Trampoline_RMSNorm;
    
    int32_t relOffset = (int32_t)((uintptr_t)replacement - ((uintptr_t)target + 5));
    
    std::vector<unsigned char> patchBytes = { 0xE9 };
    patchBytes.push_back((relOffset >> 0) & 0xFF);
    patchBytes.push_back((relOffset >> 8) & 0xFF);
    patchBytes.push_back((relOffset >> 16) & 0xFF);
    patchBytes.push_back((relOffset >> 24) & 0xFF);
    patchBytes.push_back(0x90); // NOP padding
    patchBytes.push_back(0x90);
    patchBytes.push_back(0x90);
    
    if (g_deep2Patcher.ApplyPatch("Deep2_RMSNorm", target, patchBytes)) {
        g_patchState.rmsNormPatched = true;
        g_patchState.originalRMSNorm = target;
        std::cout << "[Deep2Patch] RMSNorm patched -> AVX2 kernel\n";
        return true;
    }
    
    return false;
}

// ============================================================================
// Public API
// ============================================================================

bool Initialize() {
    if (g_patchState.initialized) {
        return true;
    }
    
    std::cout << "[Deep2Patch] Initializing Deep2 Hotpatch Bridge...\n";
    
    // Check CPU support
    if (!Deep2_HasAVX2()) {
        std::cerr << "[Deep2Patch] ERROR: AVX2 not supported, cannot apply patches\n";
        return false;
    }
    
    std::cout << "[Deep2Patch] CPU supports AVX2\n";
    std::cout << "[Deep2Patch] CPU supports AVX512: " << (Deep2_HasAVX512() ? "YES" : "NO") << "\n";
    
    g_patchState.initialized = true;
    return true;
}

bool ApplyAllPatches() {
    if (!g_patchState.initialized) {
        if (!Initialize()) {
            return false;
        }
    }
    
    std::cout << "[Deep2Patch] Applying Deep2 kernel patches...\n";
    
    bool success = true;
    success &= ApplyVecDotPatch();
    success &= ApplySwiGLUPatch();
    success &= ApplyRMSNormPatch();
    
    if (success) {
        std::cout << "[Deep2Patch] All patches applied successfully!\n";
    } else {
        std::cerr << "[Deep2Patch] Some patches failed to apply\n";
    }
    
    return success;
}

bool RevertAllPatches() {
    std::cout << "[Deep2Patch] Reverting Deep2 patches...\n";
    
    bool success = true;
    
    if (g_patchState.vecDotPatched) {
        success &= g_deep2Patcher.RevertPatch("Deep2_VecDotProduct");
        g_patchState.vecDotPatched = false;
    }
    
    if (g_patchState.swiGLUPatched) {
        success &= g_deep2Patcher.RevertPatch("Deep2_SwiGLU");
        g_patchState.swiGLUPatched = false;
    }
    
    if (g_patchState.rmsNormPatched) {
        success &= g_deep2Patcher.RevertPatch("Deep2_RMSNorm");
        g_patchState.rmsNormPatched = false;
    }
    
    std::cout << "[Deep2Patch] Patches reverted\n";
    return success;
}

void ListPatches() {
    g_deep2Patcher.ListPatches();
}

// ============================================================================
// Benchmark Comparison
// ============================================================================

void BenchmarkComparison() {
    const size_t n = 4096;
    float* a = Deep2_AlignedAlloc(n);
    float* b = Deep2_AlignedAlloc(n);
    float* out1 = Deep2_AlignedAlloc(1);
    float* out2 = Deep2_AlignedAlloc(1);
    
    // Initialize test data
    for (size_t i = 0; i < n; ++i) {
        a[i] = static_cast<float>(i % 100) / 100.0f;
        b[i] = static_cast<float>((i + 50) % 100) / 100.0f;
    }
    
    std::cout << "\n[Deep2Patch] Benchmark: VecDotProduct (n=" << n << ")\n";
    
    // Benchmark original (scalar)
    auto t0 = GetTickCount64();
    for (int iter = 0; iter < 1000; ++iter) {
        OriginalVecDotProduct(a, b, out1, n);
    }
    auto t1 = GetTickCount64();
    double scalarMs = static_cast<double>(t1 - t0);
    
    // Benchmark Deep2 (AVX2)
    t0 = GetTickCount64();
    for (int iter = 0; iter < 1000; ++iter) {
        Deep2_VecDotProduct(a, b, out2, n);
    }
    t1 = GetTickCount64();
    double avx2Ms = static_cast<double>(t1 - t0);
    
    std::cout << "  Scalar: " << scalarMs << " ms\n";
    std::cout << "  AVX2:   " << avx2Ms << " ms\n";
    std::cout << "  Speedup: " << (scalarMs / avx2Ms) << "x\n";
    std::cout << "  Results match: " << (std::abs(*out1 - *out2) < 0.01f ? "YES" : "NO") << "\n";
    
    Deep2_AlignedFree(a);
    Deep2_AlignedFree(b);
    Deep2_AlignedFree(out1);
    Deep2_AlignedFree(out2);
}

} // namespace HotPatch
} // namespace Deep2

// ============================================================================
// C Interface
// ============================================================================

extern "C" {

int Deep2HotPatch_Initialize() {
    return Deep2::HotPatch::Initialize() ? 1 : 0;
}

int Deep2HotPatch_ApplyAll() {
    return Deep2::HotPatch::ApplyAllPatches() ? 1 : 0;
}

int Deep2HotPatch_RevertAll() {
    return Deep2::HotPatch::RevertAllPatches() ? 1 : 0;
}

void Deep2HotPatch_List() {
    Deep2::HotPatch::ListPatches();
}

void Deep2HotPatch_Benchmark() {
    Deep2::HotPatch::BenchmarkComparison();
}

}
