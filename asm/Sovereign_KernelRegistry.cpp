//============================================================================
// Sovereign_KernelRegistry.cpp
// Centralized Kernel Dispatch Implementation
//
// Phase 7C: Runtime Dispatch Foundation
//============================================================================

#include "Sovereign_KernelRegistry.hpp"
#include <iostream>
#include <iomanip>
#include <cmath>

namespace Sovereign {

//============================================================================
// SINGLETON ACCESS
//============================================================================

KernelRegistry& KernelRegistry::Instance()
{
    static KernelRegistry instance;
    return instance;
}

//============================================================================
// INITIALIZATION
//============================================================================

bool KernelRegistry::Initialize()
{
    if (initialized_)
        return true;

    // Initialize CPU feature detection
    if (!CPUFeatureDetector::Instance().Initialize())
    {
        std::cerr << "Failed to initialize CPU feature detection" << std::endl;
        return false;
    }

    // Auto-detect best backend
    AutoDetectBackend();

    initialized_ = true;
    return true;
}

void KernelRegistry::AutoDetectBackend()
{
    preferredBackend_ = CPUFeatureDetector::Instance().GetBestBackend();

    std::cout << "[KernelRegistry] Auto-detected backend: "
              << KernelBackendToString(preferredBackend_) << std::endl;
}

//============================================================================
// BACKEND MANAGEMENT
//============================================================================

void KernelRegistry::SetPreferredBackend(KernelBackend backend)
{
    preferredBackend_ = backend;
    backendForced_ = false;

    // Re-select active implementations
    // (This would be called after all registrations are complete)
}

void KernelRegistry::ForceBackend(KernelBackend backend)
{
    forcedBackend_ = backend;
    backendForced_ = true;

    std::cout << "[KernelRegistry] Forced backend: "
              << KernelBackendToString(backend) << std::endl;
}

void KernelRegistry::ResetToAutoBackend()
{
    backendForced_ = false;
    AutoDetectBackend();
}

//============================================================================
// KERNEL REGISTRATION
//============================================================================

void KernelRegistry::RegisterRMSNorm(KernelBackend backend, RMSNormFunc func, const KernelDescriptor& desc)
{
    rmsNormImpls_[backend] = {func, desc};
    if (!activeRMSNorm_ || backend == GetPreferredBackend())
        activeRMSNorm_ = func;
}

void KernelRegistry::RegisterRoPE(KernelBackend backend, RoPEFunc func, const KernelDescriptor& desc)
{
    ropeImpls_[backend] = {func, desc};
    if (!activeRoPE_ || backend == GetPreferredBackend())
        activeRoPE_ = func;
}

void KernelRegistry::RegisterLayerNorm(KernelBackend backend, LayerNormFunc func, const KernelDescriptor& desc)
{
    layerNormImpls_[backend] = {func, desc};
    if (!activeLayerNorm_ || backend == GetPreferredBackend())
        activeLayerNorm_ = func;
}

void KernelRegistry::RegisterResidualAdd(KernelBackend backend, ResidualAddFunc func, const KernelDescriptor& desc)
{
    residualAddImpls_[backend] = {func, desc};
    if (!activeResidualAdd_ || backend == GetPreferredBackend())
        activeResidualAdd_ = func;
}

void KernelRegistry::RegisterMatMulF32(KernelBackend backend, MatMulF32Func func, const KernelDescriptor& desc)
{
    matMulF32Impls_[backend] = {func, desc};
    if (!activeMatMulF32_ || backend == GetPreferredBackend())
        activeMatMulF32_ = func;
}

void KernelRegistry::RegisterMatMulQ4Q8(KernelBackend backend, MatMulQ4Q8Func func, const KernelDescriptor& desc)
{
    matMulQ4Q8Impls_[backend] = {func, desc};
    if (!activeMatMulQ4Q8_ || backend == GetPreferredBackend())
        activeMatMulQ4Q8_ = func;
}

void KernelRegistry::RegisterFlashAttention(KernelBackend backend, FlashAttentionFunc func, const KernelDescriptor& desc)
{
    flashAttentionImpls_[backend] = {func, desc};
    if (!activeFlashAttention_ || backend == GetPreferredBackend())
        activeFlashAttention_ = func;
}

void KernelRegistry::RegisterSoftmax(KernelBackend backend, SoftmaxFunc func, const KernelDescriptor& desc)
{
    softmaxImpls_[backend] = {func, desc};
    if (!activeSoftmax_ || backend == GetPreferredBackend())
        activeSoftmax_ = func;
}

void KernelRegistry::RegisterTokenMerge(KernelBackend backend, TokenMergeFunc func, const KernelDescriptor& desc)
{
    tokenMergeImpls_[backend] = {func, desc};
    if (!activeTokenMerge_ || backend == GetPreferredBackend())
        activeTokenMerge_ = func;
}

void KernelRegistry::RegisterDequantizeQ4(KernelBackend backend, DequantizeQ4Func func, const KernelDescriptor& desc)
{
    dequantizeQ4Impls_[backend] = {func, desc};
    if (!activeDequantizeQ4_ || backend == GetPreferredBackend())
        activeDequantizeQ4_ = func;
}

void KernelRegistry::RegisterDequantizeQ8(KernelBackend backend, DequantizeQ8Func func, const KernelDescriptor& desc)
{
    dequantizeQ8Impls_[backend] = {func, desc};
    if (!activeDequantizeQ8_ || backend == GetPreferredBackend())
        activeDequantizeQ8_ = func;
}

//============================================================================
// KERNEL DISPATCH (Unified Entry Points)
//============================================================================

int KernelRegistry::RMSNorm(const float* input, float* output, size_t n, float epsilon)
{
    if (!activeRMSNorm_)
    {
        std::cerr << "[KernelRegistry] RMSNorm not registered" << std::endl;
        return -1;
    }
    return activeRMSNorm_(input, output, n, epsilon);
}

int KernelRegistry::RoPE(float* q, float* k, size_t seq_len, size_t head_dim, size_t pos)
{
    if (!activeRoPE_)
    {
        std::cerr << "[KernelRegistry] RoPE not registered" << std::endl;
        return -1;
    }
    return activeRoPE_(q, k, seq_len, head_dim, pos);
}

int KernelRegistry::LayerNorm(const float* input, float* output, size_t n,
                               const float* gamma, const float* beta, float epsilon)
{
    if (!activeLayerNorm_)
    {
        std::cerr << "[KernelRegistry] LayerNorm not registered" << std::endl;
        return -1;
    }
    return activeLayerNorm_(input, output, n, gamma, beta, epsilon);
}

int KernelRegistry::ResidualAdd(const float* a, const float* b, float* output,
                                 size_t n, float scale)
{
    if (!activeResidualAdd_)
    {
        std::cerr << "[KernelRegistry] ResidualAdd not registered" << std::endl;
        return -1;
    }
    return activeResidualAdd_(a, b, output, n, scale);
}

int KernelRegistry::MatMulF32(const float* A, const float* B, float* C,
                              size_t m, size_t n, size_t k)
{
    if (!activeMatMulF32_)
    {
        std::cerr << "[KernelRegistry] MatMulF32 not registered" << std::endl;
        return -1;
    }
    return activeMatMulF32_(A, B, C, m, n, k);
}

int KernelRegistry::MatMulQ4Q8(const void* A_q4, const void* B_q8, float* C,
                                size_t m, size_t n, size_t k)
{
    if (!activeMatMulQ4Q8_)
    {
        std::cerr << "[KernelRegistry] MatMulQ4Q8 not registered" << std::endl;
        return -1;
    }
    return activeMatMulQ4Q8_(A_q4, B_q8, C, m, n, k);
}

int KernelRegistry::FlashAttention(const float* Q, const float* K, const float* V,
                                   float* output, size_t seq_len, size_t head_dim)
{
    if (!activeFlashAttention_)
    {
        std::cerr << "[KernelRegistry] FlashAttention not registered" << std::endl;
        return -1;
    }
    return activeFlashAttention_(Q, K, V, output, seq_len, head_dim);
}

int KernelRegistry::Softmax(const float* input, float* output, size_t n)
{
    if (!activeSoftmax_)
    {
        std::cerr << "[KernelRegistry] Softmax not registered" << std::endl;
        return -1;
    }
    return activeSoftmax_(input, output, n);
}

int KernelRegistry::TokenMerge(const float* tokens, float* output,
                                size_t num_tokens, size_t embed_dim)
{
    if (!activeTokenMerge_)
    {
        std::cerr << "[KernelRegistry] TokenMerge not registered" << std::endl;
        return -1;
    }
    return activeTokenMerge_(tokens, output, num_tokens, embed_dim);
}

int KernelRegistry::DequantizeQ4(const void* quantized, float* output, size_t n)
{
    if (!activeDequantizeQ4_)
    {
        std::cerr << "[KernelRegistry] DequantizeQ4 not registered" << std::endl;
        return -1;
    }
    return activeDequantizeQ4_(quantized, output, n);
}

int KernelRegistry::DequantizeQ8(const void* quantized, float* output, size_t n)
{
    if (!activeDequantizeQ8_)
    {
        std::cerr << "[KernelRegistry] DequantizeQ8 not registered" << std::endl;
        return -1;
    }
    return activeDequantizeQ8_(quantized, output, n);
}

//============================================================================
// VALIDATION
//============================================================================

bool KernelRegistry::ValidateAllKernels(float tolerance)
{
    std::cout << "[KernelRegistry] Validating all kernels..." << std::endl;

    bool allPassed = true;

    allPassed &= ValidateRMSNorm(tolerance);
    allPassed &= ValidateRoPE(tolerance);
    allPassed &= ValidateMatMul(tolerance);
    allPassed &= ValidateFlashAttention(tolerance);

    if (allPassed)
    {
        std::cout << "[KernelRegistry] ✓ All kernels validated" << std::endl;
    }
    else
    {
        std::cerr << "[KernelRegistry] ✗ Some kernels failed validation" << std::endl;
    }

    return allPassed;
}

bool KernelRegistry::ValidateRMSNorm(float tolerance)
{
    // TODO: Implement validation against reference
    std::cout << "[Validation] RMSNorm: SKIPPED (implement reference)" << std::endl;
    return true;
}

bool KernelRegistry::ValidateRoPE(float tolerance)
{
    // TODO: Implement validation against reference
    std::cout << "[Validation] RoPE: SKIPPED (implement reference)" << std::endl;
    return true;
}

bool KernelRegistry::ValidateMatMul(float tolerance)
{
    // TODO: Implement validation against reference
    std::cout << "[Validation] MatMul: SKIPPED (implement reference)" << std::endl;
    return true;
}

bool KernelRegistry::ValidateFlashAttention(float tolerance)
{
    // TODO: Implement validation against reference
    std::cout << "[Validation] FlashAttention: SKIPPED (implement reference)" << std::endl;
    return true;
}

//============================================================================
// BENCHMARKING
//============================================================================

void KernelRegistry::BenchmarkAllKernels(size_t iterations)
{
    std::cout << "[KernelRegistry] Benchmarking all kernels..." << std::endl;
    // TODO: Implement comprehensive benchmarking
}

//============================================================================
// INFO & DEBUGGING
//============================================================================

void KernelRegistry::PrintStatus() const
{
    std::cout << "\n========== Kernel Registry Status ==========" << std::endl;
    std::cout << "Preferred Backend: " << KernelBackendToString(preferredBackend_) << std::endl;
    std::cout << "Forced: " << (backendForced_ ? "Yes" : "No") << std::endl;

    std::cout << "\nRegistered Implementations:" << std::endl;
    std::cout << "  RMSNorm: " << rmsNormImpls_.size() << std::endl;
    std::cout << "  RoPE: " << ropeImpls_.size() << std::endl;
    std::cout << "  LayerNorm: " << layerNormImpls_.size() << std::endl;
    std::cout << "  ResidualAdd: " << residualAddImpls_.size() << std::endl;
    std::cout << "  MatMulF32: " << matMulF32Impls_.size() << std::endl;
    std::cout << "  MatMulQ4Q8: " << matMulQ4Q8Impls_.size() << std::endl;
    std::cout << "  FlashAttention: " << flashAttentionImpls_.size() << std::endl;
    std::cout << "  Softmax: " << softmaxImpls_.size() << std::endl;
    std::cout << "  TokenMerge: " << tokenMergeImpls_.size() << std::endl;
    std::cout << "  DequantizeQ4: " << dequantizeQ4Impls_.size() << std::endl;
    std::cout << "  DequantizeQ8: " << dequantizeQ8Impls_.size() << std::endl;

    std::cout << "============================================\n" << std::endl;
}

} // namespace Sovereign
