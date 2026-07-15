//============================================================================
// Sovereign_KernelRegistry.hpp
// Centralized Kernel Dispatch Registry
//
// Phase 7C: Runtime Dispatch Foundation
// Provides unified entry points for all transformer operations
//============================================================================

#pragma once

#include "Sovereign_CPUFeatures.hpp"
#include <cstdint>
#include <functional>
#include <map>
#include <string>

namespace Sovereign {

//============================================================================
// KERNEL FUNCTION SIGNATURES
//============================================================================

// RMSNorm: y = x / sqrt(mean(x^2) + epsilon)
using RMSNormFunc = int (*)(const float* input, float* output, size_t n, float epsilon);

// RoPE: Rotary Position Embedding
using RoPEFunc = int (*)(float* q, float* k, size_t seq_len, size_t head_dim, size_t pos);

// LayerNorm: y = (x - mean) / sqrt(var + epsilon) * gamma + beta
using LayerNormFunc = int (*)(const float* input, float* output, size_t n, 
                               const float* gamma, const float* beta, float epsilon);

// ResidualAdd: output = a + b (or a + scale * b)
using ResidualAddFunc = int (*)(const float* a, const float* b, float* output, 
                                 size_t n, float scale);

// MatMul: C = A * B (various quantized formats)
using MatMulF32Func = int (*)(const float* A, const float* B, float* C,
                               size_t m, size_t n, size_t k);
using MatMulQ4Q8Func = int (*)(const void* A_q4, const void* B_q8, float* C,
                                size_t m, size_t n, size_t k);

// FlashAttention: output = softmax(Q*K^T / sqrt(d_k)) * V
using FlashAttentionFunc = int (*)(const float* Q, const float* K, const float* V,
                                    float* output, size_t seq_len, size_t head_dim);

// Softmax: output = exp(x) / sum(exp(x))
using SoftmaxFunc = int (*)(const float* input, float* output, size_t n);

// TokenMerge: Merge multiple token embeddings
using TokenMergeFunc = int (*)(const float* tokens, float* output, 
                                size_t num_tokens, size_t embed_dim);

// Dequantize: Convert quantized to float
using DequantizeQ4Func = int (*)(const void* quantized, float* output, size_t n);
using DequantizeQ8Func = int (*)(const void* quantized, float* output, size_t n);

//============================================================================
// KERNEL DESCRIPTOR
//============================================================================

struct KernelDescriptor
{
    const char* name;
    KernelBackend backend;
    const char* version;
    const char* description;
    bool validated;           // Has passed numerical validation
    float maxError;          // Maximum numerical error vs reference
    float avgTimeUs;         // Average execution time (microseconds)
    float throughputGFLOPs; // Throughput in GFLOP/s
};

//============================================================================
// KERNEL REGISTRY
//============================================================================

class KernelRegistry
{
public:
    // Singleton access
    static KernelRegistry& Instance();
    
    // Initialize registry and detect best backends
    bool Initialize();
    bool IsInitialized() const { return initialized_; }
    
    //========================================================================
    // KERNEL REGISTRATION
    //========================================================================
    
    // Register implementations for each kernel type
    void RegisterRMSNorm(KernelBackend backend, RMSNormFunc func, const KernelDescriptor& desc);
    void RegisterRoPE(KernelBackend backend, RoPEFunc func, const KernelDescriptor& desc);
    void RegisterLayerNorm(KernelBackend backend, LayerNormFunc func, const KernelDescriptor& desc);
    void RegisterResidualAdd(KernelBackend backend, ResidualAddFunc func, const KernelDescriptor& desc);
    void RegisterMatMulF32(KernelBackend backend, MatMulF32Func func, const KernelDescriptor& desc);
    void RegisterMatMulQ4Q8(KernelBackend backend, MatMulQ4Q8Func func, const KernelDescriptor& desc);
    void RegisterFlashAttention(KernelBackend backend, FlashAttentionFunc func, const KernelDescriptor& desc);
    void RegisterSoftmax(KernelBackend backend, SoftmaxFunc func, const KernelDescriptor& desc);
    void RegisterTokenMerge(KernelBackend backend, TokenMergeFunc func, const KernelDescriptor& desc);
    void RegisterDequantizeQ4(KernelBackend backend, DequantizeQ4Func func, const KernelDescriptor& desc);
    void RegisterDequantizeQ8(KernelBackend backend, DequantizeQ8Func func, const KernelDescriptor& desc);
    
    //========================================================================
    // KERNEL DISPATCH (Unified Entry Points)
    //========================================================================
    
    // These are the ONLY functions that should be called from inference code
    int RMSNorm(const float* input, float* output, size_t n, float epsilon);
    int RoPE(float* q, float* k, size_t seq_len, size_t head_dim, size_t pos);
    int LayerNorm(const float* input, float* output, size_t n,
                  const float* gamma, const float* beta, float epsilon);
    int ResidualAdd(const float* a, const float* b, float* output, 
                    size_t n, float scale);
    int MatMulF32(const float* A, const float* B, float* C,
                  size_t m, size_t n, size_t k);
    int MatMulQ4Q8(const void* A_q4, const void* B_q8, float* C,
                   size_t m, size_t n, size_t k);
    int FlashAttention(const float* Q, const float* K, const float* V,
                       float* output, size_t seq_len, size_t head_dim);
    int Softmax(const float* input, float* output, size_t n);
    int TokenMerge(const float* tokens, float* output, 
                   size_t num_tokens, size_t embed_dim);
    int DequantizeQ4(const void* quantized, float* output, size_t n);
    int DequantizeQ8(const void* quantized, float* output, size_t n);
    
    //========================================================================
    // BACKEND MANAGEMENT
    //========================================================================
    
    // Set preferred backend (auto-detected if not set)
    void SetPreferredBackend(KernelBackend backend);
    KernelBackend GetPreferredBackend() const { return preferredBackend_; }
    
    // Force specific backend for testing
    void ForceBackend(KernelBackend backend);
    void ResetToAutoBackend();
    
    // Get currently active backend for each kernel type
    KernelBackend GetActiveRMSNormBackend() const;
    KernelBackend GetActiveRoPEBackend() const;
    KernelBackend GetActiveMatMulBackend() const;
    KernelBackend GetActiveFlashAttentionBackend() const;
    
    //========================================================================
    // VALIDATION & BENCHMARKING
    //========================================================================
    
    // Validate all kernels against reference (scalar) implementation
    bool ValidateAllKernels(float tolerance = 1e-5f);
    
    // Validate specific kernel
    bool ValidateRMSNorm(float tolerance = 1e-5f);
    bool ValidateRoPE(float tolerance = 1e-5f);
    bool ValidateMatMul(float tolerance = 1e-4f);
    bool ValidateFlashAttention(float tolerance = 1e-3f);
    
    // Benchmark all kernels
    void BenchmarkAllKernels(size_t iterations = 100);
    
    // Get validation/benchmark results
    const KernelDescriptor* GetRMSNormDescriptor() const;
    const KernelDescriptor* GetRoPEDescriptor() const;
    const KernelDescriptor* GetMatMulDescriptor() const;
    const KernelDescriptor* GetFlashAttentionDescriptor() const;
    
    //========================================================================
    // INFO & DEBUGGING
    //========================================================================
    
    // Print registry status
    void PrintStatus() const;
    
    // Get number of registered implementations
    size_t GetImplementationCount(const char* kernelName) const;
    
    // List all available backends for a kernel
    std::vector<KernelBackend> GetAvailableBackends(const char* kernelName) const;

private:
    KernelRegistry() = default;
    ~KernelRegistry() = default;
    
    KernelRegistry(const KernelRegistry&) = delete;
    KernelRegistry& operator=(const KernelRegistry&) = delete;
    
    // Auto-detect best backend based on CPU features
    void AutoDetectBackend();
    
    // Select best available implementation
    template<typename FuncType>
    FuncType SelectBestImplementation(
        const std::map<KernelBackend, std::pair<FuncType, KernelDescriptor>>& registry);
    
    bool initialized_ = false;
    KernelBackend preferredBackend_ = KernelBackend::Scalar;
    KernelBackend forcedBackend_ = KernelBackend::Scalar;
    bool backendForced_ = false;
    
    // Implementation registries
    std::map<KernelBackend, std::pair<RMSNormFunc, KernelDescriptor>> rmsNormImpls_;
    std::map<KernelBackend, std::pair<RoPEFunc, KernelDescriptor>> ropeImpls_;
    std::map<KernelBackend, std::pair<LayerNormFunc, KernelDescriptor>> layerNormImpls_;
    std::map<KernelBackend, std::pair<ResidualAddFunc, KernelDescriptor>> residualAddImpls_;
    std::map<KernelBackend, std::pair<MatMulF32Func, KernelDescriptor>> matMulF32Impls_;
    std::map<KernelBackend, std::pair<MatMulQ4Q8Func, KernelDescriptor>> matMulQ4Q8Impls_;
    std::map<KernelBackend, std::pair<FlashAttentionFunc, KernelDescriptor>> flashAttentionImpls_;
    std::map<KernelBackend, std::pair<SoftmaxFunc, KernelDescriptor>> softmaxImpls_;
    std::map<KernelBackend, std::pair<TokenMergeFunc, KernelDescriptor>> tokenMergeImpls_;
    std::map<KernelBackend, std::pair<DequantizeQ4Func, KernelDescriptor>> dequantizeQ4Impls_;
    std::map<KernelBackend, std::pair<DequantizeQ8Func, KernelDescriptor>> dequantizeQ8Impls_;
    
    // Active implementations (selected based on backend)
    RMSNormFunc activeRMSNorm_ = nullptr;
    RoPEFunc activeRoPE_ = nullptr;
    LayerNormFunc activeLayerNorm_ = nullptr;
    ResidualAddFunc activeResidualAdd_ = nullptr;
    MatMulF32Func activeMatMulF32_ = nullptr;
    MatMulQ4Q8Func activeMatMulQ4Q8_ = nullptr;
    FlashAttentionFunc activeFlashAttention_ = nullptr;
    SoftmaxFunc activeSoftmax_ = nullptr;
    TokenMergeFunc activeTokenMerge_ = nullptr;
    DequantizeQ4Func activeDequantizeQ4_ = nullptr;
    DequantizeQ8Func activeDequantizeQ8_ = nullptr;
};

//============================================================================
// CONVENIENCE MACROS
//============================================================================

#define SOVEREIGN_KERNELS (::Sovereign::KernelRegistry::Instance())

} // namespace Sovereign
