// ============================================================================
// KernelRegistry.hpp
// ============================================================================
// Central registry for compute kernels. The runtime resolves kernels ONCE
// during model load, then dispatches via function pointers - no branching.
//
// Adding a new quantization = registering kernels, NOT editing inference code.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#pragma once

#include "UniversalTensorDescriptor.hpp"
#include <functional>
#include <unordered_map>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

#ifdef _MSC_VER
    #include <intrin.h>
#endif

namespace RawrXD {

// ============================================================================
// Kernel Function Signatures (unified ABI)
// ============================================================================

// GEMV: y = A * x  (matrix-vector)
// A is [rows, cols] quantized, x is [cols] float, y is [rows] float
using GEMVKernel = void(*)(
    const void* weights,    // Quantized weight matrix
    const float* input,     // Input vector [cols]
    float* output,          // Output vector [rows]
    uint32_t rows,
    uint32_t cols,
    const void* scales,     // Per-block scales (may be null for F32/F16)
    const void* zeros       // Per-block zeros (may be null)
);

// GEMM: C = A * B  (matrix-matrix)
using GEMMKernel = void(*)(
    const void* A,
    const void* B,
    void* C,
    uint32_t M, uint32_t N, uint32_t K,
    const void* scalesA,
    const void* scalesB
);

// Attention: fused Q@K^T -> softmax -> @V
using AttentionKernel = void(*)(
    float* output,          // [num_q, head_dim]
    const float* Q,         // [num_q, head_dim]
    const void* K,          // [num_k, head_dim] (may be quantized)
    const void* V,          // [num_k, head_dim] (may be quantized)
    uint32_t num_q,
    uint32_t num_k,
    uint32_t head_dim,
    const uint8_t* mask,    // Tree mask (may be null)
    const void* kScales,    // K dequant scales (null if F32)
    const void* vScales     // V dequant scales (null if F32)
);

// RMSNorm: y = x / sqrt(mean(x^2) + eps) * weight
using RMSNormKernel = void(*)(
    const float* x,
    const float* weight,
    float* output,
    uint32_t dim,
    float eps
);

// RoPE: rotary position embedding
using RoPEKernel = void(*)(
    float* x,
    uint32_t dim,
    uint32_t position,
    float theta
);

// SiLU: x * sigmoid(x)
using SiLUKernel = void(*)(
    const float* x,
    float* output,
    uint32_t dim
);

// MoE Router: select top-k experts
using MoERouterKernel = void(*)(
    const float* hidden,        // [hidden_dim]
    const float* routerWeight,  // [num_experts, hidden_dim]
    uint32_t* selectedExperts,  // [top_k] output
    float* selectedWeights,     // [top_k] output
    uint32_t numExperts,
    uint32_t hiddenDim,
    uint32_t topK
);

// MoE Expert FFN: fused gate + silu + up + down
using MoEExpertKernel = void(*)(
    const void* gateWeight,     // Quantized
    const void* upWeight,        // Quantized
    const void* downWeight,      // Quantized
    const float* input,          // [hidden_dim]
    float* output,               // [hidden_dim]
    uint32_t hiddenDim,
    uint32_t interDim,
    const void* gateScales,
    const void* upScales,
    const void* downScales
);

// Sampler: top-k + top-p + temperature
using SamplerKernel = void(*)(
    const float* logits,     // [vocab_size]
    float* probs,            // [vocab_size] output
    uint32_t vocabSize,
    uint32_t topK,
    float topP,
    float temperature
);

// ============================================================================
// Kernel Type Enum
// ============================================================================
enum class KernelType : uint8_t {
    GEMV        = 0,
    GEMM        = 1,
    ATTENTION   = 2,
    RMSNORM     = 3,
    ROPE        = 4,
    SILU        = 5,
    MOE_ROUTER  = 6,
    MOE_EXPERT  = 7,
    SAMPLER     = 8,
};

// ============================================================================
// ISA Target
// ============================================================================
enum class ISATarget : uint8_t {
    SCALAR  = 0,   // Pure C++ fallback
    AVX2    = 1,   // AVX2 + FMA
    AVX512  = 2,   // AVX-512F/BW/VL
    AVX512_VNNI = 3, // AVX-512 with VNNI
    AMX     = 4,   // Intel AMX
    GPU     = 5,   // GPU (Vulkan/CUDA/DirectML)
    FUTURE  = 0xFF // Future ISA
};

// ============================================================================
// Kernel Registry Key
// ============================================================================
struct KernelKey {
    KernelType type;
    QuantType quantType;
    ISATarget isa;

    bool operator==(const KernelKey& other) const {
        return type == other.type &&
               quantType == other.quantType &&
               isa == other.isa;
    }

    // Hash for unordered_map
    uint64_t hash() const {
        return (static_cast<uint64_t>(type) << 32) |
               (static_cast<uint64_t>(quantType) << 16) |
               static_cast<uint64_t>(isa);
    }
};

struct KernelKeyHash {
    uint64_t operator()(const KernelKey& k) const { return k.hash(); }
};

// ============================================================================
// Kernel Registry - Singleton
// ============================================================================
// Resolves kernels ONCE during model load. After that, dispatch is O(1)
// function pointer call - no branching, no string compares, no format checks.
// ============================================================================
class KernelRegistry {
public:
    static KernelRegistry& Instance() {
        static KernelRegistry instance;
        return instance;
    }

    // ------------------------------------------------------------------------
    // Registration (called by kernel modules at startup or model load)
    // ------------------------------------------------------------------------
    void RegisterGEMV(QuantType quant, ISATarget isa, GEMVKernel kernel) {
        KernelKey key{KernelType::GEMV, quant, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        gemvKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterGEMM(QuantType quant, ISATarget isa, GEMMKernel kernel) {
        KernelKey key{KernelType::GEMM, quant, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        gemmKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterAttention(QuantType quant, ISATarget isa, AttentionKernel kernel) {
        KernelKey key{KernelType::ATTENTION, quant, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        attentionKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterRMSNorm(ISATarget isa, RMSNormKernel kernel) {
        KernelKey key{KernelType::RMSNORM, QuantType::F32, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        rmsnormKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterRoPE(ISATarget isa, RoPEKernel kernel) {
        KernelKey key{KernelType::ROPE, QuantType::F32, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        ropeKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterSiLU(ISATarget isa, SiLUKernel kernel) {
        KernelKey key{KernelType::SILU, QuantType::F32, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        siluKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterMoERouter(ISATarget isa, MoERouterKernel kernel) {
        KernelKey key{KernelType::MOE_ROUTER, QuantType::F32, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        moeRouterKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterMoEExpert(QuantType quant, ISATarget isa, MoEExpertKernel kernel) {
        KernelKey key{KernelType::MOE_EXPERT, quant, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        moeExpertKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    void RegisterSampler(ISATarget isa, SamplerKernel kernel) {
        KernelKey key{KernelType::SAMPLER, QuantType::F32, isa};
        std::lock_guard<std::mutex> lock(mutex_);
        samplerKernels_[key] = reinterpret_cast<void*>(kernel);
    }

    // ------------------------------------------------------------------------
    // Resolution (called ONCE during model load, cached in execution graph)
    // ------------------------------------------------------------------------
    GEMVKernel ResolveGEMV(QuantType quant, ISATarget isa) const {
        KernelKey key{KernelType::GEMV, quant, isa};
        auto it = gemvKernels_.find(key);
        if (it != gemvKernels_.end()) {
            return reinterpret_cast<GEMVKernel>(it->second);
        }
        // Fallback to scalar
        if (isa != ISATarget::SCALAR) {
            return ResolveGEMV(quant, ISATarget::SCALAR);
        }
        return nullptr;
    }

    GEMMKernel ResolveGEMM(QuantType quant, ISATarget isa) const {
        KernelKey key{KernelType::GEMM, quant, isa};
        auto it = gemmKernels_.find(key);
        if (it != gemmKernels_.end()) {
            return reinterpret_cast<GEMMKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveGEMM(quant, ISATarget::SCALAR);
        }
        return nullptr;
    }

    AttentionKernel ResolveAttention(QuantType quant, ISATarget isa) const {
        KernelKey key{KernelType::ATTENTION, quant, isa};
        auto it = attentionKernels_.find(key);
        if (it != attentionKernels_.end()) {
            return reinterpret_cast<AttentionKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveAttention(quant, ISATarget::SCALAR);
        }
        return nullptr;
    }

    RMSNormKernel ResolveRMSNorm(ISATarget isa) const {
        KernelKey key{KernelType::RMSNORM, QuantType::F32, isa};
        auto it = rmsnormKernels_.find(key);
        if (it != rmsnormKernels_.end()) {
            return reinterpret_cast<RMSNormKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveRMSNorm(ISATarget::SCALAR);
        }
        return nullptr;
    }

    RoPEKernel ResolveRoPE(ISATarget isa) const {
        KernelKey key{KernelType::ROPE, QuantType::F32, isa};
        auto it = ropeKernels_.find(key);
        if (it != ropeKernels_.end()) {
            return reinterpret_cast<RoPEKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveRoPE(ISATarget::SCALAR);
        }
        return nullptr;
    }

    SiLUKernel ResolveSiLU(ISATarget isa) const {
        KernelKey key{KernelType::SILU, QuantType::F32, isa};
        auto it = siluKernels_.find(key);
        if (it != siluKernels_.end()) {
            return reinterpret_cast<SiLUKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveSiLU(ISATarget::SCALAR);
        }
        return nullptr;
    }

    MoERouterKernel ResolveMoERouter(ISATarget isa) const {
        KernelKey key{KernelType::MOE_ROUTER, QuantType::F32, isa};
        auto it = moeRouterKernels_.find(key);
        if (it != moeRouterKernels_.end()) {
            return reinterpret_cast<MoERouterKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveMoERouter(ISATarget::SCALAR);
        }
        return nullptr;
    }

    MoEExpertKernel ResolveMoEExpert(QuantType quant, ISATarget isa) const {
        KernelKey key{KernelType::MOE_EXPERT, quant, isa};
        auto it = moeExpertKernels_.find(key);
        if (it != moeExpertKernels_.end()) {
            return reinterpret_cast<MoEExpertKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveMoEExpert(quant, ISATarget::SCALAR);
        }
        return nullptr;
    }

    SamplerKernel ResolveSampler(ISATarget isa) const {
        KernelKey key{KernelType::SAMPLER, QuantType::F32, isa};
        auto it = samplerKernels_.find(key);
        if (it != samplerKernels_.end()) {
            return reinterpret_cast<SamplerKernel>(it->second);
        }
        if (isa != ISATarget::SCALAR) {
            return ResolveSampler(ISATarget::SCALAR);
        }
        return nullptr;
    }

    // ------------------------------------------------------------------------
    // Query: what kernels are registered?
    // ------------------------------------------------------------------------
    struct KernelInfo {
        KernelType type;
        QuantType quant;
        ISATarget isa;
    };

    std::vector<KernelInfo> ListRegistered() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<KernelInfo> result;
        for (const auto& [k, v] : gemvKernels_) {
            result.push_back({k.type, k.quantType, k.isa});
        }
        for (const auto& [k, v] : gemmKernels_) {
            result.push_back({k.type, k.quantType, k.isa});
        }
        for (const auto& [k, v] : attentionKernels_) {
            result.push_back({k.type, k.quantType, k.isa});
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // Detect best available ISA
    // ------------------------------------------------------------------------
    static ISATarget DetectBestISA() {
        // Check AVX-512
        int cpuInfo[4];
        __cpuid(cpuInfo, 7);
        bool hasAVX512F = (cpuInfo[1] & (1 << 16)) != 0;
        bool hasAVX512BW = (cpuInfo[1] & (1 << 30)) != 0;
        bool hasAVX512VL = (cpuInfo[1] & (1 << 31)) != 0;
        bool hasAVX512VNNI = (cpuInfo[2] & (1 << 11)) != 0;

        if (hasAVX512VNNI && hasAVX512BW && hasAVX512VL) {
            return ISATarget::AVX512_VNNI;
        }
        if (hasAVX512F && hasAVX512BW && hasAVX512VL) {
            return ISATarget::AVX512;
        }

        // Check AVX2
        __cpuid(cpuInfo, 1);
        bool hasAVX2 = (cpuInfo[2] & (1 << 5)) != 0;
        if (hasAVX2) {
            return ISATarget::AVX2;
        }

        return ISATarget::SCALAR;
    }

private:
    KernelRegistry() = default;

    mutable std::mutex mutex_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> gemvKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> gemmKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> attentionKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> rmsnormKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> ropeKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> siluKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> moeRouterKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> moeExpertKernels_;
    std::unordered_map<KernelKey, void*, KernelKeyHash> samplerKernels_;
};

// ============================================================================
// Resolved Kernel Table (per-model, cached at load time)
// ============================================================================
// The execution graph holds one of these. Zero runtime branching.
// ============================================================================
struct ResolvedKernelTable {
    ISATarget isa;

    // Per-tensor resolved kernels (indexed by tensor role)
    GEMVKernel       gemv;
    GEMMKernel       gemm;
    AttentionKernel  attention;
    RMSNormKernel    rmsnorm;
    RoPEKernel       rope;
    SiLUKernel       silu;
    MoERouterKernel  moeRouter;
    MoEExpertKernel  moeExpert;
    SamplerKernel    sampler;

    // Resolve all kernels for a given quantization
    static ResolvedKernelTable Resolve(QuantType weightQuant, QuantType kvQuant) {
        ResolvedKernelTable table;
        table.isa = KernelRegistry::DetectBestISA();

        auto& reg = KernelRegistry::Instance();
        table.gemv       = reg.ResolveGEMV(weightQuant, table.isa);
        table.gemm        = reg.ResolveGEMM(weightQuant, table.isa);
        table.attention   = reg.ResolveAttention(kvQuant, table.isa);
        table.rmsnorm     = reg.ResolveRMSNorm(table.isa);
        table.rope        = reg.ResolveRoPE(table.isa);
        table.silu        = reg.ResolveSiLU(table.isa);
        table.moeRouter   = reg.ResolveMoERouter(table.isa);
        table.moeExpert   = reg.ResolveMoEExpert(weightQuant, table.isa);
        table.sampler     = reg.ResolveSampler(table.isa);

        return table;
    }
};

} // namespace RawrXD
