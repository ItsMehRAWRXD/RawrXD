// ============================================================================
// RuntimePlanner.hpp
// ============================================================================
// The runtime planner decides which execution strategy to use based on
// tensor descriptors and available kernels. This is where "Q doesn't matter"
// becomes concrete: quantization and attention implementation become
// runtime-selected execution strategies, not model-format constraints.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#pragma once

#include "UniversalTensorDescriptor.hpp"
#include "KernelRegistry.hpp"
#include "UniversalModelLoader.hpp"
#include "TensorHop.hpp"
#include <vector>
#include <memory>
#include <string>

namespace RawrXD {

// ============================================================================
// Execution Strategy (chosen at runtime, not compile time)
// ============================================================================
enum class ExecutionStrategy : uint8_t {
    // Attention strategies
    FUSED_ATTENTION_AVX512   = 0,  // VAL-038 fused kernel
    TREE_ATTENTION_SPARSE    = 1,  // Sparse tree mask
    STANDARD_ATTENTION       = 2,  // Dense fallback
    GPU_ATTENTION            = 3,  // GPU offload

    // MoE strategies
    MOE_FUSED_AVX512         = 10, // Fused expert FFN
    MOE_PAGED_NVME           = 11, // NVMe expert paging
    MOE_WARMUP_CACHE         = 12, // Warm-up cache hit
    MOE_STREAMING            = 13, // Streaming expert load

    // Memory strategies
    MEMORY_RESIDENT          = 20, // All in RAM
    MEMORY_NVME_PAGED        = 21, // NVMe paging
    MEMORY_MAPPED            = 22, // Memory-mapped
    MEMORY_STREAMED          = 23, // Streaming (not fully loaded)

    // Compression strategies
    COMPRESS_NONE            = 30,
    COMPRESS_NU_FUSED        = 31, // NU-Fused decompression
    COMPRESS_XVA             = 32, // XVA packed
    COMPRESS_RESOURCE        = 33, // Resource packed
};

// ============================================================================
// Execution Plan (per-layer, per-token)
// ============================================================================
struct ExecutionPlan {
    // Attention
    ExecutionStrategy attentionStrategy;
    AttentionKernel attentionKernel;
    const void* kWeights;
    const void* vWeights;
    const void* kScales;
    const void* vScales;
    QuantType kvQuant;

    // MoE
    bool useMoE;
    ExecutionStrategy moeStrategy;
    MoERouterKernel moeRouterKernel;
    MoEExpertKernel moeExpertKernel;
    uint32_t numExperts;
    uint32_t topK;

    // Memory
    ExecutionStrategy memoryStrategy;
    std::unique_ptr<Deep2::DMAScheduler> dmaScheduler;

    // Resolved kernels
    ResolvedKernelTable kernels;
};

// ============================================================================
// Runtime Planner
// ============================================================================
class RuntimePlanner {
public:
    RuntimePlanner();
    ~RuntimePlanner();

    // Initialize from loaded model
    bool Initialize(const ModelMetadata& metadata, const ResolvedKernelTable& kernels);

    // Plan execution for a specific layer
    ExecutionPlan PlanLayer(uint32_t layerIdx,
                            const UniversalTensorDescriptor& kDesc,
                            const UniversalTensorDescriptor& vDesc,
                            const UniversalTensorDescriptor& expertDesc);

    // Plan memory strategy based on tensor residency
    static ExecutionStrategy PlanMemoryStrategy(const UniversalTensorDescriptor& desc);

    // Plan attention strategy based on mask and quantization
    static ExecutionStrategy PlanAttentionStrategy(QuantType kvQuant,
                                                    bool hasTreeMask,
                                                    ISATarget isa);

    // Plan MoE strategy based on expert residency
    static ExecutionStrategy PlanMoEStrategy(QuantType expertQuant,
                                              bool expertsResident,
                                              bool hasNVMePaging);

private:
    ModelMetadata metadata_;
    ResolvedKernelTable kernels_;
    bool initialized_;
};

// ============================================================================
// Inline implementations
// ============================================================================

inline ExecutionStrategy RuntimePlanner::PlanMemoryStrategy(const UniversalTensorDescriptor& desc) {
    switch (desc.memorySpace) {
        case UniversalTensorDescriptor::MemorySpace::HOST:     return ExecutionStrategy::MEMORY_RESIDENT;
        case UniversalTensorDescriptor::MemorySpace::DEVICE:   return ExecutionStrategy::MEMORY_RESIDENT;
        case UniversalTensorDescriptor::MemorySpace::NVME:     return ExecutionStrategy::MEMORY_NVME_PAGED;
        case UniversalTensorDescriptor::MemorySpace::MAPPED:   return ExecutionStrategy::MEMORY_MAPPED;
        case UniversalTensorDescriptor::MemorySpace::STREAMED: return ExecutionStrategy::MEMORY_STREAMED;
        default: return ExecutionStrategy::MEMORY_RESIDENT;
    }
}

inline ExecutionStrategy RuntimePlanner::PlanAttentionStrategy(QuantType kvQuant,
                                                                 bool hasTreeMask,
                                                                 ISATarget isa) {
    // If we have a tree mask, use sparse attention
    if (hasTreeMask) {
        if (isa >= ISATarget::AVX512) {
            return ExecutionStrategy::FUSED_ATTENTION_AVX512;
        }
        return ExecutionStrategy::TREE_ATTENTION_SPARSE;
    }

    // Dense attention
    if (isa >= ISATarget::AVX512) {
        return ExecutionStrategy::FUSED_ATTENTION_AVX512;
    }
    return ExecutionStrategy::STANDARD_ATTENTION;
}

inline ExecutionStrategy RuntimePlanner::PlanMoEStrategy(QuantType expertQuant,
                                                           bool expertsResident,
                                                           bool hasNVMePaging) {
    if (expertsResident) {
        return ExecutionStrategy::MOE_FUSED_AVX512;
    }
    if (hasNVMePaging) {
        return ExecutionStrategy::MOE_PAGED_NVME;
    }
    return ExecutionStrategy::MOE_STREAMING;
}

} // namespace RawrXD
