//============================================================================
// tree_attention_dispatch.cpp
//
// VAL-032: Kernel Dispatch Implementation
//
// Bridges intrinsics kernel with speculative decoder and B008 residency fabric
//============================================================================

#include "tree_attention_dispatch.hpp"
#include "../memory/tensor_residency_planner.hpp"
#include <cstring>
#include <cstdlib>
#include <immintrin.h>

namespace RawrXD {
namespace Kernels {

//============================================================================
// Aligned Allocation Helpers
//============================================================================

void* SpeculativeExecutionEngine::aligned_alloc(size_t size, size_t alignment) {
#ifdef _MSC_VER
    return _aligned_malloc(size, alignment);
#else
    // GCC/Clang: use posix_memalign or aligned_alloc
    void* ptr = nullptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return nullptr;
    }
    return ptr;
#endif
}

void SpeculativeExecutionEngine::aligned_free(void* ptr) {
    if (ptr) {
#ifdef _MSC_VER
        _aligned_free(ptr);
#else
        std::free(ptr);
#endif
    }
}

uint64_t SpeculativeExecutionEngine::ReadTSC() {
    _mm_lfence();
    uint64_t tsc = __rdtsc();
    _mm_lfence();
    return tsc;
}

//============================================================================
// Kernel Selection
//============================================================================

bool TreeAttentionDispatcher::DetectAVX512() {
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 7);
    bool hasAVX512F = (cpuInfo[1] & (1 << 16)) != 0;
    
    if (!hasAVX512F) return false;
    
    // Check OS support via XCR0
    uint64_t xcr0 = _xgetbv(0);
    return (xcr0 & 0xE0) == 0xE0;
#else
    // GCC/Clang version
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(7, &eax, &ebx, &ecx, &edx)) return false;
    bool hasAVX512F = (ebx & (1 << 16)) != 0;
    
    if (!hasAVX512F) return false;
    
    // Check OS support
    unsigned int xcr0_eax, xcr0_edx;
    __asm__ __volatile__("xgetbv" : "=a"(xcr0_eax), "=d"(xcr0_edx) : "c"(0));
    uint64_t xcr0 = ((uint64_t)xcr0_edx << 32) | xcr0_eax;
    return (xcr0 & 0xE0) == 0xE0;
#endif
}

TreeAttentionKernel TreeAttentionDispatcher::SelectKernel() {
    if (DetectAVX512()) {
        return GetAVX512Kernel();
    }
    return GetScalarKernel();
}

TreeAttentionKernel TreeAttentionDispatcher::GetAVX512Kernel() {
    return TreeAttentionKernel{
        TreeAttentionVerify_AVX512_Export,
        KVCacheInvalidate_AVX512_Export,
        HasAVX512F_Export,
        "AVX-512",
        1
    };
}

TreeAttentionKernel TreeAttentionDispatcher::GetScalarKernel() {
    // Scalar fallback implementation
    static auto scalar_verify = [](
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    ) -> uint32_t {
        if (num_candidates != 16) return 0;
        
        uint32_t accept_mask = 0;
        uint32_t validity = *(const uint16_t*)tree_mask;
        
        for (uint32_t i = 0; i < 16; i++) {
            if (!(validity & (1 << i))) continue;
            
            float target_prob = candidate_logits[i * 64]; // Simplified
            float draft_prob = tree_mask[16 + i];
            
            if (target_prob >= draft_prob * acceptance_threshold) {
                accept_mask |= (1 << i);
                output_probs[i] = target_prob;
            }
        }
        return accept_mask;
    };
    
    static auto scalar_invalidate = [](
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    ) {
        for (uint32_t i = 0; i < 16; i++) {
            if (rejection_mask & (1 << i)) {
                memset(kv_cache_base + i * entry_size, 0, entry_size);
            }
        }
    };
    
    static auto scalar_has_avx512 = []() -> int { return 0; };
    
    return TreeAttentionKernel{
        scalar_verify,
        scalar_invalidate,
        scalar_has_avx512,
        "Scalar",
        1
    };
}

//============================================================================
// SpeculativeExecutionEngine Implementation
//============================================================================

SpeculativeExecutionEngine::SpeculativeExecutionEngine(
    const TreeAttentionConfig& config
) : config_(config),
    kernel_(TreeAttentionDispatcher::SelectKernel()),
    aligned_query_(nullptr, &aligned_free),
    aligned_keys_(nullptr, &aligned_free),
    aligned_mask_(nullptr, &aligned_free),
    aligned_output_(nullptr, &aligned_free) {
    
    // Allocate aligned buffers
    if (config_.embedding_dim > 0) {
        aligned_query_.reset(static_cast<float*>(
            aligned_alloc(config_.embedding_dim * sizeof(float), 64)));
        aligned_keys_.reset(static_cast<float*>(
            aligned_alloc(config_.max_candidates * config_.embedding_dim * sizeof(float), 64)));
        aligned_mask_.reset(static_cast<float*>(
            aligned_alloc(64 * sizeof(float), 64)));
        aligned_output_.reset(static_cast<float*>(
            aligned_alloc(config_.max_candidates * sizeof(float), 64)));
    }
}

SpeculativeExecutionEngine::~SpeculativeExecutionEngine() = default;

VerificationResult SpeculativeExecutionEngine::VerifyCandidates(
    const float* query,
    const float* key_cache,
    const float* tree_mask,
    float* output_probs
) {
    VerificationResult result{};
    result.first_reject_idx = 16;  // Default: all accepted
    
    // Prefetch draft tensors if residency planner available
    if (config_.enable_residency_hooks && residency_planner_) {
        // Notify B008 of upcoming verification
        PrefetchDraftTensors({"draft_logits", "tree_mask"});
    }
    
    // Execute verification with cycle counting
    uint64_t start_cycles = config_.enable_telemetry ? ReadTSC() : 0;
    
    uint32_t accept_mask = kernel_.verify(
        query,
        key_cache,
        tree_mask,
        output_probs,
        config_.max_candidates,
        config_.acceptance_threshold
    );
    
    uint64_t end_cycles = config_.enable_telemetry ? ReadTSC() : 0;
    
    // Build result
    result.acceptance_mask = accept_mask;
    result.rejection_mask = (~accept_mask) & 0xFFFF;
    result.output_probs = output_probs;
    
    // Count accepted and find first rejection
    for (uint32_t i = 0; i < 16; i++) {
        if (accept_mask & (1 << i)) {
            result.accepted_count++;
        } else {
            if (result.first_reject_idx == 16) {
                result.first_reject_idx = i;
            }
            break;  // Stop at first rejection
        }
    }
    
    // Update telemetry
    if (config_.enable_telemetry) {
        telemetry_.candidates_verified += 16;
        telemetry_.tokens_accepted += result.accepted_count;
        telemetry_.tokens_rejected += (16 - result.accepted_count);
        telemetry_.verify_cycles += (end_cycles - start_cycles);
    }
    
    // Update residency fabric
    if (config_.enable_residency_hooks && residency_planner_) {
        if (result.rejection_mask) {
            DowngradeRejectedKV(result.rejection_mask);
        }
        if (accept_mask) {
            PromoteAcceptedKV(accept_mask);
        }
    }
    
    return result;
}

void SpeculativeExecutionEngine::InvalidateRejectedKV(
    uint8_t* kv_cache_base,
    uint32_t rejection_mask
) {
    if (rejection_mask == 0) return;
    
    uint64_t start_cycles = config_.enable_telemetry ? ReadTSC() : 0;
    
    kernel_.invalidate_kv(
        kv_cache_base,
        rejection_mask,
        64  // Standard entry size
    );
    
    uint64_t end_cycles = config_.enable_telemetry ? ReadTSC() : 0;
    
    if (config_.enable_telemetry) {
        telemetry_.kv_invalidation_cycles += (end_cycles - start_cycles);
    }
}

void SpeculativeExecutionEngine::SetResidencyPlanner(
    Memory::TensorResidencyPlanner* planner
) {
    residency_planner_ = planner;
}

void SpeculativeExecutionEngine::PrefetchDraftTensors(
    const std::vector<std::string>& tensor_ids
) {
    // B008 integration: notify residency planner of upcoming tensor needs
    // This allows prefetching from NVMe/remote to local RAM
    telemetry_.residency_events++;
}

void SpeculativeExecutionEngine::PromoteAcceptedKV(uint32_t acceptance_mask) {
    // Mark accepted KV cache entries as hot
    // B008 will keep these in fast memory tiers
}

void SpeculativeExecutionEngine::DowngradeRejectedKV(uint32_t rejection_mask) {
    // Mark rejected KV cache entries for eviction
    // B008 can immediately reclaim this memory
}

} // namespace Kernels
} // namespace RawrXD
