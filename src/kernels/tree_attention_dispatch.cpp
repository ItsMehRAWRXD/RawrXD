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

#ifdef _MSC_VER
#include <intrin.h>  // For __cpuid on Windows
#else
#include <cpuid.h>
#include <malloc.h>  // For posix_memalign
#endif

//============================================================================
// External exports from kernel implementations
//============================================================================

// AVX-512 stub implementations - these are overridden when tree_attention_avx512_intrinsics.cpp is linked
// The "weak" attribute allows the real implementations to replace these
extern "C" {
#ifdef _MSC_VER
    // MSVC doesn't support __attribute__((weak)), use pragma instead
    #pragma comment(linker, "/alternatename:TreeAttentionVerify_AVX512_Export=TreeAttentionVerify_AVX512_Stub")
    #pragma comment(linker, "/alternatename:KVCacheInvalidate_AVX512_Export=KVCacheInvalidate_AVX512_Stub")
    #pragma comment(linker, "/alternatename:HasAVX512F_Export=HasAVX512F_Stub")
    
    uint32_t TreeAttentionVerify_AVX512_Stub(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    ) {
        (void)candidate_logits; (void)draft_logits; (void)tree_mask;
        (void)output_probs; (void)num_candidates; (void)acceptance_threshold;
        return 0;  // All rejected
    }
    
    void KVCacheInvalidate_AVX512_Stub(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    ) {
        (void)kv_cache_base; (void)rejection_mask; (void)entry_size;
    }
    
    int HasAVX512F_Stub() {
        return 0;  // Not supported
    }
    
    // Declare the actual exports as extern (will be resolved at link time)
    __declspec(dllimport) uint32_t TreeAttentionVerify_AVX512_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    );
    
    __declspec(dllimport) void KVCacheInvalidate_AVX512_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    );
    
    __declspec(dllimport) int HasAVX512F_Export();
#else
    __attribute__((weak)) uint32_t TreeAttentionVerify_AVX512_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    ) {
        (void)candidate_logits; (void)draft_logits; (void)tree_mask;
        (void)output_probs; (void)num_candidates; (void)acceptance_threshold;
        return 0;  // All rejected
    }
    
    __attribute__((weak)) void KVCacheInvalidate_AVX512_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    ) {
        (void)kv_cache_base; (void)rejection_mask; (void)entry_size;
    }
    
    __attribute__((weak)) int HasAVX512F_Export() {
        return 0;  // Not supported
    }
#endif
    
    // AVX2 exports
    uint32_t TreeAttentionVerify_AVX2_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    );
    
    void KVCacheInvalidate_AVX2_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    );
    
    // Scalar exports
    uint32_t TreeAttentionVerify_Scalar_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    );
    
    void KVCacheInvalidate_Scalar_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    );
}

namespace RawrXD {
namespace Kernels {

//============================================================================
// Aligned Allocation Helpers
//============================================================================

void* SpeculativeExecutionEngine::aligned_alloc(size_t size, size_t alignment) {
    return _aligned_malloc(size, alignment);
}

void SpeculativeExecutionEngine::aligned_free(void* ptr) {
    if (ptr) {
        _aligned_free(ptr);
    }
}

//============================================================================
// Kernel Selection
//============================================================================

//============================================================================
// ISA Feature Detection
//============================================================================

//============================================================================
// CPU Feature Detection with proper OSXSAVE/XGETBV checks
//============================================================================

// Helper: Check if OSXSAVE is enabled (CPUID.1:ECX[27])
static bool CheckOSXSAVE() {
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 1, 0);
    return (cpuInfo[2] & (1 << 27)) != 0;
#else
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
    return (ecx & (1 << 27)) != 0;
#endif
}

// Helper: Check XCR0 state for AVX (bits 1-2 must be set)
static bool CheckXCR0_AVX() {
#ifdef _MSC_VER
    uint64_t xcr0 = _xgetbv(0);
    return (xcr0 & 0x06) == 0x06;  // XMM and YMM state enabled
#else
    unsigned int xcr0_eax, xcr0_edx;
    __asm__ __volatile__("xgetbv" : "=a"(xcr0_eax), "=d"(xcr0_edx) : "c"(0));
    uint64_t xcr0 = ((uint64_t)xcr0_edx << 32) | xcr0_eax;
    return (xcr0 & 0x06) == 0x06;
#endif
}

// Helper: Check XCR0 state for AVX-512 (bits 5-7 must be set)
static bool CheckXCR0_AVX512() {
#ifdef _MSC_VER
    uint64_t xcr0 = _xgetbv(0);
    return (xcr0 & 0xE0) == 0xE0;  // OPMASK, ZMM_HI256, HI16_ZMM enabled
#else
    unsigned int xcr0_eax, xcr0_edx;
    __asm__ __volatile__("xgetbv" : "=a"(xcr0_eax), "=d"(xcr0_edx) : "c"(0));
    uint64_t xcr0 = ((uint64_t)xcr0_edx << 32) | xcr0_eax;
    return (xcr0 & 0xE0) == 0xE0;
#endif
}

bool TreeAttentionDispatcher::DetectAVX512() {
    // Step 1: Check CPUID leaf 7, subleaf 0 for AVX-512F (bit 16 of EBX)
    unsigned int eax = 7, ebx = 0, ecx = 0, edx = 0;
    
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 7, 0);
    ebx = cpuInfo[1];
#else
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
#endif
    
    bool hasAVX512F = (ebx & (1 << 16)) != 0;
    if (!hasAVX512F) return false;
    
    // Step 2: Check OSXSAVE (required for XGETBV)
    if (!CheckOSXSAVE()) return false;
    
    // Step 3: Check XCR0 for AVX-512 state
    return CheckXCR0_AVX512();
}

bool TreeAttentionDispatcher::DetectAVX2() {
    // Step 1: Check CPUID leaf 7 for AVX2 (bit 5 of EBX)
    unsigned int eax = 7, ebx = 0, ecx = 0, edx = 0;
    
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 7, 0);
    ebx = cpuInfo[1];
#else
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
#endif
    
    bool hasAVX2 = (ebx & (1 << 5)) != 0;
    if (!hasAVX2) return false;
    
    // Step 2: Check OSXSAVE
    if (!CheckOSXSAVE()) return false;
    
    // Step 3: Check XCR0 for AVX state
    return CheckXCR0_AVX();
}

bool TreeAttentionDispatcher::DetectSSE42() {
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    
#ifdef _MSC_VER
    int cpuInfo[4] = {0};
    __cpuidex(cpuInfo, 1, 0);
    ecx = cpuInfo[2];
#else
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
#endif
    
    // SSE4.2 is bit 20 of ECX (leaf 1)
    return (ecx & (1 << 20)) != 0;
}

TreeAttentionKernel TreeAttentionDispatcher::SelectKernel() {
    // Check if AVX-512 is both supported by CPU AND has real implementation linked
    // We check HasAVX512F_Export() which returns 1 only if real implementation is linked
    if (DetectAVX512() && HasAVX512F_Export()) {
        return GetAVX512Kernel();
    }
    if (DetectAVX2()) {
        return GetAVX2Kernel();
    }
    return GetScalarKernel();
}

TreeAttentionKernel TreeAttentionDispatcher::GetAVX2Kernel() {
    return TreeAttentionKernel{
        TreeAttentionVerify_AVX2_Export,
        KVCacheInvalidate_AVX2_Export,
        nullptr,  // No TSC export for AVX2
        "AVX2",
        2
    };
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
    return TreeAttentionKernel{
        TreeAttentionVerify_Scalar_Export,
        KVCacheInvalidate_Scalar_Export,
        nullptr,  // No AVX-512 check for scalar
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
    kernel_(TreeAttentionDispatcher::SelectKernel()) {
    
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
    
    // Safety check: ensure kernel matches CPU capabilities
    if (strcmp(kernel_.name, "AVX-512") == 0 && !TreeAttentionDispatcher::DetectAVX512()) {
        // AVX-512 kernel selected but CPU doesn't support it - fallback to scalar
        kernel_ = TreeAttentionDispatcher::GetScalarKernel();
    }
    
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
