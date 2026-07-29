//============================================================================
// tree_attention_avx512_intrinsics.cpp
//
// VAL-032: AVX-512 Intrinsics Reference Kernel
//
// Phase 1: Algorithm validation before MASM optimization
// Uses Intel intrinsics for portable, debuggable implementation
//============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <immintrin.h>

#ifdef _MSC_VER
#include <intrin.h>  // For __cpuidex on Windows
#else
#include <cpuid.h>
#endif

#include "avx512_runtime_gate.hpp"

// Compile with: /arch:AVX512 or -mavx512f

namespace RawrXD {
namespace Kernels {

// Global flag to indicate AVX-512 implementation is available
// This overrides the weak symbol in tree_attention_dispatch.cpp
int g_avx512_available = 1;

// Feature detection with hard gating
// This function is always available but checks runtime CPU support
extern "C" bool HasAVX512F() {
    // Use runtime detection via CPUID
    #ifdef _MSC_VER
        int cpuInfo[4] = {0};
        // Check max leaf first
        __cpuid(cpuInfo, 0);
        int maxLeaf = cpuInfo[0];
        if (maxLeaf < 7) return false;
        
        // Check AVX-512F (leaf 7, EBX bit 16)
        __cpuidex(cpuInfo, 7, 0);
        bool hasAVX512F = (cpuInfo[1] & (1 << 16)) != 0;
        
        if (!hasAVX512F) return false;
        
        // Check OS support via XCR0 (must have ZMM_HI256 and HI256_XSTATE)
        uint64_t xcr0 = _xgetbv(0);
        return (xcr0 & 0xE0) == 0xE0;
    #else
        // GCC/Clang version
        unsigned int eax, ebx, ecx, edx;
        
        // Check max leaf
        if (!__get_cpuid(0, &eax, &ebx, &ecx, &edx)) return false;
        if (eax < 7) return false;
        
        // Check AVX-512F (leaf 7, EBX bit 16)
        if (!__get_cpuid(7, &eax, &ebx, &ecx, &edx)) return false;
        bool hasAVX512F = (ebx & (1 << 16)) != 0;
        
        if (!hasAVX512F) return false;
        
        // Check OS support via XCR0
        unsigned int xcr0_eax, xcr0_edx;
        __asm__ __volatile__("xgetbv" : "=a"(xcr0_eax), "=d"(xcr0_edx) : "c"(0));
        uint64_t xcr0 = ((uint64_t)xcr0_edx << 32) | xcr0_eax;
        return (xcr0 & 0xE0) == 0xE0;
    #endif
}

//============================================================================
// Tree Attention Verification Kernel (Intrinsics)
//============================================================================

// Input: 16 candidate tokens, each with 64-dimensional logits
// Output: 16-bit acceptance mask (1 = accept, 0 = reject)
// 
// Acceptance criterion: target_prob >= draft_prob * threshold
// where threshold = 0.6 (configurable)

extern "C" uint32_t TreeAttentionVerify_AVX512(
    const float* candidate_logits,    // rcx: 16 x 64 floats (64-byte aligned)
    const float* draft_logits,        // rdx: 16 x 64 floats (64-byte aligned)
    const float* tree_mask,           // r8:  16 floats (validity + draft probs)
    float* output_probs,              // r9:  16 floats output
    uint32_t num_candidates,          // [rsp+40]: must be 16
    float acceptance_threshold        // xmm3: typically 0.6
) {
    // Note: Runtime gate is handled by dispatch layer
    // This function assumes AVX-512 is available
    
    if (num_candidates != 16) {
        return 0;  // Invalid input: reject all
    }

    // Extract validity mask from tree_mask[0]
    uint16_t validity = *reinterpret_cast<const uint16_t*>(tree_mask);
    
    // Extract draft probabilities from tree_mask[16..31]
    const float* draft_probs = tree_mask + 16;
    
    // Process all 16 candidates
    // For each candidate: score = candidate_logits[i * 64] (simplified)
    // Acceptance: score >= draft_prob * threshold
    
    uint32_t acceptance_mask = 0;
    
    for (uint32_t i = 0; i < 16; i++) {
        // Check validity
        if (!(validity & (1u << i))) {
            continue;  // Invalid candidate, skip
        }
        
        // Get candidate score (simplified: use first value)
        float candidate_score = candidate_logits[i * 64];
        
        // Get draft probability and compute threshold
        float draft_prob = draft_probs[i];
        float threshold = draft_prob * acceptance_threshold;
        
        // Acceptance criterion
        if (candidate_score >= threshold) {
            acceptance_mask |= (1u << i);
            output_probs[i] = candidate_score;
        } else {
            output_probs[i] = 0.0f;
            // Stop at first rejection (speculative decoding rule)
            break;
        }
    }
    
    return acceptance_mask;
}

//============================================================================
// KV Cache Invalidation (Intrinsics)
//============================================================================

extern "C" void KVCacheInvalidate_AVX512(
    uint8_t* kv_cache_base,      // rcx: base pointer (64-byte aligned)
    uint32_t rejection_mask,     // rdx: 16-bit mask (1 = invalidate)
    uint32_t entry_size          // r8:  bytes per entry (typically 64)
) {
    if (!kv_cache_base || rejection_mask == 0) {
        return;  // Nothing to invalidate
    }
    
    // Hard runtime gate - use scalar fallback if AVX-512 not available
    if (!DetectAVX512F()) {
        // Fallback to scalar memset
        for (uint32_t i = 0; i < 16; i++) {
            if (rejection_mask & (1u << i)) {
                memset(kv_cache_base + i * entry_size, 0, entry_size);
            }
        }
        return;
    }
    
    // AVX-512 branchless invalidation
    __m512i zero = _mm512_setzero_si512();
    __mmask16 mask = static_cast<__mmask16>(rejection_mask);
    
    // Invalidate entries 0-15 based on mask
    // Each entry is entry_size bytes
    // For entry_size == 64, we can zero one zmm register per entry
    
    if (entry_size == 64) {
        // Direct 64-byte invalidation per entry
        for (uint32_t i = 0; i < 16; i++) {
            if (rejection_mask & (1u << i)) {
                _mm512_storeu_si512(
                    reinterpret_cast<__m512i*>(kv_cache_base + i * 64), 
                    zero
                );
            }
        }
    } else {
        // Variable entry size: use masked stores
        for (uint32_t i = 0; i < 16; i++) {
            if (rejection_mask & (1u << i)) {
                // Store zeros to entry i
                uint8_t* entry_ptr = kv_cache_base + i * entry_size;
                
                // Zero in chunks of 64 bytes
                uint32_t remaining = entry_size;
                while (remaining >= 64) {
                    _mm512_storeu_si512(reinterpret_cast<__m512i*>(entry_ptr), zero);
                    entry_ptr += 64;
                    remaining -= 64;
                }
                
                // Remainder with smaller stores
                if (remaining >= 32) {
                    _mm256_storeu_si256(
                        reinterpret_cast<__m256i*>(entry_ptr), 
                        _mm256_setzero_si256()
                    );
                    entry_ptr += 32;
                    remaining -= 32;
                }
                if (remaining >= 16) {
                    _mm_storeu_si128(
                        reinterpret_cast<__m128i*>(entry_ptr), 
                        _mm_setzero_si128()
                    );
                    entry_ptr += 16;
                    remaining -= 16;
                }
                while (remaining > 0) {
                    *entry_ptr++ = 0;
                    remaining--;
                }
            }
        }
    }
}

//============================================================================
// Cycle-Accurate Timing
//============================================================================

extern "C" uint64_t ReadTSC() {
    _mm_lfence();
    uint64_t tsc = __rdtsc();
    _mm_lfence();
    return tsc;
}

//============================================================================
// Batch Verification (for 4x4 tree)
//============================================================================

struct TreeVerificationResult {
    uint32_t acceptance_mask;    // 16 bits: 1 = accept
    uint32_t rejection_mask;     // 16 bits: 1 = reject
    uint32_t accepted_count;     // Number of accepted tokens
    uint32_t first_reject_idx;   // Index of first rejection (or 16 if all accepted)
};

extern "C" TreeVerificationResult TreeVerify_Batch_4x4_Intrinsics(
    const float* query,           // 64 floats (query vector)
    const float* key_cache,       // 16 x 64 floats (key vectors)
    const float* tree_mask,       // Tree structure and metadata
    float* output_probs,          // Output probabilities
    uint32_t num_candidates
) {
    TreeVerificationResult result = {};
    
    if (num_candidates != 16 || !DetectAVX512F()) {
        result.rejection_mask = 0xFFFF;  // Reject all
        result.first_reject_idx = 0;
        return result;
    }
    
    // Load query (4 zmm registers for 64 floats)
    __m512 q0 = _mm512_loadu_ps(query);
    __m512 q1 = _mm512_loadu_ps(query + 16);
    __m512 q2 = _mm512_loadu_ps(query + 32);
    __m512 q3 = _mm512_loadu_ps(query + 48);
    
    // Compute dot products for 16 candidates
    // Each candidate: 64-dim key vector
    float scores[16];
    
    for (uint32_t c = 0; c < 16; c++) {
        const float* k = key_cache + c * 64;
        
        __m512 k0 = _mm512_loadu_ps(k);
        __m512 k1 = _mm512_loadu_ps(k + 16);
        __m512 k2 = _mm512_loadu_ps(k + 32);
        __m512 k3 = _mm512_loadu_ps(k + 48);
        
        // Dot product: sum of element-wise products
        __m512 prod0 = _mm512_mul_ps(q0, k0);
        __m512 prod1 = _mm512_mul_ps(q1, k1);
        __m512 prod2 = _mm512_mul_ps(q2, k2);
        __m512 prod3 = _mm512_mul_ps(q3, k3);
        
        // Horizontal sum using AVX-512
        __m512 sum01 = _mm512_add_ps(prod0, prod1);
        __m512 sum23 = _mm512_add_ps(prod2, prod3);
        __m512 sum_all = _mm512_add_ps(sum01, sum23);
        
        // Reduce to scalar
        scores[c] = _mm512_reduce_add_ps(sum_all);
    }
    
    // Load tree mask
    uint32_t validity = *(const uint16_t*)tree_mask;
    float draft_probs[16];
    memcpy(draft_probs, tree_mask + 16, sizeof(draft_probs));
    
    // Acceptance threshold
    const float threshold = 0.6f;
    
    // Verify each candidate
    result.acceptance_mask = 0;
    result.rejection_mask = 0;
    result.accepted_count = 0;
    result.first_reject_idx = 16;  // Default: all accepted
    
    for (uint32_t c = 0; c < 16; c++) {
        bool is_valid = (validity >> c) & 1;
        
        if (!is_valid) {
            result.rejection_mask |= (1u << c);
            if (result.first_reject_idx == 16) {
                result.first_reject_idx = c;
            }
            continue;
        }
        
        float target_prob = scores[c];
        float draft_prob = draft_probs[c];
        float threshold_prob = draft_prob * threshold;
        
        if (target_prob >= threshold_prob) {
            // Accept
            result.acceptance_mask |= (1u << c);
            result.accepted_count++;
            output_probs[c] = target_prob;
        } else {
            // Reject
            result.rejection_mask |= (1u << c);
            if (result.first_reject_idx == 16) {
                result.first_reject_idx = c;
            }
            // Stop at first rejection (speculative decoding rule)
            break;
        }
    }
    
    return result;
}

} // namespace Kernels
} // namespace RawrXD

// C-compatible exports
extern "C" {

using namespace RawrXD::Kernels;

__declspec(dllexport) uint32_t TreeAttentionVerify_AVX512_Export(
    const float* candidate_logits,
    const float* draft_logits,
    const float* tree_mask,
    float* output_probs,
    uint32_t num_candidates,
    float acceptance_threshold
) {
    return TreeAttentionVerify_AVX512(
        candidate_logits, draft_logits, tree_mask, 
        output_probs, num_candidates, acceptance_threshold
    );
}

__declspec(dllexport) void KVCacheInvalidate_AVX512_Export(
    uint8_t* kv_cache_base,
    uint32_t rejection_mask,
    uint32_t entry_size
) {
    KVCacheInvalidate_AVX512(kv_cache_base, rejection_mask, entry_size);
}

__declspec(dllexport) uint64_t ReadTSC_Export() {
    return ReadTSC();
}

__declspec(dllexport) int HasAVX512F_Export() {
    return HasAVX512F() ? 1 : 0;
}

} // extern "C"
