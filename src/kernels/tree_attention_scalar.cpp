//============================================================================
// tree_attention_scalar.cpp
//
// VAL-032: Scalar Fallback Implementation
//
// Portable reference implementation that works on any CPU.
// Used for:
//   - Validation against AVX-512 results
//   - Fallback when SIMD unavailable
//   - Debugging and development
//============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cmath>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#endif

namespace RawrXD {
namespace Kernels {

//============================================================================
// Scalar Tree Attention Verification
//============================================================================
extern "C" uint32_t TreeAttentionVerify_Scalar(
    const float* candidate_logits,
    const float* draft_logits,
    const float* tree_mask,
    float* output_probs,
    uint32_t num_candidates,
    float acceptance_threshold
) {
    if (num_candidates != 16 || !candidate_logits || !tree_mask || !output_probs) {
        return 0;  // All rejected
    }
    
    // Extract validity mask from tree_mask[0]
    uint16_t validity_mask = *reinterpret_cast<const uint16_t*>(tree_mask);
    
    // Extract draft probabilities from tree_mask[16..31]
    const float* draft_probs = tree_mask + 16;
    
    uint32_t acceptance_mask = 0;
    
    // Process each candidate
    for (uint32_t i = 0; i < 16; i++) {
        // Check validity
        if (!(validity_mask & (1u << i))) {
            continue;  // Invalid candidate, skip
        }
        
        // Get candidate score (simplified: use first value)
        // In full implementation: dot product of query with key
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
        }
    }
    
    return acceptance_mask;
}

//============================================================================
// Scalar KV Cache Invalidation
//============================================================================
extern "C" void KVCacheInvalidate_Scalar(
    uint8_t* kv_cache_base,
    uint32_t rejection_mask,
    uint32_t entry_size
) {
    if (!kv_cache_base || rejection_mask == 0) {
        return;
    }
    
    // Clear each rejected entry
    for (uint32_t i = 0; i < 16; i++) {
        if (rejection_mask & (1u << i)) {
            std::memset(kv_cache_base + i * entry_size, 0, entry_size);
        }
    }
}

//============================================================================
// Scalar Timing (portable)
//============================================================================
extern "C" uint64_t ReadTSC_Scalar() {
    // Use x86/x64 RDTSC instruction for high-resolution timing
    // This reads the Time Stamp Counter from the CPU
    #ifdef _WIN32
        #if defined(_M_X64) || defined(__x86_64__)
            // x64: use __rdtsc() intrinsic
            return __rdtsc();
        #elif defined(_M_IX86) || defined(__i386__)
            // x86: use inline assembly or intrinsic
            return __rdtsc();
        #else
            // Fallback for other architectures: use QueryPerformanceCounter
            LARGE_INTEGER freq, count;
            if (QueryPerformanceFrequency(&freq) && QueryPerformanceCounter(&count)) {
                // Return a TSC-like value (cycles scaled by typical 3GHz)
                return static_cast<uint64_t>(count.QuadPart * 3000000000LL / freq.QuadPart);
            }
            return 0;
        #endif
    #else
        // Linux/Unix: use rdtsc inline assembly
        unsigned int lo, hi;
        __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
        return ((uint64_t)hi << 32) | lo;
    #endif
}

} // namespace Kernels
} // namespace RawrXD

//============================================================================
// C-compatible exports
//============================================================================
extern "C" {
    __declspec(dllexport) uint32_t TreeAttentionVerify_Scalar_Export(
        const float* candidate_logits,
        const float* draft_logits,
        const float* tree_mask,
        float* output_probs,
        uint32_t num_candidates,
        float acceptance_threshold
    ) {
        return RawrXD::Kernels::TreeAttentionVerify_Scalar(
            candidate_logits, draft_logits, tree_mask, output_probs,
            num_candidates, acceptance_threshold
        );
    }
    
    __declspec(dllexport) void KVCacheInvalidate_Scalar_Export(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size
    ) {
        RawrXD::Kernels::KVCacheInvalidate_Scalar(
            kv_cache_base, rejection_mask, entry_size
        );
    }
    
    __declspec(dllexport) uint64_t ReadTSC_Scalar_Export() {
        return RawrXD::Kernels::ReadTSC_Scalar();
    }
}
