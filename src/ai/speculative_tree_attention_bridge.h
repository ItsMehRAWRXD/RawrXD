//============================================================================
// speculative_tree_attention_bridge.h
//
// VAL-032: Bridge between ISA-optimized tree attention kernels
//          and the speculative decoding pipeline
//
// Provides a clean interface for the StreamingInferenceEngine to use
// the optimized tree attention verification kernels.
//============================================================================

#pragma once
#include <cstdint>
#include <vector>
#include <memory>
#include <cstdlib>

// Forward declarations from kernel dispatch
namespace RawrXD {
namespace Kernels {
    class SpeculativeExecutionEngine;
    struct SpeculativeTelemetry;
}
}

namespace RawrXD {

//============================================================================
// Tree Attention Speculative Bridge
//
// Connects the streaming inference engine with the ISA-optimized
// tree attention kernels for speculative decoding.
//============================================================================
class TreeAttentionSpeculativeBridge {
public:
    // Verification result structure
    struct VerificationResult {
        uint32_t acceptance_mask;      // 16 bits: 1 = accept
        uint32_t rejection_mask;       // 16 bits: 1 = reject
        uint32_t accepted_count;       // Number of accepted tokens
        int first_reject_idx;          // First rejection position (-1 if all accepted)
        std::vector<float> output_probs; // Verified probabilities
    };
    
    // Construction/Destruction
    TreeAttentionSpeculativeBridge();
    ~TreeAttentionSpeculativeBridge();
    
    // Disable copy/move
    TreeAttentionSpeculativeBridge(const TreeAttentionSpeculativeBridge&) = delete;
    TreeAttentionSpeculativeBridge& operator=(const TreeAttentionSpeculativeBridge&) = delete;
    
    //============================================================================
    // Core API: Draft Token Verification
    //============================================================================
    
    // Verify draft tokens against target model logits
    // 
    // Parameters:
    //   candidate_logits - Target model logits for 16 candidates (16 x 64 floats)
    //   draft_logits     - Draft model logits for 16 candidates (16 x 64 floats)
    //   draft_probs      - Draft model probabilities (16 floats)
    //   validity_mask    - 16-bit mask indicating valid candidates
    //
    // Returns:
    //   VerificationResult with acceptance/rejection masks
    VerificationResult VerifyDraftTokens(
        const std::vector<float>& candidate_logits,
        const std::vector<float>& draft_logits,
        const std::vector<float>& draft_probs,
        uint16_t validity_mask = 0xFFFF
    );
    
    // Batch verification for multiple draft candidates
    // Returns indices of accepted tokens (stops at first rejection)
    std::vector<uint32_t> VerifyDraftBatch(
        const std::vector<std::vector<float>>& draft_candidates,
        const std::vector<float>& target_logits,
        float acceptance_threshold = 0.6f
    );
    
    //============================================================================
    // KV Cache Management
    //============================================================================
    
    // Invalidate rejected KV cache entries
    // 
    // Parameters:
    //   kv_cache_base - Base pointer to KV cache
    //   rejection_mask - 16-bit mask of rejected entries
    //   entry_size     - Size of each KV cache entry in bytes
    void InvalidateRejectedKV(
        uint8_t* kv_cache_base,
        uint32_t rejection_mask,
        uint32_t entry_size = 64
    );
    
    //============================================================================
    // Telemetry and Diagnostics
    //============================================================================
    
    // Get performance telemetry
    Kernels::SpeculativeTelemetry GetTelemetry() const;
    
    // Reset telemetry counters
    void ResetTelemetry();
    
    // Get name of active kernel (for debugging)
    const char* GetActiveKernelName() const;
    
    // Check if AVX-512 is being used
    bool IsUsingAVX512() const;
    
    // Check if AVX2 is being used
    bool IsUsingAVX2() const;

private:
    // Aligned buffers for kernel execution
    std::unique_ptr<float, decltype(&_aligned_free)> aligned_candidate_logits_;
    std::unique_ptr<float, decltype(&_aligned_free)> aligned_draft_logits_;
    std::unique_ptr<float, decltype(&_aligned_free)> aligned_tree_mask_;
    std::unique_ptr<float, decltype(&_aligned_free)> aligned_output_probs_;
    
    // Speculative execution engine
    std::unique_ptr<Kernels::SpeculativeExecutionEngine> engine_;
};

} // namespace RawrXD
