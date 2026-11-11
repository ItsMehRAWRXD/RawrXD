//============================================================================
// speculative_tree_attention_bridge.cpp
//
// VAL-032: Integration of ISA-optimized tree attention kernels
//          with the speculative decoding pipeline
//
// Bridges the SpeculativeExecutionEngine with the streaming inference engine
//============================================================================

#include "speculative_tree_attention_bridge.h"
#include "../kernels/tree_attention_dispatch.hpp"
#include <cstring>
#include <algorithm>
#include <intrin.h>  // For __builtin_popcount on MSVC

namespace RawrXD {

//============================================================================
// TreeAttentionSpeculativeBridge Implementation
//============================================================================

TreeAttentionSpeculativeBridge::TreeAttentionSpeculativeBridge()
    : aligned_candidate_logits_(nullptr, &_aligned_free)
    , aligned_draft_logits_(nullptr, &_aligned_free)
    , aligned_tree_mask_(nullptr, &_aligned_free)
    , aligned_output_probs_(nullptr, &_aligned_free)
    , engine_(std::make_unique<Kernels::SpeculativeExecutionEngine>(
        Kernels::TreeAttentionConfig{
            16,     // max_candidates
            64,     // embedding_dim
            0.6f,   // acceptance_threshold
            true,   // enable_telemetry
            true    // enable_residency_hooks
        }
    ))
{
    // Initialize aligned buffers for tree attention
    aligned_candidate_logits_.reset(static_cast<float*>(
        _aligned_malloc(16 * 64 * sizeof(float), 64)));
    aligned_draft_logits_.reset(static_cast<float*>(
        _aligned_malloc(16 * 64 * sizeof(float), 64)));
    aligned_tree_mask_.reset(static_cast<float*>(
        _aligned_malloc(64 * sizeof(float), 64)));
    aligned_output_probs_.reset(static_cast<float*>(
        _aligned_malloc(16 * sizeof(float), 64)));
    
    // Clear buffers
    std::memset(aligned_candidate_logits_.get(), 0, 16 * 64 * sizeof(float));
    std::memset(aligned_draft_logits_.get(), 0, 16 * 64 * sizeof(float));
    std::memset(aligned_tree_mask_.get(), 0, 64 * sizeof(float));
    std::memset(aligned_output_probs_.get(), 0, 16 * sizeof(float));
}

TreeAttentionSpeculativeBridge::~TreeAttentionSpeculativeBridge() = default;

//============================================================================
// Draft Token Verification
//============================================================================

TreeAttentionSpeculativeBridge::VerificationResult 
TreeAttentionSpeculativeBridge::VerifyDraftTokens(
    const std::vector<float>& candidate_logits,
    const std::vector<float>& draft_logits,
    const std::vector<float>& draft_probs,
    uint16_t validity_mask
) {
    VerificationResult result{};
    result.accepted_count = 0;
    result.first_reject_idx = -1;
    
    // Validate input sizes
    if (candidate_logits.size() < 16 * 64 || 
        draft_logits.size() < 16 * 64 ||
        draft_probs.size() < 16) {
        // Invalid input - reject all
        result.rejection_mask = 0xFFFF;
        return result;
    }
    
    // Copy data to aligned buffers
    std::memcpy(aligned_candidate_logits_.get(), 
                candidate_logits.data(), 
                16 * 64 * sizeof(float));
    std::memcpy(aligned_draft_logits_.get(), 
                draft_logits.data(), 
                16 * 64 * sizeof(float));
    
    // Build tree mask: [0:15] validity bits, [16:31] draft probs
    std::memcpy(aligned_tree_mask_.get(), 
                &validity_mask, 
                sizeof(validity_mask));
    std::memcpy(aligned_tree_mask_.get() + 16, 
                draft_probs.data(), 
                16 * sizeof(float));
    
    // Get the selected kernel (cached from dispatch)
    static const Kernels::TreeAttentionKernel kernel = 
        Kernels::TreeAttentionDispatcher::SelectKernel();
    
    // Execute verification
    uint32_t accept_mask = kernel.verify(
        aligned_candidate_logits_.get(),
        aligned_draft_logits_.get(),
        aligned_tree_mask_.get(),
        aligned_output_probs_.get(),
        16,     // num_candidates
        0.6f    // acceptance_threshold
    );
    
    // Build result
    result.acceptance_mask = accept_mask;
    result.rejection_mask = (~accept_mask) & 0xFFFF;
#ifdef _MSC_VER
    result.accepted_count = __popcnt(accept_mask);
#else
    result.accepted_count = __builtin_popcount(accept_mask);
#endif
    
    // Find first rejection
    for (int i = 0; i < 16; i++) {
        if (!(accept_mask & (1u << i))) {
            result.first_reject_idx = i;
            break;
        }
    }
    
    // Copy output probabilities
    result.output_probs.resize(16);
    std::memcpy(result.output_probs.data(), 
                aligned_output_probs_.get(), 
                16 * sizeof(float));
    
    return result;
}

//============================================================================
// Batch Verification for Speculative Decode
//============================================================================

std::vector<uint32_t> TreeAttentionSpeculativeBridge::VerifyDraftBatch(
    const std::vector<std::vector<float>>& draft_candidates,
    const std::vector<float>& target_logits,
    float acceptance_threshold
) {
    std::vector<uint32_t> accepted_tokens;
    
    if (draft_candidates.empty()) {
        return accepted_tokens;
    }
    
    // Prepare candidate logits (simplified: use first 16 candidates)
    std::vector<float> candidate_logits(16 * 64, 0.0f);
    std::vector<float> draft_logits(16 * 64, 0.0f);
    std::vector<float> draft_probs(16, 0.0f);
    
    uint16_t validity_mask = 0;
    
    for (size_t i = 0; i < std::min(size_t(16), draft_candidates.size()); i++) {
        if (draft_candidates[i].size() >= 64) {
            // Copy candidate logits (simplified: just first 64 values)
            std::memcpy(&candidate_logits[i * 64],
                       draft_candidates[i].data(),
                       64 * sizeof(float));
            
            // Draft logits would come from draft model
            std::memcpy(&draft_logits[i * 64],
                       draft_candidates[i].data(),
                       64 * sizeof(float));
            
            // Draft probability (simplified)
            draft_probs[i] = 0.5f;
            
            validity_mask |= (1u << i);
        }
    }
    
    // Verify
    auto result = VerifyDraftTokens(candidate_logits, draft_logits, draft_probs, validity_mask);
    
    // Return accepted token indices
    for (int i = 0; i < 16; i++) {
        if (result.acceptance_mask & (1u << i)) {
            accepted_tokens.push_back(static_cast<uint32_t>(i));
        } else {
            // Stop at first rejection (speculative decoding rule)
            break;
        }
    }
    
    return accepted_tokens;
}

//============================================================================
// KV Cache Management
//============================================================================

void TreeAttentionSpeculativeBridge::InvalidateRejectedKV(
    uint8_t* kv_cache_base,
    uint32_t rejection_mask,
    uint32_t entry_size
) {
    if (!kv_cache_base || rejection_mask == 0) {
        return;
    }
    
    static const Kernels::TreeAttentionKernel kernel = 
        Kernels::TreeAttentionDispatcher::SelectKernel();
    
    kernel.invalidate_kv(kv_cache_base, rejection_mask, entry_size);
}

//============================================================================
// Telemetry
//============================================================================

Kernels::SpeculativeTelemetry TreeAttentionSpeculativeBridge::GetTelemetry() const {
    if (engine_) {
        return engine_->GetTelemetry();
    }
    return Kernels::SpeculativeTelemetry{};
}

void TreeAttentionSpeculativeBridge::ResetTelemetry() {
    if (engine_) {
        engine_->ResetTelemetry();
    }
}

const char* TreeAttentionSpeculativeBridge::GetActiveKernelName() const {
    static const Kernels::TreeAttentionKernel kernel = 
        Kernels::TreeAttentionDispatcher::SelectKernel();
    return kernel.name;
}

} // namespace RawrXD
