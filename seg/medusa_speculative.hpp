// ============================================================================
// Medusa Speculative Decoding
// ============================================================================
// Predicts multiple tokens in parallel for massive speedup
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>

namespace SEG {

// Medusa head configuration
struct MedusaConfig {
    static constexpr uint32_t NUM_HEADS = 4;        // Number of Medusa heads
    static constexpr uint32_t TOP_K = 8;            // Top-k candidates per head
    static constexpr uint32_t MAX_DRAFT = 8;        // Max tokens to draft
    static constexpr float TEMPERATURE = 0.6f;      // Sampling temperature
};

// Medusa head - predicts token at position (current + head_id + 1)
struct MedusaHead {
    // Tree attention structure for parallel verification
    struct TreeNode {
        uint32_t token_id;
        uint32_t parent_idx;
        float cumulative_prob;
        bool accepted;
    };
    
    // Candidates for this head
    std::array<uint32_t, MedusaConfig::TOP_K> candidates;
    std::array<float, MedusaConfig::TOP_K> probabilities;
    uint32_t num_candidates;
};

// Medusa speculative decoder
class MedusaDecoder {
public:
    MedusaDecoder(uint32_t vocab_size, uint32_t hidden_size);
    
    // Generate draft tokens using Medusa heads
    // Returns number of draft tokens generated
    uint32_t GenerateDraft(const float* hidden_state, 
                           uint32_t* draft_tokens,
                           uint32_t max_draft);
    
    // Verify draft tokens against base model
    // Returns number of accepted tokens
    uint32_t VerifyDraft(const uint32_t* draft_tokens,
                         uint32_t num_draft,
                         const float* logits,
                         uint32_t* accepted_tokens);
    
    // Update Medusa heads with accepted tokens for learning
    void UpdateHeads(const uint32_t* accepted_tokens, 
                     uint32_t num_accepted,
                     const float* hidden_states);
    
    // Get acceptance rate statistics
    float GetAcceptanceRate() const;
    uint32_t GetTotalDrafted() const { return total_drafted_; }
    uint32_t GetTotalAccepted() const { return total_accepted_; }

private:
    uint32_t vocab_size_;
    uint32_t hidden_size_;
    uint32_t total_drafted_ = 0;
    uint32_t total_accepted_ = 0;
    
    // Medusa heads - each predicts at different offsets
    std::array<MedusaHead, MedusaConfig::NUM_HEADS> heads_;
    
    // Tree attention mask for parallel verification
    std::vector<std::vector<uint32_t>> tree_mask_;
    
    // Simple MLP heads for prediction (could be replaced with lookup tables)
    std::vector<float> head_weights_;  // Simplified for demo
};

// Optimized tree attention for Medusa
// Processes all draft tokens in parallel
void MedusaTreeAttention(const float* q, const float* k_cache, const float* v_cache,
                         const uint32_t* draft_tokens,
                         uint32_t num_draft,
                         float* output,
                         uint32_t head_dim,
                         uint32_t max_seq_len);

// Fast draft generation with early stopping
uint32_t FastDraftGeneration(const float* hidden_state,
                              uint32_t* draft_tokens,
                              uint32_t max_draft,
                              float confidence_threshold);

} // namespace SEG
