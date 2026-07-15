#pragma once
// ============================================================================
// C8: Speculative Decoding
// ============================================================================
// Draft model generates K candidate tokens, target model verifies in parallel
// Expected 2-3x speedup for inference
// ============================================================================

#include "seg_runtime.hpp"
#include "seg_graph.hpp"
#include "seg_executor.hpp"
#include "seg_memory.hpp"
#include "../runtime/telemetry_masm_bridge.hpp"
#include <cstdint>
#include <vector>
#include <memory>
#include <functional>

namespace seg {

// Speculative decoding configuration
struct SpeculativeConfig {
    // Number of draft tokens to generate per step
    uint32_t draft_tokens = 4;
    
    // Temperature for draft sampling (higher = more diverse)
    float draft_temperature = 1.2f;
    
    // Minimum acceptance probability threshold
    float min_accept_prob = 0.6f;
    
    // Maximum rejection rate before falling back
    float max_rejection_rate = 0.5f;
    
    // Whether to use shared KV cache
    bool shared_kv_cache = true;
    
    // Telemetry tags for draft vs target
    bool enable_telemetry = true;
};

// Token acceptance result
struct AcceptanceResult {
    // Number of tokens accepted (0 to draft_tokens)
    uint32_t accepted_count = 0;
    
    // Index of first rejected token (if any)
    uint32_t rejected_index = 0;
    
    // Whether to use the target's token at rejected position
    bool use_target_token = false;
    
    // Target token ID at rejection point
    uint32_t target_token = 0;
    
    // Acceptance rate for telemetry
    float acceptance_rate = 0.0f;
};

// Draft model interface (can be smaller/faster model)
class DraftModel {
public:
    virtual ~DraftModel() = default;
    
    // Generate draft tokens given current context
    virtual std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    ) = 0;
    
    // Get draft model latency estimate (for telemetry)
    virtual float GetLatencyEstimate() const = 0;
};

// Target model interface (full model for verification)
class TargetModel {
public:
    virtual ~TargetModel() = default;
    
    // Verify draft tokens and return logits for each position
    // Returns logits for all positions in parallel
    virtual std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens
    ) = 0;
    
    // Get target model latency estimate (for telemetry)
    virtual float GetLatencyEstimate() const = 0;
};

// Speculative decoder using SEG
class SpeculativeDecoder {
public:
    SpeculativeDecoder();
    ~SpeculativeDecoder();
    
    // Initialize with draft and target models
    bool Initialize(
        std::unique_ptr<DraftModel> draft,
        std::unique_ptr<TargetModel> target,
        const SpeculativeConfig& config = {}
    );
    
    // Generate tokens with speculative decoding
    // Returns generated tokens (both accepted and final)
    std::vector<uint32_t> Generate(
        const std::vector<uint32_t>& prompt,
        uint32_t max_tokens,
        std::function<void(uint32_t)> token_callback = nullptr
    );
    
    // Single speculative step
    // Returns accepted tokens + possibly one target token
    std::vector<uint32_t> SpeculativeStep(
        const std::vector<uint32_t>& context
    );
    
    // Get telemetry statistics
    struct Stats {
        uint64_t total_steps = 0;
        uint64_t draft_tokens_generated = 0;
        uint64_t tokens_accepted = 0;
        uint64_t tokens_rejected = 0;
        float avg_acceptance_rate = 0.0f;
        float speedup_vs_baseline = 1.0f;
        uint64_t draft_time_us = 0;
        uint64_t target_time_us = 0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    std::unique_ptr<DraftModel> draft_model_;
    std::unique_ptr<TargetModel> target_model_;
    SpeculativeConfig config_;
    
    // Statistics
    Stats stats_;
    
    // Accept/reject logic
    AcceptanceResult AcceptReject(
        const std::vector<uint32_t>& draft_tokens,
        const std::vector<std::vector<float>>& target_logits
    );
    
    // Sample from logits
    uint32_t SampleToken(const std::vector<float>& logits, float temperature);
};

// Simple draft model using n-gram approximation
class NGramDraftModel : public DraftModel {
public:
    NGramDraftModel(uint32_t vocab_size = 32000);
    
    // Build n-gram statistics from training data
    void BuildStats(const std::vector<std::vector<uint32_t>>& sequences);
    
    // DraftModel interface
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    ) override;
    
    float GetLatencyEstimate() const override { return 0.1f; } // 0.1ms

private:
    uint32_t vocab_size_;
    
    // Bigram statistics: P(next | current)
    std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, float>>> bigrams_;
};

// SEG-based target model wrapper
class SEGTargetModel : public TargetModel {
public:
    SEGTargetModel(
        Executor& executor,
        Graph& graph,
        Memory& memory
    );
    
    // TargetModel interface
    std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens
    ) override;
    
    float GetLatencyEstimate() const override { return 5.0f; } // 5ms

private:
    Executor& executor_;
    Graph& graph_;
    Memory& memory_;
};

} // namespace seg
