// ============================================================================
// Speculative Inference Pipeline
// ============================================================================
// Integrates C8 speculative decoding into the sovereign inference path
// Expected 2-3x speedup over standard autoregressive generation
// ============================================================================

#pragma once

#include "speculative_decoder.hpp"
#include "transformer_forward.hpp"
#include <cstdint>
#include <vector>
#include <memory>

namespace seg {

// ============================================================================
// Model Configuration for Draft/Target Pair
// ============================================================================
struct SpeculativePipelineConfig {
    // Target model (full size)
    uint32_t target_num_layers = 24;
    uint32_t target_hidden_size = 2048;
    uint32_t target_num_heads = 32;
    
    // Draft model (smaller, faster)
    uint32_t draft_num_layers = 6;
    uint32_t draft_hidden_size = 512;
    uint32_t draft_num_heads = 8;
    
    // Speculative decoding parameters
    uint32_t draft_tokens = 4;
    float draft_temperature = 1.2f;
    float min_accept_prob = 0.6f;
    
    // Vocabulary
    uint32_t vocab_size = 32000;
};

// ============================================================================
// Simple Draft Model Implementation
// ============================================================================
// Uses fewer layers for faster token generation
class SimpleDraftModel : public DraftModel {
public:
    SimpleDraftModel();
    ~SimpleDraftModel();
    
    bool Initialize(const SpeculativePipelineConfig& config);
    
    // DraftModel interface
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    ) override;
    
    float GetLatencyEstimate() const override;
    
private:
    SpeculativePipelineConfig config_;
    bool initialized_ = false;
    
    // Simplified forward pass
    std::vector<float> ForwardOnce(const std::vector<uint32_t>& tokens);
};

// ============================================================================
// Simple Target Model Implementation
// ============================================================================
// Full transformer for verification
class SimpleTargetModel : public TargetModel {
public:
    SimpleTargetModel();
    ~SimpleTargetModel();
    
    bool Initialize(const SpeculativePipelineConfig& config);
    
    // TargetModel interface
    std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens
    ) override;
    
    float GetLatencyEstimate() const override;
    
private:
    SpeculativePipelineConfig config_;
    bool initialized_ = false;
    
    // Full forward pass
    std::vector<float> ForwardOnce(const std::vector<uint32_t>& tokens);
};

// ============================================================================
// Integrated Speculative Inference Pipeline
// ============================================================================
class SpeculativeInferencePipeline {
public:
    SpeculativeInferencePipeline();
    ~SpeculativeInferencePipeline();
    
    // Initialize with configuration
    bool Initialize(const SpeculativePipelineConfig& config);
    
    // Generate tokens using speculative decoding
    // Returns generated token IDs
    std::vector<uint32_t> Generate(
        const std::vector<uint32_t>& prompt,
        uint32_t num_tokens_to_generate,
        float temperature = 0.8f
    );
    
    // Get statistics from last generation
    struct GenerationStats {
        uint32_t tokens_generated = 0;
        uint32_t draft_tokens_proposed = 0;
        uint32_t draft_tokens_accepted = 0;
        float acceptance_rate = 0.0f;
        float avg_draft_latency_ms = 0.0f;
        float avg_target_latency_ms = 0.0f;
        float total_time_ms = 0.0f;
        float tokens_per_sec = 0.0f;
    };
    
    GenerationStats GetLastStats() const { return last_stats_; }
    
    // Enable/disable speculative decoding (for comparison)
    void SetUseSpeculative(bool use) { use_speculative_ = use; }
    bool GetUseSpeculative() const { return use_speculative_; }
    
private:
    SpeculativePipelineConfig config_;
    std::unique_ptr<SpeculativeDecoder> decoder_;
    std::unique_ptr<SimpleDraftModel> draft_model_;
    std::unique_ptr<SimpleTargetModel> target_model_;
    
    bool initialized_ = false;
    bool use_speculative_ = true;
    GenerationStats last_stats_;
    
    // Standard autoregressive generation (for comparison)
    std::vector<uint32_t> GenerateAutoregressive(
        const std::vector<uint32_t>& prompt,
        uint32_t num_tokens,
        float temperature
    );
};

// ============================================================================
// Benchmark Function
// ============================================================================
void BenchmarkSpeculativePipeline(
    uint32_t num_tokens = 128,
    uint32_t num_iterations = 5
);

} // namespace seg
