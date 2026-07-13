#pragma once
// ============================================================================
// SEG Transformer Target Model - Real Inference Integration
// ============================================================================
// Connects SpeculativeDecoder to actual transformer inference via SEG
// Uses TransformerModelRuntime for forward passes
// ============================================================================

#include "speculative_decoder.hpp"
#include "../runtime/transformer_layer_runtime.hpp"
#include "../runtime/sovereign_tokenizer.hpp"
#include <memory>

namespace seg {

// ============================================================================
// TransformerTargetModel - Real Model for C8 Verification
// ============================================================================
class TransformerTargetModel : public TargetModel {
public:
    TransformerTargetModel(
        RawrXD::Runtime::TransformerModelRuntime* runtime,
        RawrXD::Runtime::SovereignTokenizer* tokenizer,
        uint32_t vocab_size = 32000
    );
    
    // TargetModel interface
    std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens
    ) override;
    
    float GetLatencyEstimate() const override;
    
    // Extended interface for real inference
    bool Initialize();
    void SetKVCache(float* key_cache, float* value_cache, uint32_t max_seq_len);
    
private:
    RawrXD::Runtime::TransformerModelRuntime* runtime_;
    RawrXD::Runtime::SovereignTokenizer* tokenizer_;
    uint32_t vocab_size_;
    
    // KV cache for attention
    float* key_cache_ = nullptr;
    float* value_cache_ = nullptr;
    uint32_t max_seq_len_ = 0;
    uint32_t current_seq_len_ = 0;
    
    // Run single forward pass
    std::vector<float> ForwardPass(const std::vector<uint32_t>& tokens);
};

// ============================================================================
// TransformerDraftModel - Smaller/Faster Model for Draft Generation
// ============================================================================
// Can be:
// - Smaller version of main model (distilled)
// - N-gram model (fast, no GPU)
// - Learned draft heads (Medusa-style)
// ============================================================================
class TransformerDraftModel : public DraftModel {
public:
    // Option 1: Use smaller transformer
    TransformerDraftModel(
        RawrXD::Runtime::TransformerModelRuntime* runtime,
        uint32_t vocab_size = 32000
    );
    
    // Option 2: Use n-gram approximation
    explicit TransformerDraftModel(uint32_t vocab_size = 32000);
    
    // DraftModel interface
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    ) override;
    
    float GetLatencyEstimate() const override;
    
    // Build n-gram stats from training data
    void BuildNgramStats(const std::vector<std::vector<uint32_t>>& sequences);
    
private:
    enum class DraftType {
        TRANSFORMER,  // Use actual model (smaller)
        NGRAM         // Use n-gram statistics
    };
    
    DraftType type_;
    RawrXD::Runtime::TransformerModelRuntime* runtime_;
    uint32_t vocab_size_;
    
    // N-gram statistics for fast draft
    std::unordered_map<uint32_t, std::vector<std::pair<uint32_t, float>>> bigrams_;
    
    // Generate using transformer
    std::vector<uint32_t> GenerateTransformerDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    );
    
    // Generate using n-grams
    std::vector<uint32_t> GenerateNgramDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    );
};

// ============================================================================
// SpeculativeInferencePipeline - Complete Integration
// ============================================================================
// Combines tokenizer + speculative decoder + transformer runtime
// ============================================================================
class SpeculativeInferencePipeline {
public:
    SpeculativeInferencePipeline();
    ~SpeculativeInferencePipeline();
    
    // Initialize with model paths
    bool Initialize(
        const std::string& tokenizer_path,
        const std::string& model_path,
        const SpeculativeConfig& config = {}
    );
    
    // Generate text with speculative decoding
    std::string Generate(
        const std::string& prompt,
        uint32_t max_new_tokens = 256,
        float temperature = 0.8f
    );
    
    // Generate with streaming callback
    void GenerateStreaming(
        const std::string& prompt,
        uint32_t max_new_tokens,
        float temperature,
        std::function<void(const std::string&)> token_callback
    );
    
    // Get telemetry statistics
    SpeculativeDecoder::Stats GetStats() const;
    void ResetStats();
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }

private:
    std::unique_ptr<SpeculativeDecoder> decoder_;
    std::unique_ptr<RawrXD::Runtime::SovereignTokenizer> tokenizer_;
    std::unique_ptr<RawrXD::Runtime::TransformerModelRuntime> target_runtime_;
    std::unique_ptr<TransformerDraftModel> draft_model_;
    std::unique_ptr<TransformerTargetModel> target_model_;
    
    bool initialized_ = false;
    SpeculativeConfig config_;
};

} // namespace seg
