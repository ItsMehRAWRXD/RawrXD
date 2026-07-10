// ============================================================================
// Speculative Autoregressive Generator
// ============================================================================
// Production integration of speculative decoding with the autoregressive generator
// ============================================================================

#ifndef SPECULATIVE_GENERATOR_HPP
#define SPECULATIVE_GENERATOR_HPP

#include "autoregressive_generator.hpp"
#include "speculative_decoder.hpp"
#include <memory>
#include <functional>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Speculative Generation Configuration
// ============================================================================
struct SpeculativeGenerationConfig {
    // Inherits base generation config
    GenerationConfig base;
    
    // Speculative-specific parameters
    uint32_t draft_tokens = 4;           // K: tokens per speculative step
    float draft_temperature = 1.2f;      // Higher = more diverse drafts
    float min_accept_prob = 0.6f;          // Minimum acceptance threshold
    bool use_shared_kv_cache = true;       // Share KV cache between draft/target
    
    // Draft model selection
    enum class DraftModelType {
        NGRAM,           // Statistical bigram model (fastest)
        SMALL_TRANSFORMER, // Smaller transformer (balanced)
        SAME_FEWER_LAYERS  // Use target with fewer layers (best quality)
    };
    DraftModelType draft_type = DraftModelType::NGRAM;
    
    // For SMALL_TRANSFORMER: number of layers for draft model
    uint32_t draft_num_layers = 6;
    uint32_t draft_hidden_size = 512;
};

// ============================================================================
// Draft Model Implementations
// ============================================================================

// N-gram statistical draft model (fastest, no neural network)
class NGramDraftModelImpl : public seg::DraftModel {
public:
    explicit NGramDraftModelImpl(int vocab_size);
    
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    ) override;
    
    float GetLatencyEstimate() const override { return 0.001f; } // 1us per token
    
    // Learn from training sequences
    void LearnFromSequence(const std::vector<uint32_t>& tokens);
    
private:
    int vocab_size_;
    // Simple bigram counts: counts_[prev][next]
    std::vector<std::vector<uint32_t>> counts_;
};

// Transformer-based draft model (better quality, slower)
class TransformerDraftModelImpl : public seg::DraftModel {
public:
    TransformerDraftModelImpl(
        std::shared_ptr<TransformerLayerInference> transformer,
        std::shared_ptr<EmbeddingTable> embeddings,
        std::shared_ptr<Tokenizer> tokenizer,
        uint32_t num_layers
    );
    
    std::vector<uint32_t> GenerateDraft(
        const std::vector<uint32_t>& context,
        uint32_t num_tokens,
        float temperature
    ) override;
    
    float GetLatencyEstimate() const override { return 0.1f; } // 100us per token
    
private:
    std::shared_ptr<TransformerLayerInference> transformer_;
    std::shared_ptr<EmbeddingTable> embeddings_;
    std::shared_ptr<Tokenizer> tokenizer_;
    uint32_t num_layers_;
    std::vector<float> hidden_buffer_;
    std::vector<float> output_buffer_;
    std::vector<float> logits_;
};

// Target model wrapper for the full transformer
class TransformerTargetModelImpl : public seg::TargetModel {
public:
    TransformerTargetModelImpl(
        std::shared_ptr<TransformerLayerInference> transformer,
        std::shared_ptr<EmbeddingTable> embeddings,
        std::shared_ptr<Tokenizer> tokenizer,
        const TransformerConfig& config
    );
    
    std::vector<std::vector<float>> VerifyDraft(
        const std::vector<uint32_t>& context,
        const std::vector<uint32_t>& draft_tokens
    ) override;
    
    float GetLatencyEstimate() const override { return 1.0f; } // 1ms per token
    
private:
    std::shared_ptr<TransformerLayerInference> transformer_;
    std::shared_ptr<EmbeddingTable> embeddings_;
    std::shared_ptr<Tokenizer> tokenizer_;
    TransformerConfig config_;
    std::vector<float> hidden_buffer_;
    std::vector<float> output_buffer_;
    std::vector<float> logits_;
};

// ============================================================================
// Speculative Autoregressive Generator
// ============================================================================
class SpeculativeAutoregressiveGenerator {
public:
    SpeculativeAutoregressiveGenerator(
        const TransformerConfig& transformer_config,
        const SpeculativeGenerationConfig& spec_config
    );
    
    ~SpeculativeAutoregressiveGenerator();
    
    // Initialize with loaded model components
    bool Initialize(
        std::shared_ptr<TransformerLayerInference> transformer,
        std::shared_ptr<EmbeddingTable> embeddings,
        std::shared_ptr<Tokenizer> tokenizer
    );
    
    // Generate text with speculative decoding
    std::string Generate(
        const std::string& prompt,
        uint32_t max_tokens = 256,
        std::function<void(const std::string&)> token_callback = nullptr
    );
    
    // Generate tokens directly
    std::vector<int> GenerateTokens(
        const std::vector<int>& prompt_tokens,
        uint32_t max_tokens = 256,
        std::function<void(int)> token_callback = nullptr
    );
    
    // Get performance statistics
    struct Stats {
        uint64_t total_steps = 0;
        uint64_t tokens_accepted = 0;
        uint64_t tokens_rejected = 0;
        float acceptance_rate = 0.0f;
        float speedup_vs_baseline = 1.0f;
        double avg_draft_time_ms = 0.0;
        double avg_target_time_ms = 0.0;
    };
    Stats GetStats() const;
    void ResetStats();
    
private:
    TransformerConfig transformer_config_;
    SpeculativeGenerationConfig spec_config_;
    
    // Model components
    std::shared_ptr<TransformerLayerInference> transformer_;
    std::shared_ptr<EmbeddingTable> embeddings_;
    std::shared_ptr<Tokenizer> tokenizer_;
    
    // Speculative decoder
    std::unique_ptr<seg::SpeculativeDecoder> spec_decoder_;
    std::unique_ptr<seg::DraftModel> draft_model_;
    std::unique_ptr<seg::TargetModel> target_model_;
    
    // Fallback to standard generator if speculative fails
    std::unique_ptr<AutoregressiveGenerator> fallback_generator_;
    
    bool initialized_ = false;
};

} // namespace Inference
} // namespace RawrXD

#endif // SPECULATIVE_GENERATOR_HPP
