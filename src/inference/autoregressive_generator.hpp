// ============================================================================
// C6: Autoregressive Generator
// The main generation loop - produces tokens one at a time
// ============================================================================

#pragma once

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include "sampling.hpp"
#include "../runtime/tokenizer_runtime.h"
#include "../runtime/embedding_lookup.hpp"
#include "../gateway/seg_gateway.hpp"
#include "../model/model_context.h"

namespace rawrxd {

// Type aliases for convenience  
using ModelContext = rawrxd::model::ModelContext;
using SegGateway = rawrxd::gateway::SegGateway;
using TokenizerRuntime = rawrxd::runtime::TokenizerRuntime;
using EmbeddingLookup = rawrxd::runtime::EmbeddingLookup;

// Generation configuration
struct GenerationConfig {
    // Sampling parameters
    SamplingConfig sampling;
    
    // Generation limits
    uint32_t max_tokens = 256;
    uint32_t max_context_length = 4096;
    
    // Stopping criteria
    std::vector<uint32_t> stop_tokens;      // Token IDs that stop generation
    std::vector<std::string> stop_strings; // Strings that stop generation
    
    // Special tokens
    uint32_t eos_token_id = 0;      // End of sequence
    uint32_t pad_token_id = 0;      // Padding
    
    // Streaming
    bool stream_output = false;
    std::function<void(uint32_t, const std::string&)> on_token;
    
    bool IsValid() const {
        return max_tokens > 0 && sampling.IsValid();
    }
};

// Generation result
struct GenerationResult {
    std::vector<uint32_t> tokens;       // All generated token IDs
    std::string text;                    // Decoded text
    uint32_t tokens_generated = 0;
    uint32_t prompt_tokens = 0;
    bool finished = false;
    std::string finish_reason;           // "stop", "length", "eos"
    
    // Performance metrics
    float tokens_per_second = 0.0f;
    float time_to_first_token_ms = 0.0f;
    float total_time_ms = 0.0f;
};

// ============================================================================
// Autoregressive Generator
// ============================================================================

class AutoregressiveGenerator {
public:
    AutoregressiveGenerator();
    ~AutoregressiveGenerator();
    
    // Initialize with model context
    bool Initialize(
        std::shared_ptr<ModelContext> model,
        std::shared_ptr<SegGateway> seg_gateway
    );
    
    // Generate text from prompt
    GenerationResult Generate(
        const std::string& prompt,
        const GenerationConfig& config
    );
    
    // Generate with pre-tokenized prompt
    GenerationResult GenerateFromTokens(
        const std::vector<uint32_t>& prompt_tokens,
        const GenerationConfig& config
    );
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }
    
    // Get model info
    std::shared_ptr<ModelContext> GetModel() const { return model_; }
    
private:
    bool initialized_ = false;
    std::shared_ptr<ModelContext> model_;
    std::shared_ptr<SegGateway> seg_gateway_;
    
    std::unique_ptr<TokenizerRuntime> tokenizer_;
    std::unique_ptr<EmbeddingLookup> embedding_lookup_;
    std::unique_ptr<SamplingEngine> sampler_;
    
    // Internal generation state
    struct State {
        std::vector<uint32_t> context;      // Current context window
        std::vector<uint32_t> generated;     // Newly generated tokens
        uint32_t position = 0;               // Current position in sequence
        bool finished = false;
        std::string finish_reason;
    };
    
    // Single generation step
    bool GenerateStep(State& state, const GenerationConfig& config);
    
    // Check stopping criteria
    bool ShouldStop(State& state, const GenerationConfig& config);
    
    // Update context window (sliding window if needed)
    void UpdateContext(State& state, uint32_t max_length);
    
    // Decode tokens to text
    std::string DecodeTokens(const std::vector<uint32_t>& tokens);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick generation with defaults
GenerationResult GenerateText(
    const std::string& prompt,
    std::shared_ptr<ModelContext> model,
    std::shared_ptr<SegGateway> gateway,
    uint32_t max_tokens = 256,
    float temperature = 0.8f
);

} // namespace rawrxd
