// ============================================================================
// C6: Autoregressive Generator Implementation
// The main generation loop - produces tokens one at a time
// ============================================================================

#include "autoregressive_generator.hpp"
#include <chrono>
#include <iostream>

namespace rawrxd {

// ============================================================================
// AutoregressiveGenerator Implementation
// ============================================================================

AutoregressiveGenerator::AutoregressiveGenerator() = default;
AutoregressiveGenerator::~AutoregressiveGenerator() = default;

bool AutoregressiveGenerator::Initialize(
    std::shared_ptr<ModelContext> model,
    std::shared_ptr<SegGateway> seg_gateway
) {
    if (!model || !seg_gateway) {
        std::cerr << "Generator: Invalid model or gateway\n";
        return false;
    }
    
    model_ = model;
    seg_gateway_ = seg_gateway;
    
    // Initialize tokenizer
    tokenizer_ = std::make_unique<TokenizerRuntime>();
    if (!tokenizer_->Initialize(*model_)) {
        std::cerr << "Generator: Failed to initialize tokenizer\n";
        return false;
    }
    
    // Initialize embedding lookup
    embedding_lookup_ = std::make_unique<EmbeddingLookup>();
    if (!embedding_lookup_->Initialize(*model_)) {
        std::cerr << "Generator: Failed to initialize embedding lookup\n";
        return false;
    }
    
    // Initialize sampler
    sampler_ = std::make_unique<SamplingEngine>();
    auto arch = model_->GetArchitectureInfo();
    if (!sampler_->Initialize(arch.vocab_size)) {
        std::cerr << "Generator: Failed to initialize sampler\n";
        return false;
    }
    
    initialized_ = true;
    return true;
}

GenerationResult AutoregressiveGenerator::Generate(
    const std::string& prompt,
    const GenerationConfig& config
) {
    GenerationResult result;
    
    if (!initialized_) {
        result.finish_reason = "error: not initialized";
        return result;
    }
    
    if (!config.IsValid()) {
        result.finish_reason = "error: invalid config";
        return result;
    }
    
    // Tokenize prompt
    auto prompt_tokens = tokenizer_->EncodeBPE(prompt);
    result.prompt_tokens = static_cast<uint32_t>(prompt_tokens.size());
    
    if (prompt_tokens.empty()) {
        result.finish_reason = "error: empty prompt";
        return result;
    }
    
    // Generate from tokens
    return GenerateFromTokens(prompt_tokens, config);
}

GenerationResult AutoregressiveGenerator::GenerateFromTokens(
    const std::vector<uint32_t>& prompt_tokens,
    const GenerationConfig& config
) {
    GenerationResult result;
    
    if (!initialized_) {
        result.finish_reason = "error: not initialized";
        return result;
    }
    
    // Initialize generation state
    State state;
    state.context = prompt_tokens;
    state.position = static_cast<uint32_t>(prompt_tokens.size());
    state.generated.reserve(config.max_tokens);
    
    result.prompt_tokens = static_cast<uint32_t>(prompt_tokens.size());
    
    // Start timing
    auto start_time = std::chrono::steady_clock::now();
    auto first_token_time = start_time;
    bool first_token = true;
    
    // Generation loop
    for (uint32_t i = 0; i < config.max_tokens && !state.finished; ++i) {
        // Generate one token
        if (!GenerateStep(state, config)) {
            result.finish_reason = "error: generation failed";
            break;
        }
        
        // Track first token time
        if (first_token) {
            first_token_time = std::chrono::steady_clock::now();
            first_token = false;
        }
        
        // Stream if callback provided
        if (config.stream_output && config.on_token) {
            std::string token_text = tokenizer_->DecodeBPE({state.generated.back()});
            config.on_token(state.generated.back(), token_text);
        }
        
        // Check stopping criteria
        if (ShouldStop(state, config)) {
            break;
        }
        
        // Update context window
        UpdateContext(state, config.max_context_length);
    }
    
    // Calculate timing
    auto end_time = std::chrono::steady_clock::now();
    result.total_time_ms = std::chrono::duration<float, std::milli>(
        end_time - start_time
    ).count();
    result.time_to_first_token_ms = std::chrono::duration<float, std::milli>(
        first_token_time - start_time
    ).count();
    
    // Populate result
    result.tokens = state.generated;
    result.tokens_generated = static_cast<uint32_t>(state.generated.size());
    result.finished = state.finished;
    result.finish_reason = state.finish_reason;
    
    // Calculate TPS
    if (result.tokens_generated > 0 && result.total_time_ms > 0) {
        result.tokens_per_second = 
            (result.tokens_generated * 1000.0f) / result.total_time_ms;
    }
    
    // Decode full text
    result.text = DecodeTokens(state.generated);
    
    return result;
}

bool AutoregressiveGenerator::GenerateStep(
    State& state,
    const GenerationConfig& config
) {
    // Get embeddings for current context
    auto embeddings = embedding_lookup_->GetEmbeddings(state.context);
    if (embeddings.empty()) {
        return false;
    }
    
    // Run transformer forward pass via SEG
    SegInferenceRequest request;
    request.input_embeddings = embeddings;
    request.input_shape = {state.context.size(), model_->GetArchitectureInfo().embedding_dim};
    
    auto response = seg_gateway_->Run(request);
    if (!response.success) {
        return false;
    }
    
    // Sample next token from logits
    SamplingResult sample_result;
    if (config.sampling.repetition_penalty != 1.0f) {
        // Include repetition penalty
        sample_result = sampler_->SampleWithPenalty(
            response.output_logits,
            config.sampling,
            state.generated
        );
    } else {
        sample_result = sampler_->Sample(response.output_logits, config.sampling);
    }
    
    if (!sample_result.success) {
        return false;
    }
    
    // Add token to generated sequence
    state.generated.push_back(sample_result.token_id);
    state.context.push_back(sample_result.token_id);
    state.position++;
    
    return true;
}

bool AutoregressiveGenerator::ShouldStop(
    State& state,
    const GenerationConfig& config
) {
    if (state.generated.empty()) {
        return false;
    }
    
    uint32_t last_token = state.generated.back();
    
    // Check EOS token
    if (last_token == config.eos_token_id) {
        state.finished = true;
        state.finish_reason = "eos";
        return true;
    }
    
    // Check stop tokens
    for (uint32_t stop_token : config.stop_tokens) {
        if (last_token == stop_token) {
            state.finished = true;
            state.finish_reason = "stop";
            return true;
        }
    }
    
    // Check max tokens
    if (state.generated.size() >= config.max_tokens) {
        state.finished = true;
        state.finish_reason = "length";
        return true;
    }
    
    // Check stop strings (would need to decode and check)
    // For now, skip this check
    
    return false;
}

void AutoregressiveGenerator::UpdateContext(State& state, uint32_t max_length) {
    if (state.context.size() <= max_length) {
        return;
    }
    
    // Simple sliding window: keep last max_length tokens
    // More sophisticated: keep prompt tokens + recent generated tokens
    size_t to_remove = state.context.size() - max_length;
    state.context.erase(state.context.begin(), state.context.begin() + to_remove);
}

std::string AutoregressiveGenerator::DecodeTokens(const std::vector<uint32_t>& tokens) {
    return tokenizer_->DecodeBPE(tokens);
}

// ============================================================================
// Convenience Functions
// ============================================================================

GenerationResult GenerateText(
    const std::string& prompt,
    std::shared_ptr<ModelContext> model,
    std::shared_ptr<SegGateway> gateway,
    uint32_t max_tokens,
    float temperature
) {
    AutoregressiveGenerator generator;
    if (!generator.Initialize(model, gateway)) {
        GenerationResult result;
        result.finish_reason = "error: initialization failed";
        return result;
    }
    
    GenerationConfig config;
    config.max_tokens = max_tokens;
    config.sampling.temperature = temperature;
    config.sampling.top_k = 40;
    config.sampling.top_p = 0.95f;
    
    return generator.Generate(prompt, config);
}

} // namespace rawrxd
