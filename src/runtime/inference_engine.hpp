/**
 * @file inference_engine.hpp
 * @brief RawrXD Inference Engine - Step C4
 *
 * Transformer forward pass: embeddings → attention → FFN → logits → tokens
 * Zero external dependencies. Pure C++17.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "embedding_lookup.hpp"
#include "../model/model_context.h"

#include <cstdint>
#include <vector>
#include <memory>
#include <functional>

namespace rawrxd {
namespace runtime {

// ============================================================================
// Forward Declarations
// ============================================================================

struct KVCache;
struct AttentionHead;
struct FeedForwardNetwork;

// ============================================================================
// Inference Configuration
// ============================================================================

struct InferenceConfig {
    uint32_t max_tokens = 256;           // Maximum tokens to generate
    float temperature = 0.8f;            // Sampling temperature
    float top_p = 0.95f;                 // Nucleus sampling threshold
    uint32_t top_k = 40;                 // Top-k sampling
    float repetition_penalty = 1.0f;     // Repetition penalty (1.0 = disabled)
    bool streaming = false;              // Enable token streaming
    
    // Advanced options
    uint32_t context_window = 4096;      // Maximum context length
    bool use_kv_cache = true;            // Enable KV-cache optimization
    bool deterministic = false;          // Deterministic sampling (seeded)
    uint32_t seed = 0;                   // Random seed for deterministic mode
};

// ============================================================================
// Inference Telemetry
// ============================================================================

struct InferenceTelemetry {
    uint32_t tokens_generated = 0;
    uint32_t tokens_prompt = 0;
    double time_to_first_token_ms = 0.0;
    double total_time_ms = 0.0;
    double tokens_per_second = 0.0;
    uint64_t memory_used_bytes = 0;
    uint32_t layers_processed = 0;
    
    // Per-layer timing (if available)
    std::vector<std::pair<std::string, double>> layer_timings;
    
    std::string ToJson() const;
    std::string Summary() const;
};

// ============================================================================
// Token Sampling Result
// ============================================================================

struct SamplingResult {
    uint32_t token_id = 0;
    float logit = 0.0f;
    float probability = 0.0f;
    bool is_eos = false;
    
    std::string ToJson() const;
};

// ============================================================================
// Streaming Callback
// ============================================================================

using TokenCallback = std::function<void(uint32_t token_id, const std::string& token_text, bool is_last)>;
using LogitsCallback = std::function<void(const std::vector<float>& logits)>;

// ============================================================================
// Inference Engine
// ============================================================================

class InferenceEngine {
public:
    InferenceEngine();
    ~InferenceEngine();
    
    // Disable copy, enable move
    InferenceEngine(const InferenceEngine&) = delete;
    InferenceEngine& operator=(const InferenceEngine&) = delete;
    InferenceEngine(InferenceEngine&&) noexcept;
    InferenceEngine& operator=(InferenceEngine&&) noexcept;
    
    /**
     * Initialize with model context.
     */
    bool Initialize(const model::ModelContext& model);
    
    /**
     * Check if initialized.
     */
    bool IsInitialized() const { return initialized_; }
    
    /**
     * Run complete inference: prompt → generated text.
     */
    std::string Generate(const std::string& prompt, const InferenceConfig& config = {});
    
    /**
     * Run inference with token IDs: input tokens → output tokens.
     */
    std::vector<uint32_t> GenerateTokens(
        const std::vector<uint32_t>& input_tokens,
        const InferenceConfig& config = {}
    );
    
    /**
     * Run inference with embeddings: embeddings → output tokens.
     */
    std::vector<uint32_t> GenerateFromEmbeddings(
        const EmbeddingMatrix& embeddings,
        const InferenceConfig& config = {}
    );
    
    /**
     * Generate with streaming callback.
     */
    void GenerateStreaming(
        const std::string& prompt,
        const TokenCallback& callback,
        const InferenceConfig& config = {}
    );
    
    /**
     * Single forward pass: embeddings → logits.
     */
    std::vector<float> Forward(const EmbeddingMatrix& embeddings);
    
    /**
     * Sample next token from logits.
     */
    SamplingResult SampleToken(
        const std::vector<float>& logits,
        const InferenceConfig& config,
        const std::vector<uint32_t>& context_tokens
    );
    
    /**
     * Reset KV cache for new conversation.
     */
    void ResetCache();
    
    /**
     * Get model info.
     */
    uint32_t GetVocabSize() const { return vocab_size_; }
    uint32_t GetNumLayers() const { return num_layers_; }
    uint32_t GetNumHeads() const { return num_heads_; }
    uint32_t GetHeadDim() const { return head_dim_; }
    uint32_t GetHiddenDim() const { return hidden_dim_; }
    
    /**
     * Get last error.
     */
    const std::string& GetLastError() const { return last_error_; }
    
    /**
     * Get telemetry from last generation.
     */
    const InferenceTelemetry& GetLastTelemetry() const { return last_telemetry_; }
    
private:
    bool initialized_ = false;
    std::string last_error_;
    InferenceTelemetry last_telemetry_;
    
    // Model dimensions
    uint32_t vocab_size_ = 0;
    uint32_t num_layers_ = 0;
    uint32_t num_heads_ = 0;
    uint32_t head_dim_ = 0;
    uint32_t hidden_dim_ = 0;
    uint32_t intermediate_dim_ = 0;
    uint32_t max_seq_len_ = 0;
    
    // Components
    std::unique_ptr<EmbeddingLookup> embedding_lookup_;
    std::unique_ptr<KVCache> kv_cache_;
    
    // Weight tensors (simplified - real impl would use mmap)
    std::vector<float> weights_;  // All transformer weights
    
    // Internal methods
    bool LoadWeights(const model::ModelContext& model);
    
    // Transformer layers
    void ApplyLayerNorm(std::vector<float>& hidden, const float* gamma, const float* beta);
    void ApplyAttention(
        std::vector<float>& hidden,
        const float* q_weights,
        const float* k_weights,
        const float* v_weights,
        const float* o_weights,
        uint32_t seq_len,
        uint32_t layer_idx
    );
    void ApplyFeedForward(
        std::vector<float>& hidden,
        const float* gate_weights,
        const float* up_weights,
        const float* down_weights
    );
    void ApplyRMSNorm(std::vector<float>& hidden, const float* rms_weights);
    
    // Activation functions
    void ApplySiLU(std::vector<float>& x);
    void ApplySoftmax(std::vector<float>& x);
    void ApplyGELU(std::vector<float>& x);
    
    // Sampling helpers
    uint32_t ArgMax(const std::vector<float>& logits);
    uint32_t TopKSampling(const std::vector<float>& logits, uint32_t k, float temperature);
    uint32_t TopPSampling(const std::vector<float>& logits, float p, float temperature);
    
    // Matrix operations
    void MatMul(
        const float* A, const float* B, float* C,
        uint32_t M, uint32_t N, uint32_t K
    );
    void MatMulAddBias(
        const float* A, const float* B, const float* bias, float* C,
        uint32_t M, uint32_t N, uint32_t K
    );
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick inference without class instantiation
std::string RunInference(
    const model::ModelContext& model,
    const std::string& prompt,
    const InferenceConfig& config = {},
    std::string* error = nullptr
);

// Calculate perplexity for a text
float CalculatePerplexity(
    const model::ModelContext& model,
    const std::string& text,
    std::string* error = nullptr
);

} // namespace runtime
} // namespace rawrxd
