// ============================================================================
// C5: Sampling - Logits to Token IDs
// Temperature, Top-K, Top-P sampling for token generation
// ============================================================================

#pragma once

#include <vector>
#include <cstdint>
#include <random>
#include <algorithm>
#include <cmath>

namespace rawrxd {

// Sampling configuration
struct SamplingConfig {
    float temperature = 0.8f;      // Temperature scaling (1.0 = no change, <1 = more focused)
    int top_k = 40;              // Top-K filtering (0 = disabled)
    float top_p = 0.95f;         // Nucleus sampling threshold (1.0 = disabled)
    float repetition_penalty = 1.0f;  // Penalty for repeating tokens (1.0 = no penalty)
    
    bool IsValid() const {
        return temperature > 0.0f && top_k >= 0 && top_p > 0.0f && top_p <= 1.0f;
    }
};

// Sampling result
struct SamplingResult {
    uint32_t token_id = 0;
    float probability = 0.0f;
    bool success = false;
};

// ============================================================================
// Sampling Engine
// ============================================================================

class SamplingEngine {
public:
    SamplingEngine();
    ~SamplingEngine();
    
    // Initialize with vocabulary size
    bool Initialize(uint32_t vocab_size);
    
    // Sample token from logits
    // logits: [vocab_size] raw logits from transformer
    // config: sampling parameters
    // returns: sampled token ID
    SamplingResult Sample(
        const std::vector<float>& logits,
        const SamplingConfig& config
    );
    
    // Sample with repetition penalty
    SamplingResult SampleWithPenalty(
        const std::vector<float>& logits,
        const SamplingConfig& config,
        const std::vector<uint32_t>& previous_tokens
    );
    
    // Greedy sampling (argmax)
    SamplingResult GreedySample(const std::vector<float>& logits);
    
    // Get last sampling statistics
    struct Stats {
        float max_logit = 0.0f;
        float min_logit = 0.0f;
        float entropy = 0.0f;
        uint32_t vocab_size = 0;
    };
    Stats GetLastStats() const { return last_stats_; }
    
private:
    uint32_t vocab_size_ = 0;
    bool initialized_ = false;
    
    std::mt19937 rng_;  // Mersenne Twister RNG
    
    Stats last_stats_;
    
    // Internal sampling methods
    void ApplyTemperature(std::vector<float>& logits, float temperature);
    void ApplyTopK(std::vector<float>& logits, int k);
    void ApplyTopP(std::vector<float>& logits, float p);
    void ApplyRepetitionPenalty(
        std::vector<float>& logits,
        const std::vector<uint32_t>& previous_tokens,
        float penalty
    );
    
    uint32_t SoftmaxSample(const std::vector<float>& logits);
    std::vector<float> ComputeSoftmax(const std::vector<float>& logits);
    
    float ComputeEntropy(const std::vector<float>& probabilities);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick sample with default config
SamplingResult SampleToken(
    const std::vector<float>& logits,
    float temperature = 0.8f,
    int top_k = 40
);

// Greedy argmax
uint32_t Argmax(const std::vector<float>& logits);

} // namespace rawrxd
