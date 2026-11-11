#pragma once
// ============================================================================
// C5: Token Sampling
// ============================================================================
// Sampling strategies for converting logits to token predictions
// Supports: Greedy, Top-K, Top-P (nucleus), Temperature scaling
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <vector>
#include <random>
#include <functional>

namespace SEG {

// ============================================================================
// Sampling Configuration
// ============================================================================

struct SamplingConfig {
    // Temperature scaling (0.0 = greedy, 1.0 = standard, >1.0 = more random)
    float temperature = 1.0f;
    
    // Top-K sampling: 0 = disabled, >0 = sample from top K
    int top_k = 0;
    
    // Top-P (nucleus) sampling: 0.0 = disabled, 1.0 = sample from all
    float top_p = 1.0f;
    
    // Repetition penalty: 1.0 = no penalty, >1.0 = penalize repeats
    float repetition_penalty = 1.0f;
    
    // Random seed (0 = use random device)
    uint64_t seed = 0;
    
    // Minimum tokens to generate before EOS allowed
    size_t min_tokens = 0;
    
    // Tokens to penalize (e.g., EOS early in generation)
    std::vector<int> penalty_tokens;
    
    // Validate configuration
    bool Validate() const;
};

// ============================================================================
// Token Probabilities
// ============================================================================

struct TokenProb {
    int token_id;
    float logit;
    float probability;
    
    bool operator<(const TokenProb& other) const {
        return probability > other.probability;  // Sort descending
    }
};

// ============================================================================
// Sampling Context
// ============================================================================

class SamplingContext {
public:
    explicit SamplingContext(const SamplingConfig& config);
    
    // Sample a token from logits
    int Sample(const float* logits, size_t vocab_size);
    
    // Sample with repetition penalty applied
    int SampleWithPenalty(const float* logits, size_t vocab_size,
                          const std::vector<int>& token_history);
    
    // Get the full probability distribution (for debugging/analysis)
    std::vector<TokenProb> GetProbabilities(const float* logits, size_t vocab_size);
    
    // Reset internal state (e.g., for new sequence)
    void Reset();
    
    // Update config
    void SetConfig(const SamplingConfig& config);
    const SamplingConfig& GetConfig() const { return config_; }
    
private:
    SamplingConfig config_;
    std::mt19937_64 rng_;
    
    // Apply temperature scaling to logits
    void ApplyTemperature(std::vector<float>& logits) const;
    
    // Apply softmax to get probabilities
    void Softmax(std::vector<float>& logits) const;
    
    // Apply top-k filtering
    void ApplyTopK(std::vector<float>& logits, int k) const;
    
    // Apply top-p (nucleus) filtering
    void ApplyTopP(std::vector<float>& logits, float p) const;
    
    // Apply repetition penalty
    void ApplyRepetitionPenalty(std::vector<float>& logits,
                                 const std::vector<int>& token_history) const;
    
    // Sample from probability distribution
    int SampleFromDistribution(const std::vector<float>& probs);
    
    // Greedy selection (argmax)
    int GreedySample(const std::vector<float>& logits) const;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Greedy sampling (argmax)
int GreedySample(const float* logits, size_t vocab_size);

// Sample with temperature only
int TemperatureSample(const float* logits, size_t vocab_size,
                      float temperature, uint64_t seed = 0);

// Sample with top-k
int TopKSample(const float* logits, size_t vocab_size,
               int k, float temperature = 1.0f, uint64_t seed = 0);

// Sample with top-p (nucleus)
int TopPSample(const float* logits, size_t vocab_size,
               float p, float temperature = 1.0f, uint64_t seed = 0);

// Combined sampling (top-k + top-p + temperature)
int CombinedSample(const float* logits, size_t vocab_size,
                   const SamplingConfig& config);

// ============================================================================
// Sampling Utilities
// ============================================================================

// Convert logits to probabilities (softmax)
std::vector<float> LogitsToProbs(const float* logits, size_t vocab_size);

// Apply temperature scaling
void ApplyTemperature(std::vector<float>& logits, float temperature);

// Get top N tokens by logit value
std::vector<TokenProb> GetTopTokens(const float* logits, size_t vocab_size, size_t n);

// Validate logits (check for NaN/Inf)
bool ValidateLogits(const float* logits, size_t vocab_size);

// Fix invalid logits (replace NaN/Inf with safe values)
void SanitizeLogits(float* logits, size_t vocab_size);

} // namespace SEG
