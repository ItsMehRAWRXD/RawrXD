// ============================================================================
// C5: Token Sampling Implementation
// ============================================================================

#include "token_sampling.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <limits>
#include <cstring>

namespace SEG {

// ============================================================================
// SamplingConfig
// ============================================================================

bool SamplingConfig::Validate() const {
    if (temperature < 0.0f) return false;
    if (top_k < 0) return false;
    if (top_p < 0.0f || top_p > 1.0f) return false;
    if (repetition_penalty < 0.0f) return false;
    return true;
}

// ============================================================================
// SamplingContext
// ============================================================================

SamplingContext::SamplingContext(const SamplingConfig& config)
    : config_(config) {
    if (config_.seed == 0) {
        std::random_device rd;
        rng_.seed(rd());
    } else {
        rng_.seed(config_.seed);
    }
}

void SamplingContext::SetConfig(const SamplingConfig& config) {
    config_ = config;
}

void SamplingContext::Reset() {
    if (config_.seed == 0) {
        std::random_device rd;
        rng_.seed(rd());
    } else {
        rng_.seed(config_.seed);
    }
}

int SamplingContext::Sample(const float* logits, size_t vocab_size) {
    // Copy logits to mutable buffer
    std::vector<float> working_logits(logits, logits + vocab_size);
    
    // Handle temperature = 0 as greedy
    if (config_.temperature <= 0.0f) {
        return GreedySample(working_logits);
    }
    
    // Apply temperature
    ApplyTemperature(working_logits);
    
    // Apply top-k if enabled
    if (config_.top_k > 0 && config_.top_k < static_cast<int>(vocab_size)) {
        ApplyTopK(working_logits, config_.top_k);
    }
    
    // Apply top-p if enabled
    if (config_.top_p < 1.0f && config_.top_p > 0.0f) {
        ApplyTopP(working_logits, config_.top_p);
    }
    
    // Convert to probabilities
    Softmax(working_logits);
    
    // Sample
    return SampleFromDistribution(working_logits);
}

int SamplingContext::SampleWithPenalty(const float* logits, size_t vocab_size,
                                        const std::vector<int>& token_history) {
    // Copy logits to mutable buffer
    std::vector<float> working_logits(logits, logits + vocab_size);
    
    // Apply repetition penalty
    ApplyRepetitionPenalty(working_logits, token_history);
    
    // Apply temperature
    ApplyTemperature(working_logits);
    
    // Apply top-k if enabled
    if (config_.top_k > 0 && config_.top_k < static_cast<int>(vocab_size)) {
        ApplyTopK(working_logits, config_.top_k);
    }
    
    // Apply top-p if enabled
    if (config_.top_p < 1.0f && config_.top_p > 0.0f) {
        ApplyTopP(working_logits, config_.top_p);
    }
    
    // Convert to probabilities
    Softmax(working_logits);
    
    // Sample
    return SampleFromDistribution(working_logits);
}

std::vector<TokenProb> SamplingContext::GetProbabilities(const float* logits, 
                                                            size_t vocab_size) {
    std::vector<float> probs(logits, logits + vocab_size);
    Softmax(probs);
    
    std::vector<TokenProb> result;
    result.reserve(vocab_size);
    
    for (size_t i = 0; i < vocab_size; ++i) {
        result.push_back({static_cast<int>(i), logits[i], probs[i]});
    }
    
    // Sort by probability descending
    std::sort(result.begin(), result.end());
    
    return result;
}

void SamplingContext::ApplyTemperature(std::vector<float>& logits) const {
    if (config_.temperature <= 0.0f) {
        // Temperature of 0 = greedy (handled separately)
        return;
    }
    
    if (config_.temperature != 1.0f) {
        float inv_temp = 1.0f / config_.temperature;
        for (auto& logit : logits) {
            logit *= inv_temp;
        }
    }
}

void SamplingContext::Softmax(std::vector<float>& logits) const {
    // Find max for numerical stability
    float max_logit = *std::max_element(logits.begin(), logits.end());
    
    // Compute exp(x - max)
    float sum = 0.0f;
    for (auto& logit : logits) {
        logit = std::exp(logit - max_logit);
        sum += logit;
    }
    
    // Normalize
    if (sum > 0.0f) {
        for (auto& logit : logits) {
            logit /= sum;
        }
    }
}

void SamplingContext::ApplyTopK(std::vector<float>& logits, int k) const {
    if (k <= 0 || k >= static_cast<int>(logits.size())) return;
    
    // Find k-th largest logit
    std::vector<float> sorted_logits = logits;
    std::nth_element(sorted_logits.begin(), 
                     sorted_logits.begin() + k, 
                     sorted_logits.end(),
                     std::greater<float>());
    float kth_logit = sorted_logits[k];
    
    // Zero out logits below k-th
    for (auto& logit : logits) {
        if (logit < kth_logit) {
            logit = -std::numeric_limits<float>::infinity();
        }
    }
}

void SamplingContext::ApplyTopP(std::vector<float>& logits, float p) const {
    if (p <= 0.0f || p >= 1.0f) return;
    
    // First apply softmax to get probabilities
    std::vector<float> probs = logits;
    Softmax(probs);
    
    // Sort probabilities descending
    std::vector<std::pair<float, size_t>> indexed_probs;
    indexed_probs.reserve(probs.size());
    for (size_t i = 0; i < probs.size(); ++i) {
        indexed_probs.push_back({probs[i], i});
    }
    std::sort(indexed_probs.begin(), indexed_probs.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    
    // Find cutoff where cumulative probability exceeds p
    float cumsum = 0.0f;
    size_t cutoff_idx = 0;
    for (size_t i = 0; i < indexed_probs.size(); ++i) {
        cumsum += indexed_probs[i].first;
        if (cumsum >= p) {
            cutoff_idx = i;
            break;
        }
    }
    
    // Get the cutoff logit value
    float cutoff_logit = logits[indexed_probs[cutoff_idx].second];
    
    // Zero out logits below cutoff
    for (auto& logit : logits) {
        if (logit < cutoff_logit) {
            logit = -std::numeric_limits<float>::infinity();
        }
    }
}

void SamplingContext::ApplyRepetitionPenalty(std::vector<float>& logits,
                                               const std::vector<int>& token_history) const {
    if (config_.repetition_penalty <= 1.0f) return;
    
    // Count token frequencies in history
    std::vector<int> token_counts(logits.size(), 0);
    for (int token : token_history) {
        if (token >= 0 && token < static_cast<int>(logits.size())) {
            token_counts[token]++;
        }
    }
    
    // Apply penalty to repeated tokens
    for (size_t i = 0; i < logits.size(); ++i) {
        if (token_counts[i] > 0) {
            // Divide logits of repeated tokens by penalty
            // This makes them less likely to be selected
            if (logits[i] > 0) {
                logits[i] /= config_.repetition_penalty;
            } else {
                logits[i] *= config_.repetition_penalty;
            }
        }
    }
    
    // Apply penalty to specific tokens
    for (int token : config_.penalty_tokens) {
        if (token >= 0 && token < static_cast<int>(logits.size())) {
            if (logits[token] > 0) {
                logits[token] /= config_.repetition_penalty;
            } else {
                logits[token] *= config_.repetition_penalty;
            }
        }
    }
}

int SamplingContext::SampleFromDistribution(const std::vector<float>& probs) {
    // Generate random number in [0, 1)
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(rng_);
    
    // Cumulative sampling
    float cumsum = 0.0f;
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[i];
        if (r < cumsum) {
            return static_cast<int>(i);
        }
    }
    
    // Fallback to last token (shouldn't happen with valid probs)
    return static_cast<int>(probs.size() - 1);
}

int SamplingContext::GreedySample(const std::vector<float>& logits) const {
    // Find argmax
    int max_idx = 0;
    float max_val = logits[0];
    for (size_t i = 1; i < logits.size(); ++i) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = static_cast<int>(i);
        }
    }
    return max_idx;
}

// ============================================================================
// Convenience Functions
// ============================================================================

int GreedySample(const float* logits, size_t vocab_size) {
    int max_idx = 0;
    float max_val = logits[0];
    for (size_t i = 1; i < vocab_size; ++i) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = static_cast<int>(i);
        }
    }
    return max_idx;
}

int TemperatureSample(const float* logits, size_t vocab_size,
                      float temperature, uint64_t seed) {
    SamplingConfig config;
    config.temperature = temperature;
    config.seed = seed;
    
    SamplingContext ctx(config);
    return ctx.Sample(logits, vocab_size);
}

int TopKSample(const float* logits, size_t vocab_size,
               int k, float temperature, uint64_t seed) {
    SamplingConfig config;
    config.top_k = k;
    config.temperature = temperature;
    config.seed = seed;
    
    SamplingContext ctx(config);
    return ctx.Sample(logits, vocab_size);
}

int TopPSample(const float* logits, size_t vocab_size,
               float p, float temperature, uint64_t seed) {
    SamplingConfig config;
    config.top_p = p;
    config.temperature = temperature;
    config.seed = seed;
    
    SamplingContext ctx(config);
    return ctx.Sample(logits, vocab_size);
}

int CombinedSample(const float* logits, size_t vocab_size,
                   const SamplingConfig& config) {
    SamplingContext ctx(config);
    return ctx.Sample(logits, vocab_size);
}

// ============================================================================
// Sampling Utilities
// ============================================================================

std::vector<float> LogitsToProbs(const float* logits, size_t vocab_size) {
    std::vector<float> probs(logits, logits + vocab_size);
    
    // Find max for numerical stability
    float max_logit = *std::max_element(probs.begin(), probs.end());
    
    // Compute exp(x - max)
    float sum = 0.0f;
    for (auto& p : probs) {
        p = std::exp(p - max_logit);
        sum += p;
    }
    
    // Normalize
    if (sum > 0.0f) {
        for (auto& p : probs) {
            p /= sum;
        }
    }
    
    return probs;
}

void ApplyTemperature(std::vector<float>& logits, float temperature) {
    if (temperature <= 0.0f || temperature == 1.0f) return;
    
    float inv_temp = 1.0f / temperature;
    for (auto& logit : logits) {
        logit *= inv_temp;
    }
}

std::vector<TokenProb> GetTopTokens(const float* logits, size_t vocab_size, size_t n) {
    std::vector<TokenProb> tokens;
    tokens.reserve(vocab_size);
    
    for (size_t i = 0; i < vocab_size; ++i) {
        tokens.push_back({static_cast<int>(i), logits[i], 0.0f});
    }
    
    // Sort by logit descending
    std::sort(tokens.begin(), tokens.end(), 
              [](const TokenProb& a, const TokenProb& b) {
                  return a.logit > b.logit;
              });
    
    // Keep top n
    if (tokens.size() > n) {
        tokens.resize(n);
    }
    
    // Compute probabilities for top tokens
    float max_logit = tokens.empty() ? 0.0f : tokens[0].logit;
    float sum = 0.0f;
    for (auto& t : tokens) {
        t.probability = std::exp(t.logit - max_logit);
        sum += t.probability;
    }
    for (auto& t : tokens) {
        t.probability /= sum;
    }
    
    return tokens;
}

bool ValidateLogits(const float* logits, size_t vocab_size) {
    for (size_t i = 0; i < vocab_size; ++i) {
        if (std::isnan(logits[i]) || std::isinf(logits[i])) {
            return false;
        }
    }
    return true;
}

void SanitizeLogits(float* logits, size_t vocab_size) {
    for (size_t i = 0; i < vocab_size; ++i) {
        if (std::isnan(logits[i]) || std::isinf(logits[i])) {
            logits[i] = -1000.0f;  // Safe negative value
        }
    }
}

} // namespace SEG
