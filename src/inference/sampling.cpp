// ============================================================================
// C5: Sampling Implementation
// Temperature, Top-K, Top-P sampling for token generation
// ============================================================================

#include "sampling.hpp"
#include <chrono>
#include <numeric>
#include <iomanip>

namespace rawrxd {

// ============================================================================
// SamplingEngine Implementation
// ============================================================================

SamplingEngine::SamplingEngine() 
    : rng_(static_cast<uint32_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()
      )) {
}

SamplingEngine::~SamplingEngine() = default;

bool SamplingEngine::Initialize(uint32_t vocab_size) {
    if (vocab_size == 0) {
        return false;
    }
    vocab_size_ = vocab_size;
    initialized_ = true;
    return true;
}

SamplingResult SamplingEngine::Sample(
    const std::vector<float>& logits,
    const SamplingConfig& config
) {
    SamplingResult result;
    
    if (!initialized_ || logits.empty()) {
        return result;
    }
    
    if (logits.size() != vocab_size_) {
        // Logits size mismatch
        return result;
    }
    
    // Make a mutable copy for processing
    std::vector<float> processed_logits = logits;
    
    // Track stats
    auto [min_it, max_it] = std::minmax_element(processed_logits.begin(), processed_logits.end());
    last_stats_.min_logit = *min_it;
    last_stats_.max_logit = *max_it;
    last_stats_.vocab_size = vocab_size_;
    
    // Apply temperature scaling
    ApplyTemperature(processed_logits, config.temperature);
    
    // Apply Top-K filtering
    if (config.top_k > 0) {
        ApplyTopK(processed_logits, config.top_k);
    }
    
    // Apply Top-P (nucleus) filtering
    if (config.top_p < 1.0f) {
        ApplyTopP(processed_logits, config.top_p);
    }
    
    // Sample from the processed logits
    result.token_id = SoftmaxSample(processed_logits);
    result.success = true;
    
    // Calculate probability
    auto probs = ComputeSoftmax(processed_logits);
    if (result.token_id < probs.size()) {
        result.probability = probs[result.token_id];
    }
    
    last_stats_.entropy = ComputeEntropy(probs);
    
    return result;
}

SamplingResult SamplingEngine::SampleWithPenalty(
    const std::vector<float>& logits,
    const SamplingConfig& config,
    const std::vector<uint32_t>& previous_tokens
) {
    if (!initialized_ || logits.empty()) {
        return SamplingResult{};
    }
    
    // Make a mutable copy
    std::vector<float> processed_logits = logits;
    
    // Apply repetition penalty
    if (config.repetition_penalty != 1.0f && !previous_tokens.empty()) {
        ApplyRepetitionPenalty(processed_logits, previous_tokens, config.repetition_penalty);
    }
    
    // Continue with normal sampling
    return Sample(processed_logits, config);
}

SamplingResult SamplingEngine::GreedySample(const std::vector<float>& logits) {
    SamplingResult result;
    
    if (logits.empty()) {
        return result;
    }
    
    // Find argmax
    result.token_id = static_cast<uint32_t>(
        std::max_element(logits.begin(), logits.end()) - logits.begin()
    );
    result.success = true;
    
    // Calculate probability
    auto probs = ComputeSoftmax(logits);
    if (result.token_id < probs.size()) {
        result.probability = probs[result.token_id];
    }
    
    return result;
}

// ============================================================================
// Internal Methods
// ============================================================================

void SamplingEngine::ApplyTemperature(std::vector<float>& logits, float temperature) {
    if (temperature == 1.0f || temperature <= 0.0f) {
        return;
    }
    
    float inv_temp = 1.0f / temperature;
    for (auto& logit : logits) {
        logit *= inv_temp;
    }
}

void SamplingEngine::ApplyTopK(std::vector<float>& logits, int k) {
    if (k <= 0 || k >= static_cast<int>(logits.size())) {
        return;
    }
    
    // Find the k-th largest value
    std::vector<float> sorted_logits = logits;
    std::nth_element(
        sorted_logits.begin(), 
        sorted_logits.begin() + k, 
        sorted_logits.end(),
        std::greater<float>()
    );
    float kth_value = sorted_logits[k];
    
    // Set all logits below k-th to -infinity
    for (auto& logit : logits) {
        if (logit < kth_value) {
            logit = -std::numeric_limits<float>::infinity();
        }
    }
}

void SamplingEngine::ApplyTopP(std::vector<float>& logits, float p) {
    if (p >= 1.0f || p <= 0.0f) {
        return;
    }
    
    // Compute softmax probabilities
    auto probs = ComputeSoftmax(logits);
    
    // Sort probabilities in descending order
    std::vector<size_t> indices(logits.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::sort(indices.begin(), indices.end(), 
        [&probs](size_t a, size_t b) { return probs[a] > probs[b]; }
    );
    
    // Find cutoff index where cumulative probability exceeds p
    float cumsum = 0.0f;
    size_t cutoff_idx = logits.size();
    for (size_t i = 0; i < indices.size(); ++i) {
        cumsum += probs[indices[i]];
        if (cumsum > p) {
            cutoff_idx = i + 1;
            break;
        }
    }
    
    // Create set of allowed indices
    std::vector<bool> allowed(logits.size(), false);
    for (size_t i = 0; i < cutoff_idx && i < indices.size(); ++i) {
        allowed[indices[i]] = true;
    }
    
    // Mask out disallowed tokens
    for (size_t i = 0; i < logits.size(); ++i) {
        if (!allowed[i]) {
            logits[i] = -std::numeric_limits<float>::infinity();
        }
    }
}

void SamplingEngine::ApplyRepetitionPenalty(
    std::vector<float>& logits,
    const std::vector<uint32_t>& previous_tokens,
    float penalty
) {
    if (penalty == 1.0f || previous_tokens.empty()) {
        return;
    }
    
    // Count token frequencies
    std::vector<int> token_counts(logits.size(), 0);
    for (uint32_t token : previous_tokens) {
        if (token < logits.size()) {
            token_counts[token]++;
        }
    }
    
    // Apply penalty
    for (size_t i = 0; i < logits.size(); ++i) {
        if (token_counts[i] > 0) {
            if (logits[i] > 0) {
                logits[i] /= penalty;
            } else {
                logits[i] *= penalty;
            }
        }
    }
}

uint32_t SamplingEngine::SoftmaxSample(const std::vector<float>& logits) {
    auto probs = ComputeSoftmax(logits);
    
    // Sample from categorical distribution
    std::uniform_real_distribution<float> dist(0.0f, 1.0f);
    float r = dist(rng_);
    
    float cumsum = 0.0f;
    for (size_t i = 0; i < probs.size(); ++i) {
        cumsum += probs[i];
        if (r <= cumsum) {
            return static_cast<uint32_t>(i);
        }
    }
    
    // Fallback to last token (shouldn't happen with valid probabilities)
    return static_cast<uint32_t>(probs.size() - 1);
}

std::vector<float> SamplingEngine::ComputeSoftmax(const std::vector<float>& logits) {
    std::vector<float> probs(logits.size());
    
    // Find max for numerical stability
    float max_logit = *std::max_element(logits.begin(), logits.end());
    
    // Compute exp(logit - max_logit)
    float sum = 0.0f;
    for (size_t i = 0; i < logits.size(); ++i) {
        if (std::isinf(logits[i]) && logits[i] < 0) {
            probs[i] = 0.0f;
        } else {
            probs[i] = std::exp(logits[i] - max_logit);
            sum += probs[i];
        }
    }
    
    // Normalize
    if (sum > 0.0f) {
        for (auto& p : probs) {
            p /= sum;
        }
    }
    
    return probs;
}

float SamplingEngine::ComputeEntropy(const std::vector<float>& probabilities) {
    float entropy = 0.0f;
    for (float p : probabilities) {
        if (p > 0.0f) {
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

// ============================================================================
// Convenience Functions
// ============================================================================

SamplingResult SampleToken(
    const std::vector<float>& logits,
    float temperature,
    int top_k
) {
    SamplingEngine engine;
    if (!engine.Initialize(static_cast<uint32_t>(logits.size()))) {
        return SamplingResult{};
    }
    
    SamplingConfig config;
    config.temperature = temperature;
    config.top_k = top_k;
    
    return engine.Sample(logits, config);
}

uint32_t Argmax(const std::vector<float>& logits) {
    if (logits.empty()) {
        return 0;
    }
    return static_cast<uint32_t>(
        std::max_element(logits.begin(), logits.end()) - logits.begin()
    );
}

} // namespace rawrxd
