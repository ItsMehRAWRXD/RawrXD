#include "advanced_sampler.hpp"
#include "../inference/sampling.hpp"

#include <algorithm>
#include <cmath>
#include <numeric>

namespace Deep2 {

//==============================================================================
// AdvancedSampler Implementation
//==============================================================================
class AdvancedSampler::Impl {
public:
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    float repetitionPenalty = 1.1f;
    
    float lastProbability = 0.0f;
    float lastEntropy = 0.0f;
    
    std::mt19937 rng{std::random_device{}()};
    
    // Apply temperature scaling
    std::vector<float> ApplyTemperature(const std::vector<float>& logits) {
        std::vector<float> scaled = logits;
        if (temperature != 1.0f && temperature > 0.0f) {
            for (auto& logit : scaled) {
                logit /= temperature;
            }
        }
        return scaled;
    }
    
    // Apply top-k filtering
    std::vector<float> ApplyTopK(std::vector<float> logits, int k) {
        if (k <= 0 || k >= static_cast<int>(logits.size())) {
            return logits;
        }
        
        // Find k-th largest
        std::vector<float> sorted = logits;
        std::nth_element(sorted.begin(), sorted.begin() + k, sorted.end(), std::greater<float>());
        float kthLargest = sorted[k];
        
        // Zero out smaller logits
        for (auto& logit : logits) {
            if (logit < kthLargest) {
                logit = -std::numeric_limits<float>::infinity();
            }
        }
        
        return logits;
    }
    
    // Apply top-p (nucleus) filtering
    std::vector<float> ApplyTopP(std::vector<float> logits, float p) {
        if (p >= 1.0f || p <= 0.0f) {
            return logits;
        }
        
        // Softmax to get probabilities
        float maxLogit = *std::max_element(logits.begin(), logits.end());
        float sumExp = 0.0f;
        std::vector<float> probs(logits.size());
        
        for (size_t i = 0; i < logits.size(); ++i) {
            probs[i] = std::exp(logits[i] - maxLogit);
            sumExp += probs[i];
        }
        
        for (auto& prob : probs) {
            prob /= sumExp;
        }
        
        // Sort by probability
        std::vector<std::pair<float, size_t>> indexedProbs;
        for (size_t i = 0; i < probs.size(); ++i) {
            indexedProbs.push_back({probs[i], i});
        }
        std::sort(indexedProbs.begin(), indexedProbs.end(), 
                  std::greater<std::pair<float, size_t>>());
        
        // Find cutoff
        float cumSum = 0.0f;
        size_t cutoff = probs.size();
        for (size_t i = 0; i < indexedProbs.size(); ++i) {
            cumSum += indexedProbs[i].first;
            if (cumSum > p) {
                cutoff = i + 1;
                break;
            }
        }
        
        // Zero out tokens beyond cutoff
        std::vector<bool> keep(logits.size(), false);
        for (size_t i = 0; i < cutoff && i < indexedProbs.size(); ++i) {
            keep[indexedProbs[i].second] = true;
        }
        
        for (size_t i = 0; i < logits.size(); ++i) {
            if (!keep[i]) {
                logits[i] = -std::numeric_limits<float>::infinity();
            }
        }
        
        return logits;
    }
    
    // Sample from logits
    int SampleLogits(const std::vector<float>& logits) {
        // Apply softmax
        float maxLogit = *std::max_element(logits.begin(), logits.end());
        float sumExp = 0.0f;
        std::vector<float> probs(logits.size());
        
        for (size_t i = 0; i < logits.size(); ++i) {
            if (logits[i] == -std::numeric_limits<float>::infinity()) {
                probs[i] = 0.0f;
            } else {
                probs[i] = std::exp(logits[i] - maxLogit);
                sumExp += probs[i];
            }
        }
        
        if (sumExp == 0.0f) {
            return 0;  // Fallback
        }
        
        for (auto& prob : probs) {
            prob /= sumExp;
        }
        
        // Calculate entropy
        lastEntropy = 0.0f;
        for (const auto& prob : probs) {
            if (prob > 0.0f) {
                lastEntropy -= prob * std::log(prob);
            }
        }
        
        // Sample
        std::uniform_real_distribution<float> dist(0.0f, 1.0f);
        float r = dist(rng);
        float cumSum = 0.0f;
        
        for (size_t i = 0; i < probs.size(); ++i) {
            cumSum += probs[i];
            if (r <= cumSum) {
                lastProbability = probs[i];
                return static_cast<int>(i);
            }
        }
        
        return static_cast<int>(probs.size() - 1);
    }
};

AdvancedSampler::AdvancedSampler() : pImpl(std::make_unique<Impl>()) {}
AdvancedSampler::~AdvancedSampler() = default;

void AdvancedSampler::Configure(float temperature, float topP, int topK) {
    pImpl->temperature = temperature;
    pImpl->topP = topP;
    pImpl->topK = topK;
}

void AdvancedSampler::SetRepetitionPenalty(float penalty) {
    pImpl->repetitionPenalty = penalty;
}

int AdvancedSampler::Sample(const std::vector<float>& logits) {
    // Apply sampling techniques
    auto scaled = pImpl->ApplyTemperature(logits);
    auto topk = pImpl->ApplyTopK(scaled, pImpl->topK);
    auto topp = pImpl->ApplyTopP(topk, pImpl->topP);
    
    return pImpl->SampleLogits(topp);
}

int AdvancedSampler::SampleWithPenalty(const std::vector<float>& logits, const std::vector<int>& previousTokens) {
    // Apply repetition penalty
    std::vector<float> penalized = logits;
    for (int token : previousTokens) {
        if (token >= 0 && token < static_cast<int>(penalized.size())) {
            if (penalized[token] > 0) {
                penalized[token] /= pImpl->repetitionPenalty;
            } else {
                penalized[token] *= pImpl->repetitionPenalty;
            }
        }
    }
    
    return Sample(penalized);
}

float AdvancedSampler::GetLastProbability() const {
    return pImpl->lastProbability;
}

float AdvancedSampler::GetLastEntropy() const {
    return pImpl->lastEntropy;
}

} // namespace Deep2
