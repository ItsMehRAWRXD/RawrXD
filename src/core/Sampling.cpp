#include "Sampling.hpp"
#include <iostream>
#include <limits>
#include <numeric>
#include <algorithm>

namespace Deep2Rom::Inference {

    void Sampler::applyTemperature(float* logits, uint32_t vocabSize) {
        if (m_params.temperature <= 0.0f) return; // Greedy, no scaling needed
        float invTemp = 1.0f / m_params.temperature;
        for (uint32_t i = 0; i < vocabSize; ++i) {
            logits[i] *= invTemp;
        }
    }

    void Sampler::applyTopK(float* logits, uint32_t vocabSize) {
        if (m_params.topK <= 0 || static_cast<uint32_t>(m_params.topK) >= vocabSize) return;

        // Find the topK-th largest logit
        std::vector<std::pair<float, uint32_t>> scored;
        scored.reserve(vocabSize);
        for (uint32_t i = 0; i < vocabSize; ++i) {
            scored.emplace_back(logits[i], i);
        }
        std::partial_sort(scored.begin(), scored.begin() + m_params.topK, scored.end(),
                          [](const auto& a, const auto& b) { return a.first > b.first; });

        float threshold = scored[m_params.topK - 1].first;
        for (uint32_t i = 0; i < vocabSize; ++i) {
            if (logits[i] < threshold) logits[i] = -std::numeric_limits<float>::infinity();
        }
    }

    void Sampler::applyTopP(float* logits, uint32_t vocabSize) {
        if (m_params.topP >= 1.0f) return;

        // Sort logits descending
        std::vector<std::pair<float, uint32_t>> scored;
        scored.reserve(vocabSize);
        for (uint32_t i = 0; i < vocabSize; ++i) {
            scored.emplace_back(logits[i], i);
        }
        std::sort(scored.begin(), scored.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });

        // Compute softmax probabilities
        float maxLogit = scored[0].first;
        float sumExp = 0.0f;
        std::vector<float> probs(vocabSize);
        for (uint32_t i = 0; i < vocabSize; ++i) {
            probs[i] = std::exp(scored[i].first - maxLogit);
            sumExp += probs[i];
        }
        for (uint32_t i = 0; i < vocabSize; ++i) {
            probs[i] /= sumExp;
        }

        // Find cutoff where cumulative probability >= topP
        float cumulative = 0.0f;
        uint32_t cutoff = vocabSize;
        for (uint32_t i = 0; i < vocabSize; ++i) {
            cumulative += probs[i];
            if (cumulative >= m_params.topP) {
                cutoff = i + 1;
                break;
            }
        }

        // Mask out tokens beyond cutoff
        float threshold = scored[cutoff - 1].first;
        for (uint32_t i = 0; i < vocabSize; ++i) {
            if (logits[i] < threshold) logits[i] = -std::numeric_limits<float>::infinity();
        }
    }

    uint32_t Sampler::sampleFromProbabilities(const float* logits, uint32_t vocabSize) {
        // Convert logits to probabilities (softmax)
        float maxLogit = -std::numeric_limits<float>::infinity();
        for (uint32_t i = 0; i < vocabSize; ++i) {
            if (logits[i] > maxLogit) maxLogit = logits[i];
        }

        // Handle case where all logits are -inf (shouldn't happen with top-k/top-p)
        if (maxLogit == -std::numeric_limits<float>::infinity()) {
            // Uniform distribution
            std::uniform_int_distribution<uint32_t> dist(0, vocabSize - 1);
            return dist(m_rng);
        }

        float sumExp = 0.0f;
        for (uint32_t i = 0; i < vocabSize; ++i) {
            if (logits[i] != -std::numeric_limits<float>::infinity()) {
                sumExp += std::exp(logits[i] - maxLogit);
            }
        }

        if (sumExp <= 0.0f) {
            std::uniform_int_distribution<uint32_t> dist(0, vocabSize - 1);
            return dist(m_rng);
        }

        // Sample using cumulative distribution
        std::uniform_real_distribution<float> dist(0.0f, 1.0f);
        float r = dist(m_rng) * sumExp;
        float cumulative = 0.0f;

        for (uint32_t i = 0; i < vocabSize; ++i) {
            if (logits[i] == -std::numeric_limits<float>::infinity()) continue;
            cumulative += std::exp(logits[i] - maxLogit);
            if (r <= cumulative) return i;
        }

        // Fallback: return last valid token
        for (uint32_t i = vocabSize; i-- > 0;) {
            if (logits[i] != -std::numeric_limits<float>::infinity()) return i;
        }
        return 0;
    }

    void Sampler::applyPenalties(float* logits, uint32_t vocabSize,
                                  const std::vector<uint32_t>& tokenHistory) {
        if (tokenHistory.empty()) return;

        // Count occurrences of each token in history
        std::vector<int> tokenCounts(vocabSize, 0);
        std::vector<bool> tokenSeen(vocabSize, false);
        for (uint32_t id : tokenHistory) {
            if (id < vocabSize) {
                tokenCounts[id]++;
                tokenSeen[id] = true;
            }
        }

        if (m_params.frequencyPenalty != 0.0f || m_params.presencePenalty != 0.0f) {
            for (uint32_t i = 0; i < vocabSize; ++i) {
                if (tokenCounts[i] > 0) {
                    // Frequency penalty: scale by number of occurrences
                    if (logits[i] > 0.0f) {
                        logits[i] -= m_params.frequencyPenalty * static_cast<float>(tokenCounts[i]);
                    } else {
                        logits[i] += m_params.frequencyPenalty * static_cast<float>(tokenCounts[i]);
                    }
                    // Presence penalty: apply once if token appeared
                    if (tokenSeen[i]) {
                        if (logits[i] > 0.0f) {
                            logits[i] -= m_params.presencePenalty;
                        } else {
                            logits[i] += m_params.presencePenalty;
                        }
                    }
                }
            }
        }
    }

    uint32_t Sampler::sample(const float* logits, uint32_t vocabSize) {
        // Make a mutable copy since we apply penalties/filtering
        std::vector<float> working(vocabSize);
        for (uint32_t i = 0; i < vocabSize; ++i) {
            working[i] = logits[i];
        }

        // Apply temperature
        applyTemperature(working.data(), vocabSize);

        // Apply top-k
        applyTopK(working.data(), vocabSize);

        // Apply top-p (nucleus)
        applyTopP(working.data(), vocabSize);

        // Sample from the filtered distribution
        return sampleFromProbabilities(working.data(), vocabSize);
    }

} // namespace Deep2Rom::Inference
