// src/engine/inference/SamplerCore.hpp
// Mathematical Token Selection — Temperature-scaled multinomial sampling
#pragma once
#include <cstdint>
#include <cmath>
#include <algorithm>
#include <random>
#include <vector>

class SamplerCore {
public:
    static uint32_t SampleLogits(const float* logits, size_t vocabSize, float temperature) {
        if (temperature <= 0.0f || vocabSize == 0) {
            // Argmax (greedy)
            return static_cast<uint32_t>(
                std::distance(logits, std::max_element(logits, logits + vocabSize)));
        }

        // Apply temperature: softmax with scaling
        float maxLogit = *std::max_element(logits, logits + vocabSize);
        float sumExp = 0.0f;

        // Compute exp((logit - maxLogit) / temperature) in-place
        // We use a temporary vector to avoid modifying the input
        std::vector<float> probs(vocabSize);
        for (size_t i = 0; i < vocabSize; ++i) {
            probs[i] = std::exp((logits[i] - maxLogit) / temperature);
            sumExp += probs[i];
        }

        if (sumExp <= 0.0f) {
            return static_cast<uint32_t>(vocabSize - 1);
        }

        // Sample from the multinomial distribution
        static std::mt19937_64 rng(std::random_device{}());
        std::uniform_real_distribution<float> dis(0.0f, sumExp);
        float target = dis(rng);

        float currentAccumulator = 0.0f;
        for (size_t i = 0; i < vocabSize; ++i) {
            currentAccumulator += probs[i];
            if (currentAccumulator >= target) {
                return static_cast<uint32_t>(i);
            }
        }
        return static_cast<uint32_t>(vocabSize - 1);
    }

    // Top-k filtering: only sample from the k highest probability tokens
    static uint32_t SampleLogitsTopK(float* logits, size_t vocabSize,
                                      float temperature, uint32_t topK) {
        if (topK == 0 || topK >= vocabSize) {
            return SampleLogits(logits, vocabSize, temperature);
        }

        // Find the top-k threshold
        std::vector<float> sorted(logits, logits + vocabSize);
        std::nth_element(sorted.begin(), sorted.begin() + topK, sorted.end(),
                         std::greater<float>());
        float threshold = sorted[topK - 1];

        // Zero out logits below threshold
        for (size_t i = 0; i < vocabSize; ++i) {
            if (logits[i] < threshold) {
                const_cast<float*>(logits)[i] = -std::numeric_limits<float>::infinity();
            }
        }

        return SampleLogits(logits, vocabSize, temperature);
    }
};
