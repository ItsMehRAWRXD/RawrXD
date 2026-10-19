#pragma once
#include <cstdint>
#include <vector>
#include <random>
#include <cmath>
#include <algorithm>

namespace Deep2Rom::Inference {

    // Sampling parameters
    struct SamplingParams {
        float temperature   = 0.7f;   // >0: higher = more random, 0 = greedy
        float topP          = 0.9f;   // Nucleus sampling (0-1], 1 = disabled
        int32_t topK        = 50;     // Top-k filtering (0 = disabled)
        float frequencyPenalty = 0.0f; // Penalty for repeated tokens
        float presencePenalty  = 0.0f; // Penalty for tokens that appeared at all
        uint64_t seed           = 42;  // RNG seed
        bool  useSeed           = true;
    };

    class Sampler {
    public:
        Sampler() = default;
        ~Sampler() = default;

        // Configure sampling parameters
        void setParams(const SamplingParams& params) { m_params = params; }
        const SamplingParams& params() const { return m_params; }

        // Set RNG seed
        void seed(uint64_t s) {
            m_params.seed = s;
            m_params.useSeed = true;
            m_rng.seed(s);
        }

        // Sample a token from logits
        // logits: array of size vocabSize (raw logits, not probabilities)
        // Returns the selected token ID
        uint32_t sample(const float* logits, uint32_t vocabSize);

        // Apply penalties to logits based on token history
        // tokenHistory: previously generated token IDs
        void applyPenalties(float* logits, uint32_t vocabSize,
                            const std::vector<uint32_t>& tokenHistory);

    private:
        SamplingParams m_params;
        std::mt19937_64 m_rng;

        // Apply temperature scaling
        void applyTemperature(float* logits, uint32_t vocabSize);

        // Apply top-k filtering
        void applyTopK(float* logits, uint32_t vocabSize);

        // Apply nucleus (top-p) filtering
        void applyTopP(float* logits, uint32_t vocabSize);

        // Sample from filtered logits (convert to probabilities, then sample)
        uint32_t sampleFromProbabilities(const float* logits, uint32_t vocabSize);
    };

} // namespace Deep2Rom::Inference
