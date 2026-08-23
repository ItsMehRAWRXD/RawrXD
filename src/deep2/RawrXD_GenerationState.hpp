#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <limits>
#include <algorithm>

namespace RawrXD {

struct GenerationState {
    std::vector<uint32_t> tokens;
    std::vector<float> logits;

    uint32_t position = 0;
    uint32_t generated = 0;

    bool finished = false;

    void Reset() {
        tokens.clear();
        logits.clear();
        position = 0;
        generated = 0;
        finished = false;
    }

    void Begin(const std::vector<uint32_t>& prompt) {
        Reset();

        tokens = prompt;

        if (!tokens.empty())
            position = static_cast<uint32_t>(tokens.size() - 1);
    }

    void Push(uint32_t token) {
        tokens.push_back(token);
        position = static_cast<uint32_t>(tokens.size() - 1);
        ++generated;
    }

    uint32_t LastToken() const {
        return tokens.empty() ? 0u : tokens.back();
    }

    bool Empty() const {
        return tokens.empty();
    }
};

class GreedySampler {
public:
    static uint32_t Select(
        const float* logits,
        size_t vocabSize)
    {
        if (!logits || vocabSize == 0)
            return 0;

        size_t best = 0;
        float bestValue = logits[0];

        for (size_t i = 1; i < vocabSize; ++i) {
            const float value = logits[i];

            if (value > bestValue) {
                bestValue = value;
                best = i;
            }
        }

        return static_cast<uint32_t>(best);
    }
};

} // namespace RawrXD
