#pragma once

#include "RawrXD_GenerationState.hpp"

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <functional>

namespace RawrXD {

class RealGeneration {
public:
    struct Config {
        uint32_t maxTokens = 128;
        int32_t eosToken = -1;
        size_t vocabSize = 0;
    };

    using ForwardFn =
        std::function<bool(
            uint32_t,
            uint32_t,
            std::vector<float>&)>;

    using DecodeFn =
        std::function<std::string(uint32_t)>;

    using EmitFn =
        std::function<bool(
            uint32_t,
            const std::string&,
            float)>;

    bool Run(
        const std::vector<uint32_t>& prompt,
        const Config& config,
        const ForwardFn& forward,
        const DecodeFn& decode,
        const EmitFn& emit)
    {
        if (prompt.empty())
            return false;

        if (!forward || !decode || !emit)
            return false;

        if (config.maxTokens == 0)
            return false;

        if (config.vocabSize == 0)
            return false;

        GenerationState state;
        state.Begin(prompt);

        for (uint32_t step = 0;
             step < config.maxTokens;
             ++step) {

            const uint32_t input =
                state.LastToken();

            const uint32_t position =
                state.position;

            state.logits.clear();

            if (!forward(
                    input,
                    position,
                    state.logits)) {
                return false;
            }

            if (state.logits.size() < config.vocabSize)
                return false;

            const uint32_t token =
                GreedySampler::Select(
                    state.logits.data(),
                    config.vocabSize);

            const float score =
                state.logits[token];

            const std::string text =
                decode(token);

            state.Push(token);

            if (!emit(
                    token,
                    text,
                    score)) {
                state.finished = true;
                return true;
            }

            if (config.eosToken >= 0 &&
                token ==
                    static_cast<uint32_t>(config.eosToken)) {

                state.finished = true;
                break;
            }
        }

        return state.generated != 0;
    }

    const GenerationState& State() const {
        return state_;
    }

private:
    GenerationState state_;
};

} // namespace RawrXD
