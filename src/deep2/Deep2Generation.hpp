#pragma once

#include "Deep2GenerationState.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

namespace rawrxd::deep2 {

inline int32_t GreedyArgmaxStable(
    const float* logits,
    std::size_t vocabSize) noexcept
{
    if (!logits || vocabSize == 0)
        return -1;

    std::size_t best = 0;
    float bestValue = -std::numeric_limits<float>::infinity();

    for (std::size_t i = 0; i < vocabSize; ++i) {
        const float v = logits[i];

        if (!std::isfinite(v))
            continue;

        if (v > bestValue) {
            bestValue = v;
            best = i;
        }
    }

    if (!std::isfinite(bestValue))
        return -1;

    return static_cast<int32_t>(best);
}

template<class ForwardTokenFn, class ComputeLogitsFn>
std::vector<int32_t> StreamGreedy(
    const std::vector<int32_t>& promptTokens,
    std::size_t maxTokens,
    std::size_t vocabSize,
    ForwardTokenFn&& forwardToken,
    ComputeLogitsFn&& computeLogits)
{
    std::vector<int32_t> generated;
    generated.reserve(maxTokens);

    if (promptTokens.empty() || maxTokens == 0)
        return generated;

    DecodeState state;
    state.begin(
        promptTokens.size(),
        promptTokens.back());

    std::vector<float> logits(vocabSize, 0.0f);

    for (std::size_t step = 0; step < maxTokens; ++step) {
        const std::size_t position = state.currentPosition();
        const int32_t token = state.currentToken();

        if (token < 0)
            break;

        /*
         * IMPORTANT:
         * position is the actual decode position.
         * It is not recomputed from the original prompt length.
         */
        if (!forwardToken(token, position))
            break;

        std::fill(logits.begin(), logits.end(), 0.0f);

        if (!computeLogits(logits.data(), logits.size(), position))
            break;

        const int32_t next = GreedyArgmaxStable(
            logits.data(),
            logits.size());

        if (next < 0)
            break;

        generated.push_back(next);

        /*
         * The generated token becomes the input token for
         * the next decode step, and the position advances once.
         */
        state.advance(next);
    }

    return generated;
}

} // namespace rawrxd::deep2
