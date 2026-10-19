#include "core/DecodeSession.hpp"

#include <chrono>

namespace deep2 {

bool DecodeSession::begin(uint32_t layers, uint32_t window, uint32_t hiddenDim) {
    if (layers == 0 || window == 0 || hiddenDim == 0) return false;
    m_kv.reset(layers, window, hiddenDim);
    m_position = 0;
    m_layers = layers;
    m_window = window;
    m_hiddenDim = hiddenDim;
    return true;
}

DecodeSession::Result DecodeSession::generate(const Step& step,
                                               const std::vector<uint32_t>& prompt,
                                               uint32_t maxTokens,
                                               Deep2Rom::Inference::Sampler& sampler,
                                               bool greedy,
                                               uint32_t endOfSequenceToken) {
    Result result;
    result.promptTokens = prompt;

    if (!step) return result;
    if (prompt.empty()) return result;

    // The prompt is one pass. Its last token's logits are what the first
    // generated token is sampled from.
    std::vector<float> logits;
    const auto promptStart = std::chrono::steady_clock::now();
    if (!step(prompt, m_position, logits)) {
        result.promptSeconds = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - promptStart).count();
        return result;
    }
    result.promptSeconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - promptStart).count();
    if (result.promptSeconds > 0.0) {
        result.promptTokensPerSecond = static_cast<double>(prompt.size()) / result.promptSeconds;
    }
    m_position += static_cast<uint32_t>(prompt.size());

    const auto decodeStart = std::chrono::steady_clock::now();

    // Each generated token is one pass at the next position. The session
    // owns the position and the cache, so the pass sees the whole prefix
    // without recomputing it.
    for (uint32_t i = 0; i < maxTokens; ++i) {
        // The greedy path takes the largest logit, which is reproducible.
        // The sampler's own path draws from the distribution, which is not,
        // so it is only used when the caller asked for it.
        uint32_t next;
        if (greedy) {
            int best = 0;
            for (size_t j = 1; j < logits.size(); ++j) {
                if (logits[j] > logits[best]) best = static_cast<int>(j);
            }
            next = static_cast<uint32_t>(best);
        } else {
            next = sampler.sample(logits.data(), static_cast<uint32_t>(logits.size()));
        }
        result.generatedTokens.push_back(next);
        if (endOfSequenceToken != kNoToken && next == endOfSequenceToken) {
            result.stopReason = kStoppedAtEndOfText;
            break;
        }
        if (i + 1 == maxTokens) break;

        // Run the token that was just chosen, so the next sample is taken
        // from the logits it produces.
        const std::vector<uint32_t> one{ next };
        if (!step(one, m_position, logits)) break;
        ++m_position;
    }

    result.decodeSeconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - decodeStart).count();
    if (result.decodeSeconds > 0.0) {
        result.decodeTokensPerSecond =
            static_cast<double>(result.generatedTokens.size()) / result.decodeSeconds;
    }
    result.contextLength = m_position;
    return result;
}

} // namespace deep2
