#pragma once

#include "core/HostKvRing.hpp"
#include "core/Sampling.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace deep2 {
// One autoregressive generation.
//
// The session owns the state that has to survive between tokens: the key
// and value cache and the position in the context.
//
// This is the point of the session. A forward pass on its own starts from
// an empty cache every time, so a loop that fed a token back into a fresh
// pass would recompute the entire prefix at every step. That looks like
// decoding and is not: the cost per token would grow with the length of
// the output, and the cache would never be exercised. The session keeps
// one ring for the whole generation and advances one position per token, so
// the work per token is the work for that token.
//
// The ring is allocated once, when the session begins, and is not
// reallocated until it ends.
class DecodeSession {
public:
    // Why a generation stopped.
    enum StopReason {
        kStoppedAtLength = 0,   // the token limit was reached
        kStoppedAtEndOfText = 1 // the model produced its end-of-sequence token
    };

    // What one generation produced.
    struct Result {
        std::vector<uint32_t> promptTokens;
        std::vector<uint32_t> generatedTokens;
        StopReason stopReason = kStoppedAtLength;

        // The time spent on the prompt and on the generated tokens, and the
        // rate each of them was produced at.
        double promptSeconds = 0.0;
        double decodeSeconds = 0.0;
        double promptTokensPerSecond = 0.0;
        double decodeTokensPerSecond = 0.0;

        // The number of positions the context ended at.
        uint32_t contextLength = 0;
    };

    // A step runs one forward pass over some tokens, starting at
    // `position` in the context, and leaves the logits for the last one in
    // `logits`.
    //
    // It is a callback so the session does not have to know about the
    // engine, and so the session can be driven by a reference
    // implementation in a test.
    using Step = std::function<bool(const std::vector<uint32_t>& tokens,
                                     uint32_t position,
                                     std::vector<float>& logits)>;

    // Prepare the session for a model.
    //
    // `window` is how many positions the cache holds. A generation longer
    // than that wraps around and the oldest positions are lost, which is
    // what a bounded context window means.
    bool begin(uint32_t layers, uint32_t window, uint32_t hiddenDim);

    // The state the session owns.
    HostKvRing& kv() { return m_kv; }
    const HostKvRing& kv() const { return m_kv; }

    // The position the next token will occupy.
    uint32_t position() const { return m_position; }
    uint32_t contextLength() const { return m_position; }

    // Run a generation.
    //
    // The prompt is run first, in one pass, and the logits of its last
    // token are the first thing sampled from. Every generated token is then
    // run as a pass of its own at the next position, and sampled from in
    // turn.
    //
    // `greedy` takes the largest logit every time, which makes a run
    // reproducible. Otherwise the sampler is used, and the run depends on
    // its seed.
    Result generate(const Step& step,
                    const std::vector<uint32_t>& prompt,
                    uint32_t maxTokens,
                    Deep2Rom::Inference::Sampler& sampler,
                    bool greedy = true,
                    uint32_t endOfSequenceToken = kNoToken);

    // A token id that cannot occur, so "no end token" can be told from
    // "the end token is id zero".
    static constexpr uint32_t kNoToken = 0xFFFFFFFFu;

private:
    HostKvRing m_kv;
    uint32_t m_position = 0;
    uint32_t m_layers = 0;
    uint32_t m_window = 0;
    uint32_t m_hiddenDim = 0;
};

} // namespace deep2
