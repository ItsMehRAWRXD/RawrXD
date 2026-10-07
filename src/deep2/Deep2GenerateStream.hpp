#pragma once
#include "Deep2Engine.h"
#include "lavapath/ProductPathSeal.hpp"
#include "lavapath/UnlimitedTokenLaw.hpp"
#include <chrono>
#include <cstdint>
#include <string>

namespace Deep2 {

struct ProductStreamResult {
    std::string text;
    uint32_t tokensCommitted = 0;
    uint64_t wallNs = 0;
    uint64_t textBytes = 0;
};

/* Real product generateStream — engine seals; this is the CLI front door.
 * maxTokens=0 → unlimited (context/EOS); pass N for hard cap. */
inline ProductStreamResult Deep2ProductGenerateStream(
    Deep2Engine& e, const std::string& prompt, uint32_t maxTokens = 0,
    const char* /*modelName*/ = nullptr) {
    GenerationOptions opts{};
    opts.maxTokens = maxTokens; /* 0 = unlimited */
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.seed = 42;
    e.clearCancel();
    ProductStreamResult r{};
    const auto t0 = std::chrono::steady_clock::now();
    e.generateStream(prompt, opts,
                     [&](int32_t, const std::string& piece) -> bool {
                         r.text += piece;
                         ++r.tokensCommitted;
                         return true;
                     });
    const auto t1 = std::chrono::steady_clock::now();
    r.wallNs = (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                   t1 - t0)
                   .count();
    r.textBytes = (uint64_t)r.text.size();
    /* Seal emits inside Deep2Engine::generateStream — do not double-seal. */
    return r;
}

inline std::string Deep2GenerateStreamAccumulate(
    Deep2Engine& e, const std::string& prompt, uint32_t maxTokens = 0) {
    return Deep2ProductGenerateStream(e, prompt, maxTokens, nullptr).text;
}

} // namespace Deep2
