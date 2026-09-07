#pragma once
#include "Deep2Engine.h"
#include <string>
namespace Deep2 {
inline std::string Deep2GenerateStreamAccumulate(
    Deep2Engine& e, const std::string& prompt, uint32_t maxTokens = 256) {
    GenerationOptions opts{};
    opts.maxTokens = maxTokens;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.seed = 42;
    e.clearCancel();
    std::string acc;
    e.generateStream(prompt, opts,
                     [&](int32_t, const std::string& piece) -> bool {
                         acc += piece;
                         return true;
                     });
    return acc;
}
} // namespace Deep2
