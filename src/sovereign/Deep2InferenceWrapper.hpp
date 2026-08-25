// ============================================================================
// Deep2InferenceWrapper.hpp — Forward declaration for isolated Deep2 wrapper
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace RawrXD {
namespace Sovereign {

struct Deep2InferenceResult {
    bool success = false;
    std::string statusMessage;
    std::string generatedText;
    std::vector<uint32_t> generatedTokens;
    std::chrono::milliseconds tokenizeMs{0};
    std::chrono::milliseconds inferenceMs{0};
    uint32_t tokensPrompt = 0;
    uint32_t tokensGenerated = 0;
    float tokensPerSecond = 0.0f;
};

Deep2InferenceResult RunDeep2Inference(
    const std::string& modelPath,
    const std::string& prompt,
    uint32_t maxTokens);

} // namespace Sovereign
} // namespace RawrXD
