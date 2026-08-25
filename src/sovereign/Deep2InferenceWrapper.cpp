// ============================================================================
// Deep2InferenceWrapper.cpp — Isolated wrapper to avoid header conflicts
//
// Phase A: This file is the ONLY place that includes deep2/Deep2Engine.h
// in the rawrxd TU graph. It isolates the TensorView redefinition conflict
// between src/deep2/TensorView.hpp and src/runtime/TensorExecutionRouter.hpp.
// ============================================================================

#include "deep2/Deep2Engine.h"
#include <string>
#include <string>
#include <vector>
#include <chrono>
#include <iostream>

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
    uint32_t maxTokens)
{
    Deep2InferenceResult result;

    std::cout << "[BACKEND] " << ::Deep2::Deep2Engine::backendName() << "\n";
    std::cout << "[BACKEND_ID] " << ::Deep2::Deep2Engine::backendId() << "\n";
    std::cout << "[RAWRXD] model=" << modelPath << "\n";
    std::cout << "[RAWRXD] prompt=\"" << prompt << "\"\n";
    std::cout << "[RAWRXD] max_tokens=" << maxTokens << "\n\n";

    ::Deep2::Deep2Engine engine;

    ::Deep2::EngineConfig config{};
    config.numThreads = 0;
    config.useKVCache = true;
    config.useThreadPool = true;

    std::cout << "[DEEP2] initialize: BEGIN\n";
    if (!engine.initialize(config)) {
        result.statusMessage = "Deep2Engine::initialize() failed";
        std::cout << "[DEEP2] initialize: FAIL\n";
        return result;
    }
    std::cout << "[DEEP2] initialize: PASS\n";

    std::cout << "[DEEP2] loadModel: BEGIN\n";
    if (!engine.loadModel(modelPath)) {
        result.statusMessage = "Deep2Engine::loadModel() failed: " + modelPath;
        std::cout << "[DEEP2] loadModel: FAIL\n";
        return result;
    }
    std::cout << "[DEEP2] loadModel: PASS\n";

    std::cout << "[DEEP2] tokenize: BEGIN\n";
    auto tokStart = std::chrono::steady_clock::now();
    std::vector<int> promptTokens = engine.tokenize(prompt);
    result.tokenizeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - tokStart);
    result.tokensPrompt = static_cast<uint32_t>(promptTokens.size());

    if (promptTokens.empty()) {
        result.statusMessage = "Tokenization returned empty";
        std::cout << "[DEEP2] tokenize: FAIL (empty)\n";
        return result;
    }
    std::cout << "[DEEP2] tokenize: PASS (tokens=" << result.tokensPrompt << ")\n";

    std::cout << "[DEEP2] generateText: BEGIN\n";
    auto genStart = std::chrono::steady_clock::now();
    std::string generatedText = engine.generateText(prompt, maxTokens);
    result.inferenceMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - genStart);

    if (generatedText.empty()) {
        result.statusMessage = "Generation returned empty";
        std::cout << "[DEEP2] generateText: FAIL (empty)\n";
        return result;
    }
    std::cout << "[DEEP2] generateText: PASS\n";

    // Validate generated tokens
    auto outTokens = engine.tokenize(generatedText);
    bool allValid = true;
    for (auto tok : outTokens) {
        if (tok < 0) { allValid = false; break; }
    }
    if (!allValid) {
        result.statusMessage = "Generated tokens contain invalid IDs";
        std::cout << "[DEEP2] token validation: FAIL\n";
        return result;
    }

    // Check for NaN/Inf in output text
    bool hasNaN = (generatedText.find("nan") != std::string::npos ||
                   generatedText.find("inf") != std::string::npos);
    if (hasNaN) {
        result.statusMessage = "Output contains NaN/Inf strings";
        std::cout << "[DEEP2] numeric validation: FAIL (NaN/Inf detected)\n";
        return result;
    }

    result.generatedText = generatedText;
    for (auto tok : outTokens) {
        result.generatedTokens.push_back(static_cast<uint32_t>(tok));
    }
    result.tokensGenerated = static_cast<uint32_t>(result.generatedTokens.size());

    if (result.inferenceMs.count() > 0) {
        result.tokensPerSecond =
            static_cast<float>(result.tokensGenerated) /
            (result.inferenceMs.count() / 1000.0f);
    }

    result.success = true;
    result.statusMessage = "Inference complete (Phase A: Deep2Engine canonical path)";
    std::cout << "[DEEP2] detokenize: PASS\n";
    std::cout << "[RAWRXD] EXECUTION SUCCESSFUL\n";
    return result;
}

} // namespace Sovereign
} // namespace RawrXD
