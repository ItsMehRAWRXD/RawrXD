#include "Deep2InferenceGateway.h"
#include "Tokenizer.hpp"
#include "../sampling/advanced_sampler.hpp"

#include <cstdio>
#include <chrono>

namespace Deep2 {

Deep2InferenceGateway::Deep2InferenceGateway() = default;
Deep2InferenceGateway::~Deep2InferenceGateway() {
    if (initialized_) {
        Shutdown();
    }
}

bool Deep2InferenceGateway::Initialize(
    const std::string& modelPath
)
{
    if (initialized_) {
        return true;
    }

    auto result = engine_.LoadModel(modelPath);
    initialized_ = result;

    if (initialized_) {
        printf("[Deep2Gateway] Model loaded: %s\n", modelPath.c_str());
    } else {
        printf("[Deep2Gateway] Model load failed: %s\n", modelPath.c_str());
    }

    return initialized_;
}

InferenceResult Deep2InferenceGateway::Generate(
    const std::string& prompt,
    size_t maxTokens,
    std::function<void(const std::string&)> callback
)
{
    InferenceResult result{};

    if (!initialized_) {
        result.success = false;
        result.text = "Error: Gateway not initialized";
        return result;
    }

    auto start = std::chrono::high_resolution_clock::now();

    // Tokenize prompt using real GGUF tokenizer
    auto tokens = Tokenizer::Encode(prompt);
    if (tokens.empty()) {
        result.success = false;
        result.text = "Error: Tokenization failed";
        return result;
    }

    std::string output;
    size_t tokenCount = 0;

    // Execute generation through Deep2Engine
    engine_.Generate(
        tokens,
        maxTokens,
        [&](const std::string& token) {
            output += token;
            tokenCount++;
            if (callback) {
                callback(token);
            }
        }
    );

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    result.text = output;
    result.tokensGenerated = tokenCount;
    result.latencyMs = ms;
    result.tokensPerSecond = (tokenCount > 0 && ms > 0) ? (tokenCount * 1000.0 / ms) : 0.0;
    result.success = tokenCount > 0;

    return result;
}

void Deep2InferenceGateway::Shutdown() {
    if (initialized_) {
        engine_.UnloadModel();
        initialized_ = false;
        printf("[Deep2Gateway] Shutdown complete\n");
    }
}

} // namespace Deep2
