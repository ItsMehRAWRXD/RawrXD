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

    initialized_ = engine_.loadModel(modelPath);

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

    std::string output = engine_.generateText(prompt, maxTokens);
    if (callback && !output.empty()) {
        callback(output);
    }

    auto end = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration<double, std::milli>(end - start).count();

    result.text = output;
    result.tokensGenerated = output.empty() ? 0 : 1;
    result.latencyMs = ms;
    result.tokensPerSecond = (result.tokensGenerated > 0 && ms > 0) ? (result.tokensGenerated * 1000.0 / ms) : 0.0;
    result.success = !output.empty();

    return result;
}

void Deep2InferenceGateway::Shutdown() {
    if (initialized_) {
        initialized_ = false;
        printf("[Deep2Gateway] Shutdown complete\n");
    }
}

} // namespace Deep2
