#pragma once

#include "Deep2Engine.h"
#include <string>
#include <functional>
#include <cstddef>

namespace Deep2 {

struct InferenceResult {
    std::string text;
    size_t tokensGenerated;
    double tokensPerSecond;
    double latencyMs;
    bool success;
};

class Deep2InferenceGateway {
public:
    Deep2InferenceGateway();
    ~Deep2InferenceGateway();

    bool Initialize(
        const std::string& modelPath
    );

    InferenceResult Generate(
        const std::string& prompt,
        size_t maxTokens,
        std::function<void(const std::string&)> callback = nullptr
    );

    bool IsInitialized() const { return initialized_; }
    void Shutdown();

private:
    Deep2Engine engine_;
    bool initialized_ = false;
};

} // namespace Deep2
