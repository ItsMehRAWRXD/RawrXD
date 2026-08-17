#pragma once
#include "../core/AIProvider.h"
#include "Deep2Engine.h"
#include "Tokenizer.hpp"
#include "advanced_sampler.hpp"

namespace RawrXD {

class Deep2Provider : public AIProvider {
public:
    Deep2Provider();
    ~Deep2Provider() override;

    bool Initialize(const std::string& modelPath) override;
    bool IsReady() const override;
    AIResponse Execute(const AIRequest& request) override;
    void ExecuteStream(const AIRequest& request, StreamCallback onToken) override;
    void Shutdown() override;

    std::string GetModelName() const override { return modelPath_; }
    size_t GetVRAMUsage() const override;
    size_t GetContextSize() const override { return contextSize_; }

private:
    std::string BuildPrompt(const AIRequest& request);
    std::string PostProcess(const std::string& raw, AIRequestType type);

    Deep2::Deep2Engine engine_;
    Deep2::Tokenizer tokenizer_;
    Deep2::AdvancedSampler sampler_;
    std::string modelPath_;
    size_t contextSize_ = 4096;
    bool initialized_ = false;
};

} // namespace RawrXD
