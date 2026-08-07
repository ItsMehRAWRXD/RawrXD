#pragma once
// =============================================================================
// RawrXDEngineAdapter.h
// Implements the Deep2Engine interface used by generation modules,
// backed by the actual RawrEngine inference pipeline.
// =============================================================================

#include "../module1_types.h"
#include "../module2_cancel.h"
#include "../module5_context.h"
#include "../module6_generate.h"
#include "../module7_glue.h"

// Forward declarations for RawrEngine components
class RawrXDTokenizer;
class VulkanInferenceEngine;
class RawrXDSampler;
class VulkanCompute;

// The interface that generation modules expect
class Deep2Engine {
public:
    virtual ~Deep2Engine() {}

    virtual bool isReady() const = 0;

    virtual bool generate(
        const char* prompt,
        const TokenCallback& tokenCb,
        const ErrorCallback& engineErrorCb,
        const ErrorCallback& nonEngineErrorCb
    ) = 0;
};

// Concrete implementation backed by RawrEngine
class RawrXDEngineAdapter : public Deep2Engine {
public:
    RawrXDEngineAdapter();
    ~RawrXDEngineAdapter();

    // --- Initialize from RawrEngine components ---
    void setInferenceEngine(std::shared_ptr<VulkanInferenceEngine> engine);
    void setTokenizer(std::shared_ptr<RawrXDTokenizer> tokenizer);
    void setSampler(std::shared_ptr<RawrXDSampler> sampler);
    void setKVCache(std::shared_ptr<VulkanCompute> kvCache);

    bool isReady() const override;

    // --- The generate() call that the generation control plane invokes ---
    bool generate(
        const char* prompt,
        const TokenCallback& tokenCb,
        const ErrorCallback& engineErrorCb,
        const ErrorCallback& nonEngineErrorCb
    ) override;

    // --- Configuration ---
    void setMaxDecodeTokens(uint32_t n) { maxDecodeTokens_ = n; }
    void setTemperature(float t);
    void setTopP(float p);
    void setTopK(int k);

private:
    std::atomic<bool> ready_;
    std::atomic<bool> modelLoaded_;
    uint32_t maxDecodeTokens_ = 512;

    // RawrEngine components
    std::shared_ptr<VulkanInferenceEngine> inferenceEngine_;
    std::shared_ptr<RawrXDTokenizer> tokenizer_;
    std::shared_ptr<RawrXDSampler> sampler_;
    std::shared_ptr<VulkanCompute> kvCache_;

    // --- Helper methods ---
    bool tokenize(const std::string& text, std::vector<int>& tokens);
    std::string detokenize(int tokenId);
    int getEosTokenId();
    bool prefill(const std::vector<int>& tokens);
    int decodeStep();
};
};