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
#include "../../rawrxd_sampler.h"

// Forward declarations for RawrEngine components
namespace RawrXD {
    class CPUInferenceEngine;
}
class RawrXDTokenizer;

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
    void setTemperature(float t) { sampler_.temperature = t; }
    void setTopP(float p) { sampler_.top_p = p; }
    void setTopK(int k) { sampler_.top_k = k; }

private:
    uint32_t maxDecodeTokens_ = 512;

    // RawrEngine components
    std::shared_ptr<RawrXD::CPUInferenceEngine> inferenceEngine_;
    RawrXDSampler sampler_;

    // --- Helper methods ---
    bool tokenize(const std::string& text, std::vector<int32_t>& tokens);
    std::string detokenize(int32_t tokenId);
    int getEosTokenId();
    bool prefill(const std::vector<int32_t>& tokens);
    int decodeStep();
};
};