#pragma once
// =============================================================================
// RawrXDEngineAdapter.h
// Implements the Deep2Engine interface used by generation modules,
// backed by the actual RawrEngine inference pipeline.
// =============================================================================

#include "../module1_types.h"
#include "../module2_cancel.h"
#include "../module5_context.h"
#include "../module6_generate.h"   // declares the abstract Deep2Engine interface
#include "../module7_glue.h"
#include "../../rawrxd_sampler.h"

// Forward declarations for RawrEngine components
namespace RawrXD {
    class CPUInferenceEngine;
}
class RawrXDTokenizer;

// The `Deep2Engine` interface is declared in module6_generate.h. It used to be
// re-declared here, and the copy in module7_glue.h was a concrete class that
// returned fabricated tokens; keeping exactly one abstract declaration is what
// makes "there is no fake engine here" a property of the code rather than a
// claim about it. RAWRXD_UNSIMULATE_001.

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
    RawrXD::RawrXDSampler sampler_;

    // --- Helper methods ---
    bool tokenize(const std::string& text, std::vector<int32_t>& tokens);
    std::string detokenize(int32_t tokenId);
    int getEosTokenId();

    // RAWRXD_UNSIMULATE_001 / RAWRXD_END_TO_END_STATE_001
    //
    // prefill() and decodeStep() are GONE, and that is the fix rather than a
    // loss. They were written against `CPUInferenceEngine::Eval()` and
    // `GetLastState()`, neither of which has ever existed on that class: its
    // actual surface is LoadModel / Tokenize / Detokenize / GenerateStreaming /
    // isModelLoaded / getStatus. The adapter therefore could not have been
    // compiled, and had it been, it would have driven a model through an API
    // with no implementation behind it.
    //
    // CPUInferenceEngine is a WHOLE-SEQUENCE streaming engine: it has no
    // per-token stepping. A per-token prefill/decode loop cannot be implemented
    // on top of it honestly, so generate() calls GenerateStreaming directly and
    // forwards each streamed piece to tokenCb. Declaring the stepping functions
    // as stubs that return an empty token would have reproduced the exact defect
    // removed from module7_glue.h: a class that looks like a working engine.
};
