#include "RawrXDEngineAdapter.h"
#include "../../cpu_inference_engine.h"

#include <memory>

RawrXDEngineAdapter::RawrXDEngineAdapter()
{
    // RAWRXD_UNSIMULATE_001: was RawrXD::CPUInferenceEngine::GetSharedInstance(),
    // which does not exist on that class. Its real surface is LoadModel,
    // Tokenize, Detokenize, GenerateStreaming, isModelLoaded and getStatus --
    // there is no shared instance, so the engine is owned here.
    //
    // A fresh engine has no model loaded, so isReady() is false until whoever
    // holds this adapter calls LoadModel. That is the correct initial state and
    // it is reported as not-ready rather than as ready.
    inferenceEngine_ = std::make_shared<RawrXD::CPUInferenceEngine>();
}

RawrXDEngineAdapter::~RawrXDEngineAdapter() = default;

bool RawrXDEngineAdapter::isReady() const {
    return inferenceEngine_ && inferenceEngine_->isModelLoaded();
}


bool RawrXDEngineAdapter::tokenize(const std::string& text, std::vector<int32_t>& tokens) {
    if (!inferenceEngine_) return false;
    tokens = inferenceEngine_->Tokenize(text);
    return !tokens.empty();
}


std::string RawrXDEngineAdapter::detokenize(int32_t tokenId) {
    if (!inferenceEngine_) return "";
    std::vector<int32_t> singleToken = { tokenId };
    return inferenceEngine_->Detokenize(singleToken);
}


int RawrXDEngineAdapter::getEosTokenId() {
    // 2 is broadly standard for Llama / Mistral / GGUF, but in production we ask the loader wrapper if exposed.
    return 2;
}



bool RawrXDEngineAdapter::generate(
    const char* prompt,
    const TokenCallback& tokenCb,
    const ErrorCallback& engineErrorCb,
    const ErrorCallback& nonEngineErrorCb
) {
    if (!prompt || prompt[0] == '\0') {
        if (nonEngineErrorCb) nonEngineErrorCb("Empty prompt");
        return false;
    }

    if (!isReady()) {
        if (nonEngineErrorCb) nonEngineErrorCb("Engine not ready");
        return false;
    }

    // --- Tokenize the prompt ---
    std::vector<int32_t> promptTokens;
    if (!tokenize(prompt, promptTokens)) {
        if (engineErrorCb) engineErrorCb("Tokenization failed");
        return false;
    }

    if (promptTokens.empty()) {
        if (nonEngineErrorCb) nonEngineErrorCb("Empty tokenized prompt");
        return false;
    }

    // --- Stream from the engine ---
    //
    // RAWRXD_UNSIMULATE_001: this used to run its own prefill/decodeStep loop
    // over CPUInferenceEngine::Eval() and GetLastState(), neither of which
    // exists on that class. There is no per-token stepping API underneath, so
    // that loop could not have been real at any point.
    //
    // CPUInferenceEngine::GenerateStreaming IS the API: prompt tokens, a token
    // budget, a per-piece callback and a completion callback. Each streamed
    // piece is forwarded to tokenCb with a monotonically increasing index,
    // which is the contract the module6 consumers rely on.
    //
    // The returned bool means "the stream produced output", and it is decided
    // by what GenerateStreaming actually did: piecesSeen is incremented from
    // the engine's own callback, so a stream that emitted nothing is reported
    // as failure rather than as an empty successful generation.
    uint32_t tokenIdx = 0;
    uint32_t piecesSeen = 0;
    inferenceEngine_->GenerateStreaming(
        promptTokens,
        static_cast<int>(maxDecodeTokens_),
        [tokenCb, &tokenIdx, &piecesSeen](const std::string& piece) {
            ++piecesSeen;
            if (tokenCb && !piece.empty()) {
                tokenCb(piece.c_str(), tokenIdx++);
            }
        },
        []() {});

    if (piecesSeen == 0) {
        if (engineErrorCb) {
            engineErrorCb("Generation produced no output: the engine streamed "
                          "no pieces");
        }
        return false;
    }
    return true;
}
