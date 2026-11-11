#include "RawrXDEngineAdapter.h"
#include "../../cpu_inference_engine.h"

#include <memory>

RawrXDEngineAdapter::RawrXDEngineAdapter()
{
    inferenceEngine_ = RawrXD::CPUInferenceEngine::GetSharedInstance();
}

RawrXDEngineAdapter::~RawrXDEngineAdapter() {
}

bool RawrXDEngineAdapter::isReady() const {
    return inferenceEngine_ && inferenceEngine_->IsModelLoaded();
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

bool RawrXDEngineAdapter::prefill(const std::vector<int32_t>& tokens) {
    if (!inferenceEngine_) return false;
    
    // CPUInferenceEngine::Eval performs a forward pass and returns logits.
    // It internally updates KV Cache via its encapsulated RawrXDInference.
    std::vector<float> logits = inferenceEngine_->Eval(tokens);
    return !logits.empty();
}

int RawrXDEngineAdapter::decodeStep() {
    if (!inferenceEngine_) return -1;
    
    // 1. Get the last computed logits from the engine.
    const auto& logits = inferenceEngine_->GetLastState();
    if (logits.empty()) return -1;

    // 2. Sample from logits.
    // Need a mutable copy for the sampler, because sampling typically mutates the logit buffer inline
    std::vector<float> mutableLogits = logits;
    uint32_t tokenId = sampler_.Sample(mutableLogits.data(), static_cast<int>(mutableLogits.size()), {});

    // 3. Preemptively run forward pass with the newly sampled token to populate KV cache and get next logits.
    std::vector<int32_t> nextToken = { static_cast<int32_t>(tokenId) };
    inferenceEngine_->Eval(nextToken);
    
    return static_cast<int>(tokenId);
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

    // --- Run prefill (prompt processing) ---
    if (!prefill(promptTokens)) {
        if (engineErrorCb) engineErrorCb("Prefill failed");
        return false;
    }

    // --- Decode loop ---
    uint32_t tokenIdx = 0;
    int eosTokenId = getEosTokenId();

    while (true) {
        // Decode one token
        int tokenId = decodeStep();
        if (tokenId < 0) {
            if (engineErrorCb) engineErrorCb("Decode step returned invalid token");
            return false;
        }

        // Check for EOS
        if (tokenId == eosTokenId) {
            return true;  // Normal stop
        }

        // Detokenize the single token to text
        std::string tokenText = detokenize(tokenId);
        if (!tokenText.empty() && tokenCb) {
            tokenCb(tokenText.c_str(), tokenIdx);
        }

        tokenIdx++;

        // Check max tokens
        if (tokenIdx >= maxDecodeTokens_) {
            return true;  // Hit length limit
        }
    }

    return true;
}