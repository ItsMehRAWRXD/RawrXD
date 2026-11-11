// =============================================================================
// RawrXDEngineAdapter — Connects generation control plane to Deep2Engine
// =============================================================================

#include "RawrXDEngineAdapter.h"
#include "../deep2/Deep2Engine.h"
#include "../deep2/Tokenizer.hpp"
#include <memory>
#include <cstring>

class RawrXDEngineAdapter::Impl {
public:
    Impl() : engine_(std::make_unique<Deep2::Deep2Engine>()) {}

    bool initialize(const EngineConfig& cfg) {
        Deep2::EngineConfig deep2Cfg;
        deep2Cfg.hiddenDim = cfg.hiddenDim;
        deep2Cfg.numLayers = cfg.numLayers;
        deep2Cfg.numHeads = cfg.numHeads;
        deep2Cfg.vocabSize = cfg.vocabSize;
        deep2Cfg.maxSeqLen = cfg.maxSeqLen;
        deep2Cfg.useKVCache = cfg.useKVCache;
        deep2Cfg.useRoPE = cfg.useRoPE;
        // modelPath is a fixed-size char buffer in Deep2::EngineConfig.
        {
            const std::string& p = cfg.modelPath;
            const size_t n = (p.size() < sizeof(deep2Cfg.modelPath) - 1)
                                 ? p.size()
                                 : sizeof(deep2Cfg.modelPath) - 1;
            std::memcpy(deep2Cfg.modelPath, p.data(), n);
            deep2Cfg.modelPath[n] = '\0';
        }

        return engine_->initialize(deep2Cfg);
    }

    std::vector<int> tokenize(const std::string& text) {
        return engine_->tokenize(text);
    }

    std::string detokenize(const std::vector<int>& tokens) {
        return engine_->detokenize(tokens);
    }

    void prefill(const std::vector<int>& tokens) {
        // Deep2Engine exposes a single-shot generate() API rather than an
        // explicit prefill/decode split; retain the prompt so decode() can
        // advance generation one token at a time.
        promptTokens_ = tokens;
    }

    int decode() {
        if (promptTokens_.empty()) return -1;
        int out = -1;
        engine_->generate(promptTokens_.data(), promptTokens_.size(),
                          &out, 1, nullptr);
        if (out >= 0) promptTokens_.push_back(out);
        return out;
    }

    void clearCache() {
        engine_->reset();
        promptTokens_.clear();
    }

private:
    std::unique_ptr<Deep2::Deep2Engine> engine_;
    std::vector<int> promptTokens_;
};

// Public API
RawrXDEngineAdapter::RawrXDEngineAdapter() : impl_(std::make_unique<Impl>()) {}
RawrXDEngineAdapter::~RawrXDEngineAdapter() = default;

bool RawrXDEngineAdapter::initialize(const EngineConfig& cfg) {
    return impl_->initialize(cfg);
}

std::vector<int> RawrXDEngineAdapter::tokenize(const std::string& text) {
    return impl_->tokenize(text);
}

std::string RawrXDEngineAdapter::detokenize(const std::vector<int>& tokens) {
    return impl_->detokenize(tokens);
}

void RawrXDEngineAdapter::prefill(const std::vector<int>& tokens) {
    impl_->prefill(tokens);
}

int RawrXDEngineAdapter::decode() {
    return impl_->decode();
}

void RawrXDEngineAdapter::clearCache() {
    impl_->clearCache();
}