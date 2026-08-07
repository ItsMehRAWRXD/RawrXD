// =============================================================================
// RawrXDEngineAdapter — Connects generation control plane to Deep2Engine
// =============================================================================

#include "RawrXDEngineAdapter.h"
#include "deep2/Deep2Engine.h"
#include "deep2/Tokenizer.hpp"
#include <memory>

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
        deep2Cfg.modelPath = cfg.modelPath;

        return engine_->initialize(deep2Cfg);
    }

    std::vector<int> tokenize(const std::string& text) {
        if (!tokenizer_) {
            tokenizer_ = std::make_unique<Deep2::Tokenizer>();
            if (!tokenizer_->load("tokenizer.model")) {
                return {};
            }
        }
        return tokenizer_->encode(text);
    }

    std::string detokenize(const std::vector<int>& tokens) {
        if (!tokenizer_) return "";
        return tokenizer_->decode(tokens);
    }

    void prefill(const std::vector<int>& tokens) {
        engine_->prefill(tokens.data(), tokens.size());
    }

    int decode() {
        return engine_->decode();
    }

    void clearCache() {
        engine_->clearKVCache();
    }

private:
    std::unique_ptr<Deep2::Deep2Engine> engine_;
    std::unique_ptr<Deep2::Tokenizer> tokenizer_;
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