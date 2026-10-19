#pragma once
#include "Tokenizer.hpp"
#include "KVCache.hpp"
#include "Sampling.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <functional>
#include <atomic>

namespace Deep2Rom::Inference {

    // Callback for running a single transformer layer forward pass
    // layerIdx: which layer (0..numLayers-1)
    // input: hidden states (size hiddenDim) or nullptr for embedding lookup on layer 0
    // output: hidden states or logits (size hiddenDim or vocabSize)
    // tokenPos: current position in sequence
    // tokenId: token ID for embedding lookup (used when input is nullptr and layerIdx == 0)
    // Returns true on success
    using ForwardFn = std::function<bool(uint32_t layerIdx,
                                         const float* input,
                                         float* output,
                                         uint64_t tokenPos,
                                         uint32_t tokenId)>;

    // Generation result
    struct GenerationResult {
        std::string text;
        std::vector<uint32_t> tokens;
        uint32_t tokensGenerated = 0;
        bool stoppedByEOS = false;
        bool stoppedByLimit = false;
        double totalTimeMs = 0.0;
        double avgTPS = 0.0;
    };

    // Generation configuration
    struct GenerationConfig {
        uint32_t maxTokens = 256;
        bool addBos = true;
        bool addEos = true;
        bool skipSpecialTokens = true;
        SamplingParams sampling;
    };

    class GenerationLoop {
    public:
        GenerationLoop() = default;
        ~GenerationLoop() = default;

        void setTokenizer(const Tokenizer& tokenizer) { m_tokenizer = &tokenizer; }
        void setKVCache(KVCache* cache) { m_kvCache = cache; }
        void setSampler(const Sampler& sampler) { m_sampler = sampler; }
        void setForwardFn(ForwardFn fn) { m_forwardFn = std::move(fn); }
        void setConfig(const GenerationConfig& config) { m_config = config; }
        void setNumLayers(uint32_t numLayers) { m_numLayers = numLayers; }
        void setHiddenDim(uint32_t hiddenDim) { m_hiddenDim = hiddenDim; }
        void setVocabSize(uint32_t vocabSize) { m_vocabSize = vocabSize; }

        bool isConfigured() const {
            return m_tokenizer != nullptr && m_forwardFn != nullptr && m_numLayers > 0;
        }

        GenerationResult generate(const std::string& prompt,
                                  std::function<void(uint32_t tokenId, const std::string& tokenText)> onToken = nullptr);

        GenerationResult generateWithControl(const std::string& prompt,
                                             std::function<bool(uint32_t tokenId, const std::string& tokenText)> onToken);

    private:
        const Tokenizer* m_tokenizer = nullptr;
        KVCache* m_kvCache = nullptr;
        Sampler m_sampler;
        GenerationConfig m_config;
        ForwardFn m_forwardFn;
        std::atomic<bool> m_stopRequested{ false };

        uint32_t m_numLayers = 0;
        uint32_t m_hiddenDim = 3072;
        uint32_t m_vocabSize = 32064;
    };

} // namespace Deep2Rom::Inference
