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

    // Callback for running a single forward pass through the model
    // layerIdx: which layer (0..numLayers-1)
    // input: hidden states (size hiddenDim)
    // output: logits or next hidden states (size vocabSize or hiddenDim)
    // tokenPos: current position in sequence
    // Returns true on success
    using ForwardFn = std::function<bool(uint32_t layerIdx,
                                         const float* input,
                                         float* output,
                                         uint64_t tokenPos)>;

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

        // Configure the generation loop
        void setTokenizer(const Tokenizer& tokenizer) { m_tokenizer = &tokenizer; }
        void setKVCache(KVCache* cache) { m_kvCache = cache; }
        void setSampler(const Sampler& sampler) { m_sampler = sampler; }
        void setForwardFn(ForwardFn fn) { m_forwardFn = std::move(fn); }
        void setConfig(const GenerationConfig& config) { m_config = config; }

        // Check if configured
        bool isConfigured() const {
            return m_tokenizer != nullptr && m_sampler.params().temperature >= 0.0f && m_forwardFn != nullptr;
        }

        // Generate text from a prompt
        // prompt: input text
        // onToken: callback for each generated token (token ID, text)
        // Returns generation result
        GenerationResult generate(const std::string& prompt,
                                  std::function<void(uint32_t tokenId, const std::string& tokenText)> onToken = nullptr);

        // Generate with a callback that can request early stopping
        // onToken should return true to continue, false to stop
        GenerationResult generateWithControl(const std::string& prompt,
                                             std::function<bool(uint32_t tokenId, const std::string& tokenText)> onToken);

    private:
        const Tokenizer* m_tokenizer = nullptr;
        KVCache* m_kvCache = nullptr;
        Sampler m_sampler;
        GenerationConfig m_config;
        ForwardFn m_forwardFn;
        std::atomic<bool> m_stopRequested{ false };

        // Run a single generation step
        // Returns the sampled token ID
        uint32_t generateStep(const std::vector<uint32_t>& inputTokens,
                              uint64_t position,
                              std::vector<uint32_t>& tokenHistory);
    };

} // namespace Deep2Rom::Inference
