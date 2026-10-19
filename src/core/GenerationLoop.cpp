#include "GenerationLoop.hpp"
#include <iostream>
#include <chrono>
#include <cstring>
#include <algorithm>

namespace Deep2Rom::Inference {

    GenerationResult GenerationLoop::generate(const std::string& prompt,
                                               std::function<void(uint32_t, const std::string&)> onToken) {
        return generateWithControl(prompt, [&](uint32_t id, const std::string& text) {
            if (onToken) onToken(id, text);
            return !m_stopRequested.load();
        });
    }

    GenerationResult GenerationLoop::generateWithControl(const std::string& prompt,
                                                          std::function<bool(uint32_t, const std::string&)> onToken) {
        GenerationResult result;
        m_stopRequested = false;

        if (!isConfigured()) {
            std::cerr << "[GenerationLoop] Not configured\n";
            return result;
        }

        auto startTime = std::chrono::high_resolution_clock::now();

        // Clear KV cache for fresh generation
        if (m_kvCache) {
            m_kvCache->clear();
        }

        // Tokenize input
        std::vector<uint32_t> inputTokens = m_tokenizer->encode(prompt, m_config.addBos, false);
        std::vector<uint32_t> allTokens = inputTokens;
        std::vector<uint32_t> tokenHistory = inputTokens;

        uint64_t position = 0;
        bool stoppedByEOS = false;
        bool stoppedByLimit = false;

        // Prefill: process each input token through all layers to populate KV cache
        for (uint64_t i = 0; i < inputTokens.size(); ++i) {
            position = i;
            uint32_t tokenId = inputTokens[i];

            // Layer 0: embedding lookup (input = nullptr, tokenId provided)
            float hidden[16384] = { 0 };
            if (!m_forwardFn(0, nullptr, hidden, position, tokenId)) {
                stoppedByLimit = true;
                break;
            }

            // Layers 1 to numLayers-1
            for (uint32_t layer = 1; layer < m_numLayers; ++layer) {
                float next[16384] = { 0 };
                if (!m_forwardFn(layer, hidden, next, position, tokenId)) {
                    stoppedByLimit = true;
                    break;
                }
                for (uint32_t j = 0; j < m_hiddenDim; ++j) hidden[j] = next[j];
            }

            if (stoppedByLimit) break;
        }

        // Generation loop
        for (uint32_t t = 0; t < m_config.maxTokens; ++t) {
            if (m_stopRequested.load()) break;

            if (allTokens.empty()) break;

            uint32_t currentToken = allTokens.back();
            position = static_cast<uint64_t>(allTokens.size()) - 1;

            // Run through all layers for the current token
            float hidden[16384] = { 0 };

            // Layer 0: embedding lookup
            if (!m_forwardFn(0, nullptr, hidden, position, currentToken)) {
                stoppedByLimit = true;
                break;
            }

            // Layers 1 to numLayers-1
            for (uint32_t layer = 1; layer < m_numLayers; ++layer) {
                float next[16384] = { 0 };
                if (!m_forwardFn(layer, hidden, next, position, currentToken)) {
                    stoppedByLimit = true;
                    break;
                }
                for (uint32_t j = 0; j < m_hiddenDim; ++j) hidden[j] = next[j];
            }

            if (stoppedByLimit) break;

            // The last layer's forwardPass already computed logits into `hidden`
            uint32_t vocabSize = m_vocabSize;
            if (vocabSize > 16384) vocabSize = 16384;

            // Apply penalties
            m_sampler.applyPenalties(hidden, vocabSize, tokenHistory);

            // Sample next token
            uint32_t nextToken = m_sampler.sample(hidden, vocabSize);

            // Check for EOS
            if (nextToken == m_tokenizer->eosTokenId()) {
                stoppedByEOS = true;
                if (m_config.addEos) {
                    allTokens.push_back(nextToken);
                    result.tokens.push_back(nextToken);
                    result.tokensGenerated++;
                    if (onToken) {
                        if (!onToken(nextToken, m_tokenizer->decode({ nextToken }, m_config.skipSpecialTokens))) {
                            break;
                        }
                    }
                }
                break;
            }

            // Add token to sequence
            allTokens.push_back(nextToken);
            result.tokens.push_back(nextToken);
            tokenHistory.push_back(nextToken);
            result.tokensGenerated++;

            std::string tokenText = m_tokenizer->decode({ nextToken }, m_config.skipSpecialTokens);

            if (onToken) {
                if (!onToken(nextToken, tokenText)) {
                    break;
                }
            }
        }

        if (result.tokensGenerated >= m_config.maxTokens) {
            stoppedByLimit = true;
        }

        auto endTime = std::chrono::high_resolution_clock::now();
        result.totalTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();
        if (result.totalTimeMs > 0.0) {
            result.avgTPS = (result.tokensGenerated / result.totalTimeMs) * 1000.0;
        }

        result.text = m_tokenizer->decode(result.tokens, m_config.skipSpecialTokens);
        result.stoppedByEOS = stoppedByEOS;
        result.stoppedByLimit = stoppedByLimit;

        return result;
    }

} // namespace Deep2Rom::Inference
