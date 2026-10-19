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

        fprintf(stderr, "[GEN_DEBUG] generateWithControl entered\n");
        fflush(stderr);

        if (!isConfigured()) {
            std::cerr << "[GenerationLoop] Not configured" << std::endl;
            return result;
        }

        std::cout << "    [Gen] Configured OK" << std::endl;

        fprintf(stderr, "[GEN_DEBUG] Configured OK, starting prefill...\n");
        fflush(stderr);

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

        // Process input tokens through the model (prefill phase)
        // For each input token, run forward pass to populate KV cache
        std::cout << "    [Gen] Prefill: " << inputTokens.size() << " input tokens" << std::endl;
        for (uint64_t i = 0; i < inputTokens.size(); ++i) {
            // Run forward pass for this input token
            // In a real implementation, this processes the token through all layers
            // and stores K/V in the cache
            position = i;
            if (i % 10 == 0) {
                std::cout << "    [Gen] Prefill progress: " << i << "/" << inputTokens.size() << std::endl;
            }
        }

        // Generation loop
        std::cout << "    [Gen] Starting generation loop, maxTokens=" << m_config.maxTokens << std::endl;
        for (uint32_t t = 0; t < m_config.maxTokens; ++t) {
            if (m_stopRequested.load()) break;

            // Get the last token's hidden state from the model
            // For the prefill phase, the last input token is the context
            // For generation, we sample from the last position
            uint32_t currentToken = allTokens.back();

            std::cout << "    [Gen] Step " << t << "/" << m_config.maxTokens
                      << ", currentToken=" << currentToken << std::endl;

            // Run forward pass to get logits for the next token
            // We pass the current hidden state through all layers
            float logits[16384] = { 0 };  // Max vocab size buffer
            uint32_t vocabSize = m_tokenizer->vocabSize();
            if (vocabSize > 16384) vocabSize = 16384;  // Safety cap

            // Run through all layers
            uint32_t numLayers = 32; // Default; in production this comes from model config
            for (uint32_t layer = 0; layer < numLayers; ++layer) {
                if (layer % 8 == 0) {
                    std::cout << "    [Gen] Layer " << layer << "/" << numLayers << std::endl;
                }
                float layerOut[16384] = { 0 };
                if (!m_forwardFn(layer,
                                 allTokens.empty() ? nullptr : reinterpret_cast<const float*>(&allTokens.back()),
                                 layerOut,
                                 position)) {
                    // Forward pass failed, stop generation
                    stoppedByLimit = true;
                    break;
                }
                // Copy layer output back as input to next layer
                // In a real implementation, this would be proper hidden state propagation
            }

            // Get logits from the last layer output (simplified: use last forward output)
            // In a real implementation, the forward pass would output logits directly
            float finalLogits[16384] = { 0 };
            m_forwardFn(0, reinterpret_cast<const float*>(&currentToken), finalLogits, position);

            // Apply penalties
            m_sampler.applyPenalties(finalLogits, vocabSize, tokenHistory);

            // Sample next token
            uint32_t nextToken = m_sampler.sample(finalLogits, vocabSize);

            // Check for EOS
            if (nextToken == m_tokenizer->eosTokenId()) {
                stoppedByEOS = true;
                if (m_config.addEos) {
                    allTokens.push_back(nextToken);
                    result.tokens.push_back(nextToken);
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

            std::cout << "    [Gen] Token " << result.tokensGenerated << "/" << m_config.maxTokens
                      << " (id=" << nextToken << ")" << std::endl;

            // Decode token text for callback
            std::string tokenText = m_tokenizer->decode({ nextToken }, m_config.skipSpecialTokens);

            // Call callback
            if (onToken) {
                if (!onToken(nextToken, tokenText)) {
                    break;  // Callback requested stop
                }
            }

            position++;
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

    uint32_t GenerationLoop::generateStep(const std::vector<uint32_t>& inputTokens,
                                           uint64_t position,
                                           std::vector<uint32_t>& tokenHistory) {
        // This is called per-step; the main loop in generateWithControl handles the logic
        return 0;
    }

} // namespace Deep2Rom::Inference
