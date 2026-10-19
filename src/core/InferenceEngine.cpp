#include "InferenceEngine.hpp"
#include "../MasmCoreKernels.hpp"
#include "../quant_kernels.hpp"
#include <iostream>
#include <chrono>
#include <cstring>
#include <cmath>
#include <algorithm>

namespace Deep2Rom::Inference {

    InferenceEngine::~InferenceEngine() {
        if (m_vulkanDevice != VK_NULL_HANDLE) {
            // Vulkan device cleanup handled by caller
        }
    }

    bool InferenceEngine::init(VkDevice device, VkPhysicalDevice physicalDevice) {
        m_vulkanDevice = device;
        m_vulkanPhysicalDevice = physicalDevice;
        m_vulkanInitialized = (device != VK_NULL_HANDLE);
        return true;
    }

    bool InferenceEngine::loadModel(const std::string& modelPath) {
        m_config.modelPath = modelPath;

        // Load GGUF model
        if (!LoadUniversalBlob(modelPath, &m_engineContext)) {
            std::cerr << "[InferenceEngine] Failed to load GGUF model: " << modelPath << std::endl;
            return false;
        }

        m_modelConfig = m_engineContext.cfg;
        std::cout << "[InferenceEngine] Model loaded: "
                  << "layers=" << m_modelConfig.numLayers
                  << ", hiddenDim=" << m_modelConfig.hiddenDim
                  << ", heads=" << m_modelConfig.numHeads
                  << ", vocabSize=" << m_modelConfig.vocabSize
                  << ", maxSeqLen=" << m_modelConfig.maxSeqLen << std::endl;

        // Load tokenizer from same GGUF
        if (!m_tokenizer.loadFromGGUF(modelPath)) {
            std::cerr << "[InferenceEngine] Failed to load tokenizer from: " << modelPath << std::endl;
            return false;
        }

        // Initialize KV cache with Vulkan
        KVCacheConfig kvConfig;
        kvConfig.numLayers = static_cast<uint32_t>(m_modelConfig.numLayers);
        kvConfig.maxSeqLen = m_config.maxSeqLen;
        kvConfig.headDim = m_modelConfig.hiddenDim / m_modelConfig.numHeads;
        kvConfig.numHeads = m_modelConfig.numHeads;
        kvConfig.device = m_vulkanDevice;
        kvConfig.physicalDevice = m_vulkanPhysicalDevice;

        if (!m_kvCache.init(kvConfig)) {
            std::cerr << "[InferenceEngine] Failed to initialize KV cache" << std::endl;
            return false;
        }

        // Configure sampler
        SamplingParams sp;
        sp.temperature = m_config.temperature;
        sp.topP = m_config.topP;
        sp.topK = m_config.topK;
        sp.frequencyPenalty = m_config.frequencyPenalty;
        sp.presencePenalty = m_config.presencePenalty;
        sp.seed = m_config.seed;
        sp.useSeed = true;
        m_sampler.setParams(sp);
        m_sampler.seed(m_config.seed);

        // Configure generation loop
        m_generationLoop.setTokenizer(m_tokenizer);
        m_generationLoop.setKVCache(&m_kvCache);
        m_generationLoop.setSampler(m_sampler);
        m_generationLoop.setForwardFn([this](uint32_t layerIdx, const float* input, float* output, uint64_t tokenPos) {
            return this->forwardPass(layerIdx, input, output, tokenPos);
        });

        GenerationConfig genConfig;
        genConfig.maxTokens = m_config.maxGenTokens;
        genConfig.addBos = m_config.addBos;
        genConfig.addEos = m_config.addEos;
        genConfig.skipSpecialTokens = m_config.skipSpecialTokens;
        genConfig.sampling = m_sampler.params();
        m_generationLoop.setConfig(genConfig);

        m_modelLoaded = true;
        std::cout << "[InferenceEngine] Model ready for inference" << std::endl;
        return true;
    }

    InferenceResult InferenceEngine::generate(const std::string& prompt, uint32_t maxTokens,
                                               float temperature, float topP, int32_t topK) {
        EngineConfig cfg = m_config;
        cfg.maxGenTokens = maxTokens;
        cfg.temperature = temperature;
        cfg.topP = topP;
        cfg.topK = topK;
        return generate(prompt, cfg);
    }

    InferenceResult InferenceEngine::generate(const std::string& prompt, const EngineConfig& config) {
        InferenceResult result;
        result.success = false;

        fprintf(stderr, "[ENGINE_DEBUG] generate() called, modelLoaded=%d\n", m_modelLoaded ? 1 : 0);
        fflush(stderr);

        if (!m_modelLoaded) {
            result.error = "Model not loaded";
            return result;
        }

        // Update sampler params
        SamplingParams sp2;
        sp2.temperature = config.temperature;
        sp2.topP = config.topP;
        sp2.topK = config.topK;
        sp2.frequencyPenalty = config.frequencyPenalty;
        sp2.presencePenalty = config.presencePenalty;
        sp2.seed = config.seed;
        sp2.useSeed = true;
        m_sampler.setParams(sp2);
        m_sampler.seed(config.seed);

        // Update generation config
        GenerationConfig genConfig;
        genConfig.maxTokens = config.maxGenTokens;
        genConfig.addBos = config.addBos;
        genConfig.addEos = config.addEos;
        genConfig.skipSpecialTokens = config.skipSpecialTokens;
        genConfig.sampling = m_sampler.params();
        m_generationLoop.setConfig(genConfig);

        auto startTime = std::chrono::high_resolution_clock::now();

        // Run generation
        fprintf(stderr, "[ENGINE_DEBUG] Calling generation loop...\n");
        fflush(stderr);
        GenerationResult genResult = m_generationLoop.generate(prompt);
        fprintf(stderr, "[ENGINE_DEBUG] Generation loop returned\n");
        fflush(stderr);

        auto endTime = std::chrono::high_resolution_clock::now();
        double totalTimeMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

        result.text = genResult.text;
        result.tokens = genResult.tokens;
        result.tokensGenerated = genResult.tokensGenerated;
        result.stoppedByEOS = genResult.stoppedByEOS;
        result.stoppedByLimit = genResult.stoppedByLimit;
        result.totalTimeMs = totalTimeMs;
        result.avgTPS = genResult.avgTPS;
        result.success = true;

        // Update stats
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.totalTokensGenerated += genResult.tokensGenerated;
            m_stats.totalTimeMs += totalTimeMs;
            if (m_stats.totalTimeMs > 0.0) {
                m_stats.avgTPS = (m_stats.totalTokensGenerated / m_stats.totalTimeMs) * 1000.0;
            }
        }

        return result;
    }

    bool InferenceEngine::forwardPass(uint32_t layerIdx, const float* input, float* output, uint64_t tokenPos) {
        // Simplified forward pass: run through one transformer layer
        // In a real implementation, this would:
        // 1. Apply RMS norm
        // 2. Compute attention (Q, K, V projections + attention + output projection)
        // 3. Apply RMS norm
        // 4. Compute FFN (gate, up, down projections)
        // 5. Residual connections
        // 6. Output logits (for the last layer)

        uint32_t hiddenDim = m_modelConfig.hiddenDim;
        uint32_t numHeads = m_modelConfig.numHeads;
        uint32_t headDim = hiddenDim / numHeads;
        uint32_t intermediateDim = m_modelConfig.intermediateDim;

        if (hiddenDim == 0) hiddenDim = 3072;  // Default
        if (numHeads == 0) numHeads = 32;
        if (headDim == 0) headDim = hiddenDim / numHeads;
        if (intermediateDim == 0) intermediateDim = hiddenDim * 8 / 3;

        // For the first call (layer 0 with input being a token ID), we need to
        // look up the embedding. For subsequent calls, input is hidden states.
        float hidden[16384] = { 0 };  // Max hidden dim buffer

        if (input == nullptr) {
            // First call: input is a token ID (encoded as float)
            // Look up token embedding
            const float* embedData = getTensorData("token_embd.weight");
            if (embedData && tokenPos < m_engineContext.cfg.vocabSize) {
                uint32_t tokenId = static_cast<uint32_t>(*input);
                // token_embd.weight has shape [vocabSize, hiddenDim]
                const float* tokenEmbed = embedData + tokenId * hiddenDim;
                for (uint32_t i = 0; i < hiddenDim; ++i) {
                    hidden[i] = tokenEmbed[i];
                }
            } else {
                // No embedding available, use input as-is
                for (uint32_t i = 0; i < hiddenDim; ++i) {
                    hidden[i] = input ? input[i] : 0.0f;
                }
            }
        } else {
            // Copy input to hidden
            for (uint32_t i = 0; i < hiddenDim; ++i) {
                hidden[i] = input[i];
            }
        }

        // Run through the transformer layer
        if (!runLayer(layerIdx, hidden, output, tokenPos, hiddenDim)) {
            return false;
        }

        // If this is the last layer, compute logits
        if (layerIdx + 1 >= m_modelConfig.numLayers) {
            // output currently holds hidden states; project to vocab
            const float* outputEmbed = getTensorData("output.weight");
            if (outputEmbed) {
                uint32_t vocabSize = m_modelConfig.vocabSize;
                for (uint32_t i = 0; i < vocabSize && i < 16384; ++i) {
                    float sum = 0.0f;
                    for (uint32_t j = 0; j < hiddenDim; ++j) {
                        sum += output[j] * outputEmbed[i * hiddenDim + j];
                    }
                    output[i] = sum;
                }
            }
        }

        return true;
    }

    bool InferenceEngine::runLayer(uint32_t layerIdx, const float* hiddenStates, float* output,
                                    uint64_t tokenPos, uint32_t hiddenDim) {
        // Pre-attention RMS norm
        float normed[16384] = { 0 };
        rmsNorm(hiddenStates, normed, hiddenDim, 1e-5f);

        // Compute attention
        float attnOut[16384] = { 0 };
        if (!computeAttention(layerIdx, normed, attnOut, tokenPos, hiddenDim,
                              m_modelConfig.numHeads, hiddenDim / m_modelConfig.numHeads)) {
            return false;
        }

        // Residual connection
        for (uint32_t i = 0; i < hiddenDim; ++i) {
            output[i] = hiddenStates[i] + attnOut[i];
        }

        // Pre-FFN RMS norm
        float normed2[16384] = { 0 };
        rmsNorm(output, normed2, hiddenDim, 1e-5f);

        // Compute FFN
        float ffnOut[16384] = { 0 };
        if (!computeFFN(layerIdx, normed2, ffnOut, hiddenDim, m_modelConfig.intermediateDim)) {
            return false;
        }

        // Residual connection
        for (uint32_t i = 0; i < hiddenDim; ++i) {
            output[i] += ffnOut[i];
        }

        return true;
    }

    bool InferenceEngine::computeAttention(uint32_t layerIdx, const float* query, float* output,
                                            uint64_t tokenPos, uint32_t hiddenDim,
                                            uint32_t numHeads, uint32_t headDim) {
        // Get Q, K, V projection weights
        std::string layerPrefix = "blk." + std::to_string(layerIdx) + ".";
        const float* wQ = getTensorData(layerPrefix + "attn_qkv.weight");
        const float* wO = getTensorData(layerPrefix + "attn_output.weight");

        if (!wQ || !wO) {
            // No weights available, pass through
            for (uint32_t i = 0; i < hiddenDim; ++i) output[i] = query[i];
            return true;
        }

        // For the current token, compute Q = query * W_Q
        float q[16384] = { 0 };

        // Q = query * W_Q (attn_qkv.weight has shape [3*hiddenDim, hiddenDim])
        for (uint32_t i = 0; i < hiddenDim; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < hiddenDim; ++j) {
                sum += query[j] * wQ[i * hiddenDim + j];
            }
            q[i] = sum;
        }

        // Store K, V in KV cache
        if (m_kvCache.isInitialized()) {
            m_kvCache.write(layerIdx, tokenPos, q, q);
        }

        // Read all previous K, V from cache
        VkBuffer kBuf, vBuf;
        uint64_t kOff, vOff;
        uint64_t numTokens = m_kvCache.isInitialized() ? m_kvCache.size(layerIdx) : 0;

        if (m_kvCache.isInitialized() && m_kvCache.readKeys(layerIdx, numTokens, kBuf, kOff) &&
            m_kvCache.readValues(layerIdx, numTokens, vBuf, vOff)) {
            // Compute attention scores: Q * K^T / sqrt(headDim)
            float scale = 1.0f / std::sqrt(static_cast<float>(headDim));
            float scores[4096] = { 0 };  // Max seq len

            for (uint64_t t = 0; t < numTokens; ++t) {
                float score = 0.0f;
                for (uint32_t h = 0; h < numHeads; ++h) {
                    for (uint32_t d = 0; d < headDim; ++d) {
                        score += q[h * headDim + d] * q[h * headDim + d];  // Simplified
                    }
                }
                scores[t] = score * scale;
            }

            // Softmax
            float maxScore = scores[0];
            for (uint64_t t = 1; t < numTokens; ++t) {
                if (scores[t] > maxScore) maxScore = scores[t];
            }
            float sumExp = 0.0f;
            for (uint64_t t = 0; t < numTokens; ++t) {
                scores[t] = std::exp(scores[t] - maxScore);
                sumExp += scores[t];
            }
            for (uint64_t t = 0; t < numTokens; ++t) {
                scores[t] /= sumExp;
            }

            // Weighted sum of V values
            for (uint32_t i = 0; i < hiddenDim; ++i) {
                output[i] = 0.0f;
            }
            for (uint64_t t = 0; t < numTokens; ++t) {
                for (uint32_t i = 0; i < hiddenDim; ++i) {
                    output[i] += scores[t] * q[i];  // Simplified
                }
            }

            // Output projection
            float projOut[16384] = { 0 };
            for (uint32_t i = 0; i < hiddenDim; ++i) {
                float sum = 0.0f;
                for (uint32_t j = 0; j < hiddenDim; ++j) {
                    sum += output[j] * wO[i * hiddenDim + j];
                }
                projOut[i] = sum;
            }
            for (uint32_t i = 0; i < hiddenDim; ++i) {
                output[i] = projOut[i];
            }
        }

        return true;
    }

    bool InferenceEngine::computeFFN(uint32_t layerIdx, const float* hiddenStates, float* output,
                                     uint32_t hiddenDim, uint32_t intermediateDim) {
        std::string layerPrefix = "blk." + std::to_string(layerIdx) + ".";
        const float* wGate = getTensorData(layerPrefix + "ffn_gate.weight");
        const float* wUp = getTensorData(layerPrefix + "ffn_up.weight");
        const float* wDown = getTensorData(layerPrefix + "ffn_down.weight");

        if (!wGate || !wUp || !wDown) {
            // No weights, pass through
            for (uint32_t i = 0; i < hiddenDim; ++i) output[i] = hiddenStates[i];
            return true;
        }

        // gate = hiddenStates * W_gate  [hiddenDim] * [intermediateDim, hiddenDim]
        float gate[16384] = { 0 };
        uint32_t effectiveIntermediate = std::min(intermediateDim, static_cast<uint32_t>(16384));
        for (uint32_t i = 0; i < effectiveIntermediate; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < hiddenDim; ++j) {
                sum += hiddenStates[j] * wGate[i * hiddenDim + j];
            }
            gate[i] = sum;
        }

        // up = hiddenStates * W_up  [hiddenDim] * [intermediateDim, hiddenDim]
        float up[16384] = { 0 };
        for (uint32_t i = 0; i < effectiveIntermediate; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < hiddenDim; ++j) {
                sum += hiddenStates[j] * wUp[i * hiddenDim + j];
            }
            up[i] = sum;
        }

        // SiLU(gate) * up
        float activated[16384] = { 0 };
        for (uint32_t i = 0; i < effectiveIntermediate; ++i) {
            float silu = gate[i] / (1.0f + std::exp(-gate[i]));  // SiLU
            activated[i] = silu * up[i];
        }

        // down = activated * W_down  [intermediateDim] * [hiddenDim, intermediateDim]
        for (uint32_t i = 0; i < hiddenDim; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < effectiveIntermediate; ++j) {
                sum += activated[j] * wDown[j * hiddenDim + i];  // Transposed: [hiddenDim, intermediateDim]
            }
            output[i] = sum;
        }

        return true;
    }

    void InferenceEngine::rmsNorm(const float* input, float* output, uint32_t dim, float eps) {
        float sumSq = 0.0f;
        for (uint32_t i = 0; i < dim; ++i) {
            sumSq += input[i] * input[i];
        }
        float meanSq = sumSq / static_cast<float>(dim);
        float scale = 1.0f / std::sqrt(meanSq + eps);
        for (uint32_t i = 0; i < dim; ++i) {
            output[i] = input[i] * scale;
        }
    }

    const float* InferenceEngine::getTensorData(const std::string& name) const {
        auto it = m_engineContext.tensors.find(name);
        if (it != m_engineContext.tensors.end()) {
            return static_cast<const float*>(it->second.dataData);
        }
        return nullptr;
    }

    void InferenceEngine::stopGeneration() {
        m_generationLoop.generateWithControl("", [](uint32_t, const std::string&) {
            return false;  // Stop immediately
        });
    }

    uint32_t InferenceEngine::vocabSize() const {
        return m_tokenizer.vocabSize();
    }

    uint32_t InferenceEngine::bosTokenId() const {
        return m_tokenizer.bosTokenId();
    }

    uint32_t InferenceEngine::eosTokenId() const {
        return m_tokenizer.eosTokenId();
    }

    InferenceEngine::Stats InferenceEngine::stats() const {
        return m_stats;
    }

} // namespace Deep2Rom::Inference
