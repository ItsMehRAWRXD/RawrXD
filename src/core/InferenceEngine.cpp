#include "InferenceEngine.hpp"
#include "../MasmCoreKernels.hpp"
#include "../quant_kernels.hpp"
#include <iostream>
#include <chrono>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <vector>

namespace Deep2Rom::Inference {

    void dequantize_q2k_block(const uint8_t* block_data, uint32_t num_elements, float* out) {
        const uint8_t* qs = block_data;
        const uint8_t* scales = block_data + 64;
        uint16_t d_raw = uint16_t(block_data[80]) | (uint16_t(block_data[81]) << 8);

        uint32_t sign = (d_raw & 0x8000u) << 16;
        uint32_t exp = (d_raw & 0x7C00u) >> 10;
        uint32_t frac = d_raw & 0x03FFu;
        uint32_t f32 = 0;
        if (exp == 31) {
            f32 = sign | 0x7F800000u | (frac << 13);
        } else if (exp == 0) {
            if (frac != 0) {
                while ((frac & 0x0400u) == 0) { frac <<= 1u; exp--; }
                exp++;
                frac &= ~0x0400u;
                f32 = sign | ((exp + (127u - 15u)) << 23) | (frac << 13);
            } else {
                f32 = sign;
            }
        } else {
            f32 = sign | ((exp + (127u - 15u)) << 23) | (frac << 13);
        }
        float d;
        memcpy(&d, &f32, 4);
        if (isnan(d) || isinf(d)) d = 0.0f;

        for (uint32_t e = 0; e < num_elements; ++e) {
            uint32_t byte_idx = e / 4;
            uint32_t bit_offset = (3u - (e % 4u)) * 2u;
            uint8_t q = (qs[byte_idx] >> bit_offset) & 0x03u;
            uint32_t group_idx = byte_idx / 4u;
            float scale = static_cast<float>(scales[group_idx]) / 64.0f;
            out[e] = (static_cast<float>(q) - 1.5f) * scale * d;
        }
    }

    InferenceEngine::~InferenceEngine() {
        for (auto& [name, meta] : m_engineContext.tensors) {
            if (meta.dequantizedData != nullptr) {
                delete[] meta.dequantizedData;
                meta.dequantizedData = nullptr;
            }
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

        if (!m_tokenizer.loadFromGGUF(modelPath)) {
            std::cerr << "[InferenceEngine] Failed to load tokenizer from: " << modelPath << std::endl;
            return false;
        }

        KVCacheConfig kvConfig;
        kvConfig.numLayers = static_cast<uint32_t>(m_modelConfig.numLayers);
        kvConfig.maxSeqLen = std::min<uint64_t>(m_modelConfig.maxSeqLen, 4096);
        kvConfig.headDim = m_modelConfig.hiddenDim / m_modelConfig.numHeads;
        kvConfig.numHeads = m_modelConfig.numHeads;
        kvConfig.device = m_vulkanDevice;
        kvConfig.physicalDevice = m_vulkanPhysicalDevice;

        if (!m_kvCache.init(kvConfig)) {
            std::cerr << "[InferenceEngine] Failed to initialize KV cache" << std::endl;
            return false;
        }

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

        m_generationLoop.setTokenizer(m_tokenizer);
        m_generationLoop.setKVCache(&m_kvCache);
        m_generationLoop.setSampler(m_sampler);
        m_generationLoop.setForwardFn([this](uint32_t layerIdx, const float* input, float* output, uint64_t tokenPos, uint32_t tokenId) {
            return this->forwardPass(layerIdx, input, output, tokenPos, tokenId);
        });
        m_generationLoop.setNumLayers(static_cast<uint32_t>(m_modelConfig.numLayers));
        m_generationLoop.setHiddenDim(m_modelConfig.hiddenDim);
        m_generationLoop.setVocabSize(m_modelConfig.vocabSize);

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

        if (!m_modelLoaded) {
            result.error = "Model not loaded";
            return result;
        }

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

        GenerationConfig genConfig;
        genConfig.maxTokens = config.maxGenTokens;
        genConfig.addBos = config.addBos;
        genConfig.addEos = config.addEos;
        genConfig.skipSpecialTokens = config.skipSpecialTokens;
        genConfig.sampling = m_sampler.params();
        m_generationLoop.setConfig(genConfig);

        auto startTime = std::chrono::high_resolution_clock::now();
        GenerationResult genResult = m_generationLoop.generate(prompt);
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

    bool InferenceEngine::forwardPass(uint32_t layerIdx, const float* input, float* output, uint64_t tokenPos, uint32_t tokenId) {
        uint32_t hiddenDim = m_modelConfig.hiddenDim;
        uint32_t numHeads = m_modelConfig.numHeads;
        uint32_t headDim = hiddenDim / numHeads;
        uint32_t intermediateDim = m_modelConfig.intermediateDim;

        if (hiddenDim == 0) hiddenDim = 3072;
        if (numHeads == 0) numHeads = 32;
        if (headDim == 0) headDim = hiddenDim / numHeads;
        if (intermediateDim == 0) intermediateDim = hiddenDim * 8 / 3;

        static thread_local float hidden[16384];
        static thread_local float normed[16384];
        static thread_local float attnOut[16384];
        static thread_local float q[16384];
        static thread_local float k[16384];
        static thread_local float v[16384];
        static thread_local float ffnOut[16384];
        static thread_local float normed2[16384];
        static thread_local float gate[16384];
        static thread_local float up[16384];
        static thread_local float activated[16384];

        if (input == nullptr) {
            const float* embedData = getTensorData("token_embd.weight");
            if (embedData && tokenId < m_modelConfig.vocabSize) {
                const float* tokenEmbed = embedData + tokenId * hiddenDim;
                for (uint32_t i = 0; i < hiddenDim; ++i) hidden[i] = tokenEmbed[i];
            } else {
                for (uint32_t i = 0; i < hiddenDim; ++i) hidden[i] = 0.0f;
            }
        } else {
            for (uint32_t i = 0; i < hiddenDim; ++i) hidden[i] = input[i];
        }

        std::string layerPrefix = "blk." + std::to_string(layerIdx) + ".";

        const float* attnNormW = getTensorFP32(layerPrefix + "attn_norm.weight");
        float attnNormEps = 1e-5f;
        rmsNorm(hidden, normed, hiddenDim, attnNormW, attnNormEps);

        const float* wQKV = getTensorFP32(layerPrefix + "attn_qkv.weight");
        if (!wQKV) {
            for (uint32_t i = 0; i < hiddenDim; ++i) output[i] = hidden[i];
            return true;
        }

        // QKV projections via CPU GEMV
        uint32_t qkvRows = hiddenDim * 3;
        uint32_t qkvCols = hiddenDim;
        for (uint32_t i = 0; i < qkvRows; ++i) {
            float sum = 0.0f;
            for (uint32_t j = 0; j < qkvCols; j += 8) {
                uint32_t remaining = qkvCols - j;
                if (remaining >= 8) {
                    __m256 w = _mm256_loadu_ps(&wQKV[i * qkvCols + j]);
                    __m256 x = _mm256_loadu_ps(&normed[j]);
                    __m256 p = _mm256_mul_ps(w, x);
                    float tmp[8];
                    _mm256_storeu_ps(tmp, p);
                    sum += tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
                    j += 7;
                } else {
                    sum += normed[j] * wQKV[i * qkvCols + j];
                }
            }
            if (i < hiddenDim) q[i] = sum;
            else if (i < 2 * hiddenDim) k[i - hiddenDim] = sum;
            else v[i - 2 * hiddenDim] = sum;
        }

        // Apply RoPE to Q and K
        float ropeTheta = m_modelConfig.ropeThetaGlobal;
        if (ropeTheta == 0.0f) ropeTheta = 10000.0f;

        for (uint32_t h = 0; h < numHeads; ++h) {
            for (uint32_t d = 0; d < headDim; d += 2) {
                float freq = 1.0f / std::powf(ropeTheta, static_cast<float>(d) / static_cast<float>(headDim));
                float angle = static_cast<float>(tokenPos) * freq;
                float cos_a = std::cosf(angle);
                float sin_a = std::sinf(angle);

                float q0 = q[h * headDim + d];
                float q1 = q[h * headDim + d + 1];
                float k0 = k[h * headDim + d];
                float k1 = k[h * headDim + d + 1];

                q[h * headDim + d] = q0 * cos_a - q1 * sin_a;
                q[h * headDim + d + 1] = q0 * sin_a + q1 * cos_a;
                k[h * headDim + d] = k0 * cos_a - k1 * sin_a;
                k[h * headDim + d + 1] = k0 * sin_a + k1 * cos_a;
            }
        }

        if (m_kvCache.isInitialized()) {
            m_kvCache.write(layerIdx, tokenPos, q, v);
        }

        uint64_t numTokens = m_kvCache.isInitialized() ? m_kvCache.size(layerIdx) : 0;
        if (numTokens == 0) numTokens = 1;

        float scores[4096];
        float scale = 1.0f / std::sqrtf(static_cast<float>(headDim));

        for (uint64_t t = 0; t < numTokens; ++t) {
            float score = 0.0f;
            for (uint32_t h = 0; h < numHeads; ++h) {
                for (uint32_t d = 0; d < headDim; ++d) {
                    score += q[h * headDim + d] * k[h * headDim + d];
                }
            }
            scores[t] = score * scale;
        }

        float maxScore = scores[0];
        for (uint64_t t = 1; t < numTokens; ++t) {
            if (scores[t] > maxScore) maxScore = scores[t];
        }
        float sumExp = 0.0f;
        for (uint64_t t = 0; t < numTokens; ++t) {
            scores[t] = std::expf(scores[t] - maxScore);
            sumExp += scores[t];
        }
        for (uint64_t t = 0; t < numTokens; ++t) {
            scores[t] /= sumExp;
        }

        for (uint32_t i = 0; i < hiddenDim; ++i) attnOut[i] = 0.0f;
        for (uint64_t t = 0; t < numTokens; ++t) {
            for (uint32_t i = 0; i < hiddenDim; ++i) {
                attnOut[i] += scores[t] * v[i];
            }
        }

        const float* wO = getTensorFP32(layerPrefix + "attn_output.weight");
        if (wO) {
            for (uint32_t i = 0; i < hiddenDim; ++i) {
                float sum = 0.0f;
                for (uint32_t j = 0; j < hiddenDim; j += 8) {
                    uint32_t remaining = hiddenDim - j;
                    if (remaining >= 8) {
                        __m256 w = _mm256_loadu_ps(&wO[i * hiddenDim + j]);
                        __m256 x = _mm256_loadu_ps(&attnOut[j]);
                        __m256 p = _mm256_mul_ps(w, x);
                        float tmp[8];
                        _mm256_storeu_ps(tmp, p);
                        sum += tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
                        j += 7;
                    } else {
                        sum += attnOut[j] * wO[i * hiddenDim + j];
                    }
                }
                attnOut[i] = sum;
            }
        }

        // Residual connection
        for (uint32_t i = 0; i < hiddenDim; ++i) {
            hidden[i] = hidden[i] + attnOut[i];
        }

        // Pre-FFN RMSNorm
        const float* ffnNormW = getTensorFP32(layerPrefix + "ffn_norm.weight");
        rmsNorm(hidden, normed2, hiddenDim, ffnNormW, attnNormEps);

        // FFN
        const float* wGate = getTensorFP32(layerPrefix + "ffn_gate.weight");
        const float* wUp = getTensorFP32(layerPrefix + "ffn_up.weight");
        const float* wDown = getTensorFP32(layerPrefix + "ffn_down.weight");

        uint32_t effIntermediate = std::min<uint32_t>(intermediateDim, 16384u);

        if (wGate && wUp && wDown) {
            // gate = normed2 @ W_gate
            for (uint32_t i = 0; i < effIntermediate; ++i) {
                float sum = 0.0f;
                for (uint32_t j = 0; j < hiddenDim; j += 8) {
                    uint32_t remaining = hiddenDim - j;
                    if (remaining >= 8) {
                        __m256 w = _mm256_loadu_ps(&wGate[i * hiddenDim + j]);
                        __m256 x = _mm256_loadu_ps(&normed2[j]);
                        __m256 p = _mm256_mul_ps(w, x);
                        float tmp[8];
                        _mm256_storeu_ps(tmp, p);
                        sum += tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
                        j += 7;
                    } else {
                        sum += normed2[j] * wGate[i * hiddenDim + j];
                    }
                }
                gate[i] = sum;
            }

            // up = normed2 @ W_up
            for (uint32_t i = 0; i < effIntermediate; ++i) {
                float sum = 0.0f;
                for (uint32_t j = 0; j < hiddenDim; j += 8) {
                    uint32_t remaining = hiddenDim - j;
                    if (remaining >= 8) {
                        __m256 w = _mm256_loadu_ps(&wUp[i * hiddenDim + j]);
                        __m256 x = _mm256_loadu_ps(&normed2[j]);
                        __m256 p = _mm256_mul_ps(w, x);
                        float tmp[8];
                        _mm256_storeu_ps(tmp, p);
                        sum += tmp[0] + tmp[1] + tmp[2] + tmp[3] + tmp[4] + tmp[5] + tmp[6] + tmp[7];
                        j += 7;
                    } else {
                        sum += normed2[j] * wUp[i * hiddenDim + j];
                    }
                }
                up[i] = sum;
            }

            // activated = SiLU(gate) * up
            for (uint32_t i = 0; i < effIntermediate; ++i) {
                float silu = gate[i] / (1.0f + std::expf(-gate[i]));
                activated[i] = silu * up[i];
            }

            // down = activated @ W_down
            for (uint32_t i = 0; i < hiddenDim; ++i) {
                float sum = 0.0f;
                for (uint32_t j = 0; j < effIntermediate; j += 8) {
                    uint32_t remaining = effIntermediate - j;
                    if (remaining >= 8) {
                        sum += activated[j] * wDown[j * hiddenDim + i];
                        if (j + 1 < effIntermediate) sum += activated[j+1] * wDown[(j+1) * hiddenDim + i];
                        if (j + 2 < effIntermediate) sum += activated[j+2] * wDown[(j+2) * hiddenDim + i];
                        if (j + 3 < effIntermediate) sum += activated[j+3] * wDown[(j+3) * hiddenDim + i];
                        if (j + 4 < effIntermediate) sum += activated[j+4] * wDown[(j+4) * hiddenDim + i];
                        if (j + 5 < effIntermediate) sum += activated[j+5] * wDown[(j+5) * hiddenDim + i];
                        if (j + 6 < effIntermediate) sum += activated[j+6] * wDown[(j+6) * hiddenDim + i];
                        if (j + 7 < effIntermediate) sum += activated[j+7] * wDown[(j+7) * hiddenDim + i];
                        j += 7;
                    } else {
                        sum += activated[j] * wDown[j * hiddenDim + i];
                    }
                }
                output[i] = sum;
            }
        } else {
            for (uint32_t i = 0; i < hiddenDim; ++i) output[i] = 0.0f;
        }

        // Residual connection
        for (uint32_t i = 0; i < hiddenDim; ++i) {
            output[i] = hidden[i] + output[i];
        }

        return true;
    }

    void InferenceEngine::rmsNorm(const float* input, float* output, uint32_t dim,
                                   const float* weight, float eps) {
        float sumSq = 0.0f;
        for (uint32_t i = 0; i < dim; ++i) {
            sumSq += input[i] * input[i];
        }
        float meanSq = sumSq / static_cast<float>(dim);
        float scale = 1.0f / std::sqrtf(meanSq + eps);
        for (uint32_t i = 0; i < dim; ++i) {
            float val = input[i] * scale;
            if (weight) val *= weight[i];
            output[i] = val;
        }
    }

    void InferenceEngine::stopGeneration() {
        m_generationLoop.generateWithControl("", [](uint32_t, const std::string&) {
            return false;
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

    const float* InferenceEngine::getTensorData(const std::string& name) const {
        auto it = m_engineContext.tensors.find(name);
        if (it != m_engineContext.tensors.end() && it->second.dataData) {
            return static_cast<const float*>(it->second.dataData);
        }
        return nullptr;
    }

    const float* InferenceEngine::getTensorFP32(const std::string& name) const {
        auto it = m_engineContext.tensors.find(name);
        if (it == m_engineContext.tensors.end()) return nullptr;

        GGUFTensorMeta& meta = const_cast<GGUFTensorMeta&>(it->second);
        if (meta.dataData == nullptr) return nullptr;

        if (meta.type == 0) {
            return static_cast<const float*>(meta.dataData);
        }

        if (meta.type == 10) {
            uint64_t elements = 1;
            for (auto d : meta.dims) elements *= d;
            uint32_t numBlocks = (elements + 255) / 256;

            if (meta.dequantizedData == nullptr) {
                meta.dequantizedData = new float[elements];
                const uint8_t* blockData = static_cast<const uint8_t*>(meta.dataData);
                for (uint32_t b = 0; b < numBlocks; ++b) {
                    uint32_t blockElements = std::min<uint32_t>(256, elements - b * 256);
                    dequantize_q2k_block(blockData + b * 84, blockElements, meta.dequantizedData + b * 256);
                }
            }
            return static_cast<const float*>(meta.dequantizedData);
        }

        return nullptr;
    }

} // namespace Deep2Rom::Inference
