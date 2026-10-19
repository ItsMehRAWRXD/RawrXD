#pragma once
#include "Tokenizer.hpp"
#include "KVCache.hpp"
#include "Sampling.hpp"
#include "GenerationLoop.hpp"
#include "VulkanComputeEngine.hpp"
#include "../GGUFLoader.hpp"
#include <vulkan/vulkan.h>
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <atomic>
#include <mutex>
#include <chrono>

namespace Deep2Rom::Compute {
    class VulkanGEMV;
}

namespace Deep2Rom::Inference {

    // Inference engine configuration
    struct EngineConfig {
        std::string modelPath;
        uint32_t maxSeqLen = 4096;
        uint32_t maxGenTokens = 256;
        float temperature = 0.7f;
        float topP = 0.9f;
        int32_t topK = 50;
        float frequencyPenalty = 0.0f;
        float presencePenalty = 0.0f;
        uint64_t seed = 42;
        bool addBos = true;
        bool addEos = true;
        bool skipSpecialTokens = true;
        VkDevice vulkanDevice = VK_NULL_HANDLE;
        VkPhysicalDevice vulkanPhysicalDevice = VK_NULL_HANDLE;
    };

    struct InferenceResult {
        std::string text;
        std::vector<uint32_t> tokens;
        uint32_t tokensGenerated = 0;
        bool stoppedByEOS = false;
        bool stoppedByLimit = false;
        double totalTimeMs = 0.0;
        double avgTPS = 0.0;
        bool success = false;
        std::string error;
    };

    class InferenceEngine {
    public:
        InferenceEngine() = default;
        ~InferenceEngine();

        bool init(VkDevice device, VkPhysicalDevice physicalDevice);
        bool loadModel(const std::string& modelPath);

        InferenceResult generate(const std::string& prompt,
                                 uint32_t maxTokens = 256,
                                 float temperature = 0.7f,
                                 float topP = 0.9f,
                                 int32_t topK = 50);

        InferenceResult generate(const std::string& prompt, const EngineConfig& config);

        bool isLoaded() const { return m_modelLoaded; }
        const ModelConfig& modelConfig() const { return m_modelConfig; }

        uint32_t vocabSize() const;
        uint32_t bosTokenId() const;
        uint32_t eosTokenId() const;

        void stopGeneration();

        struct Stats {
            uint32_t totalTokensGenerated = 0;
            double totalTimeMs = 0.0;
            double avgTPS = 0.0;
        };
        Stats stats() const;

    private:
        bool forwardPass(uint32_t layerIdx,
                         const float* input,
                         float* output,
                         uint64_t tokenPos,
                         uint32_t tokenId);

        bool runLayer(uint32_t layerIdx,
                      const float* hiddenStates,
                      float* output,
                      uint64_t tokenPos,
                      uint32_t hiddenDim);

        bool computeAttention(uint32_t layerIdx,
                              const float* query,
                              float* output,
                              uint64_t tokenPos,
                              uint32_t hiddenDim,
                              uint32_t numHeads,
                              uint32_t headDim);

        bool computeFFN(uint32_t layerIdx,
                        const float* hiddenStates,
                        float* output,
                        uint32_t hiddenDim,
                        uint32_t intermediateDim);

        void rmsNorm(const float* input, float* output, uint32_t dim, const float* weight, float eps);

        const float* getTensorData(const std::string& name) const;
        const float* getTensorFP32(const std::string& name) const;

        EngineConfig m_config;
        ModelConfig m_modelConfig;
        EngineContext m_engineContext;
        Tokenizer m_tokenizer;
        KVCache m_kvCache;
        GenerationLoop m_generationLoop;
        Sampler m_sampler;

        bool m_modelLoaded = false;
        bool m_vulkanInitialized = false;
        VkDevice m_vulkanDevice = VK_NULL_HANDLE;
        VkPhysicalDevice m_vulkanPhysicalDevice = VK_NULL_HANDLE;

        Stats m_stats;
        std::mutex m_statsMutex;
    };

} // namespace Deep2Rom::Inference
