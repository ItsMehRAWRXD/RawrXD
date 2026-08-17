#include "Deep2Engine.h"
#include "../inference/InferenceEngine.h"
#include "../inference/InferenceEngine.hpp"
#include "../tokenizer/tokenizer_base.hpp"
#include "../inference/sampling.hpp"

#include <chrono>
#include <algorithm>
#include <random>

namespace Deep2 {

//==============================================================================
// Deep2Engine Implementation
//==============================================================================
class Deep2Engine::Impl {
public:
    std::unique_ptr<RawrXD::Inference::InferenceEngine> inferenceEngine;
    std::unique_ptr<tokenizer::TokenizerBase> tokenizer;
    rawrxd::SamplingEngine sampler;
    
    std::string modelPath;
    bool modelLoaded = false;
    size_t maxContextSize = 4096;
    size_t vramUsage = 0;
    size_t parameterCount = 0;
    RawrXD::Inference::ModelInfo modelInfo;
    
    // Performance tracking
    std::chrono::high_resolution_clock::time_point generationStart;
    float tokensPerSecond = 0.0f;
    
    bool InitializeEngine() {
        // Initialize with default config
        return true;
    }
    
    bool LoadGGUFModel(const std::string& path) {
        // Use the existing InferenceEngine infrastructure
        RawrXD::Inference::EngineConfig config;
        config.modelPath = path;
        config.maxContextLength = 32768;  // Default to 32K context
        config.useGPU = true;
        config.useMemoryMapping = true;
        
        // Create inference engine using factory
        inferenceEngine = RawrXD::Inference::InferenceEngine::Create(config);
        
        if (!inferenceEngine->LoadModel(path)) {
            return false;
        }
        
        modelPath = path;
        modelLoaded = true;
        
        // Get model info
        modelInfo = inferenceEngine->GetModelInfo();
        maxContextSize = modelInfo.contextLength;

        // Estimate parameter count from model dimensions
        // params ≈ vocab_size * embedding_dim + num_layers * (4 * embedding_dim^2)
        // This is a rough estimate; real count comes from tensor metadata
        if (modelInfo.vocabSize > 0 && modelInfo.embeddingDim > 0 && modelInfo.numLayers > 0) {
            size_t embeddingParams = static_cast<size_t>(modelInfo.vocabSize) * modelInfo.embeddingDim;
            size_t layerParams = static_cast<size_t>(modelInfo.numLayers) * 4 * modelInfo.embeddingDim * modelInfo.embeddingDim;
            parameterCount = embeddingParams + layerParams;
        }

        // Estimate VRAM usage from model size
        vramUsage = modelInfo.modelSize;

        return true;
    }
    
    GenerationResult GenerateTokens(const std::string& prompt, const SamplingConfig& config) {
        GenerationResult result;
        
        if (!modelLoaded || !inferenceEngine) {
            result.error = "No model loaded";
            return result;
        }
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Use the inference engine
        RawrXD::Inference::GenerationParams params;
        params.maxTokens = config.maxTokens;
        params.temperature = config.temperature;
        params.topP = config.topP;
        params.topK = config.topK;
        params.repeatPenalty = config.repetitionPenalty;
        
        auto genResult = inferenceEngine->Generate(prompt, params);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        // Convert result
        result.success = genResult.success;
        result.totalTokens = genResult.tokens.size();
        
        if (duration.count() > 0) {
            result.tokensPerSecond = (result.totalTokens * 1000.0f) / duration.count();
        }
        
        // Convert tokens
        for (const auto& token : genResult.tokens) {
            Token t;
            t.id = token.id;
            t.text = token.text;
            t.logit = token.logprob;
            result.tokens.push_back(t);
        }
        
        return result;
    }
    
    void GenerateTokensStream(const std::string& prompt, 
                              const SamplingConfig& config,
                              std::function<void(const std::string& token, bool finished)> callback) {
        if (!modelLoaded || !inferenceEngine) {
            if (callback) callback("", true);
            return;
        }
        
        RawrXD::Inference::GenerationParams params;
        params.maxTokens = config.maxTokens;
        params.temperature = config.temperature;
        params.topP = config.topP;
        params.topK = config.topK;
        
        // Stream generation
        inferenceEngine->GenerateStreaming(prompt, params, 
            [&callback](const RawrXD::Inference::TokenInfo& token) {
                if (callback) {
                    callback(token.text, token.isSpecial);  // Use isSpecial as end marker
                }
                return true;  // Continue streaming
            });
    }
};

//==============================================================================
// Deep2Engine Public Interface
//==============================================================================
Deep2Engine::Deep2Engine() : pImpl(std::make_unique<Impl>()) {}
Deep2Engine::~Deep2Engine() = default;

bool Deep2Engine::LoadModel(const std::string& modelPath) {
    return pImpl->LoadGGUFModel(modelPath);
}

void Deep2Engine::UnloadModel() {
    pImpl->inferenceEngine.reset();
    pImpl->modelLoaded = false;
    pImpl->modelPath.clear();
    pImpl->vramUsage = 0;
    pImpl->parameterCount = 0;
    pImpl->modelInfo = {};
}

bool Deep2Engine::IsModelLoaded() const {
    return pImpl->modelLoaded;
}

std::string Deep2Engine::GetModelName() const {
    return pImpl->modelPath;
}

size_t Deep2Engine::GetMaxContextSize() const {
    return pImpl->maxContextSize;
}

size_t Deep2Engine::GetVRAMUsage() const {
    // Return actual VRAM usage from model info
    return pImpl->vramUsage;
}

size_t Deep2Engine::GetParameterCount() const {
    // Return estimated parameter count from model metadata
    return pImpl->parameterCount;
}

GenerationResult Deep2Engine::Generate(const std::string& prompt, const SamplingConfig& config) {
    return pImpl->GenerateTokens(prompt, config);
}

void Deep2Engine::GenerateStream(const std::string& prompt, 
                                  const SamplingConfig& config,
                                  std::function<void(const std::string& token, bool finished)> callback) {
    pImpl->GenerateTokensStream(prompt, config, callback);
}

std::vector<int> Deep2Engine::Tokenize(const std::string& text) {
    if (pImpl->inferenceEngine) {
        return pImpl->inferenceEngine->Tokenize(text);
    }
    return {};
}

std::string Deep2Engine::Detokenize(const std::vector<int>& tokens) {
    if (pImpl->inferenceEngine) {
        return pImpl->inferenceEngine->Detokenize(tokens);
    }
    return "";
}

void Deep2Engine::ClearContext() {
    if (pImpl->inferenceEngine) {
        pImpl->inferenceEngine->ClearContext();
    }
}

size_t Deep2Engine::GetContextLength() const {
    if (pImpl->inferenceEngine) {
        return pImpl->inferenceEngine->GetContextLength();
    }
    return 0;
}

} // namespace Deep2
