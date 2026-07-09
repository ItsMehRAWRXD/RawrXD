/**
 * @file InferenceEngine.h
 * @brief Unified inference engine interface
 * 
 * Part of Production Framework - Phase 5
 * Provides abstract interface for model inference operations.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "ErrorHandling.h"
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Agentic {

/**
 * @brief Model information structure
 */
struct ModelInfo {
    std::string name;
    std::string architecture;
    size_t parameterCount;
    size_t contextLength;
    size_t embeddingSize;
    size_t headCount;
    size_t layerCount;
    size_t vocabSize;
    std::string quantization;
    std::string version;
};

/**
 * @brief Generation parameters
 */
struct GenerationParams {
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    int maxTokens = 256;
    float repetitionPenalty = 1.0f;
    std::vector<std::string> stopSequences;
    unsigned int seed = 0;
    bool streamOutput = false;
};

/**
 * @brief Generation result
 */
struct GenerationResult {
    std::string text;
    std::vector<float> tokenLogProbs;
    int tokensGenerated;
    std::chrono::milliseconds generationTime;
    bool finished = false;
    std::string finishReason;
};

/**
 * @brief Token information
 */
struct TokenInfo {
    int id;
    std::string text;
    float logProb;
    bool isSpecial;
};

/**
 * @brief Stream callback type
 */
using StreamCallback = std::function<void(const TokenInfo&)>;

/**
 * @brief Abstract inference engine interface
 * 
 * Provides unified interface for different inference backends
 * (CPU, GPU, distributed, etc.)
 */
class InferenceEngine {
public:
    virtual ~InferenceEngine() = default;
    
    /**
     * @brief Initialize the engine
     * @return Result indicating success or failure
     */
    virtual Result<void> Initialize() = 0;
    
    /**
     * @brief Shutdown the engine
     */
    virtual void Shutdown() = 0;
    
    /**
     * @brief Check if engine is initialized
     */
    virtual bool IsInitialized() const = 0;
    
    /**
     * @brief Load a model
     * @param modelPath Path to model file
     * @return Result with model info or error
     */
    virtual Result<ModelInfo> LoadModel(const std::string& modelPath) = 0;
    
    /**
     * @brief Unload current model
     */
    virtual void UnloadModel() = 0;
    
    /**
     * @brief Check if model is loaded
     */
    virtual bool IsModelLoaded() const = 0;
    
    /**
     * @brief Get current model info
     */
    virtual Result<ModelInfo> GetModelInfo() const = 0;
    
    /**
     * @brief Generate text from prompt
     * @param prompt Input prompt
     * @param params Generation parameters
     * @return Result with generated text or error
     */
    virtual Result<GenerationResult> Generate(
        const std::string& prompt,
        const GenerationParams& params) = 0;
    
    /**
     * @brief Generate with streaming output
     * @param prompt Input prompt
     * @param params Generation parameters
     * @param callback Token callback
     * @return Result indicating success or failure
     */
    virtual Result<void> GenerateStream(
        const std::string& prompt,
        const GenerationParams& params,
        StreamCallback callback) = 0;
    
    /**
     * @brief Tokenize text
     * @param text Text to tokenize
     * @return Result with token IDs or error
     */
    virtual Result<std::vector<int>> Tokenize(const std::string& text) = 0;
    
    /**
     * @brief Detokenize tokens to text
     * @param tokens Token IDs
     * @return Result with text or error
     */
    virtual Result<std::string> Detokenize(const std::vector<int>& tokens) = 0;
    
    /**
     * @brief Get engine name
     */
    virtual std::string GetName() const = 0;
    
    /**
     * @brief Get engine version
     */
    virtual std::string GetVersion() const = 0;
};

/**
 * @brief Inference engine factory
 */
class InferenceEngineFactory {
public:
    /**
     * @brief Create CPU inference engine
     */
    static std::unique_ptr<InferenceEngine> CreateCPUEngine();
    
    /**
     * @brief Create GPU inference engine
     */
    static std::unique_ptr<InferenceEngine> CreateGPUEngine();
    
    /**
     * @brief Create engine by name
     * @param name Engine name ("cpu", "gpu", "auto")
     */
    static std::unique_ptr<InferenceEngine> CreateByName(const std::string& name);
};

} // namespace Agentic
} // namespace RawrXD
