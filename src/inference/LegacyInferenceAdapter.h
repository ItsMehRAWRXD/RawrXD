/**
 * @file LegacyInferenceAdapter.h
 * @brief Adapter that wraps existing inference code behind the new InferenceEngine interface
 * 
 * Part of Phase 2: Adapter Layer Implementation
 * Allows gradual migration from legacy inference code to unified InferenceEngine API
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "InferenceEngine.h"
#include <memory>

// Forward declarations for legacy components
class LegacyInferenceEngine;
class LegacyModel;
class LegacyTokenizer;

namespace RawrXD {
namespace Inference {

/**
 * @brief Adapter that wraps legacy inference components behind the new InferenceEngine interface
 * 
 * This adapter allows existing inference code to continue working while providing
 * the new unified InferenceEngine API. Gradually, the internal implementation will
 * be replaced with the new InferenceEngineImpl.
 * 
 * Usage:
 *   auto legacyEngine = GetExistingInferenceEngine();
 *   auto engine = LegacyInferenceAdapter::Create(legacyEngine);
 *   engine->LoadModel("model.gguf");
 *   auto result = engine->Generate("Hello", params);
 */
class LegacyInferenceAdapter : public InferenceEngine {
public:
    /**
     * @brief Create adapter wrapping existing inference engine
     * @param legacyEngine Existing inference engine instance
     * @return Adapter instance implementing InferenceEngine interface
     */
    static std::unique_ptr<InferenceEngine> Create(
        LegacyInferenceEngine* legacyEngine);

    /**
     * @brief Create adapter with configuration
     * @param legacyEngine Existing inference engine instance
     * @param config Engine configuration
     * @return Adapter instance
     */
    static std::unique_ptr<InferenceEngine> Create(
        LegacyInferenceEngine* legacyEngine,
        const EngineConfig& config);

    /**
     * @brief Destructor
     */
    ~LegacyInferenceAdapter() override;

    // ------------------------------------------------------------------------
    // Model Lifecycle
    // ------------------------------------------------------------------------
    
    /**
     * @brief Load a model from file
     * @param path Path to model file (GGUF format)
     * @return true if successful
     */
    bool LoadModel(const std::string& path) override;
    
    /**
     * @brief Unload the current model
     */
    void UnloadModel() override;
    
    /**
     * @brief Check if a model is loaded
     * @return true if model is loaded and ready
     */
    bool IsModelLoaded() const override;
    
    /**
     * @brief Get information about the loaded model
     * @return ModelInfo structure
     */
    ModelInfo GetModelInfo() const override;

    // ------------------------------------------------------------------------
    // Generation
    // ------------------------------------------------------------------------
    
    /**
     * @brief Generate text from a prompt
     * @param prompt Input prompt
     * @param params Generation parameters
     * @return Generation result
     */
    GenerationResult Generate(const std::string& prompt, 
                               const GenerationParams& params) override;
    
    /**
     * @brief Generate text with streaming callback (token-by-token)
     * @param prompt Input prompt
     * @param params Generation parameters
     * @param callback Called for each token generated
     * @return Generation result
     */
    GenerationResult GenerateStreaming(const std::string& prompt,
                                        const GenerationParams& params,
                                        std::function<bool(const TokenInfo&)> callback) override;
    
    /**
     * @brief Generate text with streaming callback (string chunks)
     * @param prompt Input prompt
     * @param params Generation parameters
     * @param callback Called with text chunks
     * @return Generation result
     */
    GenerationResult GenerateStreaming(const std::string& prompt,
                                        const GenerationParams& params,
                                        std::function<void(const std::string&)> callback) override;

    // ------------------------------------------------------------------------
    // Token Operations
    // ------------------------------------------------------------------------
    
    /**
     * @brief Tokenize text
     * @param text Input text
     * @return Vector of token IDs
     */
    std::vector<int> Tokenize(const std::string& text) override;
    
    /**
     * @brief Tokenize with BOS/EOS control
     * @param text Input text
     * @param addBOS Add beginning-of-sequence token
     * @param addEOS Add end-of-sequence token
     * @return Vector of token IDs
     */
    std::vector<int> Tokenize(const std::string& text, bool addBOS, bool addEOS) override;
    
    /**
     * @brief Convert tokens to text
     * @param tokens Vector of token IDs
     * @return Detokenized text
     */
    std::string Detokenize(const std::vector<int>& tokens) override;
    
    /**
     * @brief Convert single token to text
     * @param token Token ID
     * @return Token text
     */
    std::string Detokenize(int token) override;
    
    /**
     * @brief Get information about a token
     * @param tokenId Token ID
     * @return TokenInfo structure
     */
    TokenInfo GetTokenInfo(int tokenId) override;

    // ------------------------------------------------------------------------
    // Context Management
    // ------------------------------------------------------------------------
    
    /**
     * @brief Clear the conversation context
     */
    void ClearContext() override;
    
    /**
     * @brief Get current context length in tokens
     * @return Number of tokens in context
     */
    size_t GetContextLength() const override;
    
    /**
     * @brief Get remaining context capacity
     * @return Number of tokens that can still be added
     */
    size_t GetContextRemaining() const override;
    
    /**
     * @brief Check if context is full
     * @return true if no more tokens can be added
     */
    bool IsContextFull() const override;
    
    /**
     * @brief Set the system prompt
     * @param systemPrompt System prompt text
     */
    void SetSystemPrompt(const std::string& systemPrompt) override;

    // ------------------------------------------------------------------------
    // Metrics & Diagnostics
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get metrics from last generation
     * @return PerformanceMetrics structure
     */
    PerformanceMetrics GetLastMetrics() const override;
    
    /**
     * @brief Reset metrics
     */
    void ResetMetrics() override;
    
    /**
     * @brief Validate the loaded model
     * @return true if model is valid
     */
    bool ValidateModel() override;
    
    /**
     * @brief Get last error message
     * @return Error description
     */
    std::string GetLastError() const override;

    // ------------------------------------------------------------------------
    // Advanced Features
    // ------------------------------------------------------------------------
    
    /**
     * @brief Set progress callback for generation
     * @param callback Called with progress percentage (0.0-1.0)
     */
    void SetProgressCallback(std::function<void(float)> callback) override;
    
    /**
     * @brief Cancel ongoing generation
     */
    void CancelGeneration() override;
    
    /**
     * @brief Check if generation is in progress
     * @return true if generating
     */
    bool IsGenerating() const override;
    
    /**
     * @brief Warm up the model (pre-allocate buffers)
     * @return true if successful
     */
    bool Warmup() override;
    
    /**
     * @brief Get underlying GGML context (for advanced use)
     * @return GGML context pointer (may be null)
     */
    ggml_context* GetGGMLContext() override;

    // ------------------------------------------------------------------------
    // Legacy Access (for gradual migration)
    // ------------------------------------------------------------------------
    
    /**
     * @brief Get the underlying legacy engine
     * @return Legacy engine pointer (may be null if not set)
     */
    LegacyInferenceEngine* GetLegacyEngine() const;

private:
    // Private implementation
    class Impl;
    std::unique_ptr<Impl> m_impl;

    // Private constructor - use Create() factory method
    LegacyInferenceAdapter(LegacyInferenceEngine* legacyEngine, 
                           const EngineConfig& config);
};

} // namespace Inference
} // namespace RawrXD
