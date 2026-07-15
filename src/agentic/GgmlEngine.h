/**
 * @file GgmlEngine.h
 * @brief GGML-based inference engine implementation
 * 
 * Bridges the abstract InferenceEngine interface to actual GGML functions.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "InferenceEngine.h"
#include "Config.h"
#include "Logger.h"
#include "ErrorHandling.h"

// Forward declarations for GGML types
struct ggml_context;
struct ggml_model;
struct ggml_tensor;
struct ggml_vocab;

namespace RawrXD {
namespace Agentic {

/**
 * @brief GGML-backed inference engine implementation
 * 
 * Implements the InferenceEngine interface using GGML for:
 * - Model loading from GGUF files
 * - Transformer inference
 * - Tokenization
 * - Text generation with sampling
 */
class GgmlEngine : public InferenceEngine {
public:
    GgmlEngine();
    ~GgmlEngine() override;

    // InferenceEngine interface implementation
    Result<void> Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override;
    
    Result<ModelInfo> LoadModel(const std::string& modelPath) override;
    void UnloadModel() override;
    bool IsModelLoaded() const override;
    Result<ModelInfo> GetModelInfo() const override;
    
    Result<GenerationResult> Generate(
        const std::string& prompt,
        const GenerationParams& params) override;
    
    Result<void> GenerateStream(
        const std::string& prompt,
        const GenerationParams& params,
        StreamCallback callback) override;
    
    Result<std::vector<int>> Tokenize(const std::string& text) override;
    Result<std::string> Detokenize(const std::vector<int>& tokens) override;
    
    std::string GetName() const override { return "GGML"; }
    std::string GetVersion() const override { return "1.0.0"; }

private:
    // Internal state
    bool m_initialized;
    bool m_modelLoaded;
    ModelInfo m_modelInfo;
    
    // GGML state (opaque pointers)
    struct GGMLState;
    std::unique_ptr<GGMLState> m_state;
    
    // Internal helpers
    Result<void> InitializeGGML();
    Result<std::vector<float>> RunForward(const std::vector<int>& tokens);
    int SampleToken(const std::vector<float>& logits, const GenerationParams& params);
    Result<std::string> GenerateInternal(
        const std::string& prompt,
        const GenerationParams& params,
        StreamCallback callback);
    
    // Logging
    void Log(LogLevel level, const std::string& message);
};

} // namespace Agentic
} // namespace RawrXD
