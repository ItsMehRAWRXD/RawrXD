#pragma once

//==============================================================================
// Deep2Engine.h - Deep2 Inference Engine Core
// Phase 15B: Real Executable Build
//
// This header provides the Deep2Engine class that bridges to the existing
// RawrXD inference infrastructure (InferenceEngine, GGUF loader, etc.)
//==============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <functional>

// Forward declarations for RawrXD infrastructure
namespace RawrXD {
namespace Inference {
    class InferenceEngine;
    struct EngineConfig;
    struct GenerationParams;
}
}

namespace tokenizer {
    class TokenizerBase;
}

namespace Deep2 {

//==============================================================================
// Token - Single token with metadata
//==============================================================================
struct Token {
    int id = 0;
    std::string text;
    float logit = 0.0f;
    float probability = 0.0f;
};

//==============================================================================
// GenerationResult - Result of token generation
//==============================================================================
struct GenerationResult {
    std::vector<Token> tokens;
    bool success = false;
    std::string error;
    float tokensPerSecond = 0.0f;
    float timeToFirstToken = 0.0f;
    uint64_t totalTokens = 0;
};

//==============================================================================
// SamplingConfig - Token sampling parameters
//==============================================================================
struct SamplingConfig {
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    float repetitionPenalty = 1.1f;
    int maxTokens = 256;
};

//==============================================================================
// Deep2Engine - Core inference engine
//==============================================================================
class Deep2Engine {
public:
    Deep2Engine();
    ~Deep2Engine();

    // Model lifecycle
    bool LoadModel(const std::string& modelPath);
    void UnloadModel();
    bool IsModelLoaded() const;
    
    // Model info
    std::string GetModelName() const;
    size_t GetMaxContextSize() const;
    size_t GetVRAMUsage() const;
    size_t GetParameterCount() const;
    
    // Generation
    GenerationResult Generate(const std::string& prompt, const SamplingConfig& config);
    void GenerateStream(const std::string& prompt, 
                        const SamplingConfig& config,
                        std::function<void(const std::string& token, bool finished)> callback);
    
    // Token operations
    std::vector<int> Tokenize(const std::string& text);
    std::string Detokenize(const std::vector<int>& tokens);
    
    // Context management
    void ClearContext();
    size_t GetContextLength() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Deep2
