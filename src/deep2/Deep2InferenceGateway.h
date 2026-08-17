#pragma once

//==============================================================================
// Deep2InferenceGateway.h - Deep2 AI Backend Integration
// Phase 15: Complete System Unification
//
// This is the integration layer that exposes Deep2Engine through the
// unified IAIService interface. It connects the local inference engine
// to the IDE's AI service contract.
//==============================================================================

#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace Deep2 {

//==============================================================================
// AI Request/Response structures
// These are the data structures passed between IDE and Deep2
//==============================================================================
struct AIRequest {
    enum Operation {
        OpLoadModel,
        OpComplete,
        OpStream,
        OpChat,
        OpEmbed,
        OpUnload
    };
    
    Operation operation = OpComplete;
    
    // Model path (for OpLoadModel)
    std::string modelPath;
    
    // Completion parameters
    std::string prefix;
    std::string suffix;
    int maxTokens = 128;
    float temperature = 0.2f;
    float topP = 0.9f;
    
    // Streaming callback
    std::function<void(const std::string& token, bool finished)> streamCallback;
    
    // Chat messages
    std::vector<std::pair<std::string, std::string>> messages; // role, content
};

struct AIResponse {
    bool success = false;
    std::string text;
    float confidence = 0.0f;
    int tokensGenerated = 0;
    float latencyMs = 0.0f;
    std::string error;
    
    // Performance telemetry
    float tokensPerSecond = 0.0f;
    float timeToFirstToken = 0.0f;
};

//==============================================================================
// Deep2 Inference Gateway
// Singleton that manages the Deep2 inference engine
//==============================================================================
class Deep2InferenceGateway {
public:
    static Deep2InferenceGateway& Instance();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Main entry point - processes all AI requests
    AIResponse ProcessRequest(const AIRequest& request);
    
    // Convenience methods
    bool LoadModel(const std::string& modelPath);
    void UnloadModel();
    bool IsModelLoaded() const;
    
    // Get model info
    std::string GetModelName() const;
    size_t GetModelParameterCount() const;
    
    // Performance metrics
    float GetAverageTokensPerSecond() const;
    float GetPeakTokensPerSecond() const;
    
private:
    Deep2InferenceGateway() = default;
    ~Deep2InferenceGateway() = default;
    
    Deep2InferenceGateway(const Deep2InferenceGateway&) = delete;
    Deep2InferenceGateway& operator=(const Deep2InferenceGateway&) = delete;
    
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

} // namespace Deep2
