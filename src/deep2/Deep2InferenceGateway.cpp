//==============================================================================
// Deep2InferenceGateway.cpp - Deep2 AI Backend Integration
// Phase 15: Complete System Unification
//
// This file implements the integration between Deep2Engine and the
// unified IDE AI service interface.
//==============================================================================

#include "Deep2InferenceGateway.h"
#include "Deep2Engine.h"
#include <chrono>
#include <atomic>
#include <sstream>

namespace Deep2 {

//==============================================================================
// Implementation
//==============================================================================
class Deep2InferenceGateway::Impl {
public:
    std::atomic<bool> initialized{false};
    std::atomic<bool> modelLoaded{false};
    std::string currentModelPath;

    // Real Deep2 inference engine
    std::unique_ptr<Deep2Engine> engine;

    // Performance tracking
    float avgTokensPerSecond = 0.0f;
    float peakTokensPerSecond = 0.0f;
    int requestCount = 0;

    bool Initialize() {
        // Create the real Deep2Engine instance
        engine = std::make_unique<Deep2Engine>();
        initialized = true;
        return true;
    }

    void Shutdown() {
        if (modelLoaded) {
            UnloadModel();
        }
        engine.reset();
        initialized = false;
    }

    bool LoadModel(const std::string& modelPath) {
        if (!initialized || !engine) {
            return false;
        }

        // Delegate to Deep2Engine for actual GGUF model loading
        if (!engine->LoadModel(modelPath)) {
            return false;
        }

        currentModelPath = modelPath;
        modelLoaded = true;
        return true;
    }

    void UnloadModel() {
        if (engine) {
            engine->UnloadModel();
        }
        modelLoaded = false;
        currentModelPath.clear();
    }

    AIResponse ProcessComplete(const AIRequest& request) {
        AIResponse response;

        if (!modelLoaded || !engine) {
            response.success = false;
            response.error = "No model loaded";
            return response;
        }

        auto startTime = std::chrono::high_resolution_clock::now();

        // Build prompt from prefix/suffix
        std::string prompt = request.prefix;
        if (!request.suffix.empty()) {
            prompt += "\n" + request.suffix;
        }

        // Configure sampling
        SamplingConfig config;
        config.maxTokens = request.maxTokens;
        config.temperature = request.temperature;
        config.topP = request.topP;

        // Call Deep2Engine for real inference
        GenerationResult result = engine->Generate(prompt, config);

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        response.latencyMs = static_cast<float>(duration.count());

        if (result.success) {
            // Concatenate generated tokens into response text
            std::ostringstream oss;
            for (const auto& token : result.tokens) {
                oss << token.text;
            }
            response.text = oss.str();
            response.success = true;
            response.tokensGenerated = static_cast<int>(result.tokens.size());
            response.confidence = 0.85f;  // Could compute from logprobs

            if (response.latencyMs > 0) {
                response.tokensPerSecond = (response.tokensGenerated * 1000.0f) / response.latencyMs;
                UpdatePerformanceMetrics(response.tokensPerSecond);
            }
        } else {
            response.success = false;
            response.error = result.error.empty() ? "Generation failed" : result.error;
        }

        return response;
    }

    AIResponse ProcessStream(const AIRequest& request) {
        AIResponse response;

        if (!modelLoaded || !engine) {
            response.success = false;
            response.error = "No model loaded";
            if (request.streamCallback) {
                request.streamCallback("", true);
            }
            return response;
        }

        // Build prompt from prefix/suffix
        std::string prompt = request.prefix;
        if (!request.suffix.empty()) {
            prompt += "\n" + request.suffix;
        }

        // Configure sampling
        SamplingConfig config;
        config.maxTokens = request.maxTokens;
        config.temperature = request.temperature;
        config.topP = request.topP;

        int tokensGenerated = 0;
        auto startTime = std::chrono::high_resolution_clock::now();

        // Call Deep2Engine for real streaming inference
        engine->GenerateStream(prompt, config,
            [&request, &tokensGenerated](const std::string& token, bool finished) {
                if (request.streamCallback) {
                    request.streamCallback(token, finished);
                }
                if (!finished) {
                    tokensGenerated++;
                }
            });

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        response.latencyMs = static_cast<float>(duration.count());
        response.success = true;
        response.tokensGenerated = tokensGenerated;

        if (response.latencyMs > 0) {
            response.tokensPerSecond = (tokensGenerated * 1000.0f) / response.latencyMs;
            UpdatePerformanceMetrics(response.tokensPerSecond);
        }

        return response;
    }

    AIResponse ProcessChat(const AIRequest& request) {
        AIResponse response;

        if (!modelLoaded || !engine) {
            response.success = false;
            response.error = "No model loaded";
            return response;
        }

        // Build chat prompt from messages
        std::ostringstream promptBuilder;
        for (const auto& [role, content] : request.messages) {
            if (role == "system") {
                promptBuilder << "System: " << content << "\n\n";
            } else if (role == "user") {
                promptBuilder << "User: " << content << "\n\n";
            } else if (role == "assistant") {
                promptBuilder << "Assistant: " << content << "\n\n";
            } else {
                promptBuilder << role << ": " << content << "\n\n";
            }
        }
        promptBuilder << "Assistant: ";
        std::string prompt = promptBuilder.str();

        auto startTime = std::chrono::high_resolution_clock::now();

        // Configure sampling
        SamplingConfig config;
        config.maxTokens = request.maxTokens;
        config.temperature = request.temperature;
        config.topP = request.topP;

        // Call Deep2Engine for real inference
        GenerationResult result = engine->Generate(prompt, config);

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        response.latencyMs = static_cast<float>(duration.count());

        if (result.success) {
            std::ostringstream oss;
            for (const auto& token : result.tokens) {
                oss << token.text;
            }
            response.text = oss.str();
            response.success = true;
            response.tokensGenerated = static_cast<int>(result.tokens.size());

            if (response.latencyMs > 0) {
                response.tokensPerSecond = (response.tokensGenerated * 1000.0f) / response.latencyMs;
                UpdatePerformanceMetrics(response.tokensPerSecond);
            }
        } else {
            response.success = false;
            response.error = result.error.empty() ? "Chat generation failed" : result.error;
        }

        return response;
    }

    void UpdatePerformanceMetrics(float tps) {
        // Update running average
        if (requestCount == 0) {
            avgTokensPerSecond = tps;
        } else {
            avgTokensPerSecond = (avgTokensPerSecond * requestCount + tps) / (requestCount + 1);
        }

        // Update peak
        if (tps > peakTokensPerSecond) {
            peakTokensPerSecond = tps;
        }

        requestCount++;
    }
};

//==============================================================================
// Singleton
//==============================================================================
Deep2InferenceGateway& Deep2InferenceGateway::Instance() {
    static Deep2InferenceGateway instance;
    return instance;
}

// Constructor/destructor are defaulted in header

//==============================================================================
// Lifecycle
//==============================================================================
bool Deep2InferenceGateway::Initialize() {
    return pImpl->Initialize();
}

void Deep2InferenceGateway::Shutdown() {
    pImpl->Shutdown();
}

bool Deep2InferenceGateway::IsInitialized() const {
    return pImpl->initialized;
}

//==============================================================================
// Model Management
//==============================================================================
bool Deep2InferenceGateway::LoadModel(const std::string& modelPath) {
    return pImpl->LoadModel(modelPath);
}

void Deep2InferenceGateway::UnloadModel() {
    pImpl->UnloadModel();
}

bool Deep2InferenceGateway::IsModelLoaded() const {
    return pImpl->modelLoaded;
}

std::string Deep2InferenceGateway::GetModelName() const {
    return pImpl->currentModelPath;
}

size_t Deep2InferenceGateway::GetModelParameterCount() const {
    if (pImpl->engine && pImpl->modelLoaded) {
        return pImpl->engine->GetParameterCount();
    }
    return 0;
}

//==============================================================================
// Request Processing
//==============================================================================
AIResponse Deep2InferenceGateway::ProcessRequest(const AIRequest& request) {
    switch (request.operation) {
        case AIRequest::OpLoadModel:
            return AIResponse{LoadModel(request.modelPath)};
            
        case AIRequest::OpComplete:
            return pImpl->ProcessComplete(request);
            
        case AIRequest::OpStream:
            return pImpl->ProcessStream(request);
            
        case AIRequest::OpChat:
            return pImpl->ProcessChat(request);
            
        case AIRequest::OpUnload:
            UnloadModel();
            return AIResponse{true};
            
        default:
            return AIResponse{false, "", 0.0f, 0, 0.0f, "Unknown operation"};
    }
}

//==============================================================================
// Performance Metrics
//==============================================================================
float Deep2InferenceGateway::GetAverageTokensPerSecond() const {
    return pImpl->avgTokensPerSecond;
}

float Deep2InferenceGateway::GetPeakTokensPerSecond() const {
    return pImpl->peakTokensPerSecond;
}

} // namespace Deep2
