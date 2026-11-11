// ============================================================================
// Inference Engine with Quantized Backend Integration - Implementation
// ============================================================================

#include "inference_engine_quantized.hpp"
#include <iostream>
#include <functional>

namespace RawrXD {
namespace Core {

// ============================================================================
// Quantized Inference Engine Implementation
// ============================================================================

class QuantizedInferenceEngine::Impl {
public:
    std::unique_ptr<Inference::QuantizedInferenceRouter> router;
    InferenceEngine::InferenceConfig config;
    std::string lastError;
    bool initialized = false;
    bool running = false;
    
    bool Initialize(const InferenceEngine::InferenceConfig& cfg) {
        config = cfg;
        
        // Create production router with quantized support
        router = Inference::CreateProductionRouter();
        if (!router) {
            lastError = "Failed to create quantized inference router";
            return false;
        }
        
        initialized = true;
        return true;
    }
    
    bool LoadModel(const char* ggufPath) {
        if (!initialized) {
            lastError = "Engine not initialized";
            return false;
        }
        
        if (!router->LoadModel(ggufPath)) {
            lastError = router->GetLastError();
            return false;
        }
        
        return true;
    }
    
    InferenceEngine::InferenceResult RunInference(const char* prompt) {
        InferenceEngine::InferenceResult result;
        
        if (!initialized || !router->IsModelLoaded()) {
            result.status = InferenceEngine::InferenceResult::Status::NotInitialized;
            result.errorMessage = "Model not loaded";
            return result;
        }
        
        running = true;
        
        // Run inference through quantized router
        auto routerResult = router->RunInference(prompt);
        
        // Convert router result to engine result
        result.status = routerResult.status;
        result.outputText = routerResult.outputText;
        result.tokensGenerated = routerResult.tokensGenerated;
        result.tokensPerSecond = routerResult.tokensPerSecond;
        result.latencyMs = routerResult.latencyMs;
        result.elapsedMicroseconds = routerResult.elapsedMicroseconds;
        result.errorMessage = routerResult.errorMessage;
        
        running = false;
        return result;
    }
    
    bool RunInferenceAsync(const char* prompt, std::function<void(const InferenceEngine::InferenceResult&)> onComplete) {
        // Synchronous implementation for now
        auto result = RunInference(prompt);
        if (onComplete) {
            onComplete(result);
        }
        return result.status == InferenceEngine::InferenceResult::Status::Success;
    }
    
    void AbortInference() {
        running = false;
    }
    
    bool IsRunning() const {
        return running;
    }
    
    bool IsModelLoaded() const {
        return router && router->IsModelLoaded();
    }
    
    const char* GetLastError() const {
        return lastError.c_str();
    }
    
    size_t GetMemoryUsage() const {
        return router ? router->GetMemoryUsage() : 0;
    }
    
    size_t GetPeakMemoryUsage() const {
        return GetMemoryUsage(); // Same for now
    }
    
    void CompactMemory() {
        // No-op for now
    }
    
    bool IsUsingAVX512() const {
        return config.useAVX512;
    }
};

QuantizedInferenceEngine::QuantizedInferenceEngine() 
    : pImpl(std::make_unique<Impl>()) {}

QuantizedInferenceEngine::~QuantizedInferenceEngine() = default;

bool QuantizedInferenceEngine::Initialize(const InferenceEngine::InferenceConfig& config) {
    return pImpl->Initialize(config);
}

bool QuantizedInferenceEngine::LoadModel(const char* ggufPath) {
    return pImpl->LoadModel(ggufPath);
}

InferenceEngine::InferenceResult QuantizedInferenceEngine::RunInference(const char* prompt) {
    return pImpl->RunInference(prompt);
}

bool QuantizedInferenceEngine::RunInferenceAsync(const char* prompt, std::function<void(const InferenceEngine::InferenceResult&)> onComplete) {
    return pImpl->RunInferenceAsync(prompt, onComplete);
}

void QuantizedInferenceEngine::AbortInference() {
    pImpl->AbortInference();
}

bool QuantizedInferenceEngine::IsRunning() const {
    return pImpl->IsRunning();
}

bool QuantizedInferenceEngine::IsModelLoaded() const {
    return pImpl->IsModelLoaded();
}

const char* QuantizedInferenceEngine::GetLastError() const {
    return pImpl->GetLastError();
}

size_t QuantizedInferenceEngine::GetMemoryUsage() const {
    return pImpl->GetMemoryUsage();
}

size_t QuantizedInferenceEngine::GetPeakMemoryUsage() const {
    return pImpl->GetPeakMemoryUsage();
}

void QuantizedInferenceEngine::CompactMemory() {
    pImpl->CompactMemory();
}

bool QuantizedInferenceEngine::IsUsingAVX512() const {
    return pImpl->IsUsingAVX512();
}

bool QuantizedInferenceEngine::IsUsingQuantizedBackend() const {
    return pImpl->router && pImpl->router->IsUsingQuantizedBackend();
}

const char* QuantizedInferenceEngine::GetActiveBackendName() const {
    return pImpl->router ? pImpl->router->GetActiveBackendName() : "none";
}

const char* QuantizedInferenceEngine::GetQuantizationType() const {
    return pImpl->router ? pImpl->router->GetQuantizationType() : "unknown";
}

float QuantizedInferenceEngine::GetLastTokensPerSecond() const {
    return pImpl->router ? pImpl->router->GetLastTokensPerSecond() : 0.0f;
}

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<QuantizedInferenceEngine> CreateProductionInferenceEngine() {
    return std::make_unique<QuantizedInferenceEngine>();
}

} // namespace Core
} // namespace RawrXD
