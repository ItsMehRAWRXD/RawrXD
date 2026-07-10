// ============================================================================
// Inference Engine with Quantized Backend Integration
// Automatically routes Q4_0 models to 131 tok/s backend
// ============================================================================

#pragma once

#include "inference_engine.h"
#include "quantized_inference_router.hpp"
#include <memory>
#include <functional>

namespace RawrXD {
namespace Core {

// ============================================================================
// Quantized Inference Engine
// Wraps the standard InferenceEngine with automatic Q4_0 detection
// Note: Uses composition instead of inheritance since InferenceEngine has no virtual methods
// ============================================================================

class QuantizedInferenceEngine {
public:
    QuantizedInferenceEngine();
    ~QuantizedInferenceEngine();
    
    // Core operations (mirror InferenceEngine API)
    bool Initialize(const InferenceEngine::InferenceConfig& config);
    bool LoadModel(const char* ggufPath);
    InferenceEngine::InferenceResult RunInference(const char* prompt);
    bool RunInferenceAsync(const char* prompt, std::function<void(const InferenceEngine::InferenceResult&)> onComplete);
    void AbortInference();
    
    // Status queries
    bool IsRunning() const;
    bool IsModelLoaded() const;
    const char* GetLastError() const;
    
    // Memory tracking
    size_t GetMemoryUsage() const;
    size_t GetPeakMemoryUsage() const;
    void CompactMemory();
    
    // Hardware info
    bool IsUsingAVX512() const;
    
    // Quantized-specific queries
    bool IsUsingQuantizedBackend() const;
    const char* GetActiveBackendName() const;
    const char* GetQuantizationType() const;
    float GetLastTokensPerSecond() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Factory function for production use
std::unique_ptr<QuantizedInferenceEngine> CreateProductionInferenceEngine();

} // namespace Core
} // namespace RawrXD
