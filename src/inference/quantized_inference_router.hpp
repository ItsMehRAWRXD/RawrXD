// ============================================================================
// Production Integration: Q4_0 Quantized Inference Router
// Automatically detects and uses Q4_0 for 131 tok/s performance
// ============================================================================

#pragma once

#include "inference_engine.h"
#include "model_loader.h"
#include <memory>
#include <string>

namespace RawrXD {
namespace Inference {

// ============================================================================
// Backend Interface
// ============================================================================

class IInferenceBackend {
public:
    virtual ~IInferenceBackend() = default;
    
    virtual bool Initialize(const Core::InferenceEngine::InferenceConfig& config) = 0;
    virtual Core::InferenceEngine::InferenceResult RunInference(const char* prompt) = 0;
    virtual bool IsModelLoaded() const = 0;
    virtual const char* GetLastError() const = 0;
    virtual size_t GetMemoryUsage() const = 0;
};

// ============================================================================
// Quantized Backend (131 tok/s)
// ============================================================================

class QuantizedInferenceBackend : public IInferenceBackend {
public:
    QuantizedInferenceBackend();
    ~QuantizedInferenceBackend() override;
    
    bool Initialize(const Core::InferenceEngine::InferenceConfig& config) override;
    bool LoadModel(const char* path);
    Core::InferenceEngine::InferenceResult RunInference(const char* prompt) override;
    bool IsModelLoaded() const override;
    const char* GetLastError() const override;
    size_t GetMemoryUsage() const override;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Standard Backend (C4 Baseline - 31 tok/s)
// ============================================================================

class StandardInferenceBackend : public IInferenceBackend {
public:
    StandardInferenceBackend();
    ~StandardInferenceBackend() override;
    
    bool Initialize(const Core::InferenceEngine::InferenceConfig& config) override;
    bool LoadModel(const char* path);
    Core::InferenceEngine::InferenceResult RunInference(const char* prompt) override;
    bool IsModelLoaded() const override;
    const char* GetLastError() const override;
    size_t GetMemoryUsage() const override;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Smart Router - Auto-detects model type and routes to optimal backend
// ============================================================================

class QuantizedInferenceRouter {
public:
    // Configuration for routing decisions
    struct RouterConfig {
        bool preferQuantization = true;      // Default: use Q4_0 when available
        bool allowFallback = true;          // Fallback to standard on failure
        bool logRoutingDecision = true;      // Log which backend was selected
        float minSpeedupThreshold = 2.0f;  // Only use quantized if 2x+ faster
    };
    
    QuantizedInferenceRouter();
    ~QuantizedInferenceRouter();
    
    // Initialize with config
    bool Initialize(const RouterConfig& config);
    
    // Load model and auto-select backend
    bool LoadModel(const char* ggufPath);
    
    // Run inference with selected backend
    Core::InferenceEngine::InferenceResult RunInference(const char* prompt);
    
    // Status queries
    bool IsModelLoaded() const;
    bool IsUsingQuantizedBackend() const;
    const char* GetLastError() const;
    const char* GetActiveBackendName() const;
    const char* GetQuantizationType() const;
    
    // Performance metrics
    float GetLastTokensPerSecond() const;
    size_t GetMemoryUsage() const;
    
    // Force specific backend (for testing)
    void ForceBackend(const char* backendName);  // "quantized" or "standard"
    void ClearForcedBackend();
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick check if model is quantized (supports Q2_K, Q3_K, Q4_0, Q4_K, Q5_K, Q6_K, Q8_0)
bool IsQuantizedModel(const char* ggufPath);

// Get quantization type from filename
const char* GetQuantizationType(const char* ggufPath);

// Get recommended backend for model
const char* GetRecommendedBackend(const char* ggufPath);

// Factory: Create router with production defaults
std::unique_ptr<QuantizedInferenceRouter> CreateProductionRouter();

} // namespace Inference
} // namespace RawrXD
