#pragma once

#include "rawrxd/compatibility/GGUFCompatibilityLoader.hpp"
#include "rawrxd/inference/InferenceEngine.hpp"
#include <memory>

namespace rawrxd {
namespace compatibility {

// Integration layer between compatibility system and inference engine
class CompatibilityIntegration {
public:
    CompatibilityIntegration();
    ~CompatibilityIntegration() = default;

    // Initialize with model
    bool Initialize(const std::string& gguf_path);
    
    // Get adapter for current model
    std::shared_ptr<ModelAdapter> GetAdapter() { return adapter_; }
    
    // Apply architecture-specific configurations to inference engine
    void ConfigureInferenceEngine(InferenceEngine* engine);
    
    // Apply tokenizer adaptations
    void ConfigureTokenizer(Tokenizer* tokenizer);
    
    // Get kernel configuration for current model
    KernelConfig GetKernelConfig() const;
    
    // Check if model requires special handling
    bool RequiresSpecialHandling();
    
    // Get recommended batch size
    int GetRecommendedBatchSize() const;
    
    // Get recommended context length
    int GetRecommendedContextLength() const;
    
    // Get memory requirements
    size_t GetMemoryRequirements() const;
    
    // Validate compatibility
    bool Validate() const;
    
    // Get status
    bool IsInitialized() const { return initialized_; }
    ModelArchitecture GetArchitecture() const;
    std::string GetArchitectureName() const;

private:
    std::unique_ptr<GGUFCompatibilityLoader> loader_;
    std::shared_ptr<ModelAdapter> adapter_;
    bool initialized_ = false;
    std::string model_path_;
};

// Factory for creating integrated inference sessions
class IntegratedInferenceFactory {
public:
    // Create inference engine with automatic compatibility configuration
    static std::unique_ptr<InferenceEngine> CreateEngine(
        const std::string& gguf_path,
        const InferenceConfig& config = InferenceConfig());
    
    // Create with explicit architecture
    static std::unique_ptr<InferenceEngine> CreateEngine(
        const std::string& gguf_path,
        ModelArchitecture arch,
        const InferenceConfig& config = InferenceConfig());
    
    // Batch create for multiple models
    static std::vector<std::unique_ptr<InferenceEngine>> CreateEngines(
        const std::vector<std::string>& gguf_paths);
};

// Runtime compatibility monitoring
class CompatibilityMonitor {
public:
    struct Metrics {
        float inference_time_ms = 0.0f;
        float tokens_per_second = 0.0f;
        size_t memory_used = 0;
        size_t memory_peak = 0;
        int batch_size = 0;
        int sequence_length = 0;
        std::string kernel_used;
        bool fallback_triggered = false;
    };
    
    void RecordInference(const Metrics& metrics);
    void RecordFallback(const std::string& reason);
    void RecordError(const std::string& error);
    
    // Get recommendations based on observed performance
    std::vector<std::string> GetRecommendations() const;
    
    // Export metrics
    std::string ExportJSON() const;
    void Reset();

private:
    std::vector<Metrics> history_;
    std::vector<std::string> fallbacks_;
    std::vector<std::string> errors_;
};

} // namespace compatibility
} // namespace rawrxd
