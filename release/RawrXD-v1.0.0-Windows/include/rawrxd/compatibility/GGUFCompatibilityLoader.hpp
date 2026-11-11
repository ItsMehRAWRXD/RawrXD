#pragma once

#include "rawrxd/compatibility/ArchitectureDetector.hpp"
#include "rawrxd/compatibility/ModelAdapter.hpp"
#include "rawrxd/loader/GGUFLoader.hpp"
#include <memory>
#include <string>

namespace rawrxd {
namespace compatibility {

// Extended GGUF loader with compatibility layer
class GGUFCompatibilityLoader {
public:
    GGUFCompatibilityLoader();
    ~GGUFCompatibilityLoader() = default;

    // Load model with automatic architecture detection
    bool Load(const std::string& path);
    
    // Get detected architecture
    ModelArchitecture GetArchitecture() const { return detected_arch_; }
    
    // Get model adapter for this architecture
    std::shared_ptr<ModelAdapter> GetAdapter() { return adapter_; }
    
    // Get model configuration
    const ModelConfig& GetConfig() const { return config_; }
    
    // Check if model is supported
    bool IsSupported() const;
    
    // Get compatibility report
    std::string GetCompatibilityReport() const;
    
    // Get recommended kernel configuration
    KernelConfig GetRecommendedKernels() const;
    
    // Validate model against architecture
    bool ValidateModel();
    
    // Get tensor count
    size_t GetTensorCount() const;
    
    // Get model info
    std::string GetModelInfo() const;

private:
    std::unique_ptr<GGUFLoader> base_loader_;
    std::shared_ptr<ModelAdapter> adapter_;
    ArchitectureDetector detector_;
    ModelArchitecture detected_arch_;
    ModelConfig config_;
    std::string model_path_;
    bool loaded_ = false;
    
    // Internal helpers
    void DetectArchitecture();
    void CreateAdapter();
    bool ValidateTensors();
    bool ValidateHyperparameters();
};

// Compatibility check result
struct CompatibilityCheck {
    bool compatible = false;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::vector<std::string> recommendations;
    ModelArchitecture detected_arch = ModelArchitecture::UNKNOWN;
    float confidence = 0.0f;
};

// Standalone compatibility checker
class CompatibilityChecker {
public:
    static CompatibilityCheck Check(const std::string& gguf_path);
    static CompatibilityCheck Check(const std::string& gguf_path, 
                                    ModelArchitecture expected_arch);
    
    // Batch check multiple models
    static std::vector<CompatibilityCheck> CheckBatch(
        const std::vector<std::string>& paths);
};

// Model metadata extraction
struct ModelMetadata {
    std::string name;
    std::string architecture;
    std::string quantization;
    size_t parameter_count = 0;
    size_t file_size = 0;
    int context_length = 0;
    int vocab_size = 0;
    int num_layers = 0;
    int num_heads = 0;
    int hidden_size = 0;
    std::vector<std::string> tags;
    std::unordered_map<std::string, std::string> extra;
};

class ModelMetadataExtractor {
public:
    static ModelMetadata Extract(const std::string& gguf_path);
    static std::string ToJSON(const ModelMetadata& metadata);
    static std::string ToMarkdown(const ModelMetadata& metadata);
};

} // namespace compatibility
} // namespace rawrxd
