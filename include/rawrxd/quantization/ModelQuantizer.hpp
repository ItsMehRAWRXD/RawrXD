#pragma once

#include "rawrxd/quantization/Quantizer.hpp"
#include "rawrxd/compatibility/ArchitectureDetector.hpp"
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace rawrxd {
namespace quantization {

// Model quantization progress callback
using QuantProgressCallback = std::function<void(int currentLayer, int totalLayers, 
                                                  const std::string& layerName, 
                                                  float progress)>;

// Layer quantization result
struct LayerQuantResult {
    std::string layerName;
    QuantFormat format;
    float originalSizeMB = 0.0f;
    float quantizedSizeMB = 0.0f;
    float compressionRatio = 1.0f;
    float quantizationError = 0.0f;
    bool success = false;
    std::string errorMessage;
};

// Full model quantization result
struct ModelQuantResult {
    bool success = false;
    std::string outputPath;
    float originalSizeMB = 0.0f;
    float quantizedSizeMB = 0.0f;
    float compressionRatio = 1.0f;
    float estimatedPerplexityDelta = 0.0f;
    std::vector<LayerQuantResult> layerResults;
    QuantizationConfig config;
    std::string errorMessage;
    
    // Get number of successfully quantized layers
    int GetSuccessCount() const {
        int count = 0;
        for (const auto& result : layerResults) {
            if (result.success) count++;
        }
        return count;
    }
    
    // Get number of failed layers
    int GetFailureCount() const {
        return static_cast<int>(layerResults.size()) - GetSuccessCount();
    }
};

// Model quantizer - quantizes entire GGUF models
class ModelQuantizer {
public:
    ModelQuantizer();
    ~ModelQuantizer() = default;

    // Initialize with configuration
    bool Initialize(const QuantizationConfig& config);
    
    // Quantize a model
    ModelQuantResult QuantizeModel(const std::string& inputPath, 
                                   const std::string& outputPath);
    
    // Quantize with progress callback
    ModelQuantResult QuantizeModel(const std::string& inputPath,
                                   const std::string& outputPath,
                                   QuantProgressCallback callback);
    
    // Validate quantized model
    bool ValidateModel(const std::string& modelPath);
    
    // Compare original vs quantized
    struct ComparisonResult {
        float perplexityOriginal = 0.0f;
        float perplexityQuantized = 0.0f;
        float perplexityDelta = 0.0f;
        float accuracyRetention = 100.0f;
        std::vector<std::pair<std::string, float>> layerErrors;
    };
    ComparisonResult CompareModels(const std::string& originalPath,
                                   const std::string& quantizedPath,
                                   const std::vector<std::string>& testPrompts);
    
    // Get configuration
    const QuantizationConfig& GetConfig() const { return config_; }
    
    // Get last error
    std::string GetLastError() const { return lastError_; }
    
    // Check if initialized
    bool IsInitialized() const { return initialized_; }

private:
    QuantizationConfig config_;
    std::unique_ptr<Quantizer> quantizer_;
    bool initialized_ = false;
    std::string lastError_;
    
    // Internal methods
    bool LoadModel(const std::string& path);
    bool SaveModel(const std::string& path);
    LayerQuantResult QuantizeLayer(const std::string& layerName, 
                                   const std::vector<float>& weights,
                                   int rows, int cols);
    float ComputeLayerError(const std::vector<float>& original,
                           const std::vector<float>& quantized);
};

// Auto-quantization - automatically select best format
class AutoQuantizer {
public:
    struct Recommendation {
        QuantFormat format;
        float estimatedSizeMB;
        float estimatedPerplexityDelta;
        std::string reasoning;
    };
    
    // Analyze model and recommend quantization settings
    static Recommendation Recommend(const std::string& modelPath,
                                    float targetSizeMB = 0.0f,  // 0 = no target
                                    float maxPerplexityDelta = 0.5f);
    
    // Get format progression (from highest to lowest quality)
    static std::vector<QuantFormat> GetFormatProgression();
    
    // Estimate size for format
    static float EstimateSize(const std::string& modelPath, QuantFormat format);
    
    // Estimate quality impact
    static float EstimateQualityImpact(const std::string& modelPath, QuantFormat format);
};

// Quantization benchmark
class QuantizationBenchmark {
public:
    struct Result {
        QuantFormat format;
        float sizeMB;
        float compressionRatio;
        float perplexity;
        float tokensPerSecond;
        float memoryUsageMB;
    };
    
    // Benchmark all supported formats
    static std::vector<Result> BenchmarkModel(const std::string& modelPath,
                                               const std::vector<std::string>& testPrompts);
    
    // Generate benchmark report
    static std::string GenerateReport(const std::vector<Result>& results);
};

} // namespace quantization
} // namespace rawrxd
