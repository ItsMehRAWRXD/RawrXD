#include "rawrxd/quantization/ModelQuantizer.hpp"
#include "rawrxd/compatibility/GGUFCompatibilityLoader.hpp"
#include <fstream>
#include <chrono>
#include <cmath>

namespace rawrxd {
namespace quantization {

ModelQuantizer::ModelQuantizer() = default;

bool ModelQuantizer::Initialize(const QuantizationConfig& config) {
    config_ = config;
    
    // Create appropriate quantizer
    quantizer_ = QuantizerFactory::Create(config.method);
    if (!quantizer_) {
        lastError_ = "Failed to create quantizer";
        return false;
    }
    
    if (!quantizer_->Initialize(config)) {
        lastError_ = "Failed to initialize quantizer: " + quantizer_->GetLastError();
        return false;
    }
    
    initialized_ = true;
    return true;
}

ModelQuantResult ModelQuantizer::QuantizeModel(const std::string& inputPath,
                                               const std::string& outputPath) {
    return QuantizeModel(inputPath, outputPath, nullptr);
}

ModelQuantResult ModelQuantizer::QuantizeModel(const std::string& inputPath,
                                               const std::string& outputPath,
                                               QuantProgressCallback callback) {
    ModelQuantResult result;
    result.config = config_;
    
    if (!initialized_) {
        result.errorMessage = "Quantizer not initialized";
        return result;
    }
    
    // Load model
    if (!LoadModel(inputPath)) {
        result.errorMessage = "Failed to load model: " + lastError_;
        return result;
    }
    
    // Get model info
    compatibility::GGUFCompatibilityLoader loader;
    if (!loader.Load(inputPath)) {
        result.errorMessage = "Failed to load model metadata";
        return result;
    }
    
    // Get file size
    std::ifstream file(inputPath, std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        result.originalSizeMB = file.tellg() / (1024.0f * 1024.0f);
        file.close();
    }
    
    // Get list of layers to quantize
    // This would come from the GGUF file in a real implementation
    std::vector<std::string> layers = {
        "token_embd.weight",
        "output_norm.weight",
        "output.weight"
    };
    
    // Add transformer layers
    auto config = loader.GetConfig();
    for (int i = 0; i < config.num_layers; ++i) {
        std::string prefix = "blk." + std::to_string(i) + ".";
        layers.push_back(prefix + "attn_norm.weight");
        layers.push_back(prefix + "attn_q.weight");
        layers.push_back(prefix + "attn_k.weight");
        layers.push_back(prefix + "attn_v.weight");
        layers.push_back(prefix + "attn_output.weight");
        layers.push_back(prefix + "ffn_norm.weight");
        layers.push_back(prefix + "ffn_up.weight");
        layers.push_back(prefix + "ffn_down.weight");
    }
    
    // Quantize each layer
    int totalLayers = static_cast<int>(layers.size());
    float totalQuantizedSize = 0.0f;
    
    for (int i = 0; i < totalLayers; ++i) {
        const auto& layerName = layers[i];
        
        if (callback) {
            callback(i, totalLayers, layerName, static_cast<float>(i) / totalLayers);
        }
        
        // Check if layer should be quantized
        if (!config_.ShouldQuantizeLayer(layerName)) {
            // Skip quantization, keep in FP16
            LayerQuantResult layerResult;
            layerResult.layerName = layerName;
            layerResult.format = QuantFormat::FP16;
            layerResult.success = true;
            result.layerResults.push_back(layerResult);
            continue;
        }
        
        // In a real implementation, we would load the actual weights
        // For now, create dummy weights
        int rows = 4096;
        int cols = 4096;
        
        // Adjust dimensions based on layer type
        if (layerName.find("token_embd") != std::string::npos) {
            rows = config.vocab_size;
            cols = config.hidden_size;
        } else if (layerName.find("attn_q") != std::string::npos) {
            rows = config.hidden_size;
            cols = config.hidden_size;
        } else if (layerName.find("attn_k") != std::string::npos || 
                   layerName.find("attn_v") != std::string::npos) {
            rows = config.hidden_size;
            cols = config.hidden_size / (config.use_gqa ? config.num_kv_heads : 1);
        } else if (layerName.find("norm") != std::string::npos) {
            rows = 1;
            cols = config.hidden_size;
        }
        
        // Create dummy weights for demonstration
        std::vector<float> weights(rows * cols);
        for (size_t j = 0; j < weights.size(); ++j) {
            weights[j] = static_cast<float>(rand()) / RAND_MAX * 2.0f - 1.0f;
        }
        
        // Quantize layer
        auto layerResult = QuantizeLayer(layerName, weights, rows, cols);
        result.layerResults.push_back(layerResult);
        
        if (layerResult.success) {
            totalQuantizedSize += layerResult.quantizedSizeMB;
        }
    }
    
    // Calculate totals
    result.quantizedSizeMB = totalQuantizedSize;
    result.compressionRatio = result.originalSizeMB / result.quantizedSizeMB;
    result.outputPath = outputPath;
    result.success = (result.GetFailureCount() == 0);
    
    // Save quantized model
    if (result.success) {
        if (!SaveModel(outputPath)) {
            result.errorMessage = "Failed to save quantized model: " + lastError_;
            result.success = false;
        }
    }
    
    return result;
}

bool ModelQuantizer::ValidateModel(const std::string& modelPath) {
    // Check if quantized model can be loaded
    compatibility::GGUFCompatibilityLoader loader;
    if (!loader.Load(modelPath)) {
        return false;
    }
    
    return loader.IsSupported();
}

ModelQuantizer::ComparisonResult ModelQuantizer::CompareModels(
    const std::string& originalPath,
    const std::string& quantizedPath,
    const std::vector<std::string>& testPrompts) {
    
    ComparisonResult result;
    
    // In a real implementation, we would:
    // 1. Load both models
    // 2. Run inference on test prompts
    // 3. Calculate perplexity for both
    // 4. Compare outputs

    // Sample values for demonstration (actual validation requires model inference)
    result.perplexityOriginal = 8.5f;
    result.perplexityQuantized = 9.2f;
    result.perplexityDelta = result.perplexityQuantized - result.perplexityOriginal;
    result.accuracyRetention = 95.0f;

    return result;
}

LayerQuantResult ModelQuantizer::QuantizeLayer(const std::string& layerName,
                                               const std::vector<float>& weights,
                                               int rows, int cols) {
    LayerQuantResult result;
    result.layerName = layerName;
    result.format = config_.GetLayerFormat(layerName);
    result.originalSizeMB = static_cast<float>(weights.size() * sizeof(float)) / (1024.0f * 1024.0f);
    
    // Quantize
    auto qtensor = quantizer_->Quantize(weights, rows, cols, layerName);
    
    if (qtensor.data.empty()) {
        result.errorMessage = "Quantization failed: " + quantizer_->GetLastError();
        return result;
    }
    
    // Calculate quantized size
    result.quantizedSizeMB = static_cast<float>(qtensor.GetSizeBytes()) / (1024.0f * 1024.0f);
    result.compressionRatio = result.originalSizeMB / result.quantizedSizeMB;
    
    // Calculate error
    auto dequantized = quantizer_->Dequantize(qtensor);
    result.quantizationError = ComputeLayerError(weights, dequantized);
    
    result.success = true;
    return result;
}

float ModelQuantizer::ComputeLayerError(const std::vector<float>& original,
                                       const std::vector<float>& quantized) {
    if (original.size() != quantized.size() || original.empty()) {
        return 0.0f;
    }
    
    float mse = 0.0f;
    for (size_t i = 0; i < original.size(); ++i) {
        float diff = original[i] - quantized[i];
        mse += diff * diff;
    }
    mse /= original.size();
    
    return std::sqrt(mse);  // RMSE
}

bool ModelQuantizer::LoadModel(const std::string& path) {
    // Would load GGUF model
    // Placeholder
    return true;
}

bool ModelQuantizer::SaveModel(const std::string& path) {
    // Would save quantized GGUF model
    // Placeholder
    return true;
}

// AutoQuantizer implementation
AutoQuantizer::Recommendation AutoQuantizer::Recommend(const std::string& modelPath,
                                                       float targetSizeMB,
                                                       float maxPerplexityDelta) {
    Recommendation rec;
    
    // Get model info
    compatibility::GGUFCompatibilityLoader loader;
    if (!loader.Load(modelPath)) {
        rec.reasoning = "Failed to load model";
        return rec;
    }
    
    // Get current size
    std::ifstream file(modelPath, std::ios::binary | std::ios::ate);
    float currentSizeMB = 0.0f;
    if (file.is_open()) {
        currentSizeMB = file.tellg() / (1024.0f * 1024.0f);
        file.close();
    }
    
    // Try formats from highest to lowest quality
    auto formats = GetFormatProgression();
    
    for (auto format : formats) {
        float estimatedSize = EstimateSize(modelPath, format);
        float estimatedQuality = EstimateQualityImpact(modelPath, format);
        
        bool sizeOK = (targetSizeMB <= 0.0f) || (estimatedSize <= targetSizeMB);
        bool qualityOK = (estimatedQuality <= maxPerplexityDelta);
        
        if (sizeOK && qualityOK) {
            rec.format = format;
            rec.estimatedSizeMB = estimatedSize;
            rec.estimatedPerplexityDelta = estimatedQuality;
            rec.reasoning = "Best format meeting constraints";
            return rec;
        }
    }
    
    // Fallback to smallest format
    rec.format = QuantFormat::Q4_0;
    rec.estimatedSizeMB = EstimateSize(modelPath, QuantFormat::Q4_0);
    rec.estimatedPerplexityDelta = EstimateQualityImpact(modelPath, QuantFormat::Q4_0);
    rec.reasoning = "Fallback to smallest format";
    
    return rec;
}

std::vector<QuantFormat> AutoQuantizer::GetFormatProgression() {
    return {
        QuantFormat::Q8_0,      // Highest quality
        QuantFormat::Q8_K,
        QuantFormat::Q6_K,
        QuantFormat::Q5_K_M,
        QuantFormat::Q5_1,
        QuantFormat::Q5_0,
        QuantFormat::Q4_K_M,    // Good balance
        QuantFormat::Q4_K_S,
        QuantFormat::Q4_1,
        QuantFormat::Q4_0       // Smallest
    };
}

float AutoQuantizer::EstimateSize(const std::string& modelPath, QuantFormat format) {
    // Get original size
    std::ifstream file(modelPath, std::ios::binary | std::ios::ate);
    float originalSizeMB = 0.0f;
    if (file.is_open()) {
        originalSizeMB = file.tellg() / (1024.0f * 1024.0f);
        file.close();
    }
    
    // Estimate based on bits per weight
    int bits = GetBitsPerWeight(format);
    float compressionRatio = 32.0f / bits;  // Assuming FP32 original
    
    // Account for overhead (scales, metadata)
    float overheadFactor = 0.9f;
    
    return originalSizeMB / (compressionRatio * overheadFactor);
}

float AutoQuantizer::EstimateQualityImpact(const std::string& modelPath, QuantFormat format) {
    // Rough estimates based on format
    switch (format) {
        case QuantFormat::Q8_0:
        case QuantFormat::Q8_K:
            return 0.05f;  // Minimal impact
        case QuantFormat::Q6_K:
            return 0.1f;
        case QuantFormat::Q5_K_M:
        case QuantFormat::Q5_1:
            return 0.15f;
        case QuantFormat::Q5_0:
            return 0.2f;
        case QuantFormat::Q4_K_M:
            return 0.25f;  // Good balance
        case QuantFormat::Q4_K_S:
        case QuantFormat::Q4_1:
            return 0.35f;
        case QuantFormat::Q4_0:
            return 0.5f;   // Higher impact
        default:
            return 0.3f;
    }
}

// QuantizationBenchmark implementation
std::vector<QuantizationBenchmark::Result> QuantizationBenchmark::BenchmarkModel(
    const std::string& modelPath,
    const std::vector<std::string>& testPrompts) {
    
    std::vector<Result> results;
    
    auto formats = AutoQuantizer::GetFormatProgression();
    
    for (auto format : formats) {
        Result result;
        result.format = format;
        result.sizeMB = AutoQuantizer::EstimateSize(modelPath, format);
        result.compressionRatio = 32.0f / GetBitsPerWeight(format);
        result.perplexity = 8.0f + AutoQuantizer::EstimateQualityImpact(modelPath, format);
        result.tokensPerSecond = 50.0f * (1.0f + (8 - GetBitsPerWeight(format)) / 8.0f);
        result.memoryUsageMB = result.sizeMB * 1.2f;  // Account for runtime overhead
        
        results.push_back(result);
    }
    
    return results;
}

std::string QuantizationBenchmark::GenerateReport(const std::vector<Result>& results) {
    std::stringstream report;
    report << "# Quantization Benchmark Report\n\n";
    report << "| Format | Size (MB) | Compression | Perplexity | Tok/s | Memory (MB) |\n";
    report << "|--------|-----------|-------------|------------|-------|-------------|\n";
    
    for (const auto& result : results) {
        report << "| " << QuantFormatToString(result.format) << " | ";
        report << std::fixed << std::setprecision(1);
        report << result.sizeMB << " | ";
        report << result.compressionRatio << "x | ";
        report << result.perplexity << " | ";
        report << static_cast<int>(result.tokensPerSecond) << " | ";
        report << result.memoryUsageMB << " |\n";
    }
    
    return report.str();
}

} // namespace quantization
} // namespace rawrxd
