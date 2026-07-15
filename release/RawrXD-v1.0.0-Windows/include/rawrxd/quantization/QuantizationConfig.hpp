#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace rawrxd {
namespace quantization {

// Quantization formats supported
enum class QuantFormat {
    Q4_0,           // 4-bit, no grouping
    Q4_1,           // 4-bit, with offsets
    Q4_K_M,         // 4-bit, K-quant medium
    Q4_K_S,         // 4-bit, K-quant small
    Q5_0,           // 5-bit, no grouping
    Q5_1,           // 5-bit, with offsets
    Q5_K_M,         // 5-bit, K-quant medium
    Q6_K,           // 6-bit, K-quant
    Q8_0,           // 8-bit, no grouping
    Q8_1,           // 8-bit, with offsets
    Q8_K,           // 8-bit, K-quant
    INT8,           // 8-bit integer (calibrated)
    FP16,           // 16-bit float
    FP32,           // 32-bit float
    GPTQ,           // GPTQ 4-bit
    AWQ,            // AWQ 4-bit
    AUTO            // Auto-select based on model
};

// Quantization method
enum class QuantMethod {
    RTN,            // Round-to-nearest
    GPTQ,           // GPTQ (gradient-based)
    AWQ,            // Activation-aware weight quantization
    SMOOTHQUANT,    // SmoothQuant
    DEFAULT = RTN
};

// Layer quantization config
struct LayerQuantConfig {
    std::string layerName;
    QuantFormat format = QuantFormat::Q4_K_M;
    int groupSize = 128;            // Group size for quantization
    bool perChannel = false;        // Per-channel vs per-tensor
    float scale = 1.0f;             // Custom scale factor
    float zeroPoint = 0.0f;         // Zero point offset
};

// Full quantization configuration
struct QuantizationConfig {
    // Global settings
    QuantFormat defaultFormat = QuantFormat::Q4_K_M;
    QuantMethod method = QuantMethod::RTN;
    int defaultGroupSize = 128;
    
    // Calibration settings (for INT8)
    int calibrationSamples = 256;
    float calibrationPercentile = 99.9f;
    bool symmetricQuantization = true;
    
    // GPTQ settings
    int gptqBlockSize = 128;
    bool gptqPerChannel = true;
    float gptqActOrder = 0.0f;      // Activation order heuristic
    
    // AWQ settings
    float awqScalingFactor = 0.5f;
    int awqGroupSize = 128;
    bool awqZeroPoint = true;
    
    // Layer-specific overrides
    std::vector<LayerQuantConfig> layerConfigs;
    
    // Excluded layers (keep in FP16/FP32)
    std::vector<std::string> excludedLayers;
    
    // Special handling
    bool quantizeEmbeddings = false;    // Usually keep embeddings in FP16
    bool quantizeNorms = false;         // Usually keep norms in FP16
    bool quantizeAttention = true;
    bool quantizeFFN = true;
    
    // Get format for layer
    QuantFormat GetLayerFormat(const std::string& layerName) const;
    
    // Check if layer should be quantized
    bool ShouldQuantizeLayer(const std::string& layerName) const;
    
    // Get effective group size for layer
    int GetGroupSize(const std::string& layerName) const;
};

// Quantization statistics
struct QuantizationStats {
    float originalSizeMB = 0.0f;
    float quantizedSizeMB = 0.0f;
    float compressionRatio = 1.0f;
    float perplexityDelta = 0.0f;
    float accuracyRetention = 100.0f;
    
    // Per-layer stats
    std::unordered_map<std::string, float> layerCompressionRatios;
    std::unordered_map<std::string, float> layerErrors;
};

// Format utilities
std::string QuantFormatToString(QuantFormat format);
QuantFormat StringToQuantFormat(const std::string& str);
int GetBitsPerWeight(QuantFormat format);
bool IsKQuant(QuantFormat format);

} // namespace quantization
} // namespace rawrxd
