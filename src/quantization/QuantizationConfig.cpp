#include "rawrxd/quantization/QuantizationConfig.hpp"
#include <algorithm>

namespace rawrxd {
namespace quantization {

QuantFormat QuantizationConfig::GetLayerFormat(const std::string& layerName) const {
    // Check for layer-specific override
    for (const auto& layerConfig : layerConfigs) {
        if (layerConfig.layerName == layerName) {
            return layerConfig.format;
        }
    }
    
    // Check exclusion list
    if (std::find(excludedLayers.begin(), excludedLayers.end(), layerName) != excludedLayers.end()) {
        return QuantFormat::FP16;
    }
    
    // Check layer type patterns
    if (layerName.find("embed") != std::string::npos && !quantizeEmbeddings) {
        return QuantFormat::FP16;
    }
    
    if (layerName.find("norm") != std::string::npos && !quantizeNorms) {
        return QuantFormat::FP16;
    }
    
    if (layerName.find("attn") != std::string::npos && !quantizeAttention) {
        return QuantFormat::FP16;
    }
    
    if ((layerName.find("ffn") != std::string::npos || 
         layerName.find("mlp") != std::string::npos) && !quantizeFFN) {
        return QuantFormat::FP16;
    }
    
    return defaultFormat;
}

bool QuantizationConfig::ShouldQuantizeLayer(const std::string& layerName) const {
    // Check exclusion list
    if (std::find(excludedLayers.begin(), excludedLayers.end(), layerName) != excludedLayers.end()) {
        return false;
    }
    
    // Check layer type
    if (layerName.find("embed") != std::string::npos && !quantizeEmbeddings) {
        return false;
    }
    
    if (layerName.find("norm") != std::string::npos && !quantizeNorms) {
        return false;
    }
    
    return true;
}

int QuantizationConfig::GetGroupSize(const std::string& layerName) const {
    // Check for layer-specific override
    for (const auto& layerConfig : layerConfigs) {
        if (layerConfig.layerName == layerName) {
            return layerConfig.groupSize;
        }
    }
    
    return defaultGroupSize;
}

// Format utilities
std::string QuantFormatToString(QuantFormat format) {
    switch (format) {
        case QuantFormat::Q4_0: return "Q4_0";
        case QuantFormat::Q4_1: return "Q4_1";
        case QuantFormat::Q4_K_M: return "Q4_K_M";
        case QuantFormat::Q4_K_S: return "Q4_K_S";
        case QuantFormat::Q5_0: return "Q5_0";
        case QuantFormat::Q5_1: return "Q5_1";
        case QuantFormat::Q5_K_M: return "Q5_K_M";
        case QuantFormat::Q6_K: return "Q6_K";
        case QuantFormat::Q8_0: return "Q8_0";
        case QuantFormat::Q8_1: return "Q8_1";
        case QuantFormat::Q8_K: return "Q8_K";
        case QuantFormat::INT8: return "INT8";
        case QuantFormat::FP16: return "FP16";
        case QuantFormat::FP32: return "FP32";
        case QuantFormat::GPTQ: return "GPTQ";
        case QuantFormat::AWQ: return "AWQ";
        case QuantFormat::AUTO: return "AUTO";
        default: return "UNKNOWN";
    }
}

QuantFormat StringToQuantFormat(const std::string& str) {
    if (str == "Q4_0") return QuantFormat::Q4_0;
    if (str == "Q4_1") return QuantFormat::Q4_1;
    if (str == "Q4_K_M") return QuantFormat::Q4_K_M;
    if (str == "Q4_K_S") return QuantFormat::Q4_K_S;
    if (str == "Q5_0") return QuantFormat::Q5_0;
    if (str == "Q5_1") return QuantFormat::Q5_1;
    if (str == "Q5_K_M") return QuantFormat::Q5_K_M;
    if (str == "Q6_K") return QuantFormat::Q6_K;
    if (str == "Q8_0") return QuantFormat::Q8_0;
    if (str == "Q8_1") return QuantFormat::Q8_1;
    if (str == "Q8_K") return QuantFormat::Q8_K;
    if (str == "INT8") return QuantFormat::INT8;
    if (str == "FP16") return QuantFormat::FP16;
    if (str == "FP32") return QuantFormat::FP32;
    if (str == "GPTQ") return QuantFormat::GPTQ;
    if (str == "AWQ") return QuantFormat::AWQ;
    if (str == "AUTO") return QuantFormat::AUTO;
    return QuantFormat::Q4_K_M;  // Default
}

int GetBitsPerWeight(QuantFormat format) {
    switch (format) {
        case QuantFormat::Q4_0:
        case QuantFormat::Q4_1:
        case QuantFormat::Q4_K_M:
        case QuantFormat::Q4_K_S:
            return 4;
        case QuantFormat::Q5_0:
        case QuantFormat::Q5_1:
        case QuantFormat::Q5_K_M:
            return 5;
        case QuantFormat::Q6_K:
            return 6;
        case QuantFormat::Q8_0:
        case QuantFormat::Q8_1:
        case QuantFormat::Q8_K:
        case QuantFormat::INT8:
            return 8;
        case QuantFormat::FP16:
            return 16;
        case QuantFormat::FP32:
            return 32;
        case QuantFormat::GPTQ:
        case QuantFormat::AWQ:
            return 4;  // Typically 4-bit
        default:
            return 16;
    }
}

bool IsKQuant(QuantFormat format) {
    return format == QuantFormat::Q4_K_M ||
           format == QuantFormat::Q4_K_S ||
           format == QuantFormat::Q5_K_M ||
           format == QuantFormat::Q6_K ||
           format == QuantFormat::Q8_K;
}

} // namespace quantization
} // namespace rawrxd
