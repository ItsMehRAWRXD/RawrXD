/**
 * @file model_compressor.cpp
 * @brief Model compression implementation
 * @version 14.7.3
 * @date 2026-07-14
 */

#include "model_compressor.hpp"
#include <cmath>
#include <random>
#include <algorithm>

namespace rawrxd {
namespace edge {

// ============================================================================
// EdgeModelCompressor Implementation
// ============================================================================

class EdgeModelCompressor::Impl {
public:
    DeviceCapabilities device_;
    CompressionStats last_stats_;

    CompressedModel compressInternal(
        const std::vector<float>& weights,
        const CompressionConfig& config
    ) {
        CompressedModel result;
        result.original_format = "fp32";
        
        size_t original_size = weights.size() * sizeof(float);
        result.stats.original_size = original_size;

        std::vector<float> processed_weights = weights;

        // Apply pruning if enabled
        if (config.use_pruning) {
            float prune_ratio = getPruneRatio(config.level);
            processed_weights = PruningEngine::magnitudePrune(processed_weights, prune_ratio);
            result.compression_ops.push_back("pruning_" + std::to_string(static_cast<int>(prune_ratio * 100)) + "pct");
        }

        // Apply quantization
        if (config.use_quantization) {
            int bits = getQuantizationBits(config.level, device_);
            
            if (bits == 8) {
                auto quantized = QuantizationEngine::quantizeInt8(processed_weights);
                result.data.assign(
                    reinterpret_cast<uint8_t*>(quantized.data()),
                    reinterpret_cast<uint8_t*>(quantized.data()) + quantized.size()
                );
                result.compressed_format = "int8";
                result.stats.quantization_bits = 8;
            } else if (bits == 4) {
                auto quantized = QuantizationEngine::quantizeInt4(processed_weights);
                result.data = quantized;
                result.compressed_format = "int4";
                result.stats.quantization_bits = 4;
            } else {
                // No quantization
                result.data.assign(
                    reinterpret_cast<uint8_t*>(processed_weights.data()),
                    reinterpret_cast<uint8_t*>(processed_weights.data()) + processed_weights.size() * sizeof(float)
                );
                result.compressed_format = "fp32";
                result.stats.quantization_bits = 32;
            }
        } else {
            result.data.assign(
                reinterpret_cast<uint8_t*>(processed_weights.data()),
                reinterpret_cast<uint8_t*>(processed_weights.data()) + processed_weights.size() * sizeof(float)
            );
            result.compressed_format = "fp32";
            result.stats.quantization_bits = 32;
        }

        result.stats.compressed_size = result.data.size();
        result.stats.compression_ratio = static_cast<float>(result.stats.original_size) / result.stats.compressed_size;
        
        // Estimate quality score (simplified)
        result.stats.quality_score = estimateQuality(config.level);
        result.stats.inference_speedup = estimateSpeedup(config.level, device_);

        return result;
    }

    float getPruneRatio(CompressionLevel level) {
        switch (level) {
            case CompressionLevel::FAST: return 0.1f;
            case CompressionLevel::BALANCED: return 0.2f;
            case CompressionLevel::AGGRESSIVE: return 0.4f;
            default: return 0.0f;
        }
    }

    int getQuantizationBits(CompressionLevel level, const DeviceCapabilities& device) {
        if (!device.supports_int8) return 32;
        
        switch (level) {
            case CompressionLevel::FAST: return 8;
            case CompressionLevel::BALANCED: return 8;
            case CompressionLevel::AGGRESSIVE: return device.supports_int4 ? 4 : 8;
            default: return 32;
        }
    }

    float estimateQuality(CompressionLevel level) {
        switch (level) {
            case CompressionLevel::NONE: return 1.0f;
            case CompressionLevel::FAST: return 0.98f;
            case CompressionLevel::BALANCED: return 0.95f;
            case CompressionLevel::AGGRESSIVE: return 0.90f;
            default: return 1.0f;
        }
    }

    float estimateSpeedup(CompressionLevel level, const DeviceCapabilities& device) {
        float base_speedup = 1.0f;
        
        switch (level) {
            case CompressionLevel::FAST: base_speedup = 1.5f; break;
            case CompressionLevel::BALANCED: base_speedup = 2.0f; break;
            case CompressionLevel::AGGRESSIVE: base_speedup = 3.0f; break;
            default: break;
        }

        // Adjust for device capabilities
        if (device.has_neon || device.has_avx2) {
            base_speedup *= 1.2f;
        }

        return base_speedup;
    }
};

EdgeModelCompressor::EdgeModelCompressor() : impl_(std::make_unique<Impl>()) {}
EdgeModelCompressor::~EdgeModelCompressor() = default;

CompressedModel EdgeModelCompressor::compress(
    const std::string& model_path,
    const CompressionConfig& config,
    const DeviceCapabilities& device
) {
    impl_->device_ = device;
    
    // Load weights (simplified - would load from actual model file)
    std::vector<float> weights;
    // ... load weights from model_path ...
    
    // For now, create dummy weights for demonstration
    weights.resize(1000000);  // 1M parameters
    std::random_device rd;
    std::mt19937 gen(rd());
    std::normal_distribution<float> dist(0.0f, 0.1f);
    for (auto& w : weights) {
        w = dist(gen);
    }

    return impl_->compressInternal(weights, config);
}

CompressedModel EdgeModelCompressor::compress(
    const std::string& model_path,
    CompressionLevel level,
    const DeviceCapabilities& device
) {
    CompressionConfig config;
    config.level = level;
    config.use_pruning = (level != CompressionLevel::NONE);
    config.use_quantization = (level != CompressionLevel::NONE);
    
    return compress(model_path, config, device);
}

size_t EdgeModelCompressor::estimateSize(
    const std::string& model_path,
    const CompressionConfig& config
) const {
    // Simplified estimation
    size_t original_size = 1000000 * sizeof(float);  // Assume 1M params
    
    float compression_factor = 1.0f;
    if (config.use_quantization) {
        int bits = impl_->getQuantizationBits(config.level, impl_->device_);
        compression_factor *= 32.0f / bits;
    }
    if (config.use_pruning) {
        compression_factor *= 1.0f / (1.0f - impl_->getPruneRatio(config.level));
    }

    return static_cast<size_t>(original_size / compression_factor);
}

size_t EdgeModelCompressor::estimateSize(
    const std::string& model_path,
    CompressionLevel level
) const {
    CompressionConfig config;
    config.level = level;
    config.use_pruning = (level != CompressionLevel::NONE);
    config.use_quantization = (level != CompressionLevel::NONE);
    
    return estimateSize(model_path, config);
}

bool EdgeModelCompressor::validate(const CompressedModel& compressed) const {
    // Check if compressed data is valid
    if (compressed.data.empty()) {
        return false;
    }
    
    // Check compression ratio is reasonable
    if (compressed.stats.compression_ratio < 0.1f || compressed.stats.compression_ratio > 100.0f) {
        return false;
    }
    
    // Check quality score is reasonable
    if (compressed.stats.quality_score < 0.0f || compressed.stats.quality_score > 1.0f) {
        return false;
    }
    
    return true;
}

CompressionLevel EdgeModelCompressor::recommendLevel(const DeviceCapabilities& device) {
    if (device.available_ram < 512 * 1024 * 1024) {  // < 512MB
        return CompressionLevel::AGGRESSIVE;
    } else if (device.available_ram < 2ULL * 1024 * 1024 * 1024) {  // < 2GB
        return CompressionLevel::BALANCED;
    } else {
        return CompressionLevel::FAST;
    }
}

const char* EdgeModelCompressor::getLevelName(CompressionLevel level) {
    switch (level) {
        case CompressionLevel::NONE: return "none";
        case CompressionLevel::FAST: return "fast";
        case CompressionLevel::BALANCED: return "balanced";
        case CompressionLevel::AGGRESSIVE: return "aggressive";
        default: return "unknown";
    }
}

DeviceCapabilities EdgeModelCompressor::getDefaultCapabilities(DeviceProfile::Type profile) {
    DeviceCapabilities caps = {};
    
    switch (profile) {
        case DeviceProfile::Type::MOBILE:
            caps.supports_int8 = true;
            caps.supports_int4 = true;
            caps.supports_fp16 = true;
            caps.max_model_size = 1ULL * 1024 * 1024 * 1024;  // 1GB
            caps.available_ram = 4ULL * 1024 * 1024 * 1024;   // 4GB
            caps.has_neon = true;
            break;
            
        case DeviceProfile::Type::IOT:
            caps.supports_int8 = true;
            caps.supports_int4 = false;
            caps.supports_fp16 = false;
            caps.max_model_size = 256 * 1024 * 1024;          // 256MB
            caps.available_ram = 1ULL * 1024 * 1024 * 1024;   // 1GB
            caps.has_neon = false;
            break;
            
        case DeviceProfile::Type::EMBEDDED:
            caps.supports_int8 = true;
            caps.supports_int4 = true;
            caps.supports_fp16 = true;
            caps.max_model_size = 512 * 1024 * 1024;         // 512MB
            caps.available_ram = 2ULL * 1024 * 1024 * 1024;  // 2GB
            caps.has_avx2 = true;
            break;
            
        case DeviceProfile::Type::BROWSER:
            caps.supports_int8 = true;
            caps.supports_int4 = false;
            caps.supports_fp16 = true;
            caps.max_model_size = 512 * 1024 * 1024;         // 512MB
            caps.available_ram = 2ULL * 1024 * 1024 * 1024;   // 2GB
            break;
    }
    
    return caps;
}

// ============================================================================
// QuantizationEngine Implementation
// ============================================================================

std::vector<int8_t> QuantizationEngine::quantizeInt8(const std::vector<float>& weights) {
    if (weights.empty()) return {};
    
    float scale = calculateScale(weights);
    std::vector<int8_t> quantized(weights.size());
    
    for (size_t i = 0; i < weights.size(); ++i) {
        float scaled = weights[i] / scale;
        // Clamp to int8 range
        scaled = std::max(-128.0f, std::min(127.0f, scaled));
        quantized[i] = static_cast<int8_t>(std::round(scaled));
    }
    
    return quantized;
}

std::vector<uint8_t> QuantizationEngine::quantizeInt4(const std::vector<float>& weights) {
    if (weights.empty()) return {};
    
    float scale = calculateScale(weights);
    std::vector<uint8_t> quantized((weights.size() + 1) / 2);  // Pack 2 values per byte
    
    for (size_t i = 0; i < weights.size(); ++i) {
        float scaled = weights[i] / scale;
        // Clamp to int4 range (-8 to 7)
        scaled = std::max(-8.0f, std::min(7.0f, scaled));
        int8_t val = static_cast<int8_t>(std::round(scaled)) & 0x0F;
        
        size_t byte_idx = i / 2;
        if (i % 2 == 0) {
            quantized[byte_idx] = (val << 4) & 0xF0;
        } else {
            quantized[byte_idx] |= val & 0x0F;
        }
    }
    
    return quantized;
}

std::vector<float> QuantizationEngine::dequantizeInt8(
    const std::vector<int8_t>& quantized,
    float scale
) {
    std::vector<float> weights(quantized.size());
    for (size_t i = 0; i < quantized.size(); ++i) {
        weights[i] = static_cast<float>(quantized[i]) * scale;
    }
    return weights;
}

float QuantizationEngine::calculateScale(const std::vector<float>& weights) {
    if (weights.empty()) return 1.0f;
    
    float max_val = 0.0f;
    for (float w : weights) {
        max_val = std::max(max_val, std::abs(w));
    }
    
    // Scale to use most of int8 range (-128 to 127)
    return max_val / 127.0f;
}

// ============================================================================
// PruningEngine Implementation
// ============================================================================

std::vector<float> PruningEngine::magnitudePrune(
    const std::vector<float>& weights,
    float ratio
) {
    if (weights.empty() || ratio <= 0.0f) return weights;
    
    // Create copy with absolute values for sorting
    std::vector<std::pair<float, size_t>> abs_weights;
    abs_weights.reserve(weights.size());
    
    for (size_t i = 0; i < weights.size(); ++i) {
        abs_weights.push_back({std::abs(weights[i]), i});
    }
    
    // Sort by magnitude
    std::sort(abs_weights.begin(), abs_weights.end());
    
    // Determine threshold index
    size_t threshold_idx = static_cast<size_t>(weights.size() * ratio);
    float threshold = abs_weights[threshold_idx].first;
    
    // Prune weights below threshold
    std::vector<float> pruned = weights;
    for (size_t i = 0; i < threshold_idx; ++i) {
        pruned[abs_weights[i].second] = 0.0f;
    }
    
    return pruned;
}

std::vector<float> PruningEngine::structuredPrune(
    const std::vector<float>& weights,
    const std::vector<size_t>& dims,
    float ratio
) {
    // Simplified structured pruning - remove entire channels
    // In practice, this would be more sophisticated
    return magnitudePrune(weights, ratio);
}

float PruningEngine::calculateSparsity(const std::vector<float>& weights) {
    if (weights.empty()) return 0.0f;
    
    size_t zeros = 0;
    for (float w : weights) {
        if (w == 0.0f) zeros++;
    }
    
    return static_cast<float>(zeros) / weights.size();
}

} // namespace edge
} // namespace rawrxd
