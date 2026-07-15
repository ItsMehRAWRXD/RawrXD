#pragma once

/**
 * @file model_compressor.hpp
 * @brief Model compression for edge deployment
 * @details Quantization, pruning, and distillation for edge devices
 * @version 14.7.3
 * @date 2026-07-14
 */

#include <cstring>
#include <vector>
#include <cstdint>
#include <memory>

namespace rawrxd {
namespace edge {

/**
 * @brief Compression level presets
 */
enum class CompressionLevel {
    NONE,       ///< No compression (original model)
    FAST,       ///< INT8 quantization, minimal pruning
    BALANCED,   ///< INT8 quantization, moderate pruning
    AGGRESSIVE  ///< INT4 quantization, heavy pruning
};

/**
 * @brief Device capability profile
 */
struct DeviceCapabilities {
    bool supports_int8;      ///< INT8 quantization support
    bool supports_int4;      ///< INT4 quantization support
    bool supports_fp16;      ///< FP16 support
    size_t max_model_size;   ///< Maximum model size in bytes
    size_t available_ram;    ///< Available RAM in bytes
    bool has_neon;           ///< ARM NEON support
    bool has_avx2;           ///< x86 AVX2 support
    bool has_avx512;         ///< x86 AVX-512 support
};

/**
 * @brief Compression statistics
 */
struct CompressionStats {
    size_t original_size;
    size_t compressed_size;
    float compression_ratio;
    float quality_score;     ///< Perplexity or accuracy retention
    float inference_speedup;
    int quantization_bits;
    float pruning_ratio;
    std::chrono::milliseconds compression_time;
};

/**
 * @brief Compression configuration
 */
struct CompressionConfig {
    CompressionLevel level = CompressionLevel::BALANCED;
    bool use_pruning = true;
    bool use_quantization = true;
    bool use_distillation = false;
    float target_quality = 0.95f;  ///< Minimum quality retention
    size_t target_size = 0;          ///< Target size in bytes (0 = auto)
    bool preserve_embeddings = true; ///< Keep embeddings full precision
};

/**
 * @brief Compressed model container
 */
struct CompressedModel {
    std::vector<uint8_t> data;
    CompressionStats stats;
    std::string original_format;
    std::string compressed_format;
    std::vector<std::string> compression_ops;
};

/**
 * @brief Model compressor for edge deployment
 *
 * Compresses models using:
 * - Quantization (INT8, INT4)
 * - Structured pruning
 * - Knowledge distillation (optional)
 * - Format optimization
 */
class EdgeModelCompressor {
public:
    EdgeModelCompressor();
    ~EdgeModelCompressor();

    /**
     * @brief Compress a model for edge deployment
     * @param model_path Path to original model
     * @param config Compression configuration
     * @param device Target device capabilities
     * @return Compressed model container
     */
    CompressedModel compress(
        const std::string& model_path,
        const CompressionConfig& config,
        const DeviceCapabilities& device
    );

    /**
     * @brief Compress with preset level
     * @param model_path Path to original model
     * @param level Compression level preset
     * @param device Target device capabilities
     * @return Compressed model container
     */
    CompressedModel compress(
        const std::string& model_path,
        CompressionLevel level,
        const DeviceCapabilities& device
    );

    /**
     * @brief Estimate compressed size
     * @param model_path Path to original model
     * @param config Compression configuration
     * @return Estimated size in bytes
     */
    size_t estimateSize(
        const std::string& model_path,
        const CompressionConfig& config
    ) const;

    /**
     * @brief Estimate compressed size from level
     * @param model_path Path to original model
     * @param level Compression level
     * @return Estimated size in bytes
     */
    size_t estimateSize(
        const std::string& model_path,
        CompressionLevel level
    ) const;

    /**
     * @brief Validate compressed model
     * @param compressed Compressed model data
     * @return true if valid
     */
    bool validate(const CompressedModel& compressed) const;

    /**
     * @brief Get recommended compression level for device
     * @param device Device capabilities
     * @return Recommended compression level
     */
    static CompressionLevel recommendLevel(const DeviceCapabilities& device);

    /**
     * @brief Get compression level name
     * @param level Compression level
     * @return Human-readable name
     */
    static const char* getLevelName(CompressionLevel level);

    /**
     * @brief Get default device capabilities for profile
     * @param profile Device profile type
     * @return Default capabilities
     */
    static DeviceCapabilities getDefaultCapabilities(DeviceProfile::Type profile);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/**
 * @brief Quantization utilities
 */
class QuantizationEngine {
public:
    /**
     * @brief Quantize FP32 weights to INT8
     * @param weights FP32 weights
     * @return INT8 quantized weights
     */
    static std::vector<int8_t> quantizeInt8(const std::vector<float>& weights);

    /**
     * @brief Quantize FP32 weights to INT4
     * @param weights FP32 weights
     * @return INT4 quantized weights (packed)
     */
    static std::vector<uint8_t> quantizeInt4(const std::vector<float>& weights);

    /**
     * @brief Dequantize INT8 to FP32
     * @param quantized INT8 weights
     * @param scale Quantization scale
     * @return FP32 weights
     */
    static std::vector<float> dequantizeInt8(
        const std::vector<int8_t>& quantized,
        float scale
    );

    /**
     * @brief Calculate optimal quantization scale
     * @param weights FP32 weights
     * @return Optimal scale factor
     */
    static float calculateScale(const std::vector<float>& weights);
};

/**
 * @brief Pruning utilities
 */
class PruningEngine {
public:
    /**
     * @brief Magnitude-based pruning
     * @param weights Weights to prune
     * @param ratio Pruning ratio (0.0 - 1.0)
     * @return Pruned weights with zeros
     */
    static std::vector<float> magnitudePrune(
        const std::vector<float>& weights,
        float ratio
    );

    /**
     * @brief Structured pruning (remove entire channels)
     * @param weights Weights tensor
     * @param dims Tensor dimensions
     * @param ratio Pruning ratio
     * @return Pruned tensor
     */
    static std::vector<float> structuredPrune(
        const std::vector<float>& weights,
        const std::vector<size_t>& dims,
        float ratio
    );

    /**
     * @brief Calculate sparsity of weights
     * @param weights Weight tensor
     * @return Sparsity ratio (0.0 - 1.0)
     */
    static float calculateSparsity(const std::vector<float>& weights);
};

} // namespace edge
} // namespace rawrxd
