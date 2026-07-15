/**
 * @file compression_abi.h
 * @brief RawrXD Compression ABI - The Contract Layer
 *
 * Decouples storage representation from execution representation.
 * Different tensors, different sensitivities, different compression.
 *
 * Architecture:
 *   GGUF/Container -> Compression ABI -> Execution Format
 *
 * @copyright RawrXD 2026
 */

#ifndef RAWRXD_COMPRESSION_ABI_H
#define RAWRXD_COMPRESSION_ABI_H

#include <cstdint>
#include <cstddef>
#include <functional>
#include <vector>
#include <string>
#include <memory>

namespace rawrxd {
namespace compression {

// ============================================================================
// Compression ABI Version
// ============================================================================

constexpr uint32_t COMPRESSION_ABI_VERSION = 0x00010000; // 1.0.0

// ============================================================================
// Quantization Types (Storage Formats)
// ============================================================================

enum class QuantType : uint8_t {
    // GGML Compatible
    Q4_0 = 0,       // 4.5 bits/weight, FP16 scale
    Q4_1 = 1,       // 4.5 bits/weight, FP16 scale + min
    Q5_0 = 2,       // 5.5 bits/weight
    Q5_1 = 3,       // 5.5 bits/weight + min
    Q8_0 = 4,       // 8.5 bits/weight
    Q8_1 = 5,       // 8.5 bits/weight + min
    
    // K-Quants (Mixed Precision)
    Q2_K = 10,      // 2-6 bits mixed
    Q3_K = 11,      // 3-6 bits mixed
    Q4_K = 12,      // 4-6 bits mixed (Q4_K_M)
    Q5_K = 13,      // 5-6 bits mixed
    Q6_K = 14,      // 6 bits uniform
    
    // RawrXD Extended
    Q3_R = 20,      // 3 bits + outliers
    Q4_R = 21,      // 4 bits + adaptive
    Q6_R = 22,      // 6 bits high precision
    Q8_R = 23,      // 8 bits reference
    
    // Execution Formats
    FP16 = 30,      // Half precision
    FP32 = 31,      // Full precision
    
    // Special
    UNQUANTIZED = 0xFF
};

// ============================================================================
// Scale/Zero-Point Formats
// ============================================================================

enum class ScaleType : uint8_t {
    FP32 = 0,       // Full precision scale
    FP16 = 1,       // Half precision (most common)
    FP8_E4M3 = 2,   // 8-bit float scale
    FP8_E5M2 = 3,   // Alternative 8-bit
    INT8 = 4,       // 8-bit integer scale
    INT16 = 5,      // 16-bit integer scale
};

// ============================================================================
// Compression Profile - The Contract
// ============================================================================

/**
 * @brief Defines how a tensor is compressed and decoded
 * 
 * This is the core ABI structure - the contract between
 * storage format and execution format.
 */
struct CompressionProfile {
    // Identification
    uint32_t abi_version;           // COMPRESSION_ABI_VERSION
    QuantType quant_type;           // Storage format
    ScaleType scale_type;          // Scale representation
    ScaleType zero_type;           // Zero-point representation (if used)
    
    // Block parameters
    uint32_t block_size;            // Weights per block
    uint32_t superblock_size;       // 0 = no superblock, else N
    
    // Precision parameters
    uint8_t bits_per_weight;        // Base quantization bits
    uint8_t bits_per_scale;         // Scale quantization bits
    uint8_t bits_per_zero;          // Zero-point quantization bits
    
    // Adaptive parameters
    float outlier_threshold;        // Weights > threshold get full precision
    float outlier_budget;           // Max % of weights as outliers (0.0 - 1.0)
    
    // Execution target
    QuantType decode_target;          // Target format for decode
    
    // Metadata
    uint32_t flags;                 // Feature flags
    char name[32];                 // Human-readable name
    
    // Calculated fields (filled by builder)
    float effective_bits;           // bits_per_weight + metadata overhead
    float compression_ratio;        // 32.0 / effective_bits
    size_t bytes_per_block;       // Total block size in bytes
};

// Feature flags
constexpr uint32_t COMPRESS_FLAG_MIXED_PRECISION = 0x01;
constexpr uint32_t COMPRESS_FLAG_SUPERBLOCKS = 0x02;
constexpr uint32_t COMPRESS_FLAG_OUTLIERS = 0x04;
constexpr uint32_t COMPRESS_FLAG_ADAPTIVE = 0x08;
constexpr uint32_t COMPRESS_FLAG_SYMMETRIC = 0x10;  // No zero-point

// ============================================================================
// Compressed Block Header
// ============================================================================

/**
 * @brief Header for each compressed block
 * 
 * Allows runtime identification and validation.
 */
struct BlockHeader {
    uint32_t magic;                 // 'RAWX' = 0x52415758
    uint16_t version;             // Header version
    uint16_t checksum;            // Simple checksum
    QuantType quant_type;         // Storage format
    uint8_t reserved[3];          // Padding
    uint32_t block_size;          // Weights in this block
    uint32_t payload_size;        // Bytes following header
};

constexpr uint32_t BLOCK_MAGIC = 0x52415758; // 'RAWX'

// ============================================================================
// Decode Kernel Interface
// ============================================================================

/**
 * @brief Function signature for weight decode
 * 
 * The decoder takes a compressed block and index,
 * returns the dequantized weight.
 */
using DecodeFunction = std::function<float(
    const void* block,           // Compressed block data
    uint32_t index,              // Weight index within block
    const CompressionProfile& profile  // Decode parameters
)>;

/**
 * @brief Batch decode for efficiency
 */
using BatchDecodeFunction = std::function<void(
    const void* block,
    uint32_t start_index,
    uint32_t count,
    float* output,
    const CompressionProfile& profile
)>;

/**
 * @brief Fused decode + GEMV
 */
using FusedGemvFunction = std::function<void(
    const void* weights,
    const float* input,
    float* output,
    int rows,
    int cols,
    const CompressionProfile& profile
)>;

// ============================================================================
// Decoder Registry Entry
// ============================================================================

struct DecoderRegistryEntry {
    QuantType quant_type;
    const char* name;
    DecodeFunction decode_fn;
    BatchDecodeFunction batch_decode_fn;
    FusedGemvFunction fused_gemv_fn;
    bool is_accelerated;        // AVX2/AVX-512 available
    bool supports_outliers;     // Can handle outlier weights
};

// ============================================================================
// Tensor Compression Metadata
// ============================================================================

/**
 * @brief Per-tensor compression information
 * 
 * Allows different compression per tensor in same model.
 */
struct TensorCompressionInfo {
    std::string tensor_name;
    CompressionProfile profile;
    
    // Statistics
    float original_size_mb;
    float compressed_size_mb;
    float compression_ratio;
    float measured_error;
    
    // Sensitivity metrics
    float gradient_magnitude;       // How much this tensor learns
    float activation_variance;      // Output variance
    float attention_score;          // Importance in attention
    
    // Adaptive selection
    bool is_sensitive;              // Requires higher precision
    uint8_t recommended_bits;       // Auto-tuned recommendation
};

// ============================================================================
// Adaptive Compression Strategy
// ============================================================================

/**
 * @brief Layer-aware compression strategy
 * 
 * Different layers have different sensitivity.
 */
struct AdaptiveStrategy {
    // Token embedding - high sensitivity (first impression)
    uint8_t embedding_bits = 5;     // Q5
    
    // Attention projections - medium sensitivity
    uint8_t attention_q_bits = 4;   // Q4
    uint8_t attention_k_bits = 4;   // Q4
    uint8_t attention_v_bits = 4;   // Q4
    uint8_t attention_o_bits = 5;   // Q5 (output important)
    
    // FFN - lower sensitivity (can be aggressive)
    uint8_t ffn_up_bits = 3;        // Q3
    uint8_t ffn_gate_bits = 4;      // Q4
    uint8_t ffn_down_bits = 4;      // Q4
    
    // Output - highest sensitivity
    uint8_t output_bits = 6;        // Q6
    
    // Outlier handling
    float outlier_threshold = 0.05f;
    float outlier_budget = 0.005f;  // 0.5%
};

// ============================================================================
// Runtime Profiles (User-Facing)
// ============================================================================

enum class RuntimeProfile : uint8_t {
    ECO = 0,           // 2.5 bits/weight, maximum memory savings
    BALANCED = 1,      // 4 bits/weight, default
    PERFORMANCE = 2,   // 6 bits/weight, speed optimized
    QUALITY = 3,       // 8 bits/weight, accuracy critical
    ADAPTIVE = 4,      // Per-tensor auto-selection
    CUSTOM = 5         // User-defined
};

// Profile configurations
struct RuntimeProfileConfig {
    const char* name;
    uint8_t default_bits;
    uint8_t embedding_bits;
    uint8_t attention_bits;
    uint8_t ffn_bits;
    uint8_t output_bits;
    bool use_outliers;
    bool use_adaptive;
    const char* description;
};

// Predefined profiles
constexpr RuntimeProfileConfig ECO_PROFILE = {
    "ECO",
    3, 4, 3, 3, 5,      // Default, embed, attn, ffn, output
    true, true,
    "Maximum memory savings (~2.5-3.5 bits/weight)"
};

constexpr RuntimeProfileConfig BALANCED_PROFILE = {
    "BALANCED",
    4, 5, 4, 4, 6,
    true, false,
    "Balanced quality and performance (~4-5 bits/weight)"
};

constexpr RuntimeProfileConfig PERFORMANCE_PROFILE = {
    "PERFORMANCE",
    6, 6, 6, 5, 8,
    false, false,
    "Speed optimized (~6 bits/weight)"
};

constexpr RuntimeProfileConfig QUALITY_PROFILE = {
    "QUALITY",
    8, 8, 8, 8, 8,
    false, false,
    "Maximum accuracy (~8 bits/weight)"
};

// ============================================================================
// Compression ABI Interface
// ============================================================================

class CompressionABI {
public:
    CompressionABI();
    ~CompressionABI();
    
    // Registry management
    void RegisterDecoder(const DecoderRegistryEntry& entry);
    void UnregisterDecoder(QuantType quant_type);
    bool HasDecoder(QuantType quant_type) const;
    
    // Decode operations
    float DecodeWeight(const void* block, uint32_t index, 
                       const CompressionProfile& profile);
    void DecodeBatch(const void* block, uint32_t start, uint32_t count,
                     float* output, const CompressionProfile& profile);
    
    // Profile management
    CompressionProfile CreateProfile(RuntimeProfile runtime_profile);
    CompressionProfile CreateAdaptiveProfile(const AdaptiveStrategy& strategy);
    CompressionProfile CreateCustomProfile(QuantType quant_type, 
                                            uint32_t block_size,
                                            uint8_t bits_per_weight);
    
    // Tensor-aware compression
    TensorCompressionInfo AnalyzeTensor(const std::string& name,
                                         const float* data,
                                         size_t num_elements);
    void ApplyAdaptiveCompression(std::vector<TensorCompressionInfo>& tensors);
    
    // Validation
    bool ValidateBlock(const void* block, size_t size);
    float MeasureError(const float* original, const float* decoded,
                       size_t num_elements);
    
    // Utilities
    const char* QuantTypeToString(QuantType type);
    QuantType StringToQuantType(const char* str);
    size_t CalculateBlockSize(const CompressionProfile& profile);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Global ABI Instance
// ============================================================================

CompressionABI& GetCompressionABI();

// ============================================================================
// Convenience Macros
// ============================================================================

#define RAWRXD_COMPRESS_ECO() \
    GetCompressionABI().CreateProfile(RuntimeProfile::ECO)

#define RAWRXD_COMPRESS_BALANCED() \
    GetCompressionABI().CreateProfile(RuntimeProfile::BALANCED)

#define RAWRXD_COMPRESS_PERFORMANCE() \
    GetCompressionABI().CreateProfile(RuntimeProfile::PERFORMANCE)

#define RAWRXD_COMPRESS_QUALITY() \
    GetCompressionABI().CreateProfile(RuntimeProfile::QUALITY)

#define RAWRXD_COMPRESS_ADAPTIVE() \
    GetCompressionABI().CreateProfile(RuntimeProfile::ADAPTIVE)

} // namespace compression
} // namespace rawrxd

#endif // RAWRXD_COMPRESSION_ABI_H
