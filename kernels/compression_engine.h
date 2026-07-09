/**
 * @file compression_engine.h
 * @brief RawrXD Tunable Compression Engine
 *
 * Runtime-selectable compression ratios like adjustable engine compression.
 * Statically linked but dynamically configurable.
 *
 * @copyright RawrXD 2026
 */

#ifndef RAWRXD_COMPRESSION_ENGINE_H
#define RAWRXD_COMPRESSION_ENGINE_H

#include <cstdint>
#include <cstddef>
#include <functional>

namespace rawrxd {
namespace compression {

// ============================================================================
// Compression Ratio Presets (Engine "Tunes")
// ============================================================================

enum class CompressionTune {
    STREET_NA = 0,      // 11.0:1 - Conservative, reliable
    STRONG_NA = 1,      // 12.5:1 - Balanced performance
    RACE_NA = 2,        // 14.0:1 - Aggressive, high precision
    FORCED_INDUCTION = 3, // 6.4:1 - Q4_0, memory bandwidth optimized
    RACE_FORCED = 4,    // 6.7:1 - Q4_K_M, maximum TPS
    CUSTOM = 5          // User-defined ratio
};

// ============================================================================
// Compression Configuration (Engine "Build Spec")
// ============================================================================

struct CompressionConfig {
    // Block parameters
    uint32_t block_size;        // Weights per block (cylinder count)
    uint32_t bits_per_weight;   // Quantization bits (compression height)
    uint32_t scale_bits;        // Scale quantization bits
    uint32_t min_bits;          // Min/zero-point bits
    
    // Derived metrics
    float compression_ratio;      // Calculated: 32 / effective_bits
    float effective_bits;         // Total bits / block_size
    size_t bytes_per_block;       // Metadata + quantized weights
    
    // Tuning parameters
    float max_error_target;       // Acceptable quantization error
    bool use_mixed_precision;     // Enable 6-bit/4-bit mixing
    bool use_superblocks;         // Enable 256-weight super-blocks
    
    // Engine analogy
    const char* tune_name;        // "Street NA", "Race Forced", etc.
    const char* fuel_requirement; // "91 Pump", "110 Race", "E85"
};

// ============================================================================
// Predefined Configurations (Factory Blueprints)
// ============================================================================

// Street NA: 11.0:1 - INT8, conservative
constexpr CompressionConfig STREET_NA_CONFIG = {
    .block_size = 64,
    .bits_per_weight = 8,
    .scale_bits = 16,
    .min_bits = 0,
    .compression_ratio = 4.0f,  // 32/8
    .effective_bits = 8.25f,
    .bytes_per_block = 66,      // 64 weights * 1 byte + 2 bytes scale
    .max_error_target = 0.001f,
    .use_mixed_precision = false,
    .use_superblocks = false,
    .tune_name = "Street NA",
    .fuel_requirement = "91 Pump Gas"
};

// Strong NA: 12.5:1 - Q8_0, balanced
constexpr CompressionConfig STRONG_NA_CONFIG = {
    .block_size = 32,
    .bits_per_weight = 8,
    .scale_bits = 16,
    .min_bits = 0,
    .compression_ratio = 4.0f,
    .effective_bits = 8.5f,
    .bytes_per_block = 34,      // 32 weights + FP16 scale
    .max_error_target = 0.01f,
    .use_mixed_precision = false,
    .use_superblocks = false,
    .tune_name = "Strong NA",
    .fuel_requirement = "93 Octane"
};

// Race NA: 14.0:1 - Q6_0, aggressive precision
constexpr CompressionConfig RACE_NA_CONFIG = {
    .block_size = 64,
    .bits_per_weight = 6,
    .scale_bits = 16,
    .min_bits = 16,
    .compression_ratio = 5.33f,  // 32/6
    .effective_bits = 6.5f,
    .bytes_per_block = 52,       // 48 bytes weights + 4 bytes metadata
    .max_error_target = 0.05f,
    .use_mixed_precision = false,
    .use_superblocks = false,
    .tune_name = "Race NA",
    .fuel_requirement = "110 Race Fuel"
};

// Forced Induction: 6.4:1 - Q4_0, memory bandwidth
constexpr CompressionConfig FORCED_INDUCTION_CONFIG = {
    .block_size = 32,
    .bits_per_weight = 4,
    .scale_bits = 16,
    .min_bits = 0,
    .compression_ratio = 6.4f,   // 32/4.5 (with overhead)
    .effective_bits = 4.5f,
    .bytes_per_block = 18,       // 16 bytes nibbles + 2 bytes scale
    .max_error_target = 0.1f,
    .use_mixed_precision = false,
    .use_superblocks = false,
    .tune_name = "Forced Induction",
    .fuel_requirement = "E85"
};

// Race Forced: 6.7:1 - Q4_K_M, maximum TPS
constexpr CompressionConfig RACE_FORCED_CONFIG = {
    .block_size = 256,
    .bits_per_weight = 4,
    .scale_bits = 6,
    .min_bits = 6,
    .compression_ratio = 6.7f,  // 32/4.75
    .effective_bits = 4.75f,
    .bytes_per_block = 272,      // 256 weights + mixed metadata
    .max_error_target = 0.2f,
    .use_mixed_precision = true,
    .use_superblocks = true,
    .tune_name = "Race Forced",
    .fuel_requirement = "E85 + Meth"
};

// ============================================================================
// Compression Engine (The "Motor")
// ============================================================================

class CompressionEngine {
public:
    CompressionEngine();
    ~CompressionEngine();
    
    // Select tune (like swapping pistons)
    void SelectTune(CompressionTune tune);
    void SelectCustom(const CompressionConfig& config);
    
    // Get current configuration
    const CompressionConfig& GetCurrentConfig() const { return current_config_; }
    
    // Compression operations
    size_t Compress(const float* input, uint8_t* output, size_t num_weights);
    size_t Decompress(const uint8_t* input, float* output, size_t num_weights);
    
    // Fused GEMM with current tune
    void GemvFused(const uint8_t* weights_compressed, const float* input,
                   float* output, int rows, int cols);
    
    // Calculate memory savings
    float GetMemoryReduction() const;
    float GetBandwidthSavings() const;
    
    // Validate error bounds
    bool ValidateError(float max_error) const;
    
private:
    CompressionConfig current_config_;
    CompressionTune current_tune_;
    
    // Internal dispatch tables
    using CompressFunc = std::function<size_t(const float*, uint8_t*, size_t, const CompressionConfig&)>;
    using DecompressFunc = std::function<size_t(const uint8_t*, float*, size_t, const CompressionConfig&)>;
    using GemvFunc = std::function<void(const uint8_t*, const float*, float*, int, int, const CompressionConfig&)>;
    
    CompressFunc compress_dispatch_[6];
    DecompressFunc decompress_dispatch_[6];
    GemvFunc gemv_dispatch_[6];
    
    void InitializeDispatchTables();
};

// ============================================================================
// Global Engine Instance (Statically Linked, Runtime Configurable)
// ============================================================================

// Singleton access - statically linked but tunable at runtime
CompressionEngine& GetCompressionEngine();

// Convenience macros for tune selection
#define RAWRXD_TUNE_STREET() GetCompressionEngine().SelectTune(CompressionTune::STREET_NA)
#define RAWRXD_TUNE_STRONG() GetCompressionEngine().SelectTune(CompressionTune::STRONG_NA)
#define RAWRXD_TUNE_RACE() GetCompressionEngine().SelectTune(CompressionTune::RACE_NA)
#define RAWRXD_TUNE_FORCED() GetCompressionEngine().SelectTune(CompressionTune::FORCED_INDUCTION)
#define RAWRXD_TUNE_RACE_FORCED() GetCompressionEngine().SelectTune(CompressionTune::RACE_FORCED)

// ============================================================================
// Custom Compression Builder (Engine "Machine Shop")
// ============================================================================

class CompressionBuilder {
public:
    CompressionBuilder();
    
    // Set block size (cylinder count)
    CompressionBuilder& BlockSize(uint32_t size);
    
    // Set bits per weight (piston dome height)
    CompressionBuilder& BitsPerWeight(uint32_t bits);
    
    // Set scale precision (fuel injection precision)
    CompressionBuilder& ScaleBits(uint32_t bits);
    
    // Set zero-point (quench clearance)
    CompressionBuilder& MinBits(uint32_t bits);
    
    // Set error tolerance (knock threshold)
    CompressionBuilder& MaxError(float error);
    
    // Enable features
    CompressionBuilder& MixedPrecision(bool enable);
    CompressionBuilder& SuperBlocks(bool enable);
    
    // Build configuration
    CompressionConfig Build() const;
    
    // Calculate derived metrics
    static float CalculateCompressionRatio(const CompressionConfig& config);
    static float CalculateEffectiveBits(const CompressionConfig& config);
    static size_t CalculateBytesPerBlock(const CompressionConfig& config);
    
private:
    CompressionConfig config_;
};

// ============================================================================
// Compression Ratio Calculator
// ============================================================================

inline float CalculateCompressionRatio(uint32_t fp32_bits, uint32_t quant_bits, float overhead) {
    // CR = FP32_bits / (quant_bits + overhead_per_weight)
    return static_cast<float>(fp32_bits) / (static_cast<float>(quant_bits) + overhead);
}

// Predefined ratios
constexpr float CR_11_0 = 11.0f;  // Street NA
constexpr float CR_12_5 = 12.5f;  // Strong NA  
constexpr float CR_14_0 = 14.0f;  // Race NA
constexpr float CR_6_4 = 6.4f;    // Forced Induction
constexpr float CR_6_7 = 6.7f;    // Race Forced
constexpr float CR_8_0 = 8.0f;    // Custom high-compression

} // namespace compression
} // namespace rawrxd

#endif // RAWRXD_COMPRESSION_ENGINE_H
