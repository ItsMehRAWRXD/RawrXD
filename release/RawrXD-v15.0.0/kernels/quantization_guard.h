/**
 * @file quantization_guard.h
 * @brief RawrXD L4.2.1 Numerical Hardening - Quantization Guard
 *
 * Automatic governor that validates compression profiles before execution.
 * Rejects invalid tunes before they cause numerical explosions.
 *
 * @copyright RawrXD 2026
 */

#ifndef RAWRXD_QUANTIZATION_GUARD_H
#define RAWRXD_QUANTIZATION_GUARD_H

#include "compression_codec.h"
#include <functional>
#include <optional>

namespace rawrxd {
namespace compression {

// ============================================================================
// Quality Gates (The "Knock Sensor" Thresholds)
// ============================================================================

struct QualityGates {
    // Production gates (strict)
    static constexpr float PRODUCTION_COSINE = 0.9999f;
    static constexpr float PRODUCTION_RMSE = 0.001f;
    static constexpr float PRODUCTION_MAX_ERROR = 0.01f;
    
    // Standard gates (balanced)
    static constexpr float STANDARD_COSINE = 0.999f;
    static constexpr float STANDARD_RMSE = 0.01f;
    static constexpr float STANDARD_MAX_ERROR = 0.1f;
    
    // Experimental gates (permissive)
    static constexpr float EXPERIMENTAL_COSINE = 0.99f;
    static constexpr float EXPERIMENTAL_RMSE = 0.1f;
    static constexpr float EXPERIMENTAL_MAX_ERROR = 1.0f;
    
    // Hard limits (never exceed)
    static constexpr float HARD_COSINE_MIN = 0.95f;
    static constexpr float HARD_RMSE_MAX = 1.0f;
    static constexpr float HARD_ERROR_MAX = 10.0f;
};

// ============================================================================
// Quantization Report (Extended Validation)
// ============================================================================

struct QuantizationReport {
    // Compression metrics
    float compression_ratio;
    size_t original_bytes;
    size_t compressed_bytes;
    
    // Numerical quality
    float cosine_similarity;
    float rmse;
    float max_absolute_error;
    float mean_absolute_error;
    float relative_error_percent;
    
    // Anomaly detection
    bool overflow_detected;
    bool underflow_detected;
    bool nan_detected;
    bool inf_detected;
    bool denormal_detected;
    
    // Statistical analysis
    float original_mean;
    float original_std;
    float reconstructed_mean;
    float reconstructed_std;
    float correlation_coefficient;
    
    // Validation result
    bool valid;
    std::string rejection_reason;
    std::vector<std::string> warnings;
    
    // Print detailed report
    void Print() const;
    bool operator==(const QuantizationReport& other) const;
};

// ============================================================================
// Profile Constraints (Search Space Boundaries)
// ============================================================================

struct ProfileConstraints {
    // Compression ratio bounds
    float min_ratio = 2.0f;
    float max_ratio = 16.0f;
    float target_ratio = 6.0f;
    
    // Quality requirements
    float min_cosine = QualityGates::STANDARD_COSINE;
    float max_rmse = QualityGates::STANDARD_RMSE;
    float max_error = QualityGates::STANDARD_MAX_ERROR;
    
    // Numerical stability
    bool require_finite = true;
    bool require_no_nan = true;
    bool require_no_inf = true;
    bool check_denormals = true;
    
    // Performance hints
    bool prefer_fused_decode = true;
    bool allow_mixed_precision = true;
    uint32_t max_block_size = 512;
    
    // Validation
    bool Validate() const;
};

// ============================================================================
// Quantization Guard (The Governor)
// ============================================================================

class QuantizationGuard {
public:
    QuantizationGuard();
    ~QuantizationGuard() = default;
    
    // ------------------------------------------------------------------------
    // Profile Validation
    // ------------------------------------------------------------------------
    
    /**
     * @brief Validate a compression profile before execution
     * 
     * Runs the codec through a test tensor and validates quality.
     * 
     * @param codec The codec to validate
     * @param constraints Quality requirements
     * @return Report with validation result
     */
    QuantizationReport ValidateProfile(
        CompressionCodec* codec,
        const ProfileConstraints& constraints
    );
    
    /**
     * @brief Quick validation with default constraints
     */
    QuantizationReport QuickValidate(CompressionCodec* codec);
    
    /**
     * @brief Strict validation for production
     */
    QuantizationReport ProductionValidate(CompressionCodec* codec);
    
    // ------------------------------------------------------------------------
    // Automatic Profile Selection
    // ------------------------------------------------------------------------
    
    /**
     * @brief Find best valid profile within constraints
     * 
     * Searches compression space and returns first valid profile
     * that meets quality gates.
     * 
     * @param constraints Search boundaries
     * @return Best valid codec, or nullptr if none found
     */
    std::unique_ptr<CompressionCodec> AutoSelect(
        const ProfileConstraints& constraints
    );
    
    /**
     * @brief Binary search for optimal compression ratio
     * 
     * Finds highest compression that still meets quality gates.
     */
    float FindOptimalRatio(
        CompressionType base_type,
        const ProfileConstraints& constraints
    );
    
    // ------------------------------------------------------------------------
    // Numerical Stability Checks
    // ------------------------------------------------------------------------
    
    /**
     * @brief Check for numerical anomalies in tensor
     */
    bool CheckNumericalHealth(
        const float* data,
        size_t count,
        QuantizationReport* report = nullptr
    );
    
    /**
     * @brief Validate FP16 scale reconstruction
     */
    bool ValidateFP16Reconstruction(
        float original_scale,
        uint16_t fp16_encoded,
        float tolerance = 0.001f
    );
    
    /**
     * @brief Check quantization range is valid
     */
    bool ValidateQuantizationRange(
        const float* weights,
        size_t count,
        int bits,
        float* out_scale = nullptr
    );
    
    // ------------------------------------------------------------------------
    // Policy Enforcement
    // ------------------------------------------------------------------------
    
    /**
     * @brief Set global quality policy
     */
    void SetPolicy(const ProfileConstraints& policy);
    
    /**
     * @brief Get current policy
     */
    const ProfileConstraints& GetPolicy() const { return policy_; }
    
    /**
     * @brief Enable strict mode (reject any warnings)
     */
    void SetStrictMode(bool strict) { strict_mode_ = strict; }
    
    /**
     * @brief Register custom validation callback
     */
    void SetValidationCallback(
        std::function<bool(const QuantizationReport&)> callback
    );
    
private:
    ProfileConstraints policy_;
    bool strict_mode_ = false;
    std::function<bool(const QuantizationReport&)> custom_validator_;
    
    // Internal validation
    bool PassesQualityGates(const QuantizationReport& report) const;
    bool PassesHardLimits(const QuantizationReport& report) const;
    void AnalyzeNumericalHealth(
        const float* original,
        const float* reconstructed,
        size_t count,
        QuantizationReport* report
    );
};

// ============================================================================
// Compression Optimizer (Auto-Tuner)
// ============================================================================

class CompressionOptimizer {
public:
    CompressionOptimizer();
    ~CompressionOptimizer() = default;
    
    // Builder pattern for constraints
    CompressionOptimizer& TargetRatio(float ratio);
    CompressionOptimizer& MinimumCosine(float cosine);
    CompressionOptimizer& MaximumRMSE(float rmse);
    CompressionOptimizer& MaximumError(float error);
    CompressionOptimizer& RequireFused(bool fused);
    CompressionOptimizer& AllowMixedPrecision(bool allow);
    CompressionOptimizer& MaxBlockSize(uint32_t size);
    
    // Execute optimization
    std::unique_ptr<CompressionCodec> Select();
    QuantizationReport GetLastReport() const { return last_report_; }
    
    // Get all valid profiles ranked by compression
    std::vector<std::pair<std::unique_ptr<CompressionCodec>, QuantizationReport>>
    GetAllValidProfiles();
    
private:
    ProfileConstraints constraints_;
    QuantizationReport last_report_;
    QuantizationGuard guard_;
};

// ============================================================================
// Numerical Utilities
// ============================================================================

class NumericalUtils {
public:
    // FP16 conversion with validation
    static uint16_t FloatToFP16(float value);
    static float FP16ToFloat(uint16_t value);
    static bool IsValidFP16(float value);
    
    // Quantization with bounds checking
    static int QuantizeFloat(float value, float scale, int bits);
    static float DequantizeInt(int value, float scale, int bits);
    
    // Statistical analysis
    static void ComputeStatistics(
        const float* data,
        size_t count,
        float* mean,
        float* std_dev,
        float* min_val,
        float* max_val
    );
    
    // Cosine similarity with numerical stability
    static float StableCosineSimilarity(
        const float* a,
        const float* b,
        size_t count
    );
    
    // Check for special values
    static bool ContainsNaN(const float* data, size_t count);
    static bool ContainsInf(const float* data, size_t count);
    static bool ContainsDenormal(const float* data, size_t count);
    static bool AllFinite(const float* data, size_t count);
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define RAWRXD_GUARD_VALIDATE(codec) \
    rawrxd::compression::QuantizationGuard().QuickValidate(codec)

#define RAWRXD_GUARD_PRODUCTION(codec) \
    rawrxd::compression::QuantizationGuard().ProductionValidate(codec)

#define RAWRXD_OPTIMIZER() \
    rawrxd::compression::CompressionOptimizer()

} // namespace compression
} // namespace rawrxd

#endif // RAWRXD_QUANTIZATION_GUARD_H
