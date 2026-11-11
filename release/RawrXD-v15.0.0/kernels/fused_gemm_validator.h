/**
 * @file fused_gemm_validator.h
 * @brief RawrXD L4.2.3 Fused GEMM Reference Validation
 *
 * Numerical correctness gates for fused kernels.
 * Validates against reference GEMM before adaptive quantization.
 *
 * Validation Pipeline:
 *   Q4 GGUF Tensor
 *        |
 *        +----------------+
 *        |                |
 *   Fused GEMM      Reference GEMM
 *        |                |
 *        +----------------+
 *                 |
 *          Numerical Compare
 *                 |
 *          cosine >= 0.999
 *          RMSE <= 0.01
 *
 * @copyright RawrXD 2026
 */

#ifndef RAWRXD_FUSED_GEMM_VALIDATOR_H
#define RAWRXD_FUSED_GEMM_VALIDATOR_H

#include "fused_quant_gemm.h"
#include "quantization_guard.h"
#include <vector>
#include <functional>

namespace rawrxd {
namespace validation {

// ============================================================================
// Validation Thresholds (L4.2.3 Gates)
// ============================================================================

struct ValidationGates {
    // Production quality (strict)
    static constexpr float PRODUCTION_COSINE = 0.9999f;
    static constexpr float PRODUCTION_RMSE = 0.001f;
    static constexpr float PRODUCTION_MAX_ERROR = 0.01f;
    
    // Standard quality (balanced)
    static constexpr float STANDARD_COSINE = 0.999f;
    static constexpr float STANDARD_RMSE = 0.01f;
    static constexpr float STANDARD_MAX_ERROR = 0.1f;
    
    // Per-tensor tolerances (Q4 specific)
    static constexpr float Q4_0_COSINE = 0.995f;   // 4-bit inherent error
    static constexpr float Q4_K_COSINE = 0.997f;   // K-quant better
    static constexpr float Q8_0_COSINE = 0.9995f;  // 8-bit high quality
    
    // Edge case thresholds
    static constexpr float OUTLIER_THRESHOLD = 5.0f;  // 5 sigma
    static constexpr float ZERO_TOLERANCE = 1e-6f;
};

// ============================================================================
// Validation Report
// ============================================================================

struct FusedValidationReport {
    // Test configuration
    compression::CompressionType codec_type;
    size_t rows;
    size_t cols;
    size_t iterations;
    
    // Numerical metrics
    float cosine_similarity;
    float rmse;
    float max_absolute_error;
    float mean_absolute_error;
    float relative_error_percent;
    
    // Statistical analysis
    float reference_mean;
    float reference_std;
    float fused_mean;
    float fused_std;
    float correlation;
    
    // Edge case detection
    size_t outlier_count;
    size_t near_zero_mismatch;
    size_t sign_mismatch;
    
    // Performance
    double fused_time_ms;
    double reference_time_ms;
    double speedup;
    
    // Validation result
    bool passed;
    std::string failure_reason;
    std::vector<std::string> warnings;
    
    // Print detailed report
    void Print() const;
    bool operator==(const FusedValidationReport& other) const;
};

// ============================================================================
// Reference GEMM Implementations
// ============================================================================

class ReferenceGemm {
public:
    /**
     * @brief Reference FP32 GEMV (naive, correct)
     * 
     * Unoptimized reference implementation for validation.
     */
    static void GemvFP32(
        const float* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief Reference GEMV with dequantized weights
     * 
     * Decompress then multiply - validates decode path.
     */
    static void GemvDequantized(
        compression::CompressionType type,
        const uint8_t* compressed_weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief BLAS-style GEMM (if available)
     * 
     * Uses system BLAS for ground truth.
     */
    static void GemvBLAS(
        const float* weights,
        const float* input,
        float* output,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief High precision accumulator GEMV
     * 
     * Uses double precision for numerical ground truth.
     */
    static void GemvHighPrecision(
        const float* weights,
        const float* input,
        double* output,
        size_t rows,
        size_t cols
    );
};

// ============================================================================
// Fused GEMM Validator
// ============================================================================

class FusedGemmValidator {
public:
    FusedGemmValidator();
    ~FusedGemmValidator() = default;
    
    // ------------------------------------------------------------------------
    // Validation Entry Points
    // ------------------------------------------------------------------------
    
    /**
     * @brief Validate fused kernel against reference
     * 
     * @param type Compression type
     * @param weights_fp32 Original FP32 weights (for reference)
     * @param input Input vector
     * @param rows Number of rows
     * @param cols Number of columns
     * @param iterations Number of test iterations
     * @return Validation report
     */
    FusedValidationReport Validate(
        compression::CompressionType type,
        const float* weights_fp32,
        const float* input,
        size_t rows,
        size_t cols,
        size_t iterations = 10
    );
    
    /**
     * @brief Quick validation with default thresholds
     */
    bool QuickValidate(
        compression::CompressionType type,
        const float* weights_fp32,
        const float* input,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief Production validation with strict thresholds
     */
    FusedValidationReport ProductionValidate(
        compression::CompressionType type,
        const float* weights_fp32,
        const float* input,
        size_t rows,
        size_t cols
    );
    
    // ------------------------------------------------------------------------
    // Per-Codec Validation
    // ------------------------------------------------------------------------
    
    FusedValidationReport ValidateQ4_0(
        const float* weights_fp32,
        const float* input,
        size_t rows,
        size_t cols
    );
    
    FusedValidationReport ValidateQ4_K(
        const float* weights_fp32,
        const float* input,
        size_t rows,
        size_t cols
    );
    
    FusedValidationReport ValidateQ8_0(
        const float* weights_fp32,
        const float* input,
        size_t rows,
        size_t cols
    );
    
    // ------------------------------------------------------------------------
    // Edge Case Testing
    // ------------------------------------------------------------------------
    
    /**
     * @brief Test with edge case values
     * 
     * Tests: zeros, near-zeros, large values, alternating signs
     */
    FusedValidationReport ValidateEdgeCases(
        compression::CompressionType type,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief Test with random distributions
     * 
     * Tests: normal, uniform, sparse, clustered
     */
    FusedValidationReport ValidateDistributions(
        compression::CompressionType type,
        size_t rows,
        size_t cols
    );
    
    /**
     * @brief Stress test with adversarial inputs
     * 
     * Tests: maximum quantization error, boundary conditions
     */
    FusedValidationReport StressTest(
        compression::CompressionType type,
        size_t rows,
        size_t cols
    );
    
    // ------------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------------
    
    void SetCosineThreshold(float threshold);
    void SetRMSEThreshold(float threshold);
    void SetMaxErrorThreshold(float threshold);
    void SetVerbose(bool verbose);
    
private:
    float cosine_threshold_ = ValidationGates::STANDARD_COSINE;
    float rmse_threshold_ = ValidationGates::STANDARD_RMSE;
    float max_error_threshold_ = ValidationGates::STANDARD_MAX_ERROR;
    bool verbose_ = false;
    
    // Internal validation
    bool CheckCosine(float cosine) const;
    bool CheckRMSE(float rmse) const;
    bool CheckMaxError(float error) const;
    
    // Statistical analysis
    void AnalyzeDifferences(
        const float* reference,
        const float* fused,
        size_t count,
        FusedValidationReport* report
    );
};

// ============================================================================
// Numerical Comparison Utilities
// ============================================================================

class NumericalComparison {
public:
    /**
     * @brief Cosine similarity with numerical stability
     */
    static float CosineSimilarity(
        const float* a,
        const float* b,
        size_t count
    );
    
    /**
     * @brief RMSE calculation
     */
    static float RMSE(
        const float* reference,
        const float* test,
        size_t count
    );
    
    /**
     * @brief Relative error (handles near-zero)
     */
    static float RelativeError(
        const float* reference,
        const float* test,
        size_t count
    );
    
    /**
     * @brief Find outliers (values beyond N sigma)
     */
    static size_t CountOutliers(
        const float* reference,
        const float* test,
        size_t count,
        float sigma_threshold
    );
    
    /**
     * @brief Check for sign mismatches
     */
    static size_t CountSignMismatches(
        const float* reference,
        const float* test,
        size_t count
    );
    
    /**
     * @brief Check for near-zero mismatches
     */
    static size_t CountNearZeroMismatches(
        const float* reference,
        const float* test,
        size_t count,
        float tolerance
    );
};

// ============================================================================
// Validation Suite
// ============================================================================

class ValidationSuite {
public:
    /**
     * @brief Run full validation suite
     * 
     * Tests all codecs with multiple scenarios.
     */
    static bool RunFullSuite();
    
    /**
     * @brief Run production validation
     * 
     * Strict thresholds for deployment.
     */
    static bool RunProductionSuite();
    
    /**
     * @brief Run quick smoke test
     * 
     * Fast validation for CI.
     */
    static bool RunSmokeTest();
    
    /**
     * @brief Generate validation report
     */
    static void GenerateReport(const char* filename);
    
private:
    static bool ValidateCodec(compression::CompressionType type);
    static bool ValidateEdgeCases(compression::CompressionType type);
    static bool ValidatePerformance(compression::CompressionType type);
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define RAWRXD_VALIDATE_FUSED(type, weights, input, rows, cols) \
    rawrxd::validation::FusedGemmValidator().QuickValidate( \
        type, weights, input, rows, cols)

#define RAWRXD_VALIDATE_PRODUCTION(type, weights, input, rows, cols) \
    rawrxd::validation::FusedGemmValidator().ProductionValidate( \
        type, weights, input, rows, cols)

#define RAWRXD_RUN_VALIDATION_SUITE() \
    rawrxd::validation::ValidationSuite::RunFullSuite()

} // namespace validation
} // namespace rawrxd

#endif // RAWRXD_FUSED_GEMM_VALIDATOR_H
