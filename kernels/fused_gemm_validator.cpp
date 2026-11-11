/**
 * @file fused_gemm_validator.cpp
 * @brief RawrXD L4.2.3 Fused GEMM Reference Validation Implementation
 *
 * Numerical correctness gates for fused kernels.
 *
 * @copyright RawrXD 2026
 */

#include "fused_gemm_validator.h"
#include <cmath>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <random>
#include <cstring>

namespace rawrxd {
namespace validation {

// ============================================================================
// Validation Report
// ============================================================================

void FusedValidationReport::Print() const {
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "FUSED GEMM VALIDATION REPORT\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    std::cout << "Configuration:\n";
    std::cout << "  Codec: " << compression::CompressionTypeToString(codec_type) << "\n";
    std::cout << "  Matrix: " << rows << " x " << cols << "\n";
    std::cout << "  Iterations: " << iterations << "\n\n";
    
    std::cout << std::fixed << std::setprecision(6);
    std::cout << "Numerical Metrics:\n";
    std::cout << "  Cosine Similarity: " << cosine_similarity;
    if (cosine_similarity >= ValidationGates::PRODUCTION_COSINE) {
        std::cout << " ✅ PRODUCTION\n";
    } else if (cosine_similarity >= ValidationGates::STANDARD_COSINE) {
        std::cout << " ✅ STANDARD\n";
    } else if (cosine_similarity >= 0.99f) {
        std::cout << " ⚠️ ACCEPTABLE\n";
    } else {
        std::cout << " ❌ FAIL\n";
    }
    
    std::cout << "  RMSE: " << rmse;
    if (rmse <= ValidationGates::PRODUCTION_RMSE) {
        std::cout << " ✅ PRODUCTION\n";
    } else if (rmse <= ValidationGates::STANDARD_RMSE) {
        std::cout << " ✅ STANDARD\n";
    } else {
        std::cout << " ❌ FAIL\n";
    }
    
    std::cout << "  Max Error: " << max_absolute_error << "\n";
    std::cout << "  Mean Error: " << mean_absolute_error << "\n";
    std::cout << "  Relative Error: " << relative_error_percent << "%\n\n";
    
    std::cout << "Statistics:\n";
    std::cout << "  Reference Mean: " << reference_mean << "\n";
    std::cout << "  Reference Std: " << reference_std << "\n";
    std::cout << "  Fused Mean: " << fused_mean << "\n";
    std::cout << "  Fused Std: " << fused_std << "\n";
    std::cout << "  Correlation: " << correlation << "\n\n";
    
    std::cout << "Edge Cases:\n";
    std::cout << "  Outliers: " << outlier_count << "\n";
    std::cout << "  Near-zero Mismatches: " << near_zero_mismatch << "\n";
    std::cout << "  Sign Mismatches: " << sign_mismatch << "\n\n";
    
    std::cout << "Performance:\n";
    std::cout << "  Fused Time: " << std::setprecision(3) << fused_time_ms << " ms\n";
    std::cout << "  Reference Time: " << reference_time_ms << " ms\n";
    std::cout << "  Speedup: " << std::setprecision(2) << speedup << "x\n\n";
    
    if (!warnings.empty()) {
        std::cout << "Warnings:\n";
        for (const auto& w : warnings) {
            std::cout << "  ⚠️ " << w << "\n";
        }
        std::cout << "\n";
    }
    
    std::cout << "Validation: " << (passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    if (!passed && !failure_reason.empty()) {
        std::cout << "Reason: " << failure_reason << "\n";
    }
    
    std::cout << "═══════════════════════════════════════════════════════════════\n";
}

bool FusedValidationReport::operator==(const FusedValidationReport& other) const {
    return std::abs(cosine_similarity - other.cosine_similarity) < 0.0001f &&
           std::abs(rmse - other.rmse) < 0.0001f &&
           passed == other.passed;
}

// ============================================================================
// Reference GEMM Implementations
// ============================================================================

void ReferenceGemm::GemvFP32(
    const float* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    for (size_t r = 0; r < rows; r++) {
        double sum = 0.0;  // Use double for accumulation
        for (size_t c = 0; c < cols; c++) {
            sum += static_cast<double>(weights[r * cols + c]) * 
                   static_cast<double>(input[c]);
        }
        output[r] = static_cast<float>(sum);
    }
}

void ReferenceGemm::GemvDequantized(
    compression::CompressionType type,
    const uint8_t* compressed_weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    auto codec = compression::CodecFactory::Create(type);
    if (!codec) return;
    
    // Decompress to FP32
    std::vector<float> decompressed(rows * cols);
    codec->DecodeBlock(compressed_weights, decompressed.data(), rows * cols);
    
    // Reference GEMV
    GemvFP32(decompressed.data(), input, output, rows, cols);
}

void ReferenceGemm::GemvBLAS(
    const float* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    // Fallback to reference implementation
    // Real implementation would use cblas_sgemv
    GemvFP32(weights, input, output, rows, cols);
}

void ReferenceGemm::GemvHighPrecision(
    const float* weights,
    const float* input,
    double* output,
    size_t rows,
    size_t cols
) {
    for (size_t r = 0; r < rows; r++) {
        double sum = 0.0;
        for (size_t c = 0; c < cols; c++) {
            sum += static_cast<double>(weights[r * cols + c]) * 
                   static_cast<double>(input[c]);
        }
        output[r] = sum;
    }
}

// ============================================================================
// Fused GEMM Validator
// ============================================================================

FusedGemmValidator::FusedGemmValidator()
    : cosine_threshold_(ValidationGates::STANDARD_COSINE)
    , rmse_threshold_(ValidationGates::STANDARD_RMSE)
    , max_error_threshold_(ValidationGates::STANDARD_MAX_ERROR)
    , verbose_(false)
{}

FusedValidationReport FusedGemmValidator::Validate(
    compression::CompressionType type,
    const float* weights_fp32,
    const float* input,
    size_t rows,
    size_t cols,
    size_t iterations
) {
    FusedValidationReport report;
    report.codec_type = type;
    report.rows = rows;
    report.cols = cols;
    report.iterations = iterations;
    
    // Get codec
    auto codec = compression::CodecFactory::Create(type);
    if (!codec) {
        report.passed = false;
        report.failure_reason = "Failed to create codec";
        return report;
    }
    
    // Compress weights
    std::vector<uint8_t> compressed(codec->GetCompressedSize(rows * cols));
    codec->EncodeBlock(weights_fp32, compressed.data(), rows * cols);
    
    // Allocate outputs
    std::vector<float> reference_output(rows);
    std::vector<float> fused_output(rows);
    
    // Run reference
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t iter = 0; iter < iterations; iter++) {
        ReferenceGemm::GemvFP32(weights_fp32, input, reference_output.data(), rows, cols);
    }
    auto end = std::chrono::high_resolution_clock::now();
    report.reference_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0 / iterations;
    
    // Run fused
    start = std::chrono::high_resolution_clock::now();
    for (size_t iter = 0; iter < iterations; iter++) {
        kernels::FusedQuantGemm::GemvAuto(type, compressed.data(), input, fused_output.data(), rows, cols);
    }
    end = std::chrono::high_resolution_clock::now();
    report.fused_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0 / iterations;
    
    report.speedup = report.reference_time_ms / report.fused_time_ms;
    
    // Analyze differences
    AnalyzeDifferences(reference_output.data(), fused_output.data(), rows, &report);
    
    // Check gates
    report.passed = CheckCosine(report.cosine_similarity) &&
                    CheckRMSE(report.rmse) &&
                    CheckMaxError(report.max_absolute_error);
    
    if (!report.passed && report.failure_reason.empty()) {
        if (!CheckCosine(report.cosine_similarity)) {
            report.failure_reason = "Cosine similarity below threshold";
        } else if (!CheckRMSE(report.rmse)) {
            report.failure_reason = "RMSE above threshold";
        } else {
            report.failure_reason = "Max error above threshold";
        }
    }
    
    return report;
}

bool FusedGemmValidator::QuickValidate(
    compression::CompressionType type,
    const float* weights_fp32,
    const float* input,
    size_t rows,
    size_t cols
) {
    auto report = Validate(type, weights_fp32, input, rows, cols, 1);
    return report.passed;
}

FusedValidationReport FusedGemmValidator::ProductionValidate(
    compression::CompressionType type,
    const float* weights_fp32,
    const float* input,
    size_t rows,
    size_t cols
) {
    // Temporarily set strict thresholds
    float old_cosine = cosine_threshold_;
    float old_rmse = rmse_threshold_;
    float old_max = max_error_threshold_;
    
    cosine_threshold_ = ValidationGates::PRODUCTION_COSINE;
    rmse_threshold_ = ValidationGates::PRODUCTION_RMSE;
    max_error_threshold_ = ValidationGates::PRODUCTION_MAX_ERROR;
    
    auto report = Validate(type, weights_fp32, input, rows, cols, 100);
    
    // Restore thresholds
    cosine_threshold_ = old_cosine;
    rmse_threshold_ = old_rmse;
    max_error_threshold_ = old_max;
    
    return report;
}

FusedValidationReport FusedGemmValidator::ValidateQ4_0(
    const float* weights_fp32,
    const float* input,
    size_t rows,
    size_t cols
) {
    // Set Q4_0 specific thresholds
    float old_cosine = cosine_threshold_;
    cosine_threshold_ = ValidationGates::Q4_0_COSINE;
    
    auto report = Validate(compression::CompressionType::Q4_0, weights_fp32, input, rows, cols);
    
    cosine_threshold_ = old_cosine;
    return report;
}

FusedValidationReport FusedGemmValidator::ValidateQ4_K(
    const float* weights_fp32,
    const float* input,
    size_t rows,
    size_t cols
) {
    float old_cosine = cosine_threshold_;
    cosine_threshold_ = ValidationGates::Q4_K_COSINE;
    
    auto report = Validate(compression::CompressionType::Q4_K, weights_fp32, input, rows, cols);
    
    cosine_threshold_ = old_cosine;
    return report;
}

FusedValidationReport FusedGemmValidator::ValidateQ8_0(
    const float* weights_fp32,
    const float* input,
    size_t rows,
    size_t cols
) {
    float old_cosine = cosine_threshold_;
    cosine_threshold_ = ValidationGates::Q8_0_COSINE;
    
    auto report = Validate(compression::CompressionType::Q8_0, weights_fp32, input, rows, cols);
    
    cosine_threshold_ = old_cosine;
    return report;
}

FusedValidationReport FusedGemmValidator::ValidateEdgeCases(
    compression::CompressionType type,
    size_t rows,
    size_t cols
) {
    // Test with various edge cases
    std::vector<float> weights(rows * cols);
    std::vector<float> input(cols);
    
    // Case 1: All zeros
    std::fill(weights.begin(), weights.end(), 0.0f);
    std::fill(input.begin(), input.end(), 0.0f);
    
    auto report = Validate(type, weights.data(), input.data(), rows, cols, 1);
    report.warnings.push_back("Edge case: all zeros");
    
    // Case 2: Large values
    std::fill(weights.begin(), weights.end(), 10.0f);
    std::fill(input.begin(), input.end(), 10.0f);
    
    auto report2 = Validate(type, weights.data(), input.data(), rows, cols, 1);
    if (!report2.passed) {
        report.warnings.push_back("Edge case: large values failed");
    }
    
    return report;
}

FusedValidationReport FusedGemmValidator::ValidateDistributions(
    compression::CompressionType type,
    size_t rows,
    size_t cols
) {
    std::vector<float> weights(rows * cols);
    std::vector<float> input(cols);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> normal_dist(0.0f, 0.1f);
    std::uniform_real_distribution<float> uniform_dist(-1.0f, 1.0f);
    
    // Normal distribution
    for (auto& w : weights) w = normal_dist(rng);
    for (auto& i : input) i = normal_dist(rng);
    
    auto report = Validate(type, weights.data(), input.data(), rows, cols);
    report.warnings.push_back("Distribution: normal");
    
    return report;
}

FusedValidationReport FusedGemmValidator::StressTest(
    compression::CompressionType type,
    size_t rows,
    size_t cols
) {
    std::vector<float> weights(rows * cols);
    std::vector<float> input(cols);
    
    // Maximum quantization stress
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-0.5f, 0.5f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    auto report = Validate(type, weights.data(), input.data(), rows, cols, 1000);
    report.warnings.push_back("Stress test: 1000 iterations");
    
    return report;
}

void FusedGemmValidator::SetCosineThreshold(float threshold) {
    cosine_threshold_ = threshold;
}

void FusedGemmValidator::SetRMSEThreshold(float threshold) {
    rmse_threshold_ = threshold;
}

void FusedGemmValidator::SetMaxErrorThreshold(float threshold) {
    max_error_threshold_ = threshold;
}

void FusedGemmValidator::SetVerbose(bool verbose) {
    verbose_ = verbose;
}

bool FusedGemmValidator::CheckCosine(float cosine) const {
    return cosine >= cosine_threshold_;
}

bool FusedGemmValidator::CheckRMSE(float rmse) const {
    return rmse <= rmse_threshold_;
}

bool FusedGemmValidator::CheckMaxError(float error) const {
    return error <= max_error_threshold_;
}

void FusedGemmValidator::AnalyzeDifferences(
    const float* reference,
    const float* fused,
    size_t count,
    FusedValidationReport* report
) {
    if (!report) return;
    
    double sum_ref = 0.0, sum_fused = 0.0;
    double sum_ref_sq = 0.0, sum_fused_sq = 0.0;
    double dot_product = 0.0;
    double sum_squared_error = 0.0;
    
    report->max_absolute_error = 0.0f;
    report->mean_absolute_error = 0.0f;
    report->outlier_count = 0;
    report->near_zero_mismatch = 0;
    report->sign_mismatch = 0;
    
    for (size_t i = 0; i < count; i++) {
        float ref = reference[i];
        float fus = fused[i];
        
        // Error metrics
        float error = std::abs(ref - fus);
        report->max_absolute_error = std::max(report->max_absolute_error, error);
        report->mean_absolute_error += error;
        sum_squared_error += error * error;
        
        // Statistics
        sum_ref += ref;
        sum_fused += fus;
        sum_ref_sq += ref * ref;
        sum_fused_sq += fus * fus;
        dot_product += ref * fus;
        
        // Edge case detection
        if (error > ValidationGates::OUTLIER_THRESHOLD * std::sqrt(sum_squared_error / (i + 1))) {
            report->outlier_count++;
        }
        if (std::abs(ref) < ValidationGates::ZERO_TOLERANCE && 
            std::abs(fus) > ValidationGates::ZERO_TOLERANCE) {
            report->near_zero_mismatch++;
        }
        if ((ref > 0) != (fus > 0) && ref != 0 && fus != 0) {
            report->sign_mismatch++;
        }
    }
    
    report->mean_absolute_error /= static_cast<float>(count);
    report->rmse = static_cast<float>(std::sqrt(sum_squared_error / count));
    
    // Cosine similarity
    double norm_ref = std::sqrt(sum_ref_sq);
    double norm_fused = std::sqrt(sum_fused_sq);
    if (norm_ref > 0 && norm_fused > 0) {
        report->cosine_similarity = static_cast<float>(dot_product / (norm_ref * norm_fused));
    } else {
        report->cosine_similarity = 0.0f;
    }
    
    // Correlation
    double mean_ref = sum_ref / count;
    double mean_fused = sum_fused / count;
    double cov = dot_product - count * mean_ref * mean_fused;
    double var_ref = sum_ref_sq - count * mean_ref * mean_ref;
    double var_fused = sum_fused_sq - count * mean_fused * mean_fused;
    
    if (var_ref > 0 && var_fused > 0) {
        report->correlation = static_cast<float>(cov / std::sqrt(var_ref * var_fused));
    } else {
        report->correlation = 0.0f;
    }
    
    report->reference_mean = static_cast<float>(mean_ref);
    report->reference_std = static_cast<float>(std::sqrt(var_ref / count));
    report->fused_mean = static_cast<float>(mean_fused);
    report->fused_std = static_cast<float>(std::sqrt(var_fused / count));
    
    // Relative error
    float avg_magnitude = report->reference_mean;
    report->relative_error_percent = (avg_magnitude > 0) ? 
        (report->mean_absolute_error / avg_magnitude) * 100.0f : 0.0f;
}

// ============================================================================
// Numerical Comparison Utilities
// ============================================================================

float NumericalComparison::CosineSimilarity(
    const float* a,
    const float* b,
    size_t count
) {
    double dot = 0.0;
    double norm_a = 0.0;
    double norm_b = 0.0;
    
    for (size_t i = 0; i < count; i++) {
        dot += static_cast<double>(a[i]) * static_cast<double>(b[i]);
        norm_a += static_cast<double>(a[i]) * static_cast<double>(a[i]);
        norm_b += static_cast<double>(b[i]) * static_cast<double>(b[i]);
    }
    
    if (norm_a == 0.0 || norm_b == 0.0) return 0.0f;
    return static_cast<float>(dot / std::sqrt(norm_a * norm_b));
}

float NumericalComparison::RMSE(
    const float* reference,
    const float* test,
    size_t count
) {
    double sum_squared = 0.0;
    for (size_t i = 0; i < count; i++) {
        double diff = static_cast<double>(reference[i]) - static_cast<double>(test[i]);
        sum_squared += diff * diff;
    }
    return static_cast<float>(std::sqrt(sum_squared / count));
}

float NumericalComparison::RelativeError(
    const float* reference,
    const float* test,
    size_t count
) {
    double sum_error = 0.0;
    double sum_ref = 0.0;
    
    for (size_t i = 0; i < count; i++) {
        sum_error += std::abs(static_cast<double>(reference[i]) - static_cast<double>(test[i]));
        sum_ref += std::abs(static_cast<double>(reference[i]));
    }
    
    return (sum_ref > 0) ? static_cast<float>(sum_error / sum_ref) : 0.0f;
}

size_t NumericalComparison::CountOutliers(
    const float* reference,
    const float* test,
    size_t count,
    float sigma_threshold
) {
    // Calculate mean error
    double mean_error = 0.0;
    for (size_t i = 0; i < count; i++) {
        mean_error += std::abs(static_cast<double>(reference[i]) - static_cast<double>(test[i]));
    }
    mean_error /= count;
    
    // Calculate std dev
    double variance = 0.0;
    for (size_t i = 0; i < count; i++) {
        double error = std::abs(static_cast<double>(reference[i]) - static_cast<double>(test[i]));
        variance += (error - mean_error) * (error - mean_error);
    }
    double std_dev = std::sqrt(variance / count);
    
    // Count outliers
    size_t outliers = 0;
    for (size_t i = 0; i < count; i++) {
        double error = std::abs(static_cast<double>(reference[i]) - static_cast<double>(test[i]));
        if (error > mean_error + sigma_threshold * std_dev) {
            outliers++;
        }
    }
    
    return outliers;
}

size_t NumericalComparison::CountSignMismatches(
    const float* reference,
    const float* test,
    size_t count
) {
    size_t mismatches = 0;
    for (size_t i = 0; i < count; i++) {
        if ((reference[i] > 0) != (test[i] > 0) && reference[i] != 0 && test[i] != 0) {
            mismatches++;
        }
    }
    return mismatches;
}

size_t NumericalComparison::CountNearZeroMismatches(
    const float* reference,
    const float* test,
    size_t count,
    float tolerance
) {
    size_t mismatches = 0;
    for (size_t i = 0; i < count; i++) {
        if (std::abs(reference[i]) < tolerance && std::abs(test[i]) >= tolerance) {
            mismatches++;
        }
    }
    return mismatches;
}

// ============================================================================
// Validation Suite
// ============================================================================

bool ValidationSuite::RunFullSuite() {
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "RUNNING FULL VALIDATION SUITE\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    bool all_passed = true;
    
    // Test all codecs
    compression::CompressionType codecs[] = {
        compression::CompressionType::Q4_0,
        compression::CompressionType::Q4_K,
        compression::CompressionType::Q8_0
    };
    
    for (auto type : codecs) {
        std::cout << "\nTesting " << compression::CompressionTypeToString(type) << "...\n";
        if (!ValidateCodec(type)) {
            all_passed = false;
        }
    }
    
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "FULL SUITE: " << (all_passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    return all_passed;
}

bool ValidationSuite::RunProductionSuite() {
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "RUNNING PRODUCTION VALIDATION SUITE\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    FusedGemmValidator validator;
    validator.SetCosineThreshold(ValidationGates::PRODUCTION_COSINE);
    validator.SetRMSEThreshold(ValidationGates::PRODUCTION_RMSE);
    validator.SetMaxErrorThreshold(ValidationGates::PRODUCTION_MAX_ERROR);
    
    // Generate test data
    const size_t ROWS = 128;
    const size_t COLS = 512;
    
    std::vector<float> weights(ROWS * COLS);
    std::vector<float> input(COLS);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    bool all_passed = true;
    
    // Test Q4_0
    auto report = validator.ValidateQ4_0(weights.data(), input.data(), ROWS, COLS);
    report.Print();
    if (!report.passed) all_passed = false;
    
    // Test Q8_0
    report = validator.ValidateQ8_0(weights.data(), input.data(), ROWS, COLS);
    report.Print();
    if (!report.passed) all_passed = false;
    
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "PRODUCTION SUITE: " << (all_passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    return all_passed;
}

bool ValidationSuite::RunSmokeTest() {
    std::cout << "\n═══════════════════════════════════════════════════════════════\n";
    std::cout << "RUNNING SMOKE TEST\n";
    std::cout << "═══════════════════════════════════════════════════════════════\n";
    
    FusedGemmValidator validator;
    
    const size_t ROWS = 32;
    const size_t COLS = 128;
    
    std::vector<float> weights(ROWS * COLS);
    std::vector<float> input(COLS);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    bool passed = validator.QuickValidate(
        compression::CompressionType::Q4_0,
        weights.data(), input.data(), ROWS, COLS
    );
    
    std::cout << "SMOKE TEST: " << (passed ? "✅ PASSED" : "❌ FAILED") << "\n";
    
    return passed;
}

void ValidationSuite::GenerateReport(const char* filename) {
    // Would write detailed report to file
    (void)filename;
    std::cout << "Report generation not yet implemented\n";
}

bool ValidationSuite::ValidateCodec(compression::CompressionType type) {
    FusedGemmValidator validator;
    
    const size_t ROWS = 64;
    const size_t COLS = 256;
    
    std::vector<float> weights(ROWS * COLS);
    std::vector<float> input(COLS);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    auto report = validator.Validate(type, weights.data(), input.data(), ROWS, COLS);
    report.Print();
    
    return report.passed;
}

bool ValidationSuite::ValidateEdgeCases(compression::CompressionType type) {
    FusedGemmValidator validator;
    auto report = validator.ValidateEdgeCases(type, 32, 128);
    return report.passed;
}

bool ValidationSuite::ValidatePerformance(compression::CompressionType type) {
    FusedGemmValidator validator;
    auto report = validator.StressTest(type, 128, 512);
    return report.passed && report.speedup > 1.0f;
}

} // namespace validation
} // namespace rawrxd
