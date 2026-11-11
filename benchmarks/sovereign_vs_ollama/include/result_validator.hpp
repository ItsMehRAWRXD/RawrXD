// Result Validation and Sanity Checking
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <vector>
#include <string>
#include <functional>

namespace rawrxd::benchmark {

// ============================================================================
// Validation Severity Levels
// ============================================================================

enum class ValidationSeverity {
    INFO = 0,      // Informational, no action needed
    WARNING = 1,   // Potential issue, should review
    ERROR = 2,     // Definite issue, results may be invalid
    CRITICAL = 3   // Critical issue, results are invalid
};

inline const char* SeverityToString(ValidationSeverity severity) {
    switch (severity) {
        case ValidationSeverity::INFO: return "INFO";
        case ValidationSeverity::WARNING: return "WARNING";
        case ValidationSeverity::ERROR: return "ERROR";
        case ValidationSeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Validation Result
// ============================================================================

struct ValidationResult {
    ValidationSeverity severity;
    std::string message;
    std::string category;
    std::string suggestion;
    
    bool IsValid() const { return severity < ValidationSeverity::ERROR; }
};

// ============================================================================
// Result Validator
// ============================================================================

class ResultValidator {
public:
    // Validate benchmark result
    static std::vector<ValidationResult> ValidateResult(const BenchmarkResult& result);
    
    // Validate latency samples
    static std::vector<ValidationResult> ValidateLatencySamples(
        const std::vector<double>& samples,
        BenchmarkCategory category);
    
    // Validate throughput samples
    static std::vector<ValidationResult> ValidateThroughputSamples(
        const std::vector<double>& samples);
    
    // Validate success rate
    static ValidationResult ValidateSuccessRate(double success_rate);
    
    // Validate resource metrics
    static std::vector<ValidationResult> ValidateResourceMetrics(
        const ResourceMetrics& metrics);
    
    // Validate quality metrics
    static std::vector<ValidationResult> ValidateQualityMetrics(
        const QualityMetrics& metrics);
    
    // Check for outliers
    static std::vector<ValidationResult> CheckOutliers(
        const std::vector<double>& samples,
        double threshold = 3.0);  // Standard deviations
    
    // Check for bimodal distribution (indicates instability)
    static ValidationResult CheckBimodality(const std::vector<double>& samples);
    
    // Check for trend (increasing/decreasing latency over time)
    static ValidationResult CheckTrend(const std::vector<double>& samples);
    
    // Check sample size adequacy
    static ValidationResult CheckSampleSize(int sample_count, int minimum = 30);
    
    // Check confidence interval width
    static ValidationResult CheckConfidenceIntervalWidth(
        const ConfidenceInterval& ci, double max_width_percent = 20.0);
    
    // Check for negative values
    static std::vector<ValidationResult> CheckNegativeValues(
        const std::vector<double>& samples);
    
    // Check for NaN or Inf values
    static std::vector<ValidationResult> CheckInvalidValues(
        const std::vector<double>& samples);
    
    // Check for duplicate values (indicates caching or lack of variation)
    static ValidationResult CheckDuplicateValues(
        const std::vector<double>& samples, double threshold_percent = 10.0);
    
    // Check for reasonable ranges based on category
    static std::vector<ValidationResult> CheckCategoryRanges(
        const std::vector<double>& samples,
        BenchmarkCategory category);
    
    // Get expected latency range for category
    static std::pair<double, double> GetExpectedLatencyRange(BenchmarkCategory category);
    
    // Get expected throughput range for category
    static std::pair<double, double> GetExpectedThroughputRange(BenchmarkCategory category);
    
    // Validate comparison between two results
    static std::vector<ValidationResult> ValidateComparison(
        const BenchmarkResult& baseline,
        const BenchmarkResult& current);
    
    // Check for regression
    static ValidationResult CheckRegression(
        const BenchmarkResult& baseline,
        const BenchmarkResult& current,
        double threshold_percent = 10.0);
    
    // Check for improvement
    static ValidationResult CheckImprovement(
        const BenchmarkResult& baseline,
        const BenchmarkResult& current,
        double threshold_percent = 10.0);
    
    // Aggregate validation results
    static bool HasErrors(const std::vector<ValidationResult>& results);
    static bool HasCriticalErrors(const std::vector<ValidationResult>& results);
    static int CountBySeverity(const std::vector<ValidationResult>& results, 
                                ValidationSeverity severity);
    
    // Print validation results
    static void PrintResults(const std::vector<ValidationResult>& results);
    
    // Generate validation report
    static std::string GenerateReport(const std::vector<ValidationResult>& results);
};

// ============================================================================
// Sanity Checker
// ============================================================================

class SanityChecker {
public:
    // Quick sanity check - returns false if critical issues found
    static bool QuickCheck(const BenchmarkResult& result);
    
    // Full sanity check with detailed results
    static std::vector<ValidationResult> FullCheck(const BenchmarkResult& result);
    
    // Check if result is publishable (no errors)
    static bool IsPublishable(const BenchmarkResult& result);
    
    // Check if result needs investigation (warnings present)
    static bool NeedsInvestigation(const BenchmarkResult& result);
    
    // Set custom thresholds
    void SetLatencyThreshold(double min_ms, double max_ms);
    void SetThroughputThreshold(double min_tps);
    void SetSuccessRateThreshold(double min_rate);
    void SetOutlierThreshold(double std_devs);
    
    // Add custom validation rule
    void AddCustomRule(std::function<ValidationResult(const BenchmarkResult&)> rule);
    
    // Run all custom rules
    std::vector<ValidationResult> RunCustomRules(const BenchmarkResult& result);

private:
    double min_latency_ms_ = 1.0;
    double max_latency_ms_ = 60000.0;  // 60 seconds
    double min_throughput_tps_ = 0.1;
    double min_success_rate_ = 0.95;  // 95%
    double outlier_threshold_ = 3.0;  // 3 standard deviations
    
    std::vector<std::function<ValidationResult(const BenchmarkResult&)>> custom_rules_;
};

// ============================================================================
// Statistical Validation
// ============================================================================

class StatisticalValidator {
public:
    // Validate that sample size is sufficient for statistical power
    static ValidationResult ValidateSampleSize(
        int sample_size,
        double expected_effect_size = 0.5,  // Cohen's d
        double desired_power = 0.8,
        double alpha = 0.05);
    
    // Validate normality assumption
    static ValidationResult ValidateNormality(
        const std::vector<double>& samples,
        double alpha = 0.05);
    
    // Validate homogeneity of variance (for t-tests)
    static ValidationResult ValidateHomogeneity(
        const std::vector<double>& samples1,
        const std::vector<double>& samples2,
        double alpha = 0.05);
    
    // Validate independence assumption
    static ValidationResult ValidateIndependence(
        const std::vector<double>& samples);
    
    // Check for sufficient effect size
    static ValidationResult ValidateEffectSize(
        double cohens_d,
        double min_effect_size = 0.2);
    
    // Calculate required sample size for desired power
    static int CalculateRequiredSampleSize(
        double expected_effect_size,
        double desired_power = 0.8,
        double alpha = 0.05);
    
    // Validate that confidence interval is appropriate
    static ValidationResult ValidateConfidenceInterval(
        const ConfidenceInterval& ci,
        double expected_width = 0.0);
};

// ============================================================================
// Data Quality Checks
// ============================================================================

class DataQualityChecker {
public:
    // Check for missing data
    static ValidationResult CheckMissingData(const BenchmarkResult& result);
    
    // Check for inconsistent timestamps
    static ValidationResult CheckTimestamps(const BenchmarkResult& result);
    
    // Check for data completeness
    static std::vector<ValidationResult> CheckCompleteness(
        const BenchmarkResult& result);
    
    // Check for data consistency
    static std::vector<ValidationResult> CheckConsistency(
        const BenchmarkResult& result);
    
    // Validate raw samples
    static std::vector<ValidationResult> ValidateRawSamples(
        const std::vector<double>& samples);
    
    // Check for measurement artifacts
    static std::vector<ValidationResult> CheckArtifacts(
        const std::vector<double>& samples);
};

// ============================================================================
// Threshold Constants
// ============================================================================

namespace thresholds {
    // Latency thresholds by category (ms)
    constexpr double INFERENCE_MIN_MS = 10.0;
    constexpr double INFERENCE_MAX_MS = 30000.0;
    constexpr double AGENT_SPAWN_MIN_MS = 1.0;
    constexpr double AGENT_SPAWN_MAX_MS = 5000.0;
    constexpr double SWARM_MIN_MS = 100.0;
    constexpr double SWARM_MAX_MS = 60000.0;
    constexpr double SEG_MIN_MS = 50.0;
    constexpr double SEG_MAX_MS = 30000.0;
    constexpr double DECISION_MIN_MS = 5.0;
    constexpr double DECISION_MAX_MS = 10000.0;
    
    // Throughput thresholds by category (tokens/sec)
    constexpr double INFERENCE_MIN_TPS = 1.0;
    constexpr double INFERENCE_MAX_TPS = 10000.0;
    
    // Success rate thresholds
    constexpr double MIN_SUCCESS_RATE = 0.95;  // 95%
    constexpr double WARNING_SUCCESS_RATE = 0.90;  // 90%
    
    // Quality thresholds
    constexpr double MIN_QUALITY_SCORE = 60.0;  // Out of 100
    constexpr double WARNING_QUALITY_SCORE = 70.0;
    
    // Resource thresholds
    constexpr double MAX_CPU_PERCENT = 100.0;
    constexpr double MAX_MEMORY_GB = 128.0;
    constexpr double MAX_GPU_PERCENT = 100.0;
    
    // Statistical thresholds
    constexpr double MAX_OUTLIER_STDDEV = 3.0;
    constexpr double MIN_SAMPLE_SIZE = 30;
    constexpr double MAX_CI_WIDTH_PERCENT = 20.0;  // Relative to mean
    
} // namespace thresholds

} // namespace rawrxd::benchmark
