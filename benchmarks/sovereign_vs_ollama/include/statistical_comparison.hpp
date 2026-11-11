// Sovereign vs Ollama Benchmark Suite - Statistical Comparison
// Copyright (c) 2026 RawrXD Team
// Licensed under MIT
//
// Implements proper hypothesis testing for benchmark comparisons:
// - Welch's t-test (unequal variances)
// - Mann-Whitney U test (non-parametric)
// - Paired t-test (for repeated measures)
// - Effect size with confidence intervals
// - Power analysis

#pragma once

#include "benchmark_common.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <random>

namespace rawrxd::benchmark {

// ============================================================================
// Statistical Test Types
// ============================================================================
enum class StatisticalTestType {
    WELCH_T_TEST = 0,      // Unequal variances t-test
    STUDENT_T_TEST = 1,    // Equal variances t-test
    MANN_WHITNEY_U = 2,    // Non-parametric
    PAIRED_T_TEST = 3,     // Repeated measures
    BOOTSTRAP_DIFF = 4     // Bootstrap difference CI
};

inline const char* TestTypeToString(StatisticalTestType type) {
    switch (type) {
        case StatisticalTestType::WELCH_T_TEST: return "Welch's t-test";
        case StatisticalTestType::STUDENT_T_TEST: return "Student's t-test";
        case StatisticalTestType::MANN_WHITNEY_U: return "Mann-Whitney U";
        case StatisticalTestType::PAIRED_T_TEST: return "Paired t-test";
        case StatisticalTestType::BOOTSTRAP_DIFF: return "Bootstrap difference";
        default: return "unknown";
    }
}

// ============================================================================
// Significance Levels
// ============================================================================
enum class SignificanceLevel {
    NOT_SIGNIFICANT = 0,
    P_05 = 1,    // *   p < 0.05
    P_01 = 2,    // **  p < 0.01
    P_001 = 3    // *** p < 0.001
};

inline const char* SignificanceToStars(SignificanceLevel level) {
    switch (level) {
        case SignificanceLevel::P_001: return "***";
        case SignificanceLevel::P_01: return "**";
        case SignificanceLevel::P_05: return "*";
        default: return "ns";
    }
}

inline SignificanceLevel PValueToSignificance(double p) {
    if (p < 0.001) return SignificanceLevel::P_001;
    if (p < 0.01) return SignificanceLevel::P_01;
    if (p < 0.05) return SignificanceLevel::P_05;
    return SignificanceLevel::NOT_SIGNIFICANT;
}

// ============================================================================
// Effect Size with Confidence Interval
// ============================================================================
struct EffectSizeResult {
    double d = 0.0;                    // Cohen's d
    double ci_lower = 0.0;           // Lower bound of CI
    double ci_upper = 0.0;           // Upper bound of CI
    double confidence = 0.95;          // Confidence level
    
    std::string Interpretation() const {
        double abs_d = std::abs(d);
        if (abs_d < 0.2) return "negligible";
        if (abs_d < 0.5) return "small";
        if (abs_d < 0.8) return "medium";
        if (abs_d < 1.2) return "large";
        return "very large";
    }
    
    std::string ToString() const {
        char buf[256];
        snprintf(buf, sizeof(buf), "d=%.3f [%.3f, %.3f] (%s)",
                 d, ci_lower, ci_upper, Interpretation().c_str());
        return std::string(buf);
    }
};

// ============================================================================
// Statistical Comparison Result
// ============================================================================
struct StatisticalComparison {
    // Raw means
    double sovereign_mean = 0.0;
    double ollama_mean = 0.0;
    
    // Confidence intervals
    ConfidenceInterval sovereign_ci;
    ConfidenceInterval ollama_ci;
    
    // Difference
    double absolute_difference = 0.0;
    double percent_difference = 0.0;
    ConfidenceInterval difference_ci;  // CI for the difference
    
    // Effect size
    EffectSizeResult effect_size;
    
    // Statistical test results
    double p_value = 1.0;
    StatisticalTestType test_used = StatisticalTestType::WELCH_T_TEST;
    SignificanceLevel significance = SignificanceLevel::NOT_SIGNIFICANT;
    bool statistically_significant = false;
    
    // Practical significance
    bool practically_significant = false;
    double practical_threshold = 0.05;  // 5% minimum improvement
    
    // Sample info
    int sovereign_n = 0;
    int ollama_n = 0;
    
    // Validation
    bool IsValid() const {
        return sovereign_n > 0 && ollama_n > 0 && 
               !std::isnan(sovereign_mean) && !std::isnan(ollama_mean);
    }
    
    // Check if Sovereign is better (higher is better for throughput, lower for latency)
    bool IsSovereignBetter(bool higher_is_better = true) const {
        if (higher_is_better) {
            return sovereign_mean > ollama_mean;
        }
        return sovereign_mean < ollama_mean;
    }
    
    // Get winner with statistical backing
    std::string GetWinner(bool higher_is_better = true) const {
        if (!statistically_significant) {
            return "tie (not statistically significant)";
        }
        if (IsSovereignBetter(higher_is_better)) {
            return "sovereign";
        }
        return "ollama";
    }
    
    // Generate headline claim
    std::string GetHeadline(bool higher_is_better = true) const {
        if (!IsValid()) {
            return "Invalid comparison";
        }
        
        std::string direction = IsSovereignBetter(higher_is_better) ? "faster" : "slower";
        std::string magnitude = effect_size.Interpretation();
        std::string stars = SignificanceToStars(significance);
        
        char buf[512];
        if (higher_is_better) {
            snprintf(buf, sizeof(buf),
                "Sovereign is %.1f%% %s than Ollama (%s effect, %s, p=%.4f)",
                std::abs(percent_difference), direction.c_str(), magnitude.c_str(), stars.c_str(), p_value);
        } else {
            snprintf(buf, sizeof(buf),
                "Sovereign has %.1f%% %s latency than Ollama (%s effect, %s, p=%.4f)",
                std::abs(percent_difference), direction.c_str(), magnitude.c_str(), stars.c_str(), p_value);
        }
        return std::string(buf);
    }
    
    // JSON export
    std::string ToJson() const;
    
    // Markdown table row
    std::string ToMarkdownRow(const std::string& metric_name, bool higher_is_better = true) const;
};

// ============================================================================
// Statistical Test Functions
// ============================================================================

// Welch's t-test (unequal variances)
// Returns p-value
double WelchTTest(const std::vector<double>& sample1, 
                  const std::vector<double>& sample2,
                  double* t_statistic = nullptr);

// Student's t-test (equal variances assumed)
double StudentTTest(const std::vector<double>& sample1,
                    const std::vector<double>& sample2,
                    double* t_statistic = nullptr);

// Paired t-test (for repeated measures on same workload)
double PairedTTest(const std::vector<double>& before,
                   const std::vector<double>& after,
                   double* t_statistic = nullptr);

// Mann-Whitney U test (non-parametric)
double MannWhitneyUTest(const std::vector<double>& sample1,
                        const std::vector<double>& sample2,
                        double* u_statistic = nullptr);

// ============================================================================
// Effect Size Functions
// ============================================================================

// Cohen's d with confidence interval
EffectSizeResult CalculateCohensD(const std::vector<double>& sample1,
                                   const std::vector<double>& sample2,
                                   double confidence = 0.95);

// Hedges' g (bias-corrected Cohen's d for small samples)
EffectSizeResult CalculateHedgesG(const std::vector<double>& sample1,
                                   const std::vector<double>& sample2,
                                   double confidence = 0.95);

// Bootstrap confidence interval for difference in means
ConfidenceInterval BootstrapDifferenceCI(const std::vector<double>& sample1,
                                          const std::vector<double>& sample2,
                                          double confidence = 0.95,
                                          int iterations = 2000);

// ============================================================================
// Power Analysis
// ============================================================================

// Calculate required sample size for given effect size and power
// Returns minimum samples needed per group
int RequiredSampleSize(double expected_effect_size,
                       double alpha = 0.05,
                       double power = 0.80);

// Calculate achieved power for given sample size and effect
double CalculatePower(int sample_size,
                      double effect_size,
                      double alpha = 0.05);

// Check if current sample size is adequate
struct PowerAnalysisResult {
    int current_n = 0;
    int required_n = 0;
    double achieved_power = 0.0;
    double target_power = 0.80;
    bool is_adequate = false;
    std::string recommendation;
};

PowerAnalysisResult AnalyzePower(const std::vector<double>& sample1,
                                  const std::vector<double>& sample2,
                                  double target_power = 0.80,
                                  double alpha = 0.05);

// ============================================================================
// Main Comparison Function
// ============================================================================

// Compare two backends with full statistical rigor
StatisticalComparison CompareBackends(
    const std::vector<double>& sovereign_samples,
    const std::vector<double>& ollama_samples,
    StatisticalTestType test_type = StatisticalTestType::WELCH_T_TEST,
    double confidence = 0.95,
    double practical_threshold = 0.05);

// Paired comparison (same workloads on both backends)
StatisticalComparison CompareBackendsPaired(
    const std::vector<double>& sovereign_samples,
    const std::vector<double>& ollama_samples,
    double confidence = 0.95,
    double practical_threshold = 0.05);

// ============================================================================
// Validation Helpers
// ============================================================================

// Check if data is normally distributed (Shapiro-Wilk approximation)
bool IsNormallyDistributed(const std::vector<double>& samples, 
                            double alpha = 0.05);

// Recommend best test based on data characteristics
StatisticalTestType RecommendTest(const std::vector<double>& sample1,
                                   const std::vector<double>& sample2,
                                   bool is_paired = false);

// Check for outliers using IQR method
std::vector<size_t> DetectOutliers(const std::vector<double>& samples,
                                     double iqr_multiplier = 1.5);

} // namespace rawrxd::benchmark
