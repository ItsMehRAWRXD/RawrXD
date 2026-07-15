// Sovereign vs Ollama Benchmark Suite - Statistical Comparison Implementation
// Copyright (c) 2026 RawrXD Team

#include "statistical_comparison.hpp"
#include <cmath>
#include <algorithm>
#include <numeric>
#include <random>
#include <sstream>
#include <iomanip>

namespace rawrxd::benchmark {

// ============================================================================
// Forward declarations
// ============================================================================
static double Mean(const std::vector<double>& samples);
static double StdDev(const std::vector<double>& samples);

// ============================================================================
// StatisticalMetrics Implementation (stubs for linking)
// ============================================================================

StatisticalMetrics StatisticalMetrics::Calculate(const std::vector<double>& samples) {
    StatisticalMetrics metrics;
    if (samples.empty()) return metrics;
    
    metrics.sample_count = static_cast<int>(samples.size());
    metrics.mean = Mean(samples);
    metrics.stddev = StdDev(samples);
    
    auto sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    metrics.min = sorted.front();
    metrics.max = sorted.back();
    metrics.median = sorted[sorted.size() / 2];
    metrics.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
    metrics.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
    
    return metrics;
}

ConfidenceInterval StatisticalMetrics::CalculateMeanCI(const std::vector<double>& samples, 
                                                        double confidence) {
    ConfidenceInterval ci;
    ci.confidence = confidence;
    
    if (samples.size() < 2) return ci;
    
    double m = Mean(samples);
    double sd = StdDev(samples);
    double n = static_cast<double>(samples.size());
    double se = sd / std::sqrt(n);
    
    // t-value for 95% CI with n-1 df (approximation)
    double t = 1.96;
    if (confidence == 0.99) t = 2.576;
    if (confidence == 0.90) t = 1.645;
    if (samples.size() < 30) {
        // Adjust for small samples
        t = 2.0;
    }
    
    double margin = t * se;
    ci.lower = m - margin;
    ci.upper = m + margin;
    ci.margin_of_error = margin;
    
    return ci;
}

// ============================================================================
// Helper Functions
// ============================================================================

static double Mean(const std::vector<double>& samples) {
    if (samples.empty()) return 0.0;
    return std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
}

static double Variance(const std::vector<double>& samples, bool sample_variance = true) {
    if (samples.size() < 2) return 0.0;
    double m = Mean(samples);
    double sum_sq = 0.0;
    for (double x : samples) {
        double diff = x - m;
        sum_sq += diff * diff;
    }
    return sum_sq / (samples.size() - (sample_variance ? 1 : 0));
}

static double StdDev(const std::vector<double>& samples) {
    return std::sqrt(Variance(samples));
}

// Student's t-distribution CDF approximation (using normal approximation for large df)
static double TDistributionCDF(double t, double df) {
    // For large df, t approaches normal
    if (df > 30) {
        // Standard normal CDF approximation
        double x = t;
        // Abramowitz and Stegun approximation
        double b1 = 0.319381530;
        double b2 = -0.356563782;
        double b3 = 1.781477937;
        double b4 = -1.821255978;
        double b5 = 1.330274429;
        double p = 0.2316419;
        double c = 0.39894228;
        
        double ax = std::abs(x);
        double t_val = 1.0 / (1.0 + p * ax);
        double y = 1.0 - c * std::exp(-ax * ax / 2.0) * t_val * 
                   (t_val * (t_val * (t_val * (t_val * b5 + b4) + b3) + b2) + b1);
        
        return x >= 0 ? y : 1.0 - y;
    }
    
    // For smaller df, use approximation
    // This is a simplified approximation
    double x = df / (df + t * t);
    double beta = std::sqrt(x);
    // Incomplete beta approximation would go here
    // For now, use normal approximation with correction
    double z = t * (1.0 - 1.0 / (4.0 * df)) / std::sqrt(1.0 + t * t / (2.0 * df));
    
    // Normal CDF
    double b1 = 0.319381530;
    double b2 = -0.356563782;
    double b3 = 1.781477937;
    double b4 = -1.821255978;
    double b5 = 1.330274429;
    double p = 0.2316419;
    double c = 0.39894228;
    
    double ax = std::abs(z);
    double t_val = 1.0 / (1.0 + p * ax);
    double y = 1.0 - c * std::exp(-ax * ax / 2.0) * t_val * 
               (t_val * (t_val * (t_val * (t_val * b5 + b4) + b3) + b2) + b1);
    
    return z >= 0 ? y : 1.0 - y;
}

// Two-tailed p-value from t-statistic
static double PValueFromT(double t, double df) {
    double cdf = TDistributionCDF(std::abs(t), df);
    return 2.0 * (1.0 - cdf);
}

// ============================================================================
// Welch's T-Test
// ============================================================================

double WelchTTest(const std::vector<double>& sample1,
                  const std::vector<double>& sample2,
                  double* t_statistic) {
    if (sample1.size() < 2 || sample2.size() < 2) {
        if (t_statistic) *t_statistic = 0.0;
        return 1.0;
    }
    
    double m1 = Mean(sample1);
    double m2 = Mean(sample2);
    double v1 = Variance(sample1);
    double v2 = Variance(sample2);
    double n1 = static_cast<double>(sample1.size());
    double n2 = static_cast<double>(sample2.size());
    
    // Welch-Satterthwaite degrees of freedom
    double se1 = v1 / n1;
    double se2 = v2 / n2;
    double se = std::sqrt(se1 + se2);
    
    if (se == 0.0) {
        if (t_statistic) *t_statistic = 0.0;
        return 1.0;
    }
    
    double t = (m1 - m2) / se;
    double df = (se1 + se2) * (se1 + se2) / 
                (se1 * se1 / (n1 - 1.0) + se2 * se2 / (n2 - 1.0));
    
    if (t_statistic) *t_statistic = t;
    
    return PValueFromT(t, df);
}

// ============================================================================
// Student's T-Test
// ============================================================================

double StudentTTest(const std::vector<double>& sample1,
                    const std::vector<double>& sample2,
                    double* t_statistic) {
    if (sample1.size() < 2 || sample2.size() < 2) {
        if (t_statistic) *t_statistic = 0.0;
        return 1.0;
    }
    
    double m1 = Mean(sample1);
    double m2 = Mean(sample2);
    double v1 = Variance(sample1);
    double v2 = Variance(sample2);
    double n1 = static_cast<double>(sample1.size());
    double n2 = static_cast<double>(sample2.size());
    
    // Pooled variance
    double pooled_var = ((n1 - 1.0) * v1 + (n2 - 1.0) * v2) / (n1 + n2 - 2.0);
    double se = std::sqrt(pooled_var * (1.0 / n1 + 1.0 / n2));
    
    if (se == 0.0) {
        if (t_statistic) *t_statistic = 0.0;
        return 1.0;
    }
    
    double t = (m1 - m2) / se;
    double df = n1 + n2 - 2.0;
    
    if (t_statistic) *t_statistic = t;
    
    return PValueFromT(t, df);
}

// ============================================================================
// Paired T-Test
// ============================================================================

double PairedTTest(const std::vector<double>& before,
                   const std::vector<double>& after,
                   double* t_statistic) {
    if (before.size() != after.size() || before.size() < 2) {
        if (t_statistic) *t_statistic = 0.0;
        return 1.0;
    }
    
    // Calculate differences
    std::vector<double> diffs;
    diffs.reserve(before.size());
    for (size_t i = 0; i < before.size(); ++i) {
        diffs.push_back(after[i] - before[i]);
    }
    
    double mean_diff = Mean(diffs);
    double se = std::sqrt(Variance(diffs) / diffs.size());
    
    if (se == 0.0) {
        if (t_statistic) *t_statistic = 0.0;
        return 1.0;
    }
    
    double t = mean_diff / se;
    double df = static_cast<double>(diffs.size() - 1);
    
    if (t_statistic) *t_statistic = t;
    
    return PValueFromT(t, df);
}

// ============================================================================
// Mann-Whitney U Test (simplified approximation)
// ============================================================================

double MannWhitneyUTest(const std::vector<double>& sample1,
                        const std::vector<double>& sample2,
                        double* u_statistic) {
    // For now, use normal approximation
    // Full implementation would rank all observations
    
    double m1 = Mean(sample1);
    double m2 = Mean(sample2);
    double v1 = Variance(sample1);
    double v2 = Variance(sample2);
    double n1 = static_cast<double>(sample1.size());
    double n2 = static_cast<double>(sample2.size());
    
    // Approximate U statistic
    double u = n1 * n2 / 2.0;
    if (m1 != m2) {
        u = n1 * n2 + n1 * (n1 + 1.0) / 2.0; // Simplified
    }
    
    if (u_statistic) *u_statistic = u;
    
    // Return approximate p-value using t-test as fallback
    return WelchTTest(sample1, sample2);
}

// ============================================================================
// Cohen's D with Confidence Interval
// ============================================================================

EffectSizeResult CalculateCohensD(const std::vector<double>& sample1,
                                   const std::vector<double>& sample2,
                                   double confidence) {
    EffectSizeResult result;
    result.confidence = confidence;
    
    if (sample1.size() < 2 || sample2.size() < 2) {
        return result;
    }
    
    double m1 = Mean(sample1);
    double m2 = Mean(sample2);
    double v1 = Variance(sample1);
    double v2 = Variance(sample2);
    double n1 = static_cast<double>(sample1.size());
    double n2 = static_cast<double>(sample2.size());
    
    // Pooled standard deviation
    double pooled_sd = std::sqrt(((n1 - 1.0) * v1 + (n2 - 1.0) * v2) / (n1 + n2 - 2.0));
    
    if (pooled_sd == 0.0) {
        return result;
    }
    
    result.d = (m1 - m2) / pooled_sd;
    
    // Approximate CI using standard error
    double se_d = std::sqrt((n1 + n2) / (n1 * n2) + result.d * result.d / (2.0 * (n1 + n2)));
    double z = 1.96; // 95% CI
    if (confidence == 0.99) z = 2.576;
    if (confidence == 0.90) z = 1.645;
    
    result.ci_lower = result.d - z * se_d;
    result.ci_upper = result.d + z * se_d;
    
    return result;
}

// ============================================================================
// Bootstrap Difference CI
// ============================================================================

ConfidenceInterval BootstrapDifferenceCI(const std::vector<double>& sample1,
                                          const std::vector<double>& sample2,
                                          double confidence,
                                          int iterations) {
    ConfidenceInterval ci;
    ci.confidence = confidence;
    
    if (sample1.empty() || sample2.empty()) {
        return ci;
    }
    
    double observed_diff = Mean(sample1) - Mean(sample2);
    
    // Bootstrap
    std::vector<double> boot_diffs;
    boot_diffs.reserve(iterations);
    
    std::mt19937 rng(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<size_t> dist1(0, sample1.size() - 1);
    std::uniform_int_distribution<size_t> dist2(0, sample2.size() - 1);
    
    for (int i = 0; i < iterations; ++i) {
        std::vector<double> boot1, boot2;
        boot1.reserve(sample1.size());
        boot2.reserve(sample2.size());
        
        for (size_t j = 0; j < sample1.size(); ++j) {
            boot1.push_back(sample1[dist1(rng)]);
        }
        for (size_t j = 0; j < sample2.size(); ++j) {
            boot2.push_back(sample2[dist2(rng)]);
        }
        
        boot_diffs.push_back(Mean(boot1) - Mean(boot2));
    }
    
    // Percentile method
    std::sort(boot_diffs.begin(), boot_diffs.end());
    
    double alpha = 1.0 - confidence;
    size_t lower_idx = static_cast<size_t>(iterations * alpha / 2.0);
    size_t upper_idx = static_cast<size_t>(iterations * (1.0 - alpha / 2.0));
    
    ci.lower = boot_diffs[lower_idx];
    ci.upper = boot_diffs[upper_idx];
    ci.margin_of_error = (ci.upper - ci.lower) / 2.0;
    
    return ci;
}

// ============================================================================
// Power Analysis
// ============================================================================

int RequiredSampleSize(double expected_effect_size,
                       double alpha,
                       double power) {
    // Simplified power calculation
    // For two-sample t-test with equal n
    
    if (expected_effect_size <= 0.0) return 0;
    
    // z-values for alpha and power
    double z_alpha = 1.96; // two-tailed 0.05
    if (alpha == 0.01) z_alpha = 2.576;
    if (alpha == 0.10) z_alpha = 1.645;
    
    double z_beta = 0.84; // 80% power
    if (power == 0.90) z_beta = 1.28;
    if (power == 0.95) z_beta = 1.645;
    
    // Sample size formula
    double n = 2.0 * std::pow((z_alpha + z_beta) / expected_effect_size, 2.0);
    
    return static_cast<int>(std::ceil(n));
}

PowerAnalysisResult AnalyzePower(const std::vector<double>& sample1,
                                  const std::vector<double>& sample2,
                                  double target_power,
                                  double alpha) {
    PowerAnalysisResult result;
    result.current_n = static_cast<int>(std::min(sample1.size(), sample2.size()));
    result.target_power = target_power;
    
    // Calculate observed effect size
    EffectSizeResult effect = CalculateCohensD(sample1, sample2);
    double d = std::abs(effect.d);
    
    result.required_n = RequiredSampleSize(d, alpha, target_power);
    result.achieved_power = CalculatePower(result.current_n, d, alpha);
    result.is_adequate = result.current_n >= result.required_n;
    
    if (result.is_adequate) {
        result.recommendation = "Sample size is adequate for detected effect size";
    } else {
        std::ostringstream oss;
        oss << "Need " << result.required_n << " samples per group for " 
            << (target_power * 100) << "% power (currently have " << result.current_n << ")";
        result.recommendation = oss.str();
    }
    
    return result;
}

double CalculatePower(int sample_size, double effect_size, double alpha) {
    if (sample_size <= 0 || effect_size <= 0.0) return 0.0;
    
    double z_alpha = 1.96;
    if (alpha == 0.01) z_alpha = 2.576;
    if (alpha == 0.10) z_alpha = 1.645;
    
    double se = std::sqrt(2.0 / sample_size);
    double ncp = effect_size / se;
    
    // Approximate power
    double z_beta = ncp - z_alpha;
    // Convert to power (simplified)
    return std::min(0.99, std::max(0.05, 0.5 + z_beta / 3.0));
}

// ============================================================================
// Main Comparison Function
// ============================================================================

StatisticalComparison CompareBackends(
    const std::vector<double>& sovereign_samples,
    const std::vector<double>& ollama_samples,
    StatisticalTestType test_type,
    double confidence,
    double practical_threshold) {
    
    StatisticalComparison comp;
    comp.sovereign_n = static_cast<int>(sovereign_samples.size());
    comp.ollama_n = static_cast<int>(ollama_samples.size());
    comp.test_used = test_type;
    comp.practical_threshold = practical_threshold;
    
    if (sovereign_samples.empty() || ollama_samples.empty()) {
        return comp;
    }
    
    // Calculate means
    comp.sovereign_mean = Mean(sovereign_samples);
    comp.ollama_mean = Mean(ollama_samples);
    
    // Calculate CIs
    comp.sovereign_ci = StatisticalMetrics::CalculateMeanCI(sovereign_samples, confidence);
    comp.ollama_ci = StatisticalMetrics::CalculateMeanCI(ollama_samples, confidence);
    
    // Calculate differences
    comp.absolute_difference = comp.sovereign_mean - comp.ollama_mean;
    if (comp.ollama_mean != 0.0) {
        comp.percent_difference = (comp.absolute_difference / comp.ollama_mean) * 100.0;
    }
    
    // Bootstrap CI for difference
    comp.difference_ci = BootstrapDifferenceCI(sovereign_samples, ollama_samples, confidence);
    
    // Effect size
    comp.effect_size = CalculateCohensD(sovereign_samples, ollama_samples, confidence);
    
    // Statistical test
    switch (test_type) {
        case StatisticalTestType::WELCH_T_TEST:
            comp.p_value = WelchTTest(sovereign_samples, ollama_samples);
            break;
        case StatisticalTestType::STUDENT_T_TEST:
            comp.p_value = StudentTTest(sovereign_samples, ollama_samples);
            break;
        case StatisticalTestType::MANN_WHITNEY_U:
            comp.p_value = MannWhitneyUTest(sovereign_samples, ollama_samples);
            break;
        case StatisticalTestType::BOOTSTRAP_DIFF:
            // Use Welch as fallback for p-value
            comp.p_value = WelchTTest(sovereign_samples, ollama_samples);
            break;
        default:
            comp.p_value = WelchTTest(sovereign_samples, ollama_samples);
    }
    
    // Significance
    comp.significance = PValueToSignificance(comp.p_value);
    comp.statistically_significant = (comp.p_value < (1.0 - confidence));
    
    // Practical significance
    double abs_pct = std::abs(comp.percent_difference);
    comp.practically_significant = abs_pct >= (practical_threshold * 100.0);
    
    return comp;
}

StatisticalComparison CompareBackendsPaired(
    const std::vector<double>& sovereign_samples,
    const std::vector<double>& ollama_samples,
    double confidence,
    double practical_threshold) {
    
    StatisticalComparison comp = CompareBackends(
        sovereign_samples, ollama_samples,
        StatisticalTestType::PAIRED_T_TEST,
        confidence, practical_threshold);
    
    // Override with paired test
    comp.p_value = PairedTTest(ollama_samples, sovereign_samples);
    comp.significance = PValueToSignificance(comp.p_value);
    comp.statistically_significant = (comp.p_value < (1.0 - confidence));
    comp.test_used = StatisticalTestType::PAIRED_T_TEST;
    
    return comp;
}

// ============================================================================
// JSON Export
// ============================================================================

std::string StatisticalComparison::ToJson() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4);
    
    oss << "{\n";
    oss << "  \"sovereign\": {\n";
    oss << "    \"mean\": " << sovereign_mean << ",\n";
    oss << "    \"ci_lower\": " << sovereign_ci.lower << ",\n";
    oss << "    \"ci_upper\": " << sovereign_ci.upper << ",\n";
    oss << "    \"n\": " << sovereign_n << "\n";
    oss << "  },\n";
    oss << "  \"ollama\": {\n";
    oss << "    \"mean\": " << ollama_mean << ",\n";
    oss << "    \"ci_lower\": " << ollama_ci.lower << ",\n";
    oss << "    \"ci_upper\": " << ollama_ci.upper << ",\n";
    oss << "    \"n\": " << ollama_n << "\n";
    oss << "  },\n";
    oss << "  \"difference\": {\n";
    oss << "    \"absolute\": " << absolute_difference << ",\n";
    oss << "    \"percent\": " << percent_difference << ",\n";
    oss << "    \"ci_lower\": " << difference_ci.lower << ",\n";
    oss << "    \"ci_upper\": " << difference_ci.upper << "\n";
    oss << "  },\n";
    oss << "  \"effect_size\": {\n";
    oss << "    \"d\": " << effect_size.d << ",\n";
    oss << "    \"ci_lower\": " << effect_size.ci_lower << ",\n";
    oss << "    \"ci_upper\": " << effect_size.ci_upper << ",\n";
    oss << "    \"interpretation\": \"" << effect_size.Interpretation() << "\"\n";
    oss << "  },\n";
    oss << "  \"statistics\": {\n";
    oss << "    \"test\": \"" << TestTypeToString(test_used) << "\",\n";
    oss << "    \"p_value\": " << p_value << ",\n";
    oss << "    \"significance\": \"" << SignificanceToStars(significance) << "\",\n";
    oss << "    \"statistically_significant\": " << (statistically_significant ? "true" : "false") << ",\n";
    oss << "    \"practically_significant\": " << (practically_significant ? "true" : "false") << "\n";
    oss << "  }\n";
    oss << "}";
    
    return oss.str();
}

std::string StatisticalComparison::ToMarkdownRow(const std::string& metric_name, 
                                                   bool higher_is_better) const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    
    std::string winner = GetWinner(higher_is_better);
    std::string stars = SignificanceToStars(significance);
    
    oss << "| " << metric_name << " | ";
    oss << sovereign_mean << " | ";
    oss << ollama_mean << " | ";
    oss << percent_difference << "% | ";
    oss << effect_size.d << " | ";
    oss << stars << " | ";
    oss << winner << " |";
    
    return oss.str();
}

// ============================================================================
// Validation Helpers
// ============================================================================

bool IsNormallyDistributed(const std::vector<double>& samples, double alpha) {
    // Simplified Shapiro-Wilk approximation
    // For production, use a proper statistics library
    
    if (samples.size() < 8) return true; // Too small to test
    
    // Calculate skewness
    double m = Mean(samples);
    double sd = StdDev(samples);
    
    if (sd == 0.0) return true;
    
    double skewness = 0.0;
    for (double x : samples) {
        double z = (x - m) / sd;
        skewness += z * z * z;
    }
    skewness /= samples.size();
    
    // If skewness is small, assume normal
    return std::abs(skewness) < 1.0;
}

StatisticalTestType RecommendTest(const std::vector<double>& sample1,
                                   const std::vector<double>& sample2,
                                   bool is_paired) {
    if (is_paired) {
        return StatisticalTestType::PAIRED_T_TEST;
    }
    
    // Check normality
    bool normal1 = IsNormallyDistributed(sample1);
    bool normal2 = IsNormallyDistributed(sample2);
    
    if (!normal1 || !normal2) {
        return StatisticalTestType::MANN_WHITNEY_U;
    }
    
    // Check variance equality (simplified)
    double v1 = Variance(sample1);
    double v2 = Variance(sample2);
    
    if (v1 > 0 && v2 > 0) {
        double ratio = std::max(v1, v2) / std::min(v1, v2);
        if (ratio > 4.0) {
            return StatisticalTestType::WELCH_T_TEST; // Unequal variances
        }
    }
    
    return StatisticalTestType::STUDENT_T_TEST;
}

std::vector<size_t> DetectOutliers(const std::vector<double>& samples,
                                     double iqr_multiplier) {
    std::vector<size_t> outliers;
    
    if (samples.size() < 4) return outliers;
    
    // Sort copy for quartile calculation
    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    
    size_t n = sorted.size();
    double q1 = sorted[n / 4];
    double q3 = sorted[3 * n / 4];
    double iqr = q3 - q1;
    
    double lower_bound = q1 - iqr_multiplier * iqr;
    double upper_bound = q3 + iqr_multiplier * iqr;
    
    for (size_t i = 0; i < samples.size(); ++i) {
        if (samples[i] < lower_bound || samples[i] > upper_bound) {
            outliers.push_back(i);
        }
    }
    
    return outliers;
}

} // namespace rawrxd::benchmark
