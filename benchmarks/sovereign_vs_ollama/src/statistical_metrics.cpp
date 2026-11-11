// Statistical Metrics Implementation
// Copyright (c) 2026 RawrXD Team

#include "benchmark_common.hpp"
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>
#include <vector>

namespace rawrxd::benchmark {

// ============================================================================
// Helper Functions
// ============================================================================

// Calculate t-critical value for given confidence level and degrees of freedom
// Uses approximation for t-distribution
static double TCriticalValue(double confidence, int df) {
    // For large samples (df > 100), use normal approximation
    if (df > 100) {
        // Standard normal z-scores for common confidence levels
        static const std::map<double, double> z_scores = {
            {0.80, 1.282},
            {0.90, 1.645},
            {0.95, 1.960},
            {0.99, 2.576},
            {0.999, 3.291}
        };
        auto it = z_scores.find(confidence);
        if (it != z_scores.end()) return it->second;
        return 1.96; // Default to 95%
    }
    
    // For smaller samples, use approximate t-values
    // These are pre-calculated critical values for common confidence levels
    if (confidence == 0.95) {
        // 95% confidence t-values
        static const double t_95[] = {
            12.706, 4.303, 3.182, 2.776, 2.571,  // df 1-5
            2.447, 2.365, 2.306, 2.262, 2.228,  // df 6-10
            2.201, 2.179, 2.160, 2.145, 2.131,  // df 11-15
            2.120, 2.110, 2.101, 2.093, 2.086,  // df 16-20
            2.080, 2.074, 2.069, 2.064, 2.060,  // df 21-25
            2.056, 2.052, 2.048, 2.045, 2.042   // df 26-30
        };
        if (df <= 30) return t_95[df - 1];
        if (df <= 40) return 2.021;
        if (df <= 60) return 2.000;
        if (df <= 80) return 1.990;
        return 1.984;
    }
    
    if (confidence == 0.99) {
        // 99% confidence t-values
        static const double t_99[] = {
            63.657, 9.925, 5.841, 4.604, 4.032,  // df 1-5
            3.707, 3.499, 3.355, 3.250, 3.169,  // df 6-10
            3.106, 3.055, 3.012, 2.977, 2.947,  // df 11-15
            2.921, 2.898, 2.878, 2.861, 2.845,  // df 16-20
            2.831, 2.819, 2.807, 2.797, 2.787,  // df 21-25
            2.779, 2.771, 2.763, 2.756, 2.750   // df 26-30
        };
        if (df <= 30) return t_99[df - 1];
        if (df <= 40) return 2.704;
        if (df <= 60) return 2.660;
        if (df <= 80) return 2.639;
        return 2.626;
    }
    
    // Default to 95% if confidence level not found
    return 1.96;
}

// Chi-square critical values for variance CI
static double ChiSquareCriticalValue(double confidence, int df, bool upper) {
    // Simplified approximation - in production, use proper chi-square CDF
    // For 95% CI: lower = 0.025, upper = 0.975
    double alpha = 1.0 - confidence;
    
    if (upper) {
        // Upper critical value (1 - alpha/2)
        // Approximation using Wilson-Hilferty transformation
        double z = 1.96; // 95% confidence
        if (confidence == 0.99) z = 2.576;
        if (confidence == 0.90) z = 1.645;
        
        double df_d = static_cast<double>(df);
        return df_d * std::pow(1.0 - 2.0 / (9.0 * df_d) + z * std::sqrt(2.0 / (9.0 * df_d)), 3);
    } else {
        // Lower critical value (alpha/2)
        double z = -1.96; // 95% confidence
        if (confidence == 0.99) z = -2.576;
        if (confidence == 0.90) z = -1.645;
        
        double df_d = static_cast<double>(df);
        return df_d * std::pow(1.0 - 2.0 / (9.0 * df_d) + z * std::sqrt(2.0 / (9.0 * df_d)), 3);
    }
}

// ============================================================================
// StatisticalMetrics Implementation
// ============================================================================

StatisticalMetrics StatisticalMetrics::Calculate(const std::vector<double>& samples) {
    StatisticalMetrics metrics;
    
    if (samples.empty()) {
        return metrics;
    }
    
    metrics.sample_count = static_cast<int>(samples.size());
    
    // Calculate mean
    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    metrics.mean = sum / samples.size();
    
    // Calculate min/max
    auto [min_it, max_it] = std::minmax_element(samples.begin(), samples.end());
    metrics.min = *min_it;
    metrics.max = *max_it;
    
    // Calculate standard deviation
    double variance_sum = 0.0;
    for (double val : samples) {
        double diff = val - metrics.mean;
        variance_sum += diff * diff;
    }
    metrics.stddev = std::sqrt(variance_sum / samples.size());
    
    // Calculate median and percentiles
    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    
    size_t n = sorted.size();
    if (n % 2 == 0) {
        metrics.median = (sorted[n/2 - 1] + sorted[n/2]) / 2.0;
    } else {
        metrics.median = sorted[n/2];
    }
    
    // P95
    size_t p95_idx = static_cast<size_t>(std::ceil(n * 0.95)) - 1;
    if (p95_idx >= n) p95_idx = n - 1;
    metrics.p95 = sorted[p95_idx];
    
    // P99
    size_t p99_idx = static_cast<size_t>(std::ceil(n * 0.99)) - 1;
    if (p99_idx >= n) p99_idx = n - 1;
    metrics.p99 = sorted[p99_idx];
    
    return metrics;
}

StatisticalMetrics StatisticalMetrics::CalculateWithCI(const std::vector<double>& samples, 
                                                        double confidence) {
    StatisticalMetrics metrics = Calculate(samples);
    
    if (samples.size() < 2) {
        return metrics;
    }
    
    // Calculate confidence intervals
    metrics.mean_ci = CalculateMeanCI(samples, confidence);
    metrics.median_ci = CalculateMedianCI(samples, confidence);
    metrics.stddev_ci = CalculateStdDevCI(samples, confidence);
    
    return metrics;
}

ConfidenceInterval StatisticalMetrics::CalculateMeanCI(const std::vector<double>& samples, 
                                                          double confidence) {
    ConfidenceInterval ci;
    ci.confidence = confidence;
    
    if (samples.size() < 2) {
        return ci;
    }
    
    // Calculate mean and standard error
    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    double mean = sum / samples.size();
    
    double variance_sum = 0.0;
    for (double val : samples) {
        double diff = val - mean;
        variance_sum += diff * diff;
    }
    double stddev = std::sqrt(variance_sum / samples.size());
    double sem = stddev / std::sqrt(static_cast<double>(samples.size()));
    
    // Get t-critical value
    int df = static_cast<int>(samples.size()) - 1;
    double t_crit = TCriticalValue(confidence, df);
    
    // Calculate margin of error
    ci.margin_of_error = t_crit * sem;
    ci.lower = mean - ci.margin_of_error;
    ci.upper = mean + ci.margin_of_error;
    
    return ci;
}

ConfidenceInterval StatisticalMetrics::CalculateMedianCI(const std::vector<double>& samples,
                                                            double confidence,
                                                            int bootstrap_iterations) {
    ConfidenceInterval ci;
    ci.confidence = confidence;
    
    if (samples.size() < 2) {
        return ci;
    }
    
    // Calculate observed median
    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    double observed_median = (sorted.size() % 2 == 0) 
        ? (sorted[sorted.size()/2 - 1] + sorted[sorted.size()/2]) / 2.0
        : sorted[sorted.size()/2];
    
    // Bootstrap for median CI
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    
    std::vector<double> bootstrap_medians;
    bootstrap_medians.reserve(bootstrap_iterations);
    
    for (int i = 0; i < bootstrap_iterations; ++i) {
        std::vector<double> resample;
        resample.reserve(samples.size());
        
        for (size_t j = 0; j < samples.size(); ++j) {
            resample.push_back(samples[dist(rng)]);
        }
        
        std::sort(resample.begin(), resample.end());
        double median = (resample.size() % 2 == 0)
            ? (resample[resample.size()/2 - 1] + resample[resample.size()/2]) / 2.0
            : resample[resample.size()/2];
        bootstrap_medians.push_back(median);
    }
    
    // Calculate percentiles of bootstrap distribution
    std::sort(bootstrap_medians.begin(), bootstrap_medians.end());
    
    double alpha = 1.0 - confidence;
    size_t lower_idx = static_cast<size_t>(bootstrap_iterations * (alpha / 2));
    size_t upper_idx = static_cast<size_t>(bootstrap_iterations * (1.0 - alpha / 2));
    
    if (lower_idx >= bootstrap_medians.size()) lower_idx = 0;
    if (upper_idx >= bootstrap_medians.size()) upper_idx = bootstrap_medians.size() - 1;
    
    ci.lower = bootstrap_medians[lower_idx];
    ci.upper = bootstrap_medians[upper_idx];
    ci.margin_of_error = (ci.upper - ci.lower) / 2.0;
    
    return ci;
}

ConfidenceInterval StatisticalMetrics::CalculateStdDevCI(const std::vector<double>& samples,
                                                          double confidence) {
    ConfidenceInterval ci;
    ci.confidence = confidence;
    
    if (samples.size() < 2) {
        return ci;
    }
    
    // Calculate sample variance
    double sum = std::accumulate(samples.begin(), samples.end(), 0.0);
    double mean = sum / samples.size();
    
    double variance_sum = 0.0;
    for (double val : samples) {
        double diff = val - mean;
        variance_sum += diff * diff;
    }
    double variance = variance_sum / samples.size();
    double stddev = std::sqrt(variance);
    
    // Chi-square CI for variance
    int df = static_cast<int>(samples.size()) - 1;
    double chi_lower = ChiSquareCriticalValue(confidence, df, false);
    double chi_upper = ChiSquareCriticalValue(confidence, df, true);
    
    // CI for variance
    double var_lower = (df * variance) / chi_upper;
    double var_upper = (df * variance) / chi_lower;
    
    // CI for standard deviation (square root of variance CI)
    ci.lower = std::sqrt(var_lower);
    ci.upper = std::sqrt(var_upper);
    ci.margin_of_error = (ci.upper - ci.lower) / 2.0;
    
    return ci;
}

bool StatisticalMetrics::IsSignificantlyDifferent(const StatisticalMetrics& other,
                                                  double confidence) const {
    // Check if confidence intervals overlap
    // If CIs don't overlap, the difference is statistically significant
    
    if (mean_ci.lower == 0 && mean_ci.upper == 0) {
        // CI not calculated, use simple overlap check
        double this_range = max - min;
        double other_range = other.max - other.min;
        
        // Check if ranges overlap
        return (min > other.max) || (max < other.min);
    }
    
    // Check if mean CIs overlap
    return (mean_ci.lower > other.mean_ci.upper) || (mean_ci.upper < other.mean_ci.lower);
}

double StatisticalMetrics::EffectSize(const StatisticalMetrics& other) const {
    // Cohen's d: (mean1 - mean2) / pooled_std_dev
    
    if (stddev == 0 && other.stddev == 0) {
        return (mean == other.mean) ? 0.0 : std::numeric_limits<double>::infinity();
    }
    
    // Pooled standard deviation
    double pooled_std = std::sqrt((stddev * stddev + other.stddev * other.stddev) / 2.0);
    
    if (pooled_std == 0) {
        return 0.0;
    }
    
    return (mean - other.mean) / pooled_std;
}

} // namespace rawrxd::benchmark
