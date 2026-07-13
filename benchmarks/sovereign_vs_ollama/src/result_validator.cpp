// Result Validation and Sanity Checking Implementation
// Copyright (c) 2026 RawrXD Team

#include "result_validator.hpp"
#include <algorithm>
#include <math>
#include <iostream>
#include <sstream>

namespace rawrxd::benchmark {

// ============================================================================
// Result Validator Implementation
// ============================================================================

std::vector<ValidationResult> ResultValidator::ValidateResult(const BenchmarkResult& result) {
    std::vector<ValidationResult> results;
    
    // Validate success rate
    results.push_back(ValidateSuccessRate(result.success_rate));
    
    // Validate latency samples if available
    if (!result.raw_latencies.empty()) {
        auto latency_results = ValidateLatencySamples(result.raw_latencies, result.category);
        results.insert(results.end(), latency_results.begin(), latency_results.end());
    }
    
    // Validate resource metrics
    auto resource_results = ValidateResourceMetrics(result.resources);
    results.insert(results.end(), resource_results.begin(), resource_results.end());
    
    // Validate quality metrics
    auto quality_results = ValidateQualityMetrics(result.quality);
    results.insert(results.end(), quality_results.begin(), quality_results.end());
    
    return results;
}

std::vector<ValidationResult> ResultValidator::ValidateLatencySamples(
    const std::vector<double>& samples, BenchmarkCategory category) {
    
    std::vector<ValidationResult> results;
    
    // Check for invalid values
    auto invalid_results = CheckInvalidValues(samples);
    results.insert(results.end(), invalid_results.begin(), invalid_results.end());
    
    // Check for negative values
    auto negative_results = CheckNegativeValues(samples);
    results.insert(results.end(), negative_results.begin(), negative_results.end());
    
    // Check for outliers
    auto outlier_results = CheckOutliers(samples);
    results.insert(results.end(), outlier_results.begin(), outlier_results.end());
    
    // Check category-specific ranges
    auto range_results = CheckCategoryRanges(samples, category);
    results.insert(results.end(), range_results.begin(), range_results.end());
    
    // Check for bimodality
    results.push_back(CheckBimodality(samples));
    
    // Check for trend
    results.push_back(CheckTrend(samples));
    
    // Check for duplicates
    results.push_back(CheckDuplicateValues(samples));
    
    // Check sample size
    results.push_back(CheckSampleSize(static_cast<int>(samples.size())));
    
    return results;
}

std::vector<ValidationResult> ResultValidator::ValidateThroughputSamples(
    const std::vector<double>& samples) {
    
    std::vector<ValidationResult> results;
    
    // Check for invalid values
    auto invalid_results = CheckInvalidValues(samples);
    results.insert(results.end(), invalid_results.begin(), invalid_results.end());
    
    // Check for negative values
    auto negative_results = CheckNegativeValues(samples);
    results.insert(results.end(), negative_results.begin(), negative_results.end());
    
    // Check for outliers
    auto outlier_results = CheckOutliers(samples);
    results.insert(results.end(), outlier_results.begin(), outlier_results.end());
    
    // Check throughput ranges
    double min_tps = thresholds::INFERENCE_MIN_TPS;
    double max_tps = thresholds::INFERENCE_MAX_TPS;
    
    for (double sample : samples) {
        if (sample < min_tps) {
            results.push_back({
                ValidationSeverity::WARNING,
                "Throughput below minimum threshold: " + std::to_string(sample) + " TPS",
                "throughput",
                "Check if backend is properly configured and warmed up"
            });
        }
        if (sample > max_tps) {
            results.push_back({
                ValidationSeverity::WARNING,
                "Throughput above maximum expected: " + std::to_string(sample) + " TPS",
                "throughput",
                "Verify measurement accuracy"
            });
        }
    }
    
    return results;
}

ValidationResult ResultValidator::ValidateSuccessRate(double success_rate) {
    if (success_rate < 0.0 || success_rate > 1.0) {
        return {
            ValidationSeverity::CRITICAL,
            "Success rate out of range: " + std::to_string(success_rate),
            "success_rate",
            "Check benchmark implementation for bugs"
        };
    }
    
    if (success_rate < thresholds::MIN_SUCCESS_RATE) {
        return {
            ValidationSeverity::ERROR,
            "Success rate below threshold: " + std::to_string(success_rate * 100) + "%",
            "success_rate",
            "Investigate backend errors and retry logic"
        };
    }
    
    if (success_rate < thresholds::WARNING_SUCCESS_RATE) {
        return {
            ValidationSeverity::WARNING,
            "Success rate slightly below threshold: " + std::to_string(success_rate * 100) + "%",
            "success_rate",
            "Monitor for intermittent failures"
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "Success rate acceptable: " + std::to_string(success_rate * 100) + "%",
        "success_rate",
        ""
    };
}

std::vector<ValidationResult> ResultValidator::ValidateResourceMetrics(
    const ResourceMetrics& metrics) {
    
    std::vector<ValidationResult> results;
    
    // Check CPU usage
    if (metrics.cpu_percent < 0.0 || metrics.cpu_percent > thresholds::MAX_CPU_PERCENT) {
        results.push_back({
            ValidationSeverity::ERROR,
            "CPU usage out of range: " + std::to_string(metrics.cpu_percent) + "%",
            "resources",
            "Check resource monitoring implementation"
        });
    } else if (metrics.cpu_percent > 95.0) {
        results.push_back({
            ValidationSeverity::WARNING,
            "High CPU usage: " + std::to_string(metrics.cpu_percent) + "%",
            "resources",
            "Consider reducing load or increasing resources"
        });
    }
    
    // Check memory usage
    if (metrics.memory_mb < 0.0) {
        results.push_back({
            ValidationSeverity::ERROR,
            "Memory usage negative: " + std::to_string(metrics.memory_mb) + " MB",
            "resources",
            "Check resource monitoring implementation"
        });
    } else if (metrics.memory_mb > thresholds::MAX_MEMORY_GB * 1024) {
        results.push_back({
            ValidationSeverity::WARNING,
            "High memory usage: " + std::to_string(metrics.memory_mb / 1024) + " GB",
            "resources",
            "Consider reducing batch size or model size"
        });
    }
    
    // Check GPU usage
    if (metrics.gpu_percent < 0.0 || metrics.gpu_percent > thresholds::MAX_GPU_PERCENT) {
        results.push_back({
            ValidationSeverity::ERROR,
            "GPU usage out of range: " + std::to_string(metrics.gpu_percent) + "%",
            "resources",
            "Check GPU monitoring implementation"
        });
    }
    
    return results;
}

std::vector<ValidationResult> ResultValidator::ValidateQualityMetrics(
    const QualityMetrics& metrics) {
    
    std::vector<ValidationResult> results;
    
    // Check overall score
    if (metrics.overall_score < thresholds::MIN_QUALITY_SCORE) {
        results.push_back({
            ValidationSeverity::WARNING,
            "Quality score below threshold: " + std::to_string(metrics.overall_score),
            "quality",
            "Review response quality evaluation criteria"
        });
    }
    
    // Check individual scores
    if (metrics.structure_score < 0.0 || metrics.structure_score > 100.0) {
        results.push_back({
            ValidationSeverity::ERROR,
            "Structure score out of range",
            "quality",
            "Fix scoring implementation"
        });
    }
    
    if (metrics.correctness_score < 0.0 || metrics.correctness_score > 100.0) {
        results.push_back({
            ValidationSeverity::ERROR,
            "Correctness score out of range",
            "quality",
            "Fix scoring implementation"
        });
    }
    
    return results;
}

std::vector<ValidationResult> ResultValidator::CheckOutliers(
    const std::vector<double>& samples, double threshold) {
    
    std::vector<ValidationResult> results;
    
    if (samples.size() < 3) return results;
    
    // Calculate mean and stddev
    double sum = 0.0;
    for (double s : samples) sum += s;
    double mean = sum / samples.size();
    
    double sq_sum = 0.0;
    for (double s : samples) sq_sum += (s - mean) * (s - mean);
    double stddev = std::sqrt(sq_sum / samples.size());
    
    if (stddev == 0.0) return results;  // No variation
    
    // Count outliers
    int outlier_count = 0;
    for (double s : samples) {
        double z_score = std::abs(s - mean) / stddev;
        if (z_score > threshold) {
            outlier_count++;
        }
    }
    
    double outlier_percent = (100.0 * outlier_count) / samples.size();
    
    if (outlier_percent > 5.0) {
        results.push_back({
            ValidationSeverity::WARNING,
            "High outlier percentage: " + std::to_string(outlier_percent) + "%",
            "outliers",
            "Investigate source of variance (GC, thermal throttling, etc.)"
        });
    }
    
    return results;
}

ValidationResult ResultValidator::CheckBimodality(const std::vector<double>& samples) {
    if (samples.size() < 20) {
        return {
            ValidationSeverity::INFO,
            "Sample size too small for bimodality check",
            "distribution",
            ""
        };
    }
    
    // Simple bimodality check using histogram
    double min_val = *std::min_element(samples.begin(), samples.end());
    double max_val = *std::max_element(samples.begin(), samples.end());
    double range = max_val - min_val;
    
    if (range == 0.0) {
        return {
            ValidationSeverity::INFO,
            "No variation in samples",
            "distribution",
            ""
        };
    }
    
    // Create histogram with 10 bins
    const int bins = 10;
    std::vector<int> histogram(bins, 0);
    for (double s : samples) {
        int bin = static_cast<int>(((s - min_val) / range) * (bins - 1));
        bin = std::max(0, std::min(bin, bins - 1));
        histogram[bin]++;
    }
    
    // Count peaks (local maxima)
    int peaks = 0;
    for (int i = 1; i < bins - 1; ++i) {
        if (histogram[i] > histogram[i-1] && histogram[i] > histogram[i+1]) {
            peaks++;
        }
    }
    
    if (peaks >= 2) {
        return {
            ValidationSeverity::WARNING,
            "Bimodal or multimodal distribution detected (" + std::to_string(peaks) + " peaks)",
            "distribution",
            "Check for warmup issues or inconsistent system state"
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "Distribution appears unimodal",
        "distribution",
        ""
    };
}

ValidationResult ResultValidator::CheckTrend(const std::vector<double>& samples) {
    if (samples.size() < 10) {
        return {
            ValidationSeverity::INFO,
            "Sample size too small for trend analysis",
            "trend",
            ""
        };
    }
    
    // Simple linear regression
    double n = static_cast<double>(samples.size());
    double sum_x = 0.0, sum_y = 0.0, sum_xy = 0.0, sum_x2 = 0.0;
    
    for (size_t i = 0; i < samples.size(); ++i) {
        sum_x += static_cast<double>(i);
        sum_y += samples[i];
        sum_xy += static_cast<double>(i) * samples[i];
        sum_x2 += static_cast<double>(i) * static_cast<double>(i);
    }
    
    double slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
    double mean_y = sum_y / n;
    
    // Calculate relative trend
    double relative_trend = (slope * n) / mean_y;
    
    if (std::abs(relative_trend) > 0.1) {  // > 10% change over the run
        std::string direction = slope > 0 ? "increasing" : "decreasing";
        return {
            ValidationSeverity::WARNING,
            "Significant " + direction + " trend detected (" + 
            std::to_string(std::abs(relative_trend) * 100) + "%)",
            "trend",
            "Check for memory leaks, thermal throttling, or caching effects"
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "No significant trend detected",
        "trend",
        ""
    };
}

ValidationResult ResultValidator::CheckSampleSize(int sample_count, int minimum) {
    if (sample_count < minimum / 2) {
        return {
            ValidationSeverity::CRITICAL,
            "Sample size critically low: " + std::to_string(sample_count) + 
            " (minimum " + std::to_string(minimum) + ")",
            "sample_size",
            "Increase number of benchmark runs"
        };
    }
    
    if (sample_count < minimum) {
        return {
            ValidationSeverity::WARNING,
            "Sample size below recommended: " + std::to_string(sample_count) + 
            " (recommended " + std::to_string(minimum) + ")",
            "sample_size",
            "Consider increasing number of benchmark runs"
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "Sample size adequate: " + std::to_string(sample_count),
        "sample_size",
        ""
    };
}

ValidationResult ResultValidator::CheckConfidenceIntervalWidth(
    const ConfidenceInterval& ci, double max_width_percent) {
    
    double width = ci.Width();
    double center = (ci.lower + ci.upper) / 2.0;
    double relative_width = (width / center) * 100.0;
    
    if (relative_width > max_width_percent * 2) {
        return {
            ValidationSeverity::ERROR,
            "Confidence interval too wide: " + std::to_string(relative_width) + "%",
            "confidence_interval",
            "Increase sample size or reduce variance"
        };
    }
    
    if (relative_width > max_width_percent) {
        return {
            ValidationSeverity::WARNING,
            "Confidence interval somewhat wide: " + std::to_string(relative_width) + "%",
            "confidence_interval",
            "Consider increasing sample size"
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "Confidence interval width acceptable: " + std::to_string(relative_width) + "%",
        "confidence_interval",
        ""
    };
}

std::vector<ValidationResult> ResultValidator::CheckNegativeValues(
    const std::vector<double>& samples) {
    
    std::vector<ValidationResult> results;
    
    for (size_t i = 0; i < samples.size(); ++i) {
        if (samples[i] < 0.0) {
            results.push_back({
                ValidationSeverity::CRITICAL,
                "Negative value at index " + std::to_string(i) + ": " + std::to_string(samples[i]),
                "negative_values",
                "Check measurement implementation for bugs"
            });
        }
    }
    
    return results;
}

std::vector<ValidationResult> ResultValidator::CheckInvalidValues(
    const std::vector<double>& samples) {
    
    std::vector<ValidationResult> results;
    
    for (size_t i = 0; i < samples.size(); ++i) {
        if (std::isnan(samples[i])) {
            results.push_back({
                ValidationSeverity::CRITICAL,
                "NaN value at index " + std::to_string(i),
                "invalid_values",
                "Check for division by zero or uninitialized variables"
            });
        }
        if (std::isinf(samples[i])) {
            results.push_back({
                ValidationSeverity::CRITICAL,
                "Infinite value at index " + std::to_string(i),
                "invalid_values",
                "Check for overflow or division by zero"
            });
        }
    }
    
    return results;
}

ValidationResult ResultValidator::CheckDuplicateValues(
    const std::vector<double>& samples, double threshold_percent) {
    
    if (samples.size() < 2) {
        return {
            ValidationSeverity::INFO,
            "Too few samples for duplicate check",
            "duplicates",
            ""
        };
    }
    
    std::vector<double> sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    
    int duplicates = 0;
    for (size_t i = 1; i < sorted.size(); ++i) {
        if (sorted[i] == sorted[i-1]) {
            duplicates++;
        }
    }
    
    double duplicate_percent = (100.0 * duplicates) / samples.size();
    
    if (duplicate_percent > threshold_percent) {
        return {
            ValidationSeverity::WARNING,
            "High percentage of duplicate values: " + std::to_string(duplicate_percent) + "%",
            "duplicates",
            "Check for caching or timer resolution issues"
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "Duplicate value percentage acceptable: " + std::to_string(duplicate_percent) + "%",
        "duplicates",
        ""
    };
}

std::vector<ValidationResult> ResultValidator::CheckCategoryRanges(
    const std::vector<double>& samples, BenchmarkCategory category) {
    
    std::vector<ValidationResult> results;
    auto [min_expected, max_expected] = GetExpectedLatencyRange(category);
    
    for (size_t i = 0; i < samples.size(); ++i) {
        if (samples[i] < min_expected) {
            results.push_back({
                ValidationSeverity::WARNING,
                "Latency below expected range for " + std::string(CategoryToString(category)) + 
                ": " + std::to_string(samples[i]) + "ms",
                "latency_range",
                "Verify measurement accuracy"
            });
        }
        if (samples[i] > max_expected) {
            results.push_back({
                ValidationSeverity::WARNING,
                "Latency above expected range for " + std::string(CategoryToString(category)) + 
                ": " + std::to_string(samples[i]) + "ms",
                "latency_range",
                "Check for performance degradation or resource contention"
            });
        }
    }
    
    return results;
}

std::pair<double, double> ResultValidator::GetExpectedLatencyRange(BenchmarkCategory category) {
    switch (category) {
        case BenchmarkCategory::INFERENCE:
            return {thresholds::INFERENCE_MIN_MS, thresholds::INFERENCE_MAX_MS};
        case BenchmarkCategory::AGENT_SPAWN:
            return {thresholds::AGENT_SPAWN_MIN_MS, thresholds::AGENT_SPAWN_MAX_MS};
        case BenchmarkCategory::SWARM:
            return {thresholds::SWARM_MIN_MS, thresholds::SWARM_MAX_MS};
        case BenchmarkCategory::SEG_EXECUTION:
            return {thresholds::SEG_MIN_MS, thresholds::SEG_MAX_MS};
        case BenchmarkCategory::DECISION_MAKING:
            return {thresholds::DECISION_MIN_MS, thresholds::DECISION_MAX_MS};
        default:
            return {1.0, 60000.0};  // Generic range
    }
}

std::pair<double, double> ResultValidator::GetExpectedThroughputRange(BenchmarkCategory category) {
    // Throughput ranges are more category-agnostic
    return {thresholds::INFERENCE_MIN_TPS, thresholds::INFERENCE_MAX_TPS};
}

std::vector<ValidationResult> ResultValidator::ValidateComparison(
    const BenchmarkResult& baseline, const BenchmarkResult& current) {
    
    std::vector<ValidationResult> results;
    
    // Check for regression
    results.push_back(CheckRegression(baseline, current));
    
    // Check for improvement
    results.push_back(CheckImprovement(baseline, current));
    
    // Check if categories match
    if (baseline.category != current.category) {
        results.push_back({
            ValidationSeverity::ERROR,
            "Category mismatch between baseline and current",
            "comparison",
            "Ensure both results are from the same benchmark category"
        });
    }
    
    // Check if backends are different (they should be for comparison)
    if (baseline.backend == current.backend) {
        results.push_back({
            ValidationSeverity::WARNING,
            "Same backend for comparison - results may not be meaningful",
            "comparison",
            "Consider comparing different backends or configurations"
        });
    }
    
    return results;
}

ValidationResult ResultValidator::CheckRegression(
    const BenchmarkResult& baseline, const BenchmarkResult& current,
    double threshold_percent) {
    
    // Check latency regression
    double latency_change = ((current.latency.mean - baseline.latency.mean) / baseline.latency.mean) * 100.0;
    
    if (latency_change > threshold_percent) {
        return {
            ValidationSeverity::ERROR,
            "Latency regression detected: +" + std::to_string(latency_change) + "%",
            "regression",
            "Investigate performance degradation"
        };
    }
    
    // Check throughput regression
    double throughput_change = ((baseline.throughput.mean - current.throughput.mean) / baseline.throughput.mean) * 100.0;
    
    if (throughput_change > threshold_percent) {
        return {
            ValidationSeverity::ERROR,
            "Throughput regression detected: -" + std::to_string(throughput_change) + "%",
            "regression",
            "Investigate performance degradation"
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "No significant regression detected",
        "regression",
        ""
    };
}

ValidationResult ResultValidator::CheckImprovement(
    const BenchmarkResult& baseline, const BenchmarkResult& current,
    double threshold_percent) {
    
    // Check latency improvement
    double latency_change = ((baseline.latency.mean - current.latency.mean) / baseline.latency.mean) * 100.0;
    
    if (latency_change > threshold_percent) {
        return {
            ValidationSeverity::INFO,
            "Latency improvement detected: -" + std::to_string(latency_change) + "%",
            "improvement",
            ""
        };
    }
    
    // Check throughput improvement
    double throughput_change = ((current.throughput.mean - baseline.throughput.mean) / baseline.throughput.mean) * 100.0;
    
    if (throughput_change > threshold_percent) {
        return {
            ValidationSeverity::INFO,
            "Throughput improvement detected: +" + std::to_string(throughput_change) + "%",
            "improvement",
            ""
        };
    }
    
    return {
        ValidationSeverity::INFO,
        "No significant improvement detected",
        "improvement",
        ""
    };
}

bool ResultValidator::HasErrors(const std::vector<ValidationResult>& results) {
    for (const auto& r : results) {
        if (r.severity >= ValidationSeverity::ERROR) {
            return true;
        }
    }
    return false;
}

bool ResultValidator::HasCriticalErrors(const std::vector<ValidationResult>& results) {
    for (const auto& r : results) {
        if (r.severity == ValidationSeverity::CRITICAL) {
            return true;
        }
    }
    return false;
}

int ResultValidator::CountBySeverity(const std::vector<ValidationResult>& results,
                                        ValidationSeverity severity) {
    int count = 0;
    for (const auto& r : results) {
        if (r.severity == severity) {
            count++;
        }
    }
    return count;
}

void ResultValidator::PrintResults(const std::vector<ValidationResult>& results) {
    for (const auto& r : results) {
        const char* severity_str = SeverityToString(r.severity);
        std::cout << "[" << severity_str << "] " << r.message;
        if (!r.suggestion.empty()) {
            std::cout << " (Suggestion: " << r.suggestion << ")";
        }
        std::cout << std::endl;
    }
}

std::string ResultValidator::GenerateReport(const std::vector<ValidationResult>& results) {
    std::ostringstream oss;
    
    int info_count = CountBySeverity(results, ValidationSeverity::INFO);
    int warning_count = CountBySeverity(results, ValidationSeverity::WARNING);
    int error_count = CountBySeverity(results, ValidationSeverity::ERROR);
    int critical_count = CountBySeverity(results, ValidationSeverity::CRITICAL);
    
    oss << "Validation Report\n";
    oss << "==================\n";
    oss << "Total checks: " << results.size() << "\n";
    oss << "  INFO: " << info_count << "\n";
    oss << "  WARNING: " << warning_count << "\n";
    oss << "  ERROR: " << error_count << "\n";
    oss << "  CRITICAL: " << critical_count << "\n\n";
    
    if (critical_count > 0) {
        oss << "CRITICAL ISSUES:\n";
        for (const auto& r : results) {
            if (r.severity == ValidationSeverity::CRITICAL) {
                oss << "  - " << r.message << "\n";
                if (!r.suggestion.empty()) {
                    oss << "    Suggestion: " << r.suggestion << "\n";
                }
            }
        }
        oss << "\n";
    }
    
    if (error_count > 0) {
        oss << "ERRORS:\n";
        for (const auto& r : results) {
            if (r.severity == ValidationSeverity::ERROR) {
                oss << "  - " << r.message << "\n";
                if (!r.suggestion.empty()) {
                    oss << "    Suggestion: " << r.suggestion << "\n";
                }
            }
        }
        oss << "\n";
    }
    
    if (warning_count > 0) {
        oss << "WARNINGS:\n";
        for (const auto& r : results) {
            if (r.severity == ValidationSeverity::WARNING) {
                oss << "  - " << r.message << "\n";
                if (!r.suggestion.empty()) {
                    oss << "    Suggestion: " << r.suggestion << "\n";
                }
            }
        }
    }
    
    return oss.str();
}

} // namespace rawrxd::benchmark
