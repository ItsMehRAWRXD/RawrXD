// benchmark_optimizer.cpp
// Batch 9: Benchmark Framework Self-Optimization
//
// Analyzes and optimizes the benchmark framework itself:
// - Timer overhead compensation
// - Statistical outlier detection
// - Warmup convergence detection
// - Adaptive iteration count

#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <chrono>

namespace Benchmark {
namespace Performance {

// Timer overhead compensator
class TimerCompensator {
public:
    // Measure timer overhead
    static uint64_t MeasureOverhead() {
        constexpr int MEASUREMENTS = 10000;
        std::vector<uint64_t> overheads;
        overheads.reserve(MEASUREMENTS);
        
        auto start = std::chrono::high_resolution_clock::now();
        auto end = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < MEASUREMENTS; ++i) {
            start = std::chrono::high_resolution_clock::now();
            end = std::chrono::high_resolution_clock::now();
            overheads.push_back(
                std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count()
            );
        }
        
        // Use median to avoid outliers
        std::sort(overheads.begin(), overheads.end());
        return overheads[MEASUREMENTS / 2];
    }
    
    // Compensate measured time for timer overhead
    static uint64_t Compensate(uint64_t measured_ns, uint64_t overhead_ns) {
        if (measured_ns > overhead_ns) {
            return measured_ns - overhead_ns;
        }
        return 0; // Measurement was too short
    }
};

// Statistical outlier detector
class OutlierDetector {
public:
    enum class Method {
        IQR,        // Interquartile Range
        ZSCORE,     // Z-Score (standard deviations)
        MAD,        // Median Absolute Deviation
        GRUBBS      // Grubbs' test
    };
    
    // Detect outliers using IQR method
    static std::vector<size_t> DetectOutliersIQR(const std::vector<double>& data) {
        if (data.size() < 4) return {};
        
        std::vector<double> sorted = data;
        std::sort(sorted.begin(), sorted.end());
        
        size_t q1_idx = sorted.size() / 4;
        size_t q3_idx = 3 * sorted.size() / 4;
        
        double q1 = sorted[q1_idx];
        double q3 = sorted[q3_idx];
        double iqr = q3 - q1;
        
        double lower_bound = q1 - 1.5 * iqr;
        double upper_bound = q3 + 1.5 * iqr;
        
        std::vector<size_t> outliers;
        for (size_t i = 0; i < data.size(); ++i) {
            if (data[i] < lower_bound || data[i] > upper_bound) {
                outliers.push_back(i);
            }
        }
        
        return outliers;
    }
    
    // Detect outliers using Z-Score
    static std::vector<size_t> DetectOutliersZScore(const std::vector<double>& data,
                                                     double threshold = 3.0) {
        if (data.size() < 2) return {};
        
        double mean = std::accumulate(data.begin(), data.end(), 0.0) / data.size();
        
        double variance = 0.0;
        for (double x : data) {
            variance += (x - mean) * (x - mean);
        }
        variance /= data.size();
        double std_dev = std::sqrt(variance);
        
        if (std_dev == 0) return {};
        
        std::vector<size_t> outliers;
        for (size_t i = 0; i < data.size(); ++i) {
            double z_score = std::abs(data[i] - mean) / std_dev;
            if (z_score > threshold) {
                outliers.push_back(i);
            }
        }
        
        return outliers;
    }
    
    // Remove outliers from dataset
    static std::vector<double> RemoveOutliers(const std::vector<double>& data,
                                               const std::vector<size_t>& outlier_indices) {
        std::vector<double> cleaned;
        cleaned.reserve(data.size() - outlier_indices.size());
        
        // Create set for O(1) lookup
        std::vector<bool> is_outlier(data.size(), false);
        for (size_t idx : outlier_indices) {
            if (idx < data.size()) is_outlier[idx] = true;
        }
        
        for (size_t i = 0; i < data.size(); ++i) {
            if (!is_outlier[i]) {
                cleaned.push_back(data[i]);
            }
        }
        
        return cleaned;
    }
};

// Warmup convergence detector
class WarmupDetector {
public:
    struct Config {
        size_t min_iterations = 5;
        size_t max_iterations = 50;
        double convergence_threshold = 0.05; // 5% change
        size_t window_size = 3;
    };
    
    // Check if warmup has converged
    static bool HasConverged(const std::vector<double>& samples,
                             const Config& config = Config()) {
        if (samples.size() < config.min_iterations) {
            return false;
        }
        
        if (samples.size() >= config.max_iterations) {
            return true; // Force convergence
        }
        
        // Check last N samples for stability
        size_t start = samples.size() > config.window_size ? 
                       samples.size() - config.window_size : 0;
        
        double window_mean = 0.0;
        for (size_t i = start; i < samples.size(); ++i) {
            window_mean += samples[i];
        }
        window_mean /= (samples.size() - start);
        
        // Compare with previous window
        if (start >= config.window_size) {
            double prev_mean = 0.0;
            size_t prev_start = start - config.window_size;
            for (size_t i = prev_start; i < start; ++i) {
                prev_mean += samples[i];
            }
            prev_mean /= config.window_size;
            
            if (prev_mean > 0) {
                double change = std::abs(window_mean - prev_mean) / prev_mean;
                return change < config.convergence_threshold;
            }
        }
        
        return false;
    }
    
    // Estimate required warmup iterations
    static size_t EstimateWarmupIterations(const std::vector<double>& samples,
                                            const Config& config = Config()) {
        for (size_t i = config.min_iterations; i <= samples.size(); ++i) {
            std::vector<double> window(samples.begin(), samples.begin() + i);
            if (HasConverged(window, config)) {
                return i;
            }
        }
        return config.max_iterations;
    }
};

// Adaptive iteration count calculator
class AdaptiveIterationCalculator {
public:
    struct Config {
        double target_relative_error = 0.05; // 5%
        double confidence_level = 0.95;
        size_t min_iterations = 10;
        size_t max_iterations = 1000;
    };
    
    // Calculate required iterations for target precision
    static size_t CalculateRequiredIterations(const std::vector<double>& pilot_samples,
                                               const Config& config = Config()) {
        if (pilot_samples.size() < 2) {
            return config.min_iterations;
        }
        
        // Calculate sample statistics
        double mean = std::accumulate(pilot_samples.begin(), pilot_samples.end(), 0.0) 
                      / pilot_samples.size();
        
        double variance = 0.0;
        for (double x : pilot_samples) {
            variance += (x - mean) * (x - mean);
        }
        variance /= pilot_samples.size();
        double std_dev = std::sqrt(variance);
        
        if (std_dev == 0 || mean == 0) {
            return config.min_iterations;
        }
        
        // Calculate coefficient of variation
        double cv = std_dev / mean;
        
        // For 95% CI, t ≈ 1.96 for large n
        double t_value = 1.96;
        
        // Required iterations for target relative error
        double required = std::pow(t_value * cv / config.target_relative_error, 2);
        
        size_t iterations = static_cast<size_t>(std::ceil(required));
        
        // Clamp to min/max
        if (iterations < config.min_iterations) {
            iterations = config.min_iterations;
        }
        if (iterations > config.max_iterations) {
            iterations = config.max_iterations;
        }
        
        return iterations;
    }
    
    // Check if current precision meets target
    static bool HasTargetPrecision(const std::vector<double>& samples,
                                    double target_relative_error = 0.05) {
        if (samples.size() < 2) return false;
        
        double mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        
        double variance = 0.0;
        for (double x : samples) {
            variance += (x - mean) * (x - mean);
        }
        variance /= samples.size();
        double std_dev = std::sqrt(variance);
        
        if (mean == 0) return false;
        
        // Calculate relative standard error
        double rse = (std_dev / std::sqrt(samples.size())) / mean;
        
        return rse < target_relative_error;
    }
};

// Benchmark result validator
class ResultValidator {
public:
    struct ValidationResult {
        bool is_valid = true;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
    };
    
    // Validate benchmark results
    static ValidationResult Validate(const std::vector<double>& samples,
                                      double expected_min = 0.0,
                                      double expected_max = 1e9) {
        ValidationResult result;
        
        if (samples.empty()) {
            result.is_valid = false;
            result.errors.push_back("No samples collected");
            return result;
        }
        
        // Check for negative values (usually indicates error)
        for (double x : samples) {
            if (x < 0) {
                result.errors.push_back("Negative sample value detected");
                result.is_valid = false;
                break;
            }
        }
        
        // Check for values outside expected range
        for (double x : samples) {
            if (x < expected_min || x > expected_max) {
                result.warnings.push_back("Sample outside expected range");
                break;
            }
        }
        
        // Check for high variance
        double mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        double variance = 0.0;
        for (double x : samples) {
            variance += (x - mean) * (x - mean);
        }
        variance /= samples.size();
        double cv = (mean > 0) ? std::sqrt(variance) / mean : 0.0;
        
        if (cv > 0.5) {
            result.warnings.push_back("High coefficient of variation (>50%)");
        }
        
        // Check for insufficient samples
        if (samples.size() < 10) {
            result.warnings.push_back("Low sample count may affect statistical validity");
        }
        
        return result;
    }
};

// Performance optimization report
struct OptimizationReport {
    uint64_t timer_overhead_ns;
    size_t detected_outliers;
    size_t recommended_warmup;
    size_t recommended_iterations;
    double achieved_precision;
    bool passed_validation;
    std::vector<std::string> recommendations;
};

inline OptimizationReport GenerateOptimizationReport(const std::vector<double>& samples) {
    OptimizationReport report;
    
    // Measure timer overhead
    report.timer_overhead_ns = TimerCompensator::MeasureOverhead();
    
    // Detect outliers
    auto outliers = OutlierDetector::DetectOutliersIQR(samples);
    report.detected_outliers = outliers.size();
    
    // Estimate warmup
    report.recommended_warmup = WarmupDetector::EstimateWarmupIterations(samples);
    
    // Calculate recommended iterations
    AdaptiveIterationCalculator::Config iter_config;
    report.recommended_iterations = AdaptiveIterationCalculator::CalculateRequiredIterations(
        samples, iter_config);
    
    // Calculate achieved precision
    if (samples.size() >= 2) {
        double mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
        double variance = 0.0;
        for (double x : samples) {
            variance += (x - mean) * (x - mean);
        }
        variance /= samples.size();
        report.achieved_precision = std::sqrt(variance) / std::sqrt(samples.size()) / mean;
    }
    
    // Validate results
    auto validation = ResultValidator::Validate(samples);
    report.passed_validation = validation.is_valid;
    
    // Generate recommendations
    if (report.detected_outliers > samples.size() / 10) {
        report.recommendations.push_back("High outlier rate detected - check for system interference");
    }
    
    if (report.recommended_warmup > 20) {
        report.recommendations.push_back("Long warmup detected - consider system tuning");
    }
    
    if (report.achieved_precision > 0.1) {
        report.recommendations.push_back("Low precision achieved - consider increasing iterations");
    }
    
    return report;
}

} // namespace Performance
} // namespace Benchmark
