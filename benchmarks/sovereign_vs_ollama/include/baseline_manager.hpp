// Performance Baseline Management
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <vector>
#include <map>
#include <string>
#include <optional>

namespace rawrxd::benchmark {

// ============================================================================
// Baseline Configuration
// ============================================================================

struct BaselineConfig {
    // Minimum runs required for baseline
    int min_runs = 30;
    
    // Maximum runs to keep in baseline
    int max_runs = 100;
    
    // Confidence level for baseline
    double confidence_level = 0.95;
    
    // Maximum acceptable variance (coefficient of variation)
    double max_cv = 0.1;  // 10%
    
    // Outlier removal threshold (standard deviations)
    double outlier_threshold = 3.0;
    
    // Whether to require consecutive stable runs
    bool require_stable_consecutive = true;
    int stable_consecutive_count = 3;
    
    // Stability threshold (relative change between runs)
    double stability_threshold = 0.05;  // 5%
};

// ============================================================================
// Baseline Entry
// ============================================================================

struct BaselineEntry {
    std::string benchmark_id;
    std::string benchmark_name;
    BenchmarkCategory category;
    BackendType backend;
    std::string model_name;
    std::string timestamp;
    std::string git_commit;
    std::string git_branch;
    
    // Statistical metrics
    StatisticalMetrics latency;
    StatisticalMetrics throughput;
    double success_rate = 0.0;
    
    // Raw samples (optional)
    std::vector<double> raw_latencies;
    
    // Validation status
    bool is_valid = false;
    std::string validation_message;
    
    // Comparison methods
    bool IsSimilarTo(const BaselineEntry& other, double tolerance = 0.1) const;
    double CalculateDistance(const BaselineEntry& other) const;
};

// ============================================================================
// Baseline History
// ============================================================================

struct BaselineHistory {
    std::string benchmark_id;
    std::vector<BaselineEntry> entries;
    
    // Get latest valid entry
    std::optional<BaselineEntry> GetLatest() const;
    
    // Get entry at specific time
    std::optional<BaselineEntry> GetAtTime(const std::string& timestamp) const;
    
    // Get entries within date range
    std::vector<BaselineEntry> GetInRange(const std::string& start, 
                                              const std::string& end) const;
    
    // Calculate trend over time
    std::pair<double, double> CalculateTrend() const;  // slope, r_squared
    
    // Check if baseline is stable
    bool IsStable(const BaselineConfig& config) const;
    
    // Get stability score (0-100)
    double GetStabilityScore() const;
};

// ============================================================================
// Baseline Manager
// ============================================================================

class BaselineManager {
public:
    BaselineManager();
    ~BaselineManager();
    
    // Initialize with configuration
    bool Initialize(const std::string& storage_path, const BaselineConfig& config);
    
    // Add new baseline entry
    bool AddEntry(const BaselineEntry& entry);
    
    // Get baseline for benchmark
    std::optional<BaselineEntry> GetBaseline(const std::string& benchmark_id) const;
    
    // Get baseline history for benchmark
    BaselineHistory GetHistory(const std::string& benchmark_id) const;
    
    // Check if baseline exists
    bool HasBaseline(const std::string& benchmark_id) const;
    
    // Establish new baseline from multiple runs
    std::optional<BaselineEntry> EstablishBaseline(
        const std::string& benchmark_id,
        const std::vector<BenchmarkResult>& results);
    
    // Update existing baseline with new result
    bool UpdateBaseline(const std::string& benchmark_id, const BenchmarkResult& result);
    
    // Invalidate baseline
    bool InvalidateBaseline(const std::string& benchmark_id, const std::string& reason);
    
    // Compare result against baseline
    struct ComparisonResult {
        bool is_valid = false;
        double latency_change_percent = 0.0;
        double throughput_change_percent = 0.0;
        bool is_regression = false;
        bool is_improvement = false;
        double confidence = 0.0;
        std::string summary;
    };
    ComparisonResult CompareToBaseline(const std::string& benchmark_id,
                                        const BenchmarkResult& result) const;
    
    // Get all baseline IDs
    std::vector<std::string> GetBaselineIds() const;
    
    // Export/Import baselines
    bool ExportToFile(const std::string& path) const;
    bool ImportFromFile(const std::string& path);
    
    // Generate baseline report
    std::string GenerateReport() const;
    
    // Configuration
    void SetConfig(const BaselineConfig& config) { config_ = config; }
    BaselineConfig GetConfig() const { return config_; }

private:
    BaselineConfig config_;
    std::string storage_path_;
    std::map<std::string, BaselineHistory> baselines_;
    
    // Persistence
    bool SaveToDisk();
    bool LoadFromDisk();
    
    // Validation
    bool ValidateEntry(const BaselineEntry& entry) const;
    
    // Aggregation
    BaselineEntry AggregateEntries(const std::vector<BaselineEntry>& entries) const;
};

// ============================================================================
// Baseline Establishment Helper
// ============================================================================

class BaselineEstablishment {
public:
    // Run baseline establishment process
    static BaselineEntry Establish(const std::string& benchmark_name,
                                    BenchmarkCategory category,
                                    BackendType backend,
                                    const BenchmarkConfig& config,
                                    const BaselineConfig& baseline_config);
    
    // Check if enough samples collected
    static bool HasEnoughSamples(const std::vector<BenchmarkResult>& results,
                                  const BaselineConfig& config);
    
    // Check if samples are stable
    static bool IsStable(const std::vector<BenchmarkResult>& results,
                         const BaselineConfig& config);
    
    // Calculate required additional samples
    static int CalculateRequiredSamples(const std::vector<BenchmarkResult>& results,
                                         const BaselineConfig& config);
    
    // Remove outliers from samples
    static std::vector<double> RemoveOutliers(const std::vector<double>& samples,
                                                double threshold);
    
    // Calculate coefficient of variation
    static double CalculateCV(const std::vector<double>& samples);
    
    // Estimate convergence
    static bool HasConverged(const std::vector<double>& samples,
                               double threshold = 0.02);
};

// ============================================================================
// Regression Detection
// ============================================================================

class RegressionDetector {
public:
    struct RegressionConfig {
        double latency_threshold_percent = 10.0;
        double throughput_threshold_percent = 10.0;
        double success_rate_threshold = 0.05;  // 5% drop
        double confidence_threshold = 0.95;
        bool require_statistical_significance = true;
    };
    
    // Detect regression against baseline
    static bool DetectRegression(const BaselineEntry& baseline,
                                  const BenchmarkResult& current,
                                  const RegressionConfig& config);
    
    // Detect improvement against baseline
    static bool DetectImprovement(const BaselineEntry& baseline,
                                   const BenchmarkResult& current,
                                   const RegressionConfig& config);
    
    // Calculate change significance
    static double CalculateSignificance(const BaselineEntry& baseline,
                                         const BenchmarkResult& current);
    
    // Generate regression report
    static std::string GenerateReport(const BaselineEntry& baseline,
                                       const BenchmarkResult& current);
};

// ============================================================================
// Baseline Utilities
// ============================================================================

namespace baseline_utils {
    // Get current git commit
    std::string GetGitCommit();
    
    // Get current git branch
    std::string GetGitBranch();
    
    // Get current timestamp
    std::string GetTimestamp();
    
    // Calculate mean of samples
    double CalculateMean(const std::vector<double>& samples);
    
    // Calculate standard deviation
    double CalculateStdDev(const std::vector<double>& samples);
    
    // Calculate confidence interval
    ConfidenceInterval CalculateCI(const std::vector<double>& samples, 
                                    double confidence = 0.95);
    
} // namespace baseline_utils

} // namespace rawrxd::benchmark
