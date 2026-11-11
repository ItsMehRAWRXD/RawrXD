// Phase Z.3/5: Performance Benchmark Suite
// RawrXD Performance Benchmarks - Comprehensive performance measurement framework

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <variant>

namespace RawrXD {
namespace Integration {

// Benchmark category
enum class BenchmarkCategory {
    INFERENCE,       // Inference performance
    MEMORY,          // Memory operations
    CPU,             // CPU utilization
    IO,              // I/O operations
    NETWORK,         // Network throughput
    LATENCY,         // Response latency
    THROUGHPUT,      // System throughput
    SCALABILITY      // Scaling behavior
};

// Benchmark metric type
enum class MetricType {
    TIME,            // Duration in milliseconds
    THROUGHPUT,      // Operations per second
    LATENCY,         // Response time
    MEMORY,          // Memory usage in MB
    CPU,             // CPU percentage
    COUNT            // Raw count
};

// Benchmark metric
struct BenchmarkMetric {
    std::string name;
    MetricType type;
    double value;
    std::string unit;
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> labels;
};

// Benchmark result
struct BenchmarkResult {
    std::string benchmark_id;
    std::string name;
    BenchmarkCategory category;
    
    // Timing
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    std::chrono::milliseconds duration;
    
    // Metrics
    std::vector<BenchmarkMetric> metrics;
    
    // Statistics
    double min_value;
    double max_value;
    double avg_value;
    double median_value;
    double std_dev;
    double p50;
    double p95;
    double p99;
    
    // Status
    bool is_completed;
    bool is_valid;
    std::string error_message;
    
    // Context
    std::unordered_map<std::string, std::string> context;
    std::string hardware_info;
    std::string software_info;
};

// Benchmark configuration
struct BenchmarkConfig {
    std::string config_id;
    std::string name;
    
    // Execution
    uint32_t warmup_iterations;
    uint32_t measurement_iterations;
    uint32_t min_iterations;
    uint32_t max_iterations;
    std::chrono::seconds max_duration;
    
    // Concurrency
    uint32_t threads;
    uint32_t concurrent_requests;
    
    // Data
    std::string dataset_path;
    std::string model_path;
    std::unordered_map<std::string, std::string> parameters;
    
    // Validation
    double min_throughput;
    double max_latency_p99;
    double max_memory_mb;
};

// Benchmark definition
struct BenchmarkDefinition {
    std::string benchmark_id;
    std::string name;
    std::string description;
    BenchmarkCategory category;
    
    // Function
    std::function<BenchmarkResult(const BenchmarkConfig&)> benchmark_function;
    
    // Configuration
    BenchmarkConfig default_config;
    std::vector<std::string> required_subsystems;
    std::vector<std::string> required_features;
    
    // Metadata
    std::string version;
    std::string author;
    std::vector<std::string> tags;
};

// Benchmark suite
struct BenchmarkSuite {
    std::string suite_id;
    std::string name;
    std::string description;
    
    // Benchmarks
    std::vector<std::string> benchmark_ids;
    
    // Execution
    bool parallel_execution;
    uint32_t parallel_jobs;
    std::chrono::seconds timeout;
    
    // Configuration overrides
    std::unordered_map<std::string, BenchmarkConfig> config_overrides;
};

// Benchmark run configuration
struct BenchmarkRunConfig {
    // Filter
    std::vector<std::string> include_categories;
    std::vector<std::string> exclude_categories;
    std::vector<std::string> include_benchmarks;
    std::vector<std::string> exclude_benchmarks;
    std::vector<std::string> tags;
    
    // Execution
    bool parallel_execution;
    uint32_t parallel_jobs;
    std::chrono::seconds timeout;
    uint32_t repeat_count;
    
    // Output
    std::string output_format;  // "console", "json", "csv", "html"
    std::string output_path;
    bool verbose;
    bool save_raw_data;
    
    // Comparison
    std::string baseline_path;
    bool fail_on_regression;
    double regression_threshold_percent;
};

// Benchmark run result
struct BenchmarkRunResult {
    std::string run_id;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    
    // Summary
    uint32_t total_benchmarks;
    uint32_t completed_benchmarks;
    uint32_t failed_benchmarks;
    
    // Results
    std::vector<BenchmarkResult> results;
    
    // Comparison
    bool has_baseline;
    std::vector<std::string> regressions;
    std::vector<std::string> improvements;
    
    // Timing
    std::chrono::milliseconds total_duration;
};

// Performance benchmark interface
class IPerformanceBenchmarks {
public:
    virtual ~IPerformanceBenchmarks() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Benchmark registration
    virtual std::string RegisterBenchmark(const BenchmarkDefinition& benchmark) = 0;
    virtual bool UnregisterBenchmark(const std::string& benchmark_id) = 0;
    virtual std::string RegisterSuite(const BenchmarkSuite& suite) = 0;
    virtual bool UnregisterSuite(const std::string& suite_id) = 0;
    
    // Benchmark queries
    virtual std::vector<BenchmarkDefinition> ListBenchmarks() = 0;
    virtual std::vector<BenchmarkDefinition> ListBenchmarksByCategory(BenchmarkCategory category) = 0;
    virtual std::optional<BenchmarkDefinition> GetBenchmark(const std::string& benchmark_id) = 0;
    virtual std::vector<BenchmarkSuite> ListSuites() = 0;
    
    // Benchmark execution
    virtual BenchmarkResult RunBenchmark(const std::string& benchmark_id,
                                          const BenchmarkConfig& config = {}) = 0;
    virtual BenchmarkRunResult RunSuite(const std::string& suite_id,
                                         const BenchmarkRunConfig& config = {}) = 0;
    virtual BenchmarkRunResult RunAll(const BenchmarkRunConfig& config = {}) = 0;
    virtual BenchmarkRunResult RunFiltered(const BenchmarkRunConfig& config) = 0;
    
    // Benchmark control
    virtual bool CancelRunningBenchmarks() = 0;
    virtual bool IsBenchmarkRunning() = 0;
    
    // Baseline management
    virtual bool SaveBaseline(const std::string& path) = 0;
    virtual bool LoadBaseline(const std::string& path) = 0;
    virtual bool CompareWithBaseline(const BenchmarkResult& result) = 0;
    virtual std::vector<std::string> FindRegressions(const BenchmarkRunResult& result) = 0;
    
    // Profiling
    virtual bool StartProfiling(const std::string& output_path) = 0;
    virtual bool StopProfiling() = 0;
    virtual bool IsProfiling() = 0;
    
    // Reporting
    virtual std::string GenerateReport(const BenchmarkRunResult& result,
                                      const std::string& format = "console") = 0;
    virtual bool SaveReport(const BenchmarkRunResult& result,
                           const std::string& path,
                           const std::string& format = "json") = 0;
    virtual std::string GenerateComparisonReport(const BenchmarkRunResult& current,
                                                 const BenchmarkRunResult& baseline) = 0;
    
    // History
    virtual std::vector<BenchmarkRunResult> GetBenchmarkHistory(const std::string& benchmark_id,
                                                                  uint32_t limit = 100) = 0;
    virtual std::vector<BenchmarkRunResult> GetRunHistory(uint32_t limit = 100) = 0;
    virtual std::optional<BenchmarkRunResult> GetLastRun() = 0;
    
    // Trends
    virtual std::vector<std::pair<std::chrono::system_clock::time_point, double>> 
        GetMetricTrend(const std::string& benchmark_id, const std::string& metric_name,
                       std::chrono::days range = std::chrono::days(30)) = 0;
    
    // Statistics
    virtual struct BenchmarkStatistics {
        uint32_t total_benchmarks;
        uint32_t total_suites;
        uint32_t total_runs;
        double average_run_duration_ms;
        std::unordered_map<BenchmarkCategory, uint32_t> benchmarks_by_category;
        std::vector<std::string> slowest_benchmarks;
        std::vector<std::string> most_variable_benchmarks;
    } GetStatistics() = 0;
};

// Global performance benchmarks
extern std::unique_ptr<IPerformanceBenchmarks> g_performance_benchmarks;

// Initialize performance benchmarks
bool InitializePerformanceBenchmarks(const std::string& config_path);
void ShutdownPerformanceBenchmarks();
bool ArePerformanceBenchmarksEnabled();

// Predefined benchmarks
namespace PredefinedBenchmarks {

// Inference benchmarks
void RegisterInferenceBenchmarks();

// Memory benchmarks
void RegisterMemoryBenchmarks();

// System benchmarks
void RegisterSystemBenchmarks();

// End-to-end benchmarks
void RegisterEndToEndBenchmarks();

// Full benchmark suite
void RegisterAllBenchmarks();

} // namespace PredefinedBenchmarks

} // namespace Integration
} // namespace RawrXD
