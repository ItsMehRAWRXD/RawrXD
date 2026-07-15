// ============================================================================
// sovereign_benchmark_suite.hpp - Phase 11: Performance Benchmarking
// TPS, latency, and throughput measurement
// ============================================================================

#ifndef SOVEREIGN_BENCHMARK_SUITE_HPP
#define SOVEREIGN_BENCHMARK_SUITE_HPP

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace Sovereign {

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    // Test parameters
    uint32_t warmup_iterations = 10;
    uint32_t benchmark_iterations = 100;
    uint32_t concurrent_requests = 1;
    
    // Token parameters
    uint32_t input_tokens = 128;
    uint32_t output_tokens = 128;
    uint32_t batch_size = 1;
    
    // Timing
    uint32_t timeout_ms = 60000;
    bool enable_profiling = true;
    
    // Output
    std::string output_format = "json";  // json, csv, table
    std::string output_file = "";
};

// ============================================================================
// Benchmark Results
// ============================================================================
struct LatencyResult {
    double min_ms = 0.0;
    double max_ms = 0.0;
    double avg_ms = 0.0;
    double p50_ms = 0.0;
    double p95_ms = 0.0;
    double p99_ms = 0.0;
    double stddev_ms = 0.0;
};

struct ThroughputResult {
    double tokens_per_second = 0.0;
    double requests_per_second = 0.0;
    double total_tokens = 0.0;
    double total_time_ms = 0.0;
};

struct BenchmarkResult {
    std::string name;
    bool success = false;
    std::string error_message;
    
    // Timing
    LatencyResult latency;
    ThroughputResult throughput;
    
    // Counters
    uint64_t total_requests = 0;
    uint64_t successful_requests = 0;
    uint64_t failed_requests = 0;
    uint64_t total_tokens_in = 0;
    uint64_t total_tokens_out = 0;
    
    // System
    uint64_t memory_start_mb = 0;
    uint64_t memory_end_mb = 0;
    uint64_t memory_peak_mb = 0;
};

// ============================================================================
// Benchmark Suite
// ============================================================================
class BenchmarkSuite {
public:
    BenchmarkSuite();
    ~BenchmarkSuite();

    // Initialize benchmark environment
    bool Initialize(const BenchmarkConfig& config);
    void Shutdown();

    // Individual benchmarks
    BenchmarkResult RunLatencyBenchmark();
    BenchmarkResult RunThroughputBenchmark();
    BenchmarkResult RunConcurrencyBenchmark(uint32_t concurrency);
    BenchmarkResult RunBatchSizeBenchmark(uint32_t batch_size);
    BenchmarkResult RunEndToEndBenchmark();
    
    // Run all benchmarks
    std::vector<BenchmarkResult> RunAllBenchmarks();
    
    // Custom benchmark
    BenchmarkResult RunCustomBenchmark(
        const std::string& name,
        std::function<bool()> setup,
        std::function<bool()> iterate,
        std::function<void()> teardown
    );

    // Results export
    std::string ExportResultsJSON() const;
    std::string ExportResultsCSV() const;
    std::string ExportResultsTable() const;
    bool SaveResults(const std::string& filename) const;

    // Comparison
    static std::string CompareResults(const BenchmarkResult& baseline, 
                                       const BenchmarkResult& current);

private:
    bool initialized_;
    BenchmarkConfig config_;
    std::vector<BenchmarkResult> results_;
    HANDLE results_mutex_;
    
    // Internal helpers
    std::vector<double> CollectLatencies(std::function<void()> operation, uint32_t count);
    double CalculatePercentile(const std::vector<double>& sorted, double percentile);
    double CalculateStdDev(const std::vector<double>& values, double mean);
    uint64_t GetMemoryUsageMB();
    
    // Benchmark operations
    bool SimulateDecodeOperation(uint32_t tokens_in, uint32_t tokens_out);
    bool SimulateBatchOperation(const std::vector<uint32_t>& batch_sizes);
};

// ============================================================================
// Quick Benchmark
// ============================================================================
// Run a quick 10-second benchmark and return TPS
double QuickBenchmarkTPS(uint32_t input_tokens = 128, uint32_t output_tokens = 128);

// ============================================================================
// Stress Test
// ============================================================================
struct StressTestConfig {
    uint32_t duration_seconds = 60;
    uint32_t max_concurrent = 10;
    uint32_t ramp_up_seconds = 5;
    bool randomize_tokens = true;
};

struct StressTestResult {
    bool success = false;
    uint64_t total_requests = 0;
    uint64_t failed_requests = 0;
    double avg_tps = 0.0;
    double peak_tps = 0.0;
    double avg_latency_ms = 0.0;
    double error_rate = 0.0;
    std::vector<double> tps_over_time;
};

StressTestResult RunStressTest(const StressTestConfig& config);

// ============================================================================
// Regression Test
// ============================================================================
// Compare current results against baseline and report regressions
struct RegressionResult {
    bool has_regression = false;
    double tps_change_percent = 0.0;
    double latency_change_percent = 0.0;
    std::string summary;
};

RegressionResult CheckRegression(const BenchmarkResult& baseline,
                                   const BenchmarkResult& current,
                                   double tps_threshold = -5.0,  // 5% TPS drop
                                   double latency_threshold = 10.0);  // 10% latency increase

} // namespace Sovereign

#endif // SOVEREIGN_BENCHMARK_SUITE_HPP
