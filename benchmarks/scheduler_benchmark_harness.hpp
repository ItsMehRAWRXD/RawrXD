// scheduler_benchmark_harness.hpp
// Phase C.2 Batch 3/5 — Scheduler Performance Benchmark Harness

#ifndef SCHEDULER_BENCHMARK_HARNESS_HPP
#define SCHEDULER_BENCHMARK_HARNESS_HPP

#include <vector>
#include <string>
#include <chrono>
#include <functional>
#include <map>
#include <atomic>
#include <mutex>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <numeric>
#include <algorithm>
#include <cmath>

namespace SchedulerBenchmark {

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchmarkConfig {
    // Test parameters
    uint32_t warmup_iterations = 10;
    uint32_t benchmark_iterations = 100;
    uint32_t concurrent_tasks = 16;
    
    // Timing
    std::chrono::milliseconds max_duration{60000}; // 60 seconds max
    std::chrono::milliseconds stabilization_time{1000};
    
    // Task characteristics
    uint32_t min_task_complexity = 100;
    uint32_t max_task_complexity = 10000;
    double task_complexity_distribution = 1.0; // 1.0 = uniform, >1.0 = skewed
    
    // Worker configuration
    uint32_t min_workers = 2;
    uint32_t max_workers = 32;
    
    // Pattern simulation
    uint32_t pattern_count = 10;
    double pattern_stability = 0.8;
    
    // Output
    std::string output_directory = "d:\\rawrxd\\benchmarks\\results\\";
    bool save_raw_data = true;
    bool generate_charts = false;
};

// ============================================================================
// Benchmark Results
// ============================================================================

struct BenchmarkResult {
    // Identification
    std::string benchmark_name;
    std::string test_case;
    std::chrono::steady_clock::time_point timestamp;
    
    // Timing metrics
    double total_duration_ms;
    double average_latency_ms;
    double p50_latency_ms;
    double p95_latency_ms;
    double p99_latency_ms;
    double min_latency_ms;
    double max_latency_ms;
    double stddev_latency_ms;
    
    // Throughput metrics
    double average_tps;
    double peak_tps;
    double sustained_tps;
    
    // Task metrics
    uint64_t tasks_submitted;
    uint64_t tasks_completed;
    uint64_t tasks_failed;
    double success_rate;
    
    // Resource metrics
    double average_worker_utilization;
    double peak_worker_utilization;
    uint32_t workers_scaled_up;
    uint32_t workers_scaled_down;
    
    // Scheduling metrics
    double average_scheduling_overhead_ms;
    double average_priority_calculation_time_us;
    double average_worker_assignment_time_us;
    
    // Pattern metrics
    double pattern_match_rate;
    double average_pattern_confidence;
    double exploration_ratio;
    
    // Raw data (optional)
    std::vector<double> raw_latencies;
    std::vector<double> raw_throughputs;
    
    BenchmarkResult()
        : total_duration_ms(0.0)
        , average_latency_ms(0.0)
        , p50_latency_ms(0.0)
        , p95_latency_ms(0.0)
        , p99_latency_ms(0.0)
        , min_latency_ms(0.0)
        , max_latency_ms(0.0)
        , stddev_latency_ms(0.0)
        , average_tps(0.0)
        , peak_tps(0.0)
        , sustained_tps(0.0)
        , tasks_submitted(0)
        , tasks_completed(0)
        , tasks_failed(0)
        , success_rate(0.0)
        , average_worker_utilization(0.0)
        , peak_worker_utilization(0.0)
        , workers_scaled_up(0)
        , workers_scaled_down(0)
        , average_scheduling_overhead_ms(0.0)
        , average_priority_calculation_time_us(0.0)
        , average_worker_assignment_time_us(0.0)
        , pattern_match_rate(0.0)
        , average_pattern_confidence(0.0)
        , exploration_ratio(0.0)
    {}
    
    // Calculate statistics from raw data
    void CalculateStatistics();
    
    // Export to various formats
    std::string ToCSV() const;
    std::string ToJSON() const;
    std::string ToMarkdown() const;
    void SaveToFile(const std::string& path) const;
};

// ============================================================================
// Benchmark Harness
// ============================================================================

class SchedulerBenchmarkHarness {
public:
    SchedulerBenchmarkHarness(const BenchmarkConfig& config = BenchmarkConfig{});
    ~SchedulerBenchmarkHarness();
    
    // Registration
    void RegisterBenchmark(
        const std::string& name,
        std::function<BenchmarkResult()> benchmark_fn);
    
    // Execution
    void RunAllBenchmarks();
    void RunBenchmark(const std::string& name);
    void RunBenchmarks(const std::vector<std::string>& names);
    
    // Results
    std::vector<BenchmarkResult> GetResults() const;
    BenchmarkResult GetResult(const std::string& name) const;
    
    // Reporting
    void GenerateReport(const std::string& output_path) const;
    void GenerateComparisonChart(const std::vector<std::string>& benchmarks,
                                  const std::string& output_path) const;
    
    // Utilities
    static double CalculatePercentile(const std::vector<double>& data, double percentile);
    static double CalculateMean(const std::vector<double>& data);
    static double CalculateStdDev(const std::vector<double>& data);
    static double CalculateCV(const std::vector<double>& data); // Coefficient of variation
    
private:
    BenchmarkConfig config_;
    std::map<std::string, std::function<BenchmarkResult()>> benchmarks_;
    std::vector<BenchmarkResult> results_;
    mutable std::mutex results_mutex_;
    
    void PrintBenchmarkHeader(const std::string& name) const;
    void PrintBenchmarkResult(const BenchmarkResult& result) const;
    void PrintSummary() const;
};

// ============================================================================
// Performance Timer
// ============================================================================

class PreciseTimer {
public:
    PreciseTimer();
    
    void Start();
    void Stop();
    void Reset();
    
    double GetElapsedMicroseconds() const;
    double GetElapsedMilliseconds() const;
    double GetElapsedSeconds() const;
    
private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
    bool running_;
};

// ============================================================================
// Throughput Meter
// ============================================================================

class ThroughputMeter {
public:
    ThroughputMeter(std::chrono::milliseconds window_size = std::chrono::milliseconds(1000));
    
    void RecordOperation();
    void RecordOperations(uint64_t count);
    
    double GetCurrentTPS() const;
    double GetAverageTPS() const;
    double GetPeakTPS() const;
    
    void Reset();
    
private:
    std::chrono::milliseconds window_size_;
    std::vector<std::pair<std::chrono::steady_clock::time_point, uint64_t>> operations_;
    mutable std::mutex mutex_;
    
    void CleanupOldOperations();
};

// ============================================================================
// Latency Tracker
// ============================================================================

class LatencyTracker {
public:
    LatencyTracker();
    
    void RecordLatency(double latency_ms);
    void RecordLatencies(const std::vector<double>& latencies);
    
    double GetAverage() const;
    double GetP50() const;
    double GetP95() const;
    double GetP99() const;
    double GetMin() const;
    double GetMax() const;
    double GetStdDev() const;
    
    std::vector<double> GetLatencies() const;
    void Reset();
    
private:
    std::vector<double> latencies_;
    mutable std::mutex mutex_;
    
    void SortIfNeeded() const;
    mutable bool sorted_;
};

// ============================================================================
// Resource Monitor
// ============================================================================

class ResourceMonitor {
public:
    ResourceMonitor();
    
    void StartMonitoring();
    void StopMonitoring();
    
    double GetCurrentCPUUtilization() const;
    double GetCurrentMemoryUtilization() const;
    double GetAverageCPUUtilization() const;
    double GetPeakCPUUtilization() const;
    double GetPeakMemoryUtilization() const;
    
    std::vector<std::pair<double, double>> GetUtilizationHistory() const;
    
private:
    std::atomic<bool> monitoring_{false};
    std::thread monitor_thread_;
    std::vector<std::pair<double, double>> utilization_history_; // {cpu, memory}
    mutable std::mutex history_mutex_;
    
    void MonitoringLoop();
    double ReadCPUUtilization() const;
    double ReadMemoryUtilization() const;
};

// ============================================================================
// Benchmark Scenarios
// ============================================================================

// Standard benchmark scenarios
BenchmarkResult RunLatencyBenchmark(const BenchmarkConfig& config);
BenchmarkResult RunThroughputBenchmark(const BenchmarkConfig& config);
BenchmarkResult RunScalabilityBenchmark(const BenchmarkConfig& config);
BenchmarkResult RunPatternAdaptationBenchmark(const BenchmarkConfig& config);
BenchmarkResult RunExplorationExploitationBenchmark(const BenchmarkConfig& config);
BenchmarkResult RunWorkerScalingBenchmark(const BenchmarkConfig& config);
BenchmarkResult RunSEGBenchmark(const BenchmarkConfig& config);
BenchmarkResult RunComparisonBenchmark(const BenchmarkConfig& config);

// ============================================================================
// Statistical Analysis
// ============================================================================

struct StatisticalSummary {
    double mean;
    double median;
    double stddev;
    double cv; // Coefficient of variation
    double min;
    double max;
    double p25;
    double p75;
    double p95;
    double p99;
    double skewness;
    double kurtosis;
};

StatisticalSummary AnalyzeDistribution(const std::vector<double>& data);

// Compare two benchmark results
struct ComparisonResult {
    double latency_improvement_percent;
    double throughput_improvement_percent;
    double resource_efficiency_improvement_percent;
    bool statistically_significant;
    double p_value;
};

ComparisonResult CompareBenchmarks(const BenchmarkResult& baseline,
                                    const BenchmarkResult& optimized);

// ============================================================================
// Report Generation
// ============================================================================

class BenchmarkReportGenerator {
public:
    void GenerateHTMLReport(const std::vector<BenchmarkResult>& results,
                             const std::string& output_path) const;
    
    void GenerateMarkdownReport(const std::vector<BenchmarkResult>& results,
                               const std::string& output_path) const;
    
    void GenerateCSVReport(const std::vector<BenchmarkResult>& results,
                          const std::string& output_path) const;
    
    void GenerateJSONReport(const std::vector<BenchmarkResult>& results,
                           const std::string& output_path) const;
    
private:
    std::string GenerateHTMLHeader() const;
    std::string GenerateHTMLFooter() const;
    std::string GenerateResultTable(const std::vector<BenchmarkResult>& results) const;
    std::string GenerateCharts(const std::vector<BenchmarkResult>& results) const;
};

} // namespace SchedulerBenchmark

#endif // SCHEDULER_BENCHMARK_HARNESS_HPP
