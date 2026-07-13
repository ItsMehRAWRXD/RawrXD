// scheduler_benchmark_harness.cpp
// Phase C.2 Batch 3/5 — Scheduler Performance Benchmark Implementation

#include "scheduler_benchmark_harness.hpp"
#include "../src/scheduler/AdaptiveScheduler.hpp"
#include "../src/emergent/EmergentPatterns.hpp"
#include <thread>
#include <random>
#include <algorithm>
#include <numeric>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace SchedulerBenchmark {

// ============================================================================
// BenchmarkResult Implementation
// ============================================================================

void BenchmarkResult::CalculateStatistics() {
    if (raw_latencies.empty()) {
        return;
    }
    
    // Sort for percentile calculations
    std::sort(raw_latencies.begin(), raw_latencies.end());
    
    // Basic statistics
    min_latency_ms = raw_latencies.front();
    max_latency_ms = raw_latencies.back();
    
    // Mean
    double sum = std::accumulate(raw_latencies.begin(), raw_latencies.end(), 0.0);
    average_latency_ms = sum / raw_latencies.size();
    
    // Standard deviation
    double sq_sum = 0.0;
    for (double lat : raw_latencies) {
        sq_sum += (lat - average_latency_ms) * (lat - average_latency_ms);
    }
    stddev_latency_ms = std::sqrt(sq_sum / raw_latencies.size());
    
    // Percentiles
    p50_latency_ms = raw_latencies[raw_latencies.size() * 0.50];
    p95_latency_ms = raw_latencies[raw_latencies.size() * 0.95];
    p99_latency_ms = raw_latencies[raw_latencies.size() * 0.99];
}

std::string BenchmarkResult::ToCSV() const {
    std::ostringstream oss;
    
    oss << benchmark_name << ","
        << test_case << ","
        << total_duration_ms << ","
        << average_latency_ms << ","
        << p50_latency_ms << ","
        << p95_latency_ms << ","
        << p99_latency_ms << ","
        << min_latency_ms << ","
        << max_latency_ms << ","
        << stddev_latency_ms << ","
        << average_tps << ","
        << peak_tps << ","
        << sustained_tps << ","
        << tasks_submitted << ","
        << tasks_completed << ","
        << tasks_failed << ","
        << success_rate << ","
        << average_worker_utilization << ","
        << peak_worker_utilization << ","
        << workers_scaled_up << ","
        << workers_scaled_down << ","
        << average_scheduling_overhead_ms << ","
        << average_priority_calculation_time_us << ","
        << average_worker_assignment_time_us << ","
        << pattern_match_rate << ","
        << average_pattern_confidence << ","
        << exploration_ratio << "\n";
    
    return oss.str();
}

std::string BenchmarkResult::ToJSON() const {
    std::ostringstream oss;
    
    oss << "{\n";
    oss << "  \"benchmark_name\": \"" << benchmark_name << "\",\n";
    oss << "  \"test_case\": \"" << test_case << "\",\n";
    oss << "  \"timing\": {\n";
    oss << "    \"total_duration_ms\": " << total_duration_ms << ",\n";
    oss << "    \"average_latency_ms\": " << average_latency_ms << ",\n";
    oss << "    \"p50_latency_ms\": " << p50_latency_ms << ",\n";
    oss << "    \"p95_latency_ms\": " << p95_latency_ms << ",\n";
    oss << "    \"p99_latency_ms\": " << p99_latency_ms << ",\n";
    oss << "    \"min_latency_ms\": " << min_latency_ms << ",\n";
    oss << "    \"max_latency_ms\": " << max_latency_ms << ",\n";
    oss << "    \"stddev_latency_ms\": " << stddev_latency_ms << "\n";
    oss << "  },\n";
    oss << "  \"throughput\": {\n";
    oss << "    \"average_tps\": " << average_tps << ",\n";
    oss << "    \"peak_tps\": " << peak_tps << ",\n";
    oss << "    \"sustained_tps\": " << sustained_tps << "\n";
    oss << "  },\n";
    oss << "  \"tasks\": {\n";
    oss << "    \"submitted\": " << tasks_submitted << ",\n";
    oss << "    \"completed\": " << tasks_completed << ",\n";
    oss << "    \"failed\": " << tasks_failed << ",\n";
    oss << "    \"success_rate\": " << success_rate << "\n";
    oss << "  },\n";
    oss << "  \"resources\": {\n";
    oss << "    \"average_worker_utilization\": " << average_worker_utilization << ",\n";
    oss << "    \"peak_worker_utilization\": " << peak_worker_utilization << ",\n";
    oss << "    \"workers_scaled_up\": " << workers_scaled_up << ",\n";
    oss << "    \"workers_scaled_down\": " << workers_scaled_down << "\n";
    oss << "  },\n";
    oss << "  \"scheduling\": {\n";
    oss << "    \"average_scheduling_overhead_ms\": " << average_scheduling_overhead_ms << ",\n";
    oss << "    \"average_priority_calculation_time_us\": " << average_priority_calculation_time_us << ",\n";
    oss << "    \"average_worker_assignment_time_us\": " << average_worker_assignment_time_us << "\n";
    oss << "  },\n";
    oss << "  \"patterns\": {\n";
    oss << "    \"match_rate\": " << pattern_match_rate << ",\n";
    oss << "    \"average_confidence\": " << average_pattern_confidence << ",\n";
    oss << "    \"exploration_ratio\": " << exploration_ratio << "\n";
    oss << "  }\n";
    oss << "}\n";
    
    return oss.str();
}

std::string BenchmarkResult::ToMarkdown() const {
    std::ostringstream oss;
    
    oss << "## " << benchmark_name << " - " << test_case << "\n\n";
    
    oss << "### Timing Metrics\n\n";
    oss << "| Metric | Value |\n";
    oss << "|--------|-------|\n";
    oss << "| Total Duration | " << std::fixed << std::setprecision(2) << total_duration_ms << " ms |\n";
    oss << "| Average Latency | " << average_latency_ms << " ms |\n";
    oss << "| P50 Latency | " << p50_latency_ms << " ms |\n";
    oss << "| P95 Latency | " << p95_latency_ms << " ms |\n";
    oss << "| P99 Latency | " << p99_latency_ms << " ms |\n";
    oss << "| Min Latency | " << min_latency_ms << " ms |\n";
    oss << "| Max Latency | " << max_latency_ms << " ms |\n";
    oss << "| StdDev | " << stddev_latency_ms << " ms |\n\n";
    
    oss << "### Throughput Metrics\n\n";
    oss << "| Metric | Value |\n";
    oss << "|--------|-------|\n";
    oss << "| Average TPS | " << average_tps << " |\n";
    oss << "| Peak TPS | " << peak_tps << " |\n";
    oss << "| Sustained TPS | " << sustained_tps << " |\n\n";
    
    oss << "### Task Metrics\n\n";
    oss << "| Metric | Value |\n";
    oss << "|--------|-------|\n";
    oss << "| Submitted | " << tasks_submitted << " |\n";
    oss << "| Completed | " << tasks_completed << " |\n";
    oss << "| Failed | " << tasks_failed << " |\n";
    oss << "| Success Rate | " << success_rate * 100.0 << "% |\n\n";
    
    return oss.str();
}

void BenchmarkResult::SaveToFile(const std::string& path) const {
    std::ofstream file(path);
    if (file.is_open()) {
        file << ToJSON();
    }
}

// ============================================================================
// SchedulerBenchmarkHarness Implementation
// ============================================================================

SchedulerBenchmarkHarness::SchedulerBenchmarkHarness(const BenchmarkConfig& config)
    : config_(config) {}

SchedulerBenchmarkHarness::~SchedulerBenchmarkHarness() = default;

void SchedulerBenchmarkHarness::RegisterBenchmark(
    const std::string& name,
    std::function<BenchmarkResult()> benchmark_fn) {
    
    benchmarks_[name] = benchmark_fn;
}

void SchedulerBenchmarkHarness::RunAllBenchmarks() {
    for (const auto& [name, fn] : benchmarks_) {
        RunBenchmark(name);
    }
    
    PrintSummary();
}

void SchedulerBenchmarkHarness::RunBenchmark(const std::string& name) {
    auto it = benchmarks_.find(name);
    if (it == benchmarks_.end()) {
        std::cerr << "Benchmark not found: " << name << std::endl;
        return;
    }
    
    PrintBenchmarkHeader(name);
    
    // Run warmup
    std::cout << "  Warming up..." << std::endl;
    for (uint32_t i = 0; i < config_.warmup_iterations; ++i) {
        it->second();
    }
    
    // Run benchmark
    std::cout << "  Running benchmark..." << std::endl;
    BenchmarkResult result = it->second();
    result.benchmark_name = name;
    
    // Store result
    {
        std::lock_guard<std::mutex> lock(results_mutex_);
        results_.push_back(result);
    }
    
    PrintBenchmarkResult(result);
    
    // Save to file
    if (config_.save_raw_data) {
        std::string filename = config_.output_directory + name + "_result.json";
        result.SaveToFile(filename);
        std::cout << "  Saved to: " << filename << std::endl;
    }
}

void SchedulerBenchmarkHarness::RunBenchmarks(const std::vector<std::string>& names) {
    for (const auto& name : names) {
        RunBenchmark(name);
    }
}

std::vector<BenchmarkResult> SchedulerBenchmarkHarness::GetResults() const {
    std::lock_guard<std::mutex> lock(results_mutex_);
    return results_;
}

BenchmarkResult SchedulerBenchmarkHarness::GetResult(const std::string& name) const {
    std::lock_guard<std::mutex> lock(results_mutex_);
    
    for (const auto& result : results_) {
        if (result.benchmark_name == name) {
            return result;
        }
    }
    
    return BenchmarkResult{};
}

void SchedulerBenchmarkHarness::GenerateReport(const std::string& output_path) const {
    BenchmarkReportGenerator generator;
    generator.GenerateMarkdownReport(results_, output_path);
}

void SchedulerBenchmarkHarness::GenerateComparisonChart(
    const std::vector<std::string>& benchmarks,
    const std::string& output_path) const {
    
    // Filter results for specified benchmarks
    std::vector<BenchmarkResult> filtered;
    for (const auto& result : results_) {
        if (std::find(benchmarks.begin(), benchmarks.end(), result.benchmark_name) 
            != benchmarks.end()) {
            filtered.push_back(result);
        }
    }
    
    // Generate comparison
    BenchmarkReportGenerator generator;
    generator.GenerateHTMLReport(filtered, output_path);
}

double SchedulerBenchmarkHarness::CalculatePercentile(const std::vector<double>& data, 
                                                         double percentile) {
    if (data.empty()) return 0.0;
    
    std::vector<double> sorted = data;
    std::sort(sorted.begin(), sorted.end());
    
    size_t index = static_cast<size_t>(sorted.size() * percentile);
    index = std::min(index, sorted.size() - 1);
    
    return sorted[index];
}

double SchedulerBenchmarkHarness::CalculateMean(const std::vector<double>& data) {
    if (data.empty()) return 0.0;
    
    double sum = std::accumulate(data.begin(), data.end(), 0.0);
    return sum / data.size();
}

double SchedulerBenchmarkHarness::CalculateStdDev(const std::vector<double>& data) {
    if (data.size() < 2) return 0.0;
    
    double mean = CalculateMean(data);
    double sq_sum = 0.0;
    
    for (double val : data) {
        sq_sum += (val - mean) * (val - mean);
    }
    
    return std::sqrt(sq_sum / data.size());
}

double SchedulerBenchmarkHarness::CalculateCV(const std::vector<double>& data) {
    double mean = CalculateMean(data);
    double stddev = CalculateStdDev(data);
    
    return (mean > 0.0) ? (stddev / mean) : 0.0;
}

void SchedulerBenchmarkHarness::PrintBenchmarkHeader(const std::string& name) const {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Running: " << name << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void SchedulerBenchmarkHarness::PrintBenchmarkResult(const BenchmarkResult& result) const {
    std::cout << "\n  Results:" << std::endl;
    std::cout << "    Average Latency: " << std::fixed << std::setprecision(2) 
              << result.average_latency_ms << " ms" << std::endl;
    std::cout << "    P95 Latency: " << result.p95_latency_ms << " ms" << std::endl;
    std::cout << "    P99 Latency: " << result.p99_latency_ms << " ms" << std::endl;
    std::cout << "    Average TPS: " << result.average_tps << std::endl;
    std::cout << "    Peak TPS: " << result.peak_tps << std::endl;
    std::cout << "    Success Rate: " << result.success_rate * 100.0 << "%" << std::endl;
    std::cout << "    Worker Utilization: " << result.average_worker_utilization * 100.0 
              << "%" << std::endl;
}

void SchedulerBenchmarkHarness::PrintSummary() const {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Benchmark Summary" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    
    for (const auto& result : results_) {
        std::cout << "  " << result.benchmark_name << ": "
                  << result.average_tps << " TPS, "
                  << result.average_latency_ms << " ms avg latency" << std::endl;
    }
}

// ============================================================================
// PreciseTimer Implementation
// ============================================================================

PreciseTimer::PreciseTimer() : running_(false) {}

void PreciseTimer::Start() {
    start_time_ = std::chrono::high_resolution_clock::now();
    running_ = true;
}

void PreciseTimer::Stop() {
    end_time_ = std::chrono::high_resolution_clock::now();
    running_ = false;
}

void PreciseTimer::Reset() {
    running_ = false;
}

double PreciseTimer::GetElapsedMicroseconds() const {
    auto end = running_ ? std::chrono::high_resolution_clock::now() : end_time_;
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_time_);
    return static_cast<double>(duration.count());
}

double PreciseTimer::GetElapsedMilliseconds() const {
    return GetElapsedMicroseconds() / 1000.0;
}

double PreciseTimer::GetElapsedSeconds() const {
    return GetElapsedMicroseconds() / 1000000.0;
}

// ============================================================================
// ThroughputMeter Implementation
// ============================================================================

ThroughputMeter::ThroughputMeter(std::chrono::milliseconds window_size)
    : window_size_(window_size) {}

void ThroughputMeter::RecordOperation() {
    RecordOperations(1);
}

void ThroughputMeter::RecordOperations(uint64_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto now = std::chrono::steady_clock::now();
    operations_.push_back({now, count});
    
    CleanupOldOperations();
}

double ThroughputMeter::GetCurrentTPS() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (operations_.empty()) {
        return 0.0;
    }
    
    auto now = std::chrono::steady_clock::now();
    auto window_start = now - window_size_;
    
    uint64_t count = 0;
    for (const auto& [time, ops] : operations_) {
        if (time >= window_start) {
            count += ops;
        }
    }
    
    return static_cast<double>(count) * 1000.0 / window_size_.count();
}

double ThroughputMeter::GetAverageTPS() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (operations_.size() < 2) {
        return 0.0;
    }
    
    auto start = operations_.front().first;
    auto end = operations_.back().first;
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (duration <= 0) {
        return 0.0;
    }
    
    uint64_t total = 0;
    for (const auto& [time, ops] : operations_) {
        total += ops;
    }
    
    return static_cast<double>(total) * 1000.0 / duration;
}

double ThroughputMeter::GetPeakTPS() const {
    // Simplified: return current TPS as peak estimate
    return GetCurrentTPS();
}

void ThroughputMeter::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    operations_.clear();
}

void ThroughputMeter::CleanupOldOperations() {
    auto cutoff = std::chrono::steady_clock::now() - window_size_ * 2;
    
    while (!operations_.empty() && operations_.front().first < cutoff) {
        operations_.erase(operations_.begin());
    }
}

// ============================================================================
// LatencyTracker Implementation
// ============================================================================

LatencyTracker::LatencyTracker() : sorted_(false) {}

void LatencyTracker::RecordLatency(double latency_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    latencies_.push_back(latency_ms);
    sorted_ = false;
}

void LatencyTracker::RecordLatencies(const std::vector<double>& latencies) {
    std::lock_guard<std::mutex> lock(mutex_);
    latencies_.insert(latencies_.end(), latencies.begin(), latencies.end());
    sorted_ = false;
}

double LatencyTracker::GetAverage() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (latencies_.empty()) return 0.0;
    
    double sum = std::accumulate(latencies_.begin(), latencies_.end(), 0.0);
    return sum / latencies_.size();
}

double LatencyTracker::GetP50() const {
    SortIfNeeded();
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (latencies_.empty()) return 0.0;
    
    size_t index = latencies_.size() * 0.50;
    return latencies_[index];
}

double LatencyTracker::GetP95() const {
    SortIfNeeded();
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (latencies_.empty()) return 0.0;
    
    size_t index = latencies_.size() * 0.95;
    return latencies_[index];
}

double LatencyTracker::GetP99() const {
    SortIfNeeded();
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (latencies_.empty()) return 0.0;
    
    size_t index = latencies_.size() * 0.99;
    return latencies_[index];
}

double LatencyTracker::GetMin() const {
    SortIfNeeded();
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (latencies_.empty()) return 0.0;
    
    return latencies_.front();
}

double LatencyTracker::GetMax() const {
    SortIfNeeded();
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (latencies_.empty()) return 0.0;
    
    return latencies_.back();
}

double LatencyTracker::GetStdDev() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (latencies_.size() < 2) return 0.0;
    
    double mean = std::accumulate(latencies_.begin(), latencies_.end(), 0.0) / latencies_.size();
    double sq_sum = 0.0;
    
    for (double lat : latencies_) {
        sq_sum += (lat - mean) * (lat - mean);
    }
    
    return std::sqrt(sq_sum / latencies_.size());
}

std::vector<double> LatencyTracker::GetLatencies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return latencies_;
}

void LatencyTracker::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    latencies_.clear();
    sorted_ = false;
}

void LatencyTracker::SortIfNeeded() const {
    if (!sorted_) {
        std::sort(latencies_.begin(), latencies_.end());
        sorted_ = true;
    }
}

// ============================================================================
// Statistical Analysis
// ============================================================================

StatisticalSummary AnalyzeDistribution(const std::vector<double>& data) {
    StatisticalSummary summary{};
    
    if (data.empty()) {
        return summary;
    }
    
    std::vector<double> sorted = data;
    std::sort(sorted.begin(), sorted.end());
    
    // Basic statistics
    summary.min = sorted.front();
    summary.max = sorted.back();
    summary.mean = std::accumulate(sorted.begin(), sorted.end(), 0.0) / sorted.size();
    summary.median = sorted[sorted.size() * 0.50];
    summary.p25 = sorted[sorted.size() * 0.25];
    summary.p75 = sorted[sorted.size() * 0.75];
    summary.p95 = sorted[sorted.size() * 0.95];
    summary.p99 = sorted[sorted.size() * 0.99];
    
    // Standard deviation
    double sq_sum = 0.0;
    for (double val : sorted) {
        sq_sum += (val - summary.mean) * (val - summary.mean);
    }
    summary.stddev = std::sqrt(sq_sum / sorted.size());
    summary.cv = (summary.mean > 0.0) ? (summary.stddev / summary.mean) : 0.0;
    
    // Skewness and kurtosis (simplified)
    if (sorted.size() >= 3) {
        double m3 = 0.0, m4 = 0.0;
        for (double val : sorted) {
            double diff = val - summary.mean;
            m3 += diff * diff * diff;
            m4 += diff * diff * diff * diff;
        }
        m3 /= sorted.size();
        m4 /= sorted.size();
        
        if (summary.stddev > 0.0) {
            summary.skewness = m3 / (summary.stddev * summary.stddev * summary.stddev);
            summary.kurtosis = m4 / (summary.stddev * summary.stddev * summary.stddev * summary.stddev);
        }
    }
    
    return summary;
}

ComparisonResult CompareBenchmarks(const BenchmarkResult& baseline,
                                      const BenchmarkResult& optimized) {
    ComparisonResult result{};
    
    // Calculate improvements
    result.latency_improvement_percent = 
        (baseline.average_latency_ms - optimized.average_latency_ms) / baseline.average_latency_ms * 100.0;
    
    result.throughput_improvement_percent = 
        (optimized.average_tps - baseline.average_tps) / baseline.average_tps * 100.0;
    
    result.resource_efficiency_improvement_percent = 
        (optimized.average_worker_utilization - baseline.average_worker_utilization) / baseline.average_worker_utilization * 100.0;
    
    // Statistical significance (simplified)
    result.statistically_significant = std::abs(result.latency_improvement_percent) > 5.0 ||
                                          std::abs(result.throughput_improvement_percent) > 5.0;
    result.p_value = 0.05; // Placeholder
    
    return result;
}

// ============================================================================
// Report Generation
// ============================================================================

void BenchmarkReportGenerator::GenerateMarkdownReport(
    const std::vector<BenchmarkResult>& results,
    const std::string& output_path) const {
    
    std::ofstream file(output_path);
    if (!file.is_open()) {
        return;
    }
    
    file << "# Scheduler Benchmark Report\n\n";
    file << "Generated: " << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) << "\n\n";
    
    file << "## Summary\n\n";
    file << "| Benchmark | Avg TPS | Avg Latency | P95 Latency | Success Rate |\n";
    file << "|-----------|---------|-------------|-------------|--------------|\n";
    
    for (const auto& result : results) {
        file << "| " << result.benchmark_name << " | "
             << std::fixed << std::setprecision(2) << result.average_tps << " | "
             << result.average_latency_ms << " ms | "
             << result.p95_latency_ms << " ms | "
             << result.success_rate * 100.0 << "% |\n";
    }
    
    file << "\n";
    
    // Detailed results
    for (const auto& result : results) {
        file << result.ToMarkdown();
    }
}

void BenchmarkReportGenerator::GenerateCSVReport(
    const std::vector<BenchmarkResult>& results,
    const std::string& output_path) const {
    
    std::ofstream file(output_path);
    if (!file.is_open()) {
        return;
    }
    
    // Header
    file << "benchmark_name,test_case,total_duration_ms,average_latency_ms,"
         << "p50_latency_ms,p95_latency_ms,p99_latency_ms,min_latency_ms,"
         << "max_latency_ms,stddev_latency_ms,average_tps,peak_tps,"
         << "sustained_tps,tasks_submitted,tasks_completed,tasks_failed,"
         << "success_rate,average_worker_utilization,peak_worker_utilization,"
         << "workers_scaled_up,workers_scaled_down\n";
    
    // Data
    for (const auto& result : results) {
        file << result.ToCSV();
    }
}

void BenchmarkReportGenerator::GenerateJSONReport(
    const std::vector<BenchmarkResult>& results,
    const std::string& output_path) const {
    
    std::ofstream file(output_path);
    if (!file.is_open()) {
        return;
    }
    
    file << "[\n";
    for (size_t i = 0; i < results.size(); ++i) {
        file << results[i].ToJSON();
        if (i < results.size() - 1) {
            file << ",";
        }
        file << "\n";
    }
    file << "]\n";
}

void BenchmarkReportGenerator::GenerateHTMLReport(
    const std::vector<BenchmarkResult>& results,
    const std::string& output_path) const {
    
    std::ofstream file(output_path);
    if (!file.is_open()) {
        return;
    }
    
    file << GenerateHTMLHeader();
    file << GenerateResultTable(results);
    file << GenerateCharts(results);
    file << GenerateHTMLFooter();
}

std::string BenchmarkReportGenerator::GenerateHTMLHeader() const {
    return R"(<!DOCTYPE html>
<html>
<head>
    <title>Scheduler Benchmark Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .metric { font-weight: bold; }
    </style>
</head>
<body>
    <h1>Scheduler Benchmark Report</h1>
)";
}

std::string BenchmarkReportGenerator::GenerateHTMLFooter() const {
    return "</body>\n</html>";
}

std::string BenchmarkReportGenerator::GenerateResultTable(
    const std::vector<BenchmarkResult>& results) const {
    
    std::ostringstream oss;
    
    oss << "<table>\n";
    oss << "<tr><th>Benchmark</th><th>Avg TPS</th><th>Avg Latency</th>"
        << "<th>P95 Latency</th><th>Success Rate</th></tr>\n";
    
    for (const auto& result : results) {
        oss << "<tr>"
            << "<td>" << result.benchmark_name << "</td>"
            << "<td>" << std::fixed << std::setprecision(2) << result.average_tps << "</td>"
            << "<td>" << result.average_latency_ms << " ms</td>"
            << "<td>" << result.p95_latency_ms << " ms</td>"
            << "<td>" << result.success_rate * 100.0 << "%</td>"
            << "</tr>\n";
    }
    
    oss << "</table>\n";
    
    return oss.str();
}

std::string BenchmarkReportGenerator::GenerateCharts(
    const std::vector<BenchmarkResult>& results) const {
    // Simplified - would include actual chart generation in production
    (void)results;
    return "<div class='charts'>Charts would be generated here</div>\n";
}

} // namespace SchedulerBenchmark
