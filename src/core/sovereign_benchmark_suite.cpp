// ============================================================================
// sovereign_benchmark_suite.cpp - Phase 11: Performance Benchmarking
// TPS, latency, and throughput measurement
// ============================================================================

#include "sovereign_benchmark_suite.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <algorithm>
#include <numeric>
#include <random>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

namespace Sovereign {

// ============================================================================
// Constructor/Destructor
// ============================================================================
BenchmarkSuite::BenchmarkSuite() : initialized_(false) {
    results_mutex_ = CreateMutexA(NULL, FALSE, NULL);
}

BenchmarkSuite::~BenchmarkSuite() {
    Shutdown();
    if (results_mutex_) {
        CloseHandle(results_mutex_);
    }
}

// ============================================================================
// Initialization
// ============================================================================
bool BenchmarkSuite::Initialize(const BenchmarkConfig& config) {
    if (initialized_) {
        return true;
    }

    config_ = config;
    results_.clear();
    
    initialized_ = true;
    printf("[Benchmark] Initialized with %u iterations, %u warmup\n", 
           config.benchmark_iterations, config.warmup_iterations);
    
    return true;
}

void BenchmarkSuite::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    initialized_ = false;
}

// ============================================================================
// Latency Benchmark
// ============================================================================
BenchmarkResult BenchmarkSuite::RunLatencyBenchmark() {
    BenchmarkResult result;
    result.name = "latency";
    result.memory_start_mb = GetMemoryUsageMB();
    
    printf("\n[Benchmark] Running latency benchmark...\n");
    
    // Warmup
    printf("  Warmup (%u iterations)...\n", config_.warmup_iterations);
    for (uint32_t i = 0; i < config_.warmup_iterations; i++) {
        SimulateDecodeOperation(config_.input_tokens, config_.output_tokens);
    }
    
    // Benchmark
    printf("  Benchmarking (%u iterations)...\n", config_.benchmark_iterations);
    std::vector<double> latencies;
    latencies.reserve(config_.benchmark_iterations);
    
    for (uint32_t i = 0; i < config_.benchmark_iterations; i++) {
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        bool success = SimulateDecodeOperation(config_.input_tokens, config_.output_tokens);
        
        QueryPerformanceCounter(&end);
        
        double elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        latencies.push_back(elapsed_ms);
        
        result.total_requests++;
        if (success) {
            result.successful_requests++;
        } else {
            result.failed_requests++;
        }
        
        result.total_tokens_in += config_.input_tokens;
        result.total_tokens_out += config_.output_tokens;
    }
    
    // Calculate statistics
    std::sort(latencies.begin(), latencies.end());
    
    result.latency.min_ms = latencies.front();
    result.latency.max_ms = latencies.back();
    result.latency.avg_ms = std::accumulate(latencies.begin(), latencies.end(), 0.0) / latencies.size();
    result.latency.p50_ms = CalculatePercentile(latencies, 0.50);
    result.latency.p95_ms = CalculatePercentile(latencies, 0.95);
    result.latency.p99_ms = CalculatePercentile(latencies, 0.99);
    result.latency.stddev_ms = CalculateStdDev(latencies, result.latency.avg_ms);
    
    // Calculate throughput
    double total_time_ms = std::accumulate(latencies.begin(), latencies.end(), 0.0);
    result.throughput.total_time_ms = total_time_ms;
    result.throughput.total_tokens = result.total_tokens_in + result.total_tokens_out;
    result.throughput.tokens_per_second = (result.throughput.total_tokens / total_time_ms) * 1000.0;
    result.throughput.requests_per_second = (result.total_requests / total_time_ms) * 1000.0;
    
    result.memory_end_mb = GetMemoryUsageMB();
    result.success = (result.failed_requests == 0);
    
    // Store result
    WaitForSingleObject(results_mutex_, INFINITE);
    results_.push_back(result);
    ReleaseMutex(results_mutex_);
    
    printf("  Latency: avg=%.2fms, p95=%.2fms, p99=%.2fms\n",
           result.latency.avg_ms, result.latency.p95_ms, result.latency.p99_ms);
    printf("  Throughput: %.2f tokens/sec, %.2f req/sec\n",
           result.throughput.tokens_per_second, result.throughput.requests_per_second);
    
    return result;
}

// ============================================================================
// Throughput Benchmark
// ============================================================================
BenchmarkResult BenchmarkSuite::RunThroughputBenchmark() {
    BenchmarkResult result;
    result.name = "throughput";
    result.memory_start_mb = GetMemoryUsageMB();
    
    printf("\n[Benchmark] Running throughput benchmark...\n");
    
    // Run for fixed time and measure total throughput
    const uint32_t duration_ms = 10000;  // 10 seconds
    
    printf("  Running for %u ms...\n", duration_ms);
    
    uint64_t start_time = GetTickCount64();
    uint64_t end_time = start_time + duration_ms;
    
    while (GetTickCount64() < end_time) {
        bool success = SimulateDecodeOperation(config_.input_tokens, config_.output_tokens);
        
        result.total_requests++;
        if (success) {
            result.successful_requests++;
        } else {
            result.failed_requests++;
        }
        
        result.total_tokens_in += config_.input_tokens;
        result.total_tokens_out += config_.output_tokens;
    }
    
    double actual_duration_ms = (double)(GetTickCount64() - start_time);
    
    result.throughput.total_time_ms = actual_duration_ms;
    result.throughput.total_tokens = result.total_tokens_in + result.total_tokens_out;
    result.throughput.tokens_per_second = (result.throughput.total_tokens / actual_duration_ms) * 1000.0;
    result.throughput.requests_per_second = (result.total_requests / actual_duration_ms) * 1000.0;
    
    result.memory_end_mb = GetMemoryUsageMB();
    result.success = (result.failed_requests == 0);
    
    WaitForSingleObject(results_mutex_, INFINITE);
    results_.push_back(result);
    ReleaseMutex(results_mutex_);
    
    printf("  Completed %llu requests in %.0f ms\n", result.total_requests, actual_duration_ms);
    printf("  Throughput: %.2f tokens/sec, %.2f req/sec\n",
           result.throughput.tokens_per_second, result.throughput.requests_per_second);
    
    return result;
}

// ============================================================================
// Concurrency Benchmark
// ============================================================================
BenchmarkResult BenchmarkSuite::RunConcurrencyBenchmark(uint32_t concurrency) {
    BenchmarkResult result;
    result.name = "concurrency_" + std::to_string(concurrency);
    result.memory_start_mb = GetMemoryUsageMB();
    
    printf("\n[Benchmark] Running concurrency benchmark (%u threads)...\n", concurrency);
    
    // Simplified: simulate concurrent operations
    uint32_t iterations_per_thread = config_.benchmark_iterations / concurrency;
    
    for (uint32_t i = 0; i < config_.benchmark_iterations; i++) {
        bool success = SimulateDecodeOperation(config_.input_tokens, config_.output_tokens);
        
        result.total_requests++;
        if (success) {
            result.successful_requests++;
        } else {
            result.failed_requests++;
        }
        
        result.total_tokens_in += config_.input_tokens;
        result.total_tokens_out += config_.output_tokens;
    }
    
    result.memory_end_mb = GetMemoryUsageMB();
    result.success = (result.failed_requests == 0);
    
    WaitForSingleObject(results_mutex_, INFINITE);
    results_.push_back(result);
    ReleaseMutex(results_mutex_);
    
    printf("  Completed with %u concurrent operations\n", concurrency);
    
    return result;
}

// ============================================================================
// Batch Size Benchmark
// ============================================================================
BenchmarkResult BenchmarkSuite::RunBatchSizeBenchmark(uint32_t batch_size) {
    BenchmarkResult result;
    result.name = "batch_" + std::to_string(batch_size);
    result.memory_start_mb = GetMemoryUsageMB();
    
    printf("\n[Benchmark] Running batch size benchmark (size=%u)...\n", batch_size);
    
    std::vector<uint32_t> batch_sizes;
    for (uint32_t i = 0; i < config_.benchmark_iterations; i++) {
        batch_sizes.push_back(batch_size);
    }
    
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    bool success = SimulateBatchOperation(batch_sizes);
    
    QueryPerformanceCounter(&end);
    
    double elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
    
    result.total_requests = config_.benchmark_iterations;
    result.successful_requests = success ? config_.benchmark_iterations : 0;
    result.failed_requests = success ? 0 : config_.benchmark_iterations;
    result.total_tokens_in = config_.benchmark_iterations * batch_size * config_.input_tokens;
    result.total_tokens_out = config_.benchmark_iterations * batch_size * config_.output_tokens;
    
    result.throughput.total_time_ms = elapsed_ms;
    result.throughput.total_tokens = result.total_tokens_in + result.total_tokens_out;
    result.throughput.tokens_per_second = (result.throughput.total_tokens / elapsed_ms) * 1000.0;
    
    result.memory_end_mb = GetMemoryUsageMB();
    result.success = success;
    
    WaitForSingleObject(results_mutex_, INFINITE);
    results_.push_back(result);
    ReleaseMutex(results_mutex_);
    
    printf("  Batch size %u: %.2f tokens/sec\n", batch_size, result.throughput.tokens_per_second);
    
    return result;
}

// ============================================================================
// End-to-End Benchmark
// ============================================================================
BenchmarkResult BenchmarkSuite::RunEndToEndBenchmark() {
    BenchmarkResult result;
    result.name = "end_to_end";
    result.memory_start_mb = GetMemoryUsageMB();
    
    printf("\n[Benchmark] Running end-to-end benchmark...\n");
    
    // Simulate full pipeline: split -> decode -> sample
    for (uint32_t i = 0; i < config_.benchmark_iterations; i++) {
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Step 1: Split batch
        std::vector<uint32_t> tokens;
        for (uint32_t j = 0; j < config_.input_tokens; j++) {
            tokens.push_back(j % 1000);  // Sample token IDs
        }
        
        // Step 2: Decode
        bool success = SimulateDecodeOperation(config_.input_tokens, config_.output_tokens);
        
        QueryPerformanceCounter(&end);
        
        double elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        
        result.total_requests++;
        if (success) {
            result.successful_requests++;
        } else {
            result.failed_requests++;
        }
        
        result.total_tokens_in += config_.input_tokens;
        result.total_tokens_out += config_.output_tokens;
    }
    
    result.memory_end_mb = GetMemoryUsageMB();
    result.success = (result.failed_requests == 0);
    
    WaitForSingleObject(results_mutex_, INFINITE);
    results_.push_back(result);
    ReleaseMutex(results_mutex_);
    
    printf("  End-to-end: %llu iterations completed\n", result.total_requests);
    
    return result;
}

// ============================================================================
// Run All Benchmarks
// ============================================================================
std::vector<BenchmarkResult> BenchmarkSuite::RunAllBenchmarks() {
    printf("\n========================================");
    printf("\n  Phase 11: Performance Benchmark Suite");
    printf("\n========================================\n");
    
    RunLatencyBenchmark();
    RunThroughputBenchmark();
    RunConcurrencyBenchmark(2);
    RunConcurrencyBenchmark(4);
    RunBatchSizeBenchmark(1);
    RunBatchSizeBenchmark(4);
    RunEndToEndBenchmark();
    
    WaitForSingleObject(results_mutex_, INFINITE);
    std::vector<BenchmarkResult> all_results = results_;
    ReleaseMutex(results_mutex_);
    
    return all_results;
}

// ============================================================================
// Custom Benchmark
// ============================================================================
BenchmarkResult BenchmarkSuite::RunCustomBenchmark(
    const std::string& name,
    std::function<bool()> setup,
    std::function<bool()> iterate,
    std::function<void()> teardown
) {
    BenchmarkResult result;
    result.name = name;
    result.memory_start_mb = GetMemoryUsageMB();
    
    printf("\n[Benchmark] Running custom benchmark: %s...\n", name.c_str());
    
    if (!setup()) {
        result.success = false;
        result.error_message = "Setup failed";
        return result;
    }
    
    for (uint32_t i = 0; i < config_.benchmark_iterations; i++) {
        if (!iterate()) {
            result.failed_requests++;
        } else {
            result.successful_requests++;
        }
        result.total_requests++;
    }
    
    teardown();
    
    result.memory_end_mb = GetMemoryUsageMB();
    result.success = (result.failed_requests == 0);
    
    WaitForSingleObject(results_mutex_, INFINITE);
    results_.push_back(result);
    ReleaseMutex(results_mutex_);
    
    return result;
}

// ============================================================================
// Results Export
// ============================================================================
std::string BenchmarkSuite::ExportResultsJSON() const {
    WaitForSingleObject(results_mutex_, INFINITE);
    
    char json[16384];
    int pos = 0;
    
    pos += snprintf(json + pos, sizeof(json) - pos, "{\"benchmarks\":[");
    
    for (size_t i = 0; i < results_.size(); i++) {
        const auto& r = results_[i];
        if (i > 0) pos += snprintf(json + pos, sizeof(json) - pos, ",");
        
        pos += snprintf(json + pos, sizeof(json) - pos, "{");
        pos += snprintf(json + pos, sizeof(json) - pos, "\"name\":\"%s\",", r.name.c_str());
        pos += snprintf(json + pos, sizeof(json) - pos, "\"success\":%s,", r.success ? "true" : "false");
        pos += snprintf(json + pos, sizeof(json) - pos, "\"total_requests\":%llu,", r.total_requests);
        pos += snprintf(json + pos, sizeof(json) - pos, "\"successful\":%llu,", r.successful_requests);
        pos += snprintf(json + pos, sizeof(json) - pos, "\"failed\":%llu,", r.failed_requests);
        pos += snprintf(json + pos, sizeof(json) - pos, "\"tokens_per_sec\":%.2f,", r.throughput.tokens_per_second);
        pos += snprintf(json + pos, sizeof(json) - pos, "\"requests_per_sec\":%.2f,", r.throughput.requests_per_second);
        pos += snprintf(json + pos, sizeof(json) - pos, "\"latency_avg_ms\":%.2f", r.latency.avg_ms);
        pos += snprintf(json + pos, sizeof(json) - pos, "}");
    }
    
    pos += snprintf(json + pos, sizeof(json) - pos, "]}");
    
    ReleaseMutex(results_mutex_);
    return std::string(json);
}

std::string BenchmarkSuite::ExportResultsCSV() const {
    WaitForSingleObject(results_mutex_, INFINITE);
    
    std::string csv = "name,success,total_requests,successful,failed,tokens_per_sec,requests_per_sec,latency_avg_ms\n";
    
    for (const auto& r : results_) {
        char line[512];
        snprintf(line, sizeof(line), "%s,%s,%llu,%llu,%llu,%.2f,%.2f,%.2f\n",
            r.name.c_str(),
            r.success ? "true" : "false",
            r.total_requests,
            r.successful_requests,
            r.failed_requests,
            r.throughput.tokens_per_second,
            r.throughput.requests_per_second,
            r.latency.avg_ms);
        csv += line;
    }
    
    ReleaseMutex(results_mutex_);
    return csv;
}

std::string BenchmarkSuite::ExportResultsTable() const {
    WaitForSingleObject(results_mutex_, INFINITE);
    
    std::string table;
    table += "+---------------+--------+----------+----------+--------+-----------+-----------+-------------+\n";
    table += "| Name          | Status | Total    | Success  | Failed | TPS       | RPS       | Latency(ms) |\n";
    table += "+---------------+--------+----------+----------+--------+-----------+-----------+-------------+\n";
    
    for (const auto& r : results_) {
        char line[256];
        snprintf(line, sizeof(line), "| %-13s | %-6s | %8llu | %8llu | %6llu | %9.2f | %9.2f | %11.2f |\n",
            r.name.c_str(),
            r.success ? "PASS" : "FAIL",
            r.total_requests,
            r.successful_requests,
            r.failed_requests,
            r.throughput.tokens_per_second,
            r.throughput.requests_per_second,
            r.latency.avg_ms);
        table += line;
    }
    
    table += "+---------------+--------+----------+----------+--------+-----------+-----------+-------------+\n";
    
    ReleaseMutex(results_mutex_);
    return table;
}

bool BenchmarkSuite::SaveResults(const std::string& filename) const {
    std::string content;
    
    if (config_.output_format == "json") {
        content = ExportResultsJSON();
    } else if (config_.output_format == "csv") {
        content = ExportResultsCSV();
    } else {
        content = ExportResultsTable();
    }
    
    FILE* f = fopen(filename.c_str(), "w");
    if (!f) return false;
    
    fwrite(content.c_str(), 1, content.length(), f);
    fclose(f);
    
    return true;
}

// ============================================================================
// Comparison
// ============================================================================
std::string BenchmarkSuite::CompareResults(const BenchmarkResult& baseline, 
                                            const BenchmarkResult& current) {
    char report[1024];
    
    double tps_change = ((current.throughput.tokens_per_second - baseline.throughput.tokens_per_second) 
                         / baseline.throughput.tokens_per_second) * 100.0;
    double latency_change = ((current.latency.avg_ms - baseline.latency.avg_ms) 
                            / baseline.latency.avg_ms) * 100.0;
    
    snprintf(report, sizeof(report),
        "Comparison: %s\n"
        "  TPS: %.2f -> %.2f (%.1f%%)\n"
        "  Latency: %.2fms -> %.2fms (%.1f%%)\n"
        "  Status: %s\n",
        current.name.c_str(),
        baseline.throughput.tokens_per_second, current.throughput.tokens_per_second, tps_change,
        baseline.latency.avg_ms, current.latency.avg_ms, latency_change,
        (tps_change >= 0 && latency_change <= 0) ? "IMPROVED" : "REGRESSED");
    
    return std::string(report);
}

// ============================================================================
// Internal Helpers
// ============================================================================
std::vector<double> BenchmarkSuite::CollectLatencies(std::function<void()> operation, uint32_t count) {
    std::vector<double> latencies;
    latencies.reserve(count);
    
    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    
    for (uint32_t i = 0; i < count; i++) {
        LARGE_INTEGER start, end;
        QueryPerformanceCounter(&start);
        
        operation();
        
        QueryPerformanceCounter(&end);
        
        double elapsed_ms = (double)(end.QuadPart - start.QuadPart) * 1000.0 / freq.QuadPart;
        latencies.push_back(elapsed_ms);
    }
    
    return latencies;
}

double BenchmarkSuite::CalculatePercentile(const std::vector<double>& sorted, double percentile) {
    if (sorted.empty()) return 0.0;
    
    size_t index = (size_t)(sorted.size() * percentile);
    if (index >= sorted.size()) index = sorted.size() - 1;
    
    return sorted[index];
}

double BenchmarkSuite::CalculateStdDev(const std::vector<double>& values, double mean) {
    if (values.size() < 2) return 0.0;
    
    double sum_sq_diff = 0.0;
    for (double v : values) {
        double diff = v - mean;
        sum_sq_diff += diff * diff;
    }
    
    return sqrt(sum_sq_diff / (values.size() - 1));
}

uint64_t BenchmarkSuite::GetMemoryUsageMB() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024);
    }
    return 0;
}

bool BenchmarkSuite::SimulateDecodeOperation(uint32_t tokens_in, uint32_t tokens_out) {
    // Simulate decode latency based on token count
    // In real implementation, this would call actual decode
    uint32_t latency_ms = 1 + (tokens_in + tokens_out) / 100;  // ~100 tokens/ms
    Sleep(latency_ms);
    return true;
}

bool BenchmarkSuite::SimulateBatchOperation(const std::vector<uint32_t>& batch_sizes) {
    for (uint32_t size : batch_sizes) {
        if (!SimulateDecodeOperation(size * config_.input_tokens, 
                                      size * config_.output_tokens)) {
            return false;
        }
    }
    return true;
}

// ============================================================================
// Quick Benchmark
// ============================================================================
double QuickBenchmarkTPS(uint32_t input_tokens, uint32_t output_tokens) {
    printf("\n[QuickBenchmark] Running 10-second TPS test...\n");
    
    uint64_t start_time = GetTickCount64();
    uint64_t end_time = start_time + 10000;  // 10 seconds
    
    uint64_t total_tokens = 0;
    uint64_t iterations = 0;
    
    while (GetTickCount64() < end_time) {
        // Simulate decode
        uint32_t latency_ms = 1 + (input_tokens + output_tokens) / 100;
        Sleep(latency_ms);
        
        total_tokens += input_tokens + output_tokens;
        iterations++;
    }
    
    double actual_duration_sec = (GetTickCount64() - start_time) / 1000.0;
    double tps = total_tokens / actual_duration_sec;
    
    printf("  Completed %llu iterations in %.1f seconds\n", iterations, actual_duration_sec);
    printf("  TPS: %.2f tokens/second\n", tps);
    
    return tps;
}

// ============================================================================
// Stress Test
// ============================================================================
StressTestResult RunStressTest(const StressTestConfig& config) {
    StressTestResult result;
    
    printf("\n[StressTest] Running %u second stress test...\n", config.duration_seconds);
    printf("  Max concurrent: %u, Ramp up: %u seconds\n", config.max_concurrent, config.ramp_up_seconds);
    
    uint64_t start_time = GetTickCount64();
    uint64_t end_time = start_time + (config.duration_seconds * 1000);
    uint64_t last_report_time = start_time;
    
    uint32_t current_concurrent = 1;
    uint64_t ramp_interval = (config.ramp_up_seconds * 1000) / config.max_concurrent;
    uint64_t last_ramp = start_time;
    
    while (GetTickCount64() < end_time) {
        // Ramp up concurrency
        if (current_concurrent < config.max_concurrent && 
            GetTickCount64() - last_ramp > ramp_interval) {
            current_concurrent++;
            last_ramp = GetTickCount64();
            printf("  Ramped up to %u concurrent\n", current_concurrent);
        }
        
        // Simulate requests
        for (uint32_t i = 0; i < current_concurrent; i++) {
            uint32_t tokens = config.randomize_tokens ? (rand() % 256 + 64) : 128;
            uint32_t latency_ms = 1 + tokens / 100;
            Sleep(latency_ms);
            
            result.total_requests++;
            // Simulate occasional failures (1%)
            if (rand() % 100 == 0) {
                result.failed_requests++;
            }
        }
        
        // Report TPS every second
        if (GetTickCount64() - last_report_time > 1000) {
            double elapsed_sec = (GetTickCount64() - start_time) / 1000.0;
            double current_tps = (result.total_requests * 128) / elapsed_sec;  // Approximate
            result.tps_over_time.push_back(current_tps);
            
            if (current_tps > result.peak_tps) {
                result.peak_tps = current_tps;
            }
            
            last_report_time = GetTickCount64();
        }
    }
    
    double total_duration_sec = (GetTickCount64() - start_time) / 1000.0;
    result.avg_tps = (result.total_requests * 128) / total_duration_sec;
    result.avg_latency_ms = total_duration_sec * 1000.0 / result.total_requests;
    result.error_rate = (double)result.failed_requests / result.total_requests * 100.0;
    result.success = (result.error_rate < 5.0);  // Less than 5% errors
    
    printf("\n  Stress test completed:\n");
    printf("    Total requests: %llu\n", result.total_requests);
    printf("    Failed: %llu (%.2f%%)\n", result.failed_requests, result.error_rate);
    printf("    Avg TPS: %.2f\n", result.avg_tps);
    printf("    Peak TPS: %.2f\n", result.peak_tps);
    printf("    Avg latency: %.2f ms\n", result.avg_latency_ms);
    printf("    Status: %s\n", result.success ? "PASS" : "FAIL");
    
    return result;
}

// ============================================================================
// Regression Check
// ============================================================================
RegressionResult CheckRegression(const BenchmarkResult& baseline,
                                   const BenchmarkResult& current,
                                   double tps_threshold,
                                   double latency_threshold) {
    RegressionResult result;
    
    double tps_change = ((current.throughput.tokens_per_second - baseline.throughput.tokens_per_second) 
                         / baseline.throughput.tokens_per_second) * 100.0;
    double latency_change = ((current.latency.avg_ms - baseline.latency.avg_ms) 
                            / baseline.latency.avg_ms) * 100.0;
    
    result.tps_change_percent = tps_change;
    result.latency_change_percent = latency_change;
    
    bool tps_regression = tps_change < tps_threshold;
    bool latency_regression = latency_change > latency_threshold;
    
    result.has_regression = tps_regression || latency_regression;
    
    char summary[512];
    if (result.has_regression) {
        snprintf(summary, sizeof(summary), 
            "REGRESSION DETECTED: TPS %.1f%% (threshold %.1f%%), Latency %.1f%% (threshold %.1f%%)",
            tps_change, tps_threshold, latency_change, latency_threshold);
    } else {
        snprintf(summary, sizeof(summary), 
            "No regression: TPS %.1f%%, Latency %.1f%%",
            tps_change, latency_change);
    }
    result.summary = summary;
    
    return result;
}

} // namespace Sovereign
