/**
 * @file standardized_benchmark.hpp
 * @brief Standardized Benchmark Harness for RawrXD
 *
 * Provides reproducible, consistent performance measurements with
 * per-component profiling (embedding, attention, MLP, sampling).
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <map>
#include <cstdint>
#include <functional>

namespace rawrxd {
namespace benchmark {

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchmarkConfig {
    // Model and input
    std::string model_path;
    std::string prompt = "The quick brown fox jumps over the lazy dog";
    uint32_t max_tokens = 100;
    
    // Benchmark methodology
    uint32_t warmup_iterations = 3;
    uint32_t benchmark_iterations = 10;
    bool enable_profiling = true;
    bool verbose = true;
    
    // Sampling parameters (must be consistent)
    float temperature = 1.0f;
    uint32_t top_k = 40;
    float top_p = 1.0f;
    uint32_t seed = 42;  // For reproducibility
    
    // Output
    std::string output_format = "json";  // json, csv, console
    std::string output_file = "benchmark_results.json";
};

// ============================================================================
// Timing and Profiling
// ============================================================================

struct ComponentTiming {
    std::string name;
    double total_ms = 0.0;
    double min_ms = 0.0;
    double max_ms = 0.0;
    double mean_ms = 0.0;
    double stddev_ms = 0.0;
    uint32_t call_count = 0;
    double percentage = 0.0;  // Of total time
};

class Profiler {
public:
    void BeginRegion(const std::string& name);
    void EndRegion(const std::string& name);
    
    void Reset();
    std::map<std::string, ComponentTiming> GetResults() const;
    
private:
    struct RegionData {
        std::chrono::high_resolution_clock::time_point start;
        std::vector<double> durations_ms;
    };
    
    std::map<std::string, RegionData> active_regions_;
    std::map<std::string, std::vector<double>> completed_regions_;
};

// ============================================================================
// Benchmark Results
// ============================================================================

struct BenchmarkResults {
    // Configuration
    BenchmarkConfig config;
    
    // System info
    struct SystemInfo {
        std::string cpu_name;
        uint32_t cpu_cores = 0;
        uint32_t cpu_threads = 0;
        bool has_avx2 = false;
        bool has_avx512 = false;
        uint64_t total_memory_bytes = 0;
        uint64_t available_memory_bytes = 0;
    } system_info;
    
    // Model info
    struct ModelInfo {
        std::string path;
        uint64_t file_size_bytes = 0;
        uint32_t vocab_size = 0;
        uint32_t hidden_size = 0;
        uint32_t num_layers = 0;
        uint32_t num_heads = 0;
        std::string quantization_type;
    } model_info;
    
    // Overall metrics
    struct OverallMetrics {
        double tokens_per_second = 0.0;
        double time_to_first_token_ms = 0.0;
        double avg_latency_per_token_ms = 0.0;
        double total_time_ms = 0.0;
        uint32_t tokens_generated = 0;
        uint32_t prompt_tokens = 0;
        
        // Statistical analysis
        double tps_min = 0.0;
        double tps_max = 0.0;
        double tps_stddev = 0.0;
    } overall;
    
    // Per-component timings
    std::map<std::string, ComponentTiming> component_timings;
    
    // Memory usage
    struct MemoryMetrics {
        uint64_t peak_working_set_bytes = 0;
        uint64_t peak_private_bytes = 0;
        uint64_t model_load_bytes = 0;
    } memory;
    
    // Iteration details
    struct IterationResult {
        uint32_t iteration;
        double total_time_ms;
        double tokens_per_second;
        uint32_t tokens_generated;
    };
    std::vector<IterationResult> iterations;
    
    // Timestamp
    std::string timestamp;
    
    // Validation
    bool passed = false;
    std::string failure_reason;
};

// ============================================================================
// Benchmark Harness
// ============================================================================

class StandardizedBenchmark {
public:
    explicit StandardizedBenchmark(const BenchmarkConfig& config);
    ~StandardizedBenchmark();
    
    // Run full benchmark suite
    BenchmarkResults Run();
    
    // Export results
    bool ExportJSON(const std::string& path) const;
    bool ExportCSV(const std::string& path) const;
    std::string GenerateReport() const;

private:
    BenchmarkConfig config_;
    BenchmarkResults results_;
    Profiler profiler_;
    
    // System detection
    void DetectSystemInfo();
    
    // Model loading
    bool LoadModel();
    
    // Single benchmark iteration
    BenchmarkResults::IterationResult RunIteration(uint32_t iter);
    
    // Statistical analysis
    void CalculateStatistics();
    
    // Validation
    bool ValidateResults();
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick benchmark with defaults
BenchmarkResults QuickBenchmark(const std::string& model_path);

// Compare two benchmark runs
struct ComparisonResult {
    double tps_delta_percent;
    double latency_delta_percent;
    std::string winner;
    std::string analysis;
};

ComparisonResult CompareBenchmarks(const BenchmarkResults& baseline,
                                   const BenchmarkResults& current);

// Hardware capability check
bool CheckHardwareCompatibility(const std::string& model_path);

// Estimate benchmark duration
std::string EstimateDuration(const BenchmarkConfig& config);

} // namespace benchmark
} // namespace rawrxd
