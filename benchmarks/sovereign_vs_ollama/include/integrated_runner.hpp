// Integrated Benchmark Runner with Real Backend Support
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "backend_factory.hpp"
#include "result_validator.hpp"
#include "baseline_manager.hpp"
#include <vector>
#include <memory>
#include <functional>

namespace rawrxd::benchmark {

// ============================================================================
// Benchmark Runner Configuration
// ============================================================================

struct RunnerConfig {
    // Backend configuration
    BackendType backend = BackendType::SOVEREIGN;
    std::string endpoint;
    std::string model_name;
    
    // Run configuration
    int warmup_runs = 10;
    int measured_runs = 50;
    bool enable_validation = true;
    bool enable_baseline = true;
    bool fail_on_validation_error = false;
    
    // Reporting
    bool verbose = false;
    bool generate_report = true;
    std::string output_format = "json";  // json, markdown, html
    std::string output_path;
    
    // Comparison
    bool compare_to_baseline = true;
    std::string baseline_path;
    
    // Parallel execution
    int max_parallel = 1;
    bool enable_parallel = false;
};

// ============================================================================
// Benchmark Progress
// ============================================================================

struct BenchmarkProgress {
    std::string benchmark_name;
    int current_run = 0;
    int total_runs = 0;
    double current_latency_ms = 0.0;
    double average_latency_ms = 0.0;
    double estimated_remaining_seconds = 0.0;
    std::string status;  // "warming_up", "measuring", "validating", "complete"
    
    double GetPercentComplete() const {
        return total_runs > 0 ? (100.0 * current_run) / total_runs : 0.0;
    }
};

// ============================================================================
// Progress Callback
// ============================================================================

using ProgressCallback = std::function<void(const BenchmarkProgress&)>;
using ResultCallback = std::function<void(const BenchmarkResult&)>;
using ValidationCallback = std::function<void(const std::vector<ValidationResult>&)>;

// ============================================================================
// Integrated Benchmark Runner
// ============================================================================

class IntegratedBenchmarkRunner {
public:
    IntegratedBenchmarkRunner();
    ~IntegratedBenchmarkRunner();
    
    // Initialize runner
    bool Initialize(const RunnerConfig& config);
    
    // Shutdown runner
    void Shutdown();
    
    // Run single benchmark
    BenchmarkResult RunBenchmark(const Benchmark& benchmark);
    
    // Run multiple benchmarks
    std::vector<BenchmarkResult> RunBenchmarks(const std::vector<std::unique_ptr<Benchmark>>& benchmarks);
    
    // Run benchmark by name
    std::optional<BenchmarkResult> RunBenchmarkByName(const std::string& name);
    
    // Set callbacks
    void SetProgressCallback(ProgressCallback callback) { progress_callback_ = callback; }
    void SetResultCallback(ResultCallback callback) { result_callback_ = callback; }
    void SetValidationCallback(ValidationCallback callback) { validation_callback_ = callback; }
    
    // Get backend adapter
    BackendAdapter* GetBackend() const { return backend_.get(); }
    
    // Check if backend is ready
    bool IsBackendReady() const;
    
    // Wait for backend to be ready
    bool WaitForBackend(int timeout_seconds = 30);
    
    // Get runner status
    struct Status {
        bool initialized = false;
        bool backend_connected = false;
        int completed_benchmarks = 0;
        int failed_benchmarks = 0;
        int total_benchmarks = 0;
        std::string current_benchmark;
        std::string error_message;
    };
    Status GetStatus() const;
    
    // Get results
    std::vector<BenchmarkResult> GetResults() const { return results_; }
    
    // Clear results
    void ClearResults() { results_.clear(); }
    
    // Generate final report
    bool GenerateReport(const std::string& path) const;
    
    // Compare results to baseline
    std::vector<BaselineManager::ComparisonResult> CompareToBaseline() const;

private:
    RunnerConfig config_;
    std::unique_ptr<BackendAdapter> backend_;
    std::unique_ptr<BaselineManager> baseline_manager_;
    std::unique_ptr<SanityChecker> sanity_checker_;
    
    // State
    bool initialized_ = false;
    std::vector<BenchmarkResult> results_;
    Status status_;
    
    // Callbacks
    ProgressCallback progress_callback_;
    ResultCallback result_callback_;
    ValidationCallback validation_callback_;
    
    // Internal methods
    bool InitializeBackend();
    bool ValidateResult(const BenchmarkResult& result);
    void UpdateProgress(const BenchmarkProgress& progress);
    void ReportResult(const BenchmarkResult& result);
    void ReportValidation(const std::vector<ValidationResult>& validations);
    BenchmarkResult ExecuteWithRetry(const Benchmark& benchmark, int max_retries = 3);
    
    // Warmup
    void RunWarmup(const Benchmark& benchmark);
    
    // Measurement
    BenchmarkResult RunMeasurement(const Benchmark& benchmark);
};

// ============================================================================
// Benchmark Suite Runner
// ============================================================================

class BenchmarkSuiteRunner {
public:
    // Predefined benchmark suites
    enum class SuiteType {
        QUICK_SMOKE,      // 5 benchmarks, 10 runs each
        STANDARD,         // 10 benchmarks, 30 runs each
        COMPREHENSIVE,    // All benchmarks, 50 runs each
        CI_REGRESSION,    // Focus on regression detection
        STRESS_TEST       // Chaos and stress benchmarks
    };
    
    // Run a predefined suite
    static std::vector<BenchmarkResult> RunSuite(SuiteType suite, 
                                                   const RunnerConfig& config);
    
    // Run custom suite
    static std::vector<BenchmarkResult> RunCustomSuite(
        const std::vector<std::string>& benchmark_names,
        const RunnerConfig& config);
    
    // Get suite description
    static std::string GetSuiteDescription(SuiteType suite);
    
    // Get suite benchmark list
    static std::vector<std::string> GetSuiteBenchmarks(SuiteType suite);
    
    // Estimate suite duration
    static double EstimateDuration(SuiteType suite, const RunnerConfig& config);
};

// ============================================================================
// Benchmark Registration
// ============================================================================

class BenchmarkRegistry {
public:
    // Register benchmark
    static void Register(const std::string& name,
                          std::function<std::unique_ptr<Benchmark>()> factory);
    
    // Create benchmark by name
    static std::unique_ptr<Benchmark> Create(const std::string& name);
    
    // Get all registered benchmarks
    static std::vector<std::string> GetRegisteredNames();
    
    // Check if benchmark exists
    static bool Exists(const std::string& name);
    
    // Get benchmark info
    struct BenchmarkInfo {
        std::string name;
        std::string description;
        BenchmarkCategory category;
        double estimated_duration_seconds;
    };
    static std::optional<BenchmarkInfo> GetInfo(const std::string& name);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick run a single benchmark
BenchmarkResult QuickRun(const std::string& benchmark_name,
                          BackendType backend = BackendType::SOVEREIGN,
                          const std::string& endpoint = "");

// Run comparison between two backends
struct ComparisonRun {
    BenchmarkResult sovereign_result;
    BenchmarkResult ollama_result;
    StatisticalComparison statistical_comparison;
    std::vector<ValidationResult> validations;
    bool is_valid = false;
};
ComparisonRun RunComparison(const std::string& benchmark_name,
                            const std::string& sovereign_endpoint = "http://localhost:8080",
                            const std::string& ollama_endpoint = "http://localhost:11434");

// Run full Phase E comparison
struct PhaseEResults {
    std::vector<ComparisonRun> comparisons;
    std::string report_path;
    bool all_valid = false;
};
PhaseEResults RunPhaseE(const RunnerConfig& config);

// ============================================================================
// Main Entry Point
// ============================================================================

int RunBenchmarksMain(int argc, char** argv);

} // namespace rawrxd::benchmark
