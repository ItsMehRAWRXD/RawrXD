// Integrated Benchmark Runner Implementation
// Copyright (c) 2026 RawrXD Team

#include "integrated_runner.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <math>

namespace rawrxd::benchmark {

// ============================================================================
// Integrated Benchmark Runner Implementation
// ============================================================================

IntegratedBenchmarkRunner::IntegratedBenchmarkRunner() = default;
IntegratedBenchmarkRunner::~IntegratedBenchmarkRunner() {
    Shutdown();
}

bool IntegratedBenchmarkRunner::Initialize(const RunnerConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Initialize backend
    if (!InitializeBackend()) {
        status_.error_message = "Failed to initialize backend";
        return false;
    }
    
    // Initialize baseline manager
    if (config.enable_baseline) {
        baseline_manager_ = std::make_unique<BaselineManager>();
        BaselineConfig baseline_config;
        baseline_manager_>Initialize(config.baseline_path, baseline_config);
    }
    
    // Initialize sanity checker
    sanity_checker_ = std::make_unique<SanityChecker>();
    
    initialized_ = true;
    status_.initialized = true;
    
    return true;
}

void IntegratedBenchmarkRunner::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    if (backend_) {
        backend_>Shutdown();
        backend_.reset();
    }
    
    baseline_manager_.reset();
    sanity_checker_.reset();
    
    initialized_ = false;
    status_.initialized = false;
    status_.backend_connected = false;
}

bool IntegratedBenchmarkRunner::InitializeBackend() {
    // Create backend adapter
    backend_ = BackendFactory::Create(config_.backend);
    if (!backend_) {
        std::cerr << "Failed to create backend adapter" << std::endl;
        return false;
    }
    
    // Prepare benchmark config
    BenchmarkConfig bench_config;
    bench_config.backend = config_.backend;
    bench_config.model_name = config_.model_name;
    
    if (config_.backend == BackendType::SOVEREIGN) {
        bench_config.sovereign_endpoint = config_.endpoint.empty() ? 
            "http://localhost:8080" : config_.endpoint;
    } else if (config_.backend == BackendType::OLLAMA) {
        bench_config.ollama_url = config_.endpoint.empty() ? 
            "http://localhost:11434" : config_.endpoint;
    }
    
    bench_config.warmup_runs = config_.warmup_runs;
    bench_config.measured_runs = config_.measured_runs;
    bench_config.verbose = config_.verbose;
    
    // Initialize backend
    if (!backend_>Initialize(bench_config)) {
        std::cerr << "Failed to initialize backend" << std::endl;
        return false;
    }
    
    status_.backend_connected = true;
    
    if (config_.verbose) {
        std::cout << "Backend initialized: " << BackendTypeToString(config_.backend) << std::endl;
    }
    
    return true;
}

BenchmarkResult IntegratedBenchmarkRunner::RunBenchmark(const Benchmark& benchmark) {
    if (!initialized_) {
        BenchmarkResult result;
        result.benchmark_name = benchmark.GetName();
        result.error_message = "Runner not initialized";
        return result;
    }
    
    status_.current_benchmark = benchmark.GetName();
    
    // Run warmup
    RunWarmup(benchmark);
    
    // Run measurement
    BenchmarkResult result = RunMeasurement(benchmark);
    
    // Validate result
    if (config_.enable_validation) {
        if (!ValidateResult(result)) {
            if (config_.fail_on_validation_error) {
                status_.failed_benchmarks++;
                return result;
            }
        }
    }
    
    // Store result
    results_.push_back(result);
    status_.completed_benchmarks++;
    
    // Report result
    ReportResult(result);
    
    return result;
}

void IntegratedBenchmarkRunner::RunWarmup(const Benchmark& benchmark) {
    if (config_.warmup_runs <= 0) {
        return;
    }
    
    if (config_.verbose) {
        std::cout << "Warming up " << benchmark.GetName() << " (" << config_.warmup_runs << " runs)..." << std::endl;
    }
    
    for (int i = 0; i < config_.warmup_runs; ++i) {
        BenchmarkProgress progress;
        progress.benchmark_name = benchmark.GetName();
        progress.current_run = i + 1;
        progress.total_runs = config_.warmup_runs;
        progress.status = "warming_up";
        UpdateProgress(progress);
        
        // Execute warmup run (without storing result)
        try {
            // This would call the actual benchmark
            // For now, just simulate
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        } catch (...) {
            // Ignore warmup errors
        }
    }
}

BenchmarkResult IntegratedBenchmarkRunner::RunMeasurement(const Benchmark& benchmark) {
    BenchmarkResult result;
    result.benchmark_id = std::string(benchmark.GetName()) + "_" + 
                          std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    result.benchmark_name = benchmark.GetName();
    result.category = benchmark.GetCategory();
    result.backend = config_.backend;
    result.model_name = config_.model_name;
    result.timestamp = baseline_utils::GetTimestamp();
    
    std::vector<double> latencies;
    std::vector<double> throughputs;
    int success_count = 0;
    
    auto total_start = Clock::now();
    
    for (int i = 0; i < config_.measured_runs; ++i) {
        BenchmarkProgress progress;
        progress.benchmark_name = benchmark.GetName();
        progress.current_run = i + 1;
        progress.total_runs = config_.measured_runs;
        progress.status = "measuring";
        UpdateProgress(progress);
        
        auto run_start = Clock::now();
        
        try {
            // Execute actual benchmark
            // This would call benchmark.Run() with real backend
            // For now, simulate with a simple generation
            std::string response = backend_>Generate("Test prompt", 64);
            
            if (!response.empty()) {
                success_count++;
                
                auto run_end = Clock::now();
                double latency_ms = std::chrono::duration<double, std::milli>(run_end - run_start).count();
                latencies.push_back(latency_ms);
                
                // Estimate throughput (tokens per second)
                double tokens_per_sec = backend_>GetLastTokensPerSec();
                if (tokens_per_sec > 0) {
                    throughputs.push_back(tokens_per_sec);
                }
            }
        } catch (const std::exception& e) {
            if (config_.verbose) {
                std::cerr << "Run " << i << " failed: " << e.what() << std::endl;
            }
        }
    }
    
    auto total_end = Clock::now();
    result.total_time_ms = std::chrono::duration<double, std::milli>(total_end - total_start).count();
    
    // Calculate statistics
    if (!latencies.empty()) {
        result.latency = StatisticalMetrics::Calculate(latencies);
        result.raw_latencies = latencies;
    }
    
    if (!throughputs.empty()) {
        result.throughput = StatisticalMetrics::Calculate(throughputs);
    }
    
    result.success_rate = config_.measured_runs > 0 ? 
        static_cast<double>(success_count) / config_.measured_runs : 0.0;
    
    // Get resource metrics
    result.resources = backend_>GetResourceUsage();
    
    return result;
}

bool IntegratedBenchmarkRunner::ValidateResult(const BenchmarkResult& result) {
    auto validations = ResultValidator::ValidateResult(result);
    
    ReportValidation(validations);
    
    bool has_errors = ResultValidator::HasErrors(validations);
    
    if (has_errors && sanity_checker_) {
        return sanity_checker_>QuickCheck(result);
    }
    
    return !has_errors;
}

std::vector<BenchmarkResult> IntegratedBenchmarkRunner::RunBenchmarks(
    const std::vector<std::unique_ptr<Benchmark>>& benchmarks) {
    
    std::vector<BenchmarkResult> results;
    status_.total_benchmarks = static_cast<int>(benchmarks.size());
    
    for (const auto& benchmark : benchmarks) {
        if (!benchmark) continue;
        
        BenchmarkResult result = RunBenchmark(*benchmark);
        results.push_back(result);
    }
    
    return results;
}

std::optional<BenchmarkResult> IntegratedBenchmarkRunner::RunBenchmarkByName(
    const std::string& name) {
    
    auto benchmark = BenchmarkRegistry::Create(name);
    if (!benchmark) {
        return std::nullopt;
    }
    
    return RunBenchmark(*benchmark);
}

bool IntegratedBenchmarkRunner::IsBackendReady() const {
    if (!backend_) {
        return false;
    }
    
    // Try a simple health check
    return backend_>HealthCheck();
}

bool IntegratedBenchmarkRunner::WaitForBackend(int timeout_seconds) {
    if (!backend_) {
        return false;
    }
    
    auto start = Clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds);
    
    while (Clock::now() - start < timeout) {
        if (IsBackendReady()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    return false;
}

IntegratedBenchmarkRunner::Status IntegratedBenchmarkRunner::GetStatus() const {
    return status_;
}

bool IntegratedBenchmarkRunner::GenerateReport(const std::string& path) const {
    if (results_.empty()) {
        return false;
    }
    
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    // Generate JSON report
    file << "{\n";
    file << "  \"report_type\": \"benchmark_results\",\n";
    file << "  \"timestamp\": \"" << baseline_utils::GetTimestamp() << "\",\n";
    file << "  \"backend\": \"" << BackendTypeToString(config_.backend) << "\",\n";
    file << "  \"model\": \"" << config_.model_name << "\",\n";
    file << "  \"results\": [\n";
    
    for (size_t i = 0; i < results_.size(); ++i) {
        const auto& result = results_[i];
        file << "    {\n";
        file << "      \"benchmark_name\": \"" << result.benchmark_name << "\",\n";
        file << "      \"category\": \"" << CategoryToString(result.category) << "\",\n";
        file << "      \"latency_mean_ms\": " << result.latency.mean << ",\n";
        file << "      \"latency_p95_ms\": " << result.latency.p95 << ",\n";
        file << "      \"throughput_mean_tps\": " << result.throughput.mean << ",\n";
        file << "      \"success_rate\": " << result.success_rate << "\n";
        file << "    }";
        if (i < results_.size() - 1) {
            file << ",";
        }
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    return true;
}

std::vector<BaselineManager::ComparisonResult> IntegratedBenchmarkRunner::CompareToBaseline() const {
    std::vector<BaselineManager::ComparisonResult> comparisons;
    
    if (!baseline_manager_) {
        return comparisons;
    }
    
    for (const auto& result : results_) {
        auto comp = baseline_manager_>CompareToBaseline(result.benchmark_id, result);
        comparisons.push_back(comp);
    }
    
    return comparisons;
}

void IntegratedBenchmarkRunner::UpdateProgress(const BenchmarkProgress& progress) {
    if (progress_callback_) {
        progress_callback_(progress);
    }
    
    if (config_.verbose) {
        std::cout << "\r" << progress.benchmark_name << ": " << progress.GetPercentComplete() << "%";
        std::cout.flush();
    }
}

void IntegratedBenchmarkRunner::ReportResult(const BenchmarkResult& result) {
    if (result_callback_) {
        result_callback_(result);
    }
    
    if (config_.verbose) {
        std::cout << "\nCompleted: " << result.benchmark_name << std::endl;
        std::cout << "  Latency: " << result.latency.mean << " ms (p95: " << result.latency.p95 << ")" << std::endl;
        std::cout << "  Throughput: " << result.throughput.mean << " TPS" << std::endl;
        std::cout << "  Success Rate: " << (result.success_rate * 100) << "%" << std::endl;
    }
}

void IntegratedBenchmarkRunner::ReportValidation(const std::vector<ValidationResult>& validations) {
    if (validation_callback_) {
        validation_callback_(validations);
    }
}

// ============================================================================
// Benchmark Suite Runner Implementation
// ============================================================================

std::vector<BenchmarkResult> BenchmarkSuiteRunner::RunSuite(SuiteType suite,
                                                             const RunnerConfig& config) {
    auto benchmark_names = GetSuiteBenchmarks(suite);
    return RunCustomSuite(benchmark_names, config);
}

std::vector<BenchmarkResult> BenchmarkSuiteRunner::RunCustomSuite(
    const std::vector<std::string>& benchmark_names,
    const RunnerConfig& config) {
    
    IntegratedBenchmarkRunner runner;
    if (!runner.Initialize(config)) {
        return {};
    }
    
    std::vector<std::unique_ptr<Benchmark>> benchmarks;
    for (const auto& name : benchmark_names) {
        auto benchmark = BenchmarkRegistry::Create(name);
        if (benchmark) {
            benchmarks.push_back(std::move(benchmark));
        }
    }
    
    return runner.RunBenchmarks(benchmarks);
}

std::string BenchmarkSuiteRunner::GetSuiteDescription(SuiteType suite) {
    switch (suite) {
        case SuiteType::QUICK_SMOKE:
            return "Quick smoke test with 5 benchmarks, 10 runs each";
        case SuiteType::STANDARD:
            return "Standard benchmark suite with 10 benchmarks, 30 runs each";
        case SuiteType::COMPREHENSIVE:
            return "Comprehensive benchmark suite with all benchmarks, 50 runs each";
        case SuiteType::CI_REGRESSION:
            return "CI regression detection focused benchmarks";
        case SuiteType::STRESS_TEST:
            return "Chaos and stress testing benchmarks";
        default:
            return "Unknown suite";
    }
}

std::vector<std::string> BenchmarkSuiteRunner::GetSuiteBenchmarks(SuiteType suite) {
    switch (suite) {
        case SuiteType::QUICK_SMOKE:
            return {
                "inference_tps",
                "agent_spawn",
                "swarm16",
                "decision_making",
                "resource_usage"
            };
        case SuiteType::STANDARD:
            return {
                "inference_tps",
                "agent_spawn",
                "swarm16",
                "seg_execution",
                "decision_making",
                "self_correction",
                "response_quality",
                "context_handling",
                "autonomous_runtime",
                "resource_usage"
            };
        case SuiteType::COMPREHENSIVE:
            return {
                "inference_tps",
                "agent_spawn",
                "swarm16",
                "seg_execution",
                "decision_making",
                "self_correction",
                "response_quality",
                "context_handling",
                "autonomous_runtime",
                "resource_usage",
                "concurrent_load",
                "stress_overload",
                "chaos_resilience",
                "degradation_curve",
                "determinism"
            };
        case SuiteType::CI_REGRESSION:
            return {
                "inference_tps",
                "agent_spawn",
                "swarm16",
                "determinism"
            };
        case SuiteType::STRESS_TEST:
            return {
                "stress_overload",
                "chaos_resilience",
                "swarm_overload",
                "mutation_storm"
            };
        default:
            return {};
    }
}

double BenchmarkSuiteRunner::EstimateDuration(SuiteType suite, const RunnerConfig& config) {
    auto benchmarks = GetSuiteBenchmarks(suite);
    
    // Rough estimates per benchmark
    double seconds_per_benchmark = 0.0;
    switch (suite) {
        case SuiteType::QUICK_SMOKE:
            seconds_per_benchmark = 5.0;  // 10 runs * 0.5s
            break;
        case SuiteType::STANDARD:
            seconds_per_benchmark = 15.0;  // 30 runs * 0.5s
            break;
        case SuiteType::COMPREHENSIVE:
            seconds_per_benchmark = 25.0;  // 50 runs * 0.5s
            break;
        case SuiteType::CI_REGRESSION:
            seconds_per_benchmark = 10.0;
            break;
        case SuiteType::STRESS_TEST:
            seconds_per_benchmark = 60.0;  // Stress tests take longer
            break;
    }
    
    return benchmarks.size() * seconds_per_benchmark;
}

// ============================================================================
// Convenience Functions Implementation
// ============================================================================

BenchmarkResult QuickRun(const std::string& benchmark_name,
                          BackendType backend,
                          const std::string& endpoint) {
    RunnerConfig config;
    config.backend = backend;
    config.endpoint = endpoint;
    config.warmup_runs = 5;
    config.measured_runs = 10;
    config.verbose = true;
    
    IntegratedBenchmarkRunner runner;
    if (!runner.Initialize(config)) {
        BenchmarkResult result;
        result.benchmark_name = benchmark_name;
        result.error_message = "Failed to initialize runner";
        return result;
    }
    
    auto result_opt = runner.RunBenchmarkByName(benchmark_name);
    if (result_opt.has_value()) {
        return result_opt.value();
    }
    
    BenchmarkResult result;
    result.benchmark_name = benchmark_name;
    result.error_message = "Benchmark not found or failed";
    return result;
}

ComparisonRun RunComparison(const std::string& benchmark_name,
                            const std::string& sovereign_endpoint,
                            const std::string& ollama_endpoint) {
    ComparisonRun comparison;
    
    // Run on Sovereign
    comparison.sovereign_result = QuickRun(benchmark_name, BackendType::SOVEREIGN, sovereign_endpoint);
    
    // Run on Ollama
    comparison.ollama_result = QuickRun(benchmark_name, BackendType::OLLAMA, ollama_endpoint);
    
    // Perform statistical comparison
    if (comparison.sovereign_result.raw_latencies.empty() ||
        comparison.ollama_result.raw_latencies.empty()) {
        comparison.is_valid = false;
        return comparison;
    }
    
    comparison.statistical_comparison = StatisticalComparison::Compare(
        comparison.sovereign_result.raw_latencies,
        comparison.ollama_result.raw_latencies
    );
    
    // Validate results
    auto sovereign_validations = ResultValidator::ValidateResult(comparison.sovereign_result);
    auto ollama_validations = ResultValidator::ValidateResult(comparison.ollama_result);
    
    comparison.validations.insert(comparison.validations.end(), 
                                   sovereign_validations.begin(), 
                                   sovereign_validations.end());
    comparison.validations.insert(comparison.validations.end(), 
                                   ollama_validations.begin(), 
                                   ollama_validations.end());
    
    comparison.is_valid = !ResultValidator::HasErrors(comparison.validations);
    
    return comparison;
}

PhaseEResults RunPhaseE(const RunnerConfig& config) {
    PhaseEResults results;
    
    // Run all Phase E benchmarks
    auto benchmark_names = BenchmarkSuiteRunner::GetSuiteBenchmarks(
        BenchmarkSuiteRunner::SuiteType::STANDARD);
    
    for (const auto& name : benchmark_names) {
        auto comparison = RunComparison(name);
        results.comparisons.push_back(comparison);
        
        if (!comparison.is_valid) {
            results.all_valid = false;
        }
    }
    
    // Generate report
    if (!config.output_path.empty()) {
        results.report_path = config.output_path;
        
        std::ofstream file(config.output_path);
        if (file.is_open()) {
            file << "{\n";
            file << "  \"phase_e_results\": [\n";
            
            for (size_t i = 0; i < results.comparisons.size(); ++i) {
                const auto& comp = results.comparisons[i];
                file << "    {\n";
                file << "      \"benchmark\": \"" << comp.sovereign_result.benchmark_name << "\",\n";
                file << "      \"sovereign_latency_ms\": " << comp.sovereign_result.latency.mean << ",\n";
                file << "      \"ollama_latency_ms\": " << comp.ollama_result.latency.mean << ",\n";
                file << "      \"p_value\": " << comp.statistical_comparison.p_value << ",\n";
                file << "      \"cohens_d\": " << comp.statistical_comparison.cohens_d << ",\n";
                file << "      \"is_significant\": " << (comp.statistical_comparison.is_significant ? "true" : "false") << "\n";
                file << "    }";
                if (i < results.comparisons.size() - 1) {
                    file << ",";
                }
                file << "\n";
            }
            
            file << "  ]\n";
            file << "}\n";
        }
    }
    
    return results;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int RunBenchmarksMain(int argc, char** argv) {
    // Parse configuration
    auto config = ConfigurationManager::LoadFromArgs(argc, argv);
    
    // Load from environment
    auto env_config = ConfigurationManager::LoadFromEnvironment();
    config = ConfigurationManager::Merge(config, env_config);
    
    // Validate configuration
    std::string error;
    if (!ConfigurationManager::Validate(config, error)) {
        std::cerr << "Configuration error: " << error << std::endl;
        return 1;
    }
    
    // Print configuration
    ConfigurationManager::Print(config);
    
    // Create runner configuration
    RunnerConfig runner_config;
    runner_config.backend = config.backend;
    runner_config.model_name = config.model_name;
    runner_config.warmup_runs = config.warmup_runs;
    runner_config.measured_runs = config.measured_runs;
    runner_config.verbose = config.verbose;
    
    if (config.backend == BackendType::SOVEREIGN) {
        runner_config.endpoint = config.sovereign_endpoint;
    } else {
        runner_config.endpoint = config.ollama_url;
    }
    
    // Run benchmarks
    auto results = BenchmarkSuiteRunner::RunSuite(
        BenchmarkSuiteRunner::SuiteType::STANDARD, runner_config);
    
    // Print summary
    std::cout << "\n========================================\n";
    std::cout << "Benchmark Summary\n";
    std::cout << "========================================\n";
    std::cout << "Completed: " << results.size() << " benchmarks\n";
    
    int success_count = 0;
    for (const auto& result : results) {
        if (result.success_rate >= 0.95) {
            success_count++;
        }
    }
    
    std::cout << "Successful: " << success_count << "\n";
    std::cout << "Failed: " << (results.size() - success_count) << "\n";
    
    return (success_count == results.size()) ? 0 : 1;
}

} // namespace rawrxd::benchmark
