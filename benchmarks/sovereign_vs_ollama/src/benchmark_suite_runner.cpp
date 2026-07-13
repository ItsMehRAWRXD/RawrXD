// benchmark_suite_runner.cpp
// Batch 5: Benchmark Suite Runner
//
// Orchestrates execution of all benchmarks with proper sequencing
// Features: Tier-based execution, parallel/serial modes, progress tracking
// Output: Comprehensive results with pass/fail status

#include "benchmark_tiers.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <functional>
#include <algorithm>

namespace Benchmark {

// Forward declarations for all benchmark runners
void RunInferenceTPSBenchmark(const std::string& backend);
void RunContextScalingBenchmark(const std::string& backend);
void RunConcurrentLoadBenchmark(const std::string& backend);
void RunLatencyPercentilesBenchmark(const std::string& backend);
void RunResourceMonitoringBenchmark(const std::string& backend);
void RunPlanningTaskBenchmark(const std::string& backend);
void RunToolUseBenchmark(const std::string& backend);
void RunSEGMutationBenchmark(const std::string& backend);
void RunSwarmCoordinationBenchmark(const std::string& backend);
void RunAutonomousRecoveryBenchmark(const std::string& backend);
void RunMemoryLeakBenchmark(const std::string& backend);
void RunPerformanceDriftBenchmark(const std::string& backend);
void RunDeterminismBenchmark(const std::string& backend);
void RunWorkflowExplainRepoBenchmark(const std::string& backend);
void RunWorkflowBugFixBenchmark(const std::string& backend);
void RunStressOverloadBenchmark(const std::string& backend);
void RunChaosFaultInjectionBenchmark(const std::string& backend);
void RunDegradationCurveBenchmark(const std::string& backend);
void RunResourcePressureBenchmark(const std::string& backend);
void RunMutationStormBenchmark(const std::string& backend);
void RunSwarmOverloadBenchmark(const std::string& backend);

class BenchmarkSuiteRunner {
public:
    enum class ExecutionMode {
        SERIAL,      // Run benchmarks one at a time
        PARALLEL,    // Run independent benchmarks in parallel
        TIER_BASED   // Run by tier (Tier 1 first, then 2, etc.)
    };

    struct Config {
        std::string backend = "sovereign";
        ExecutionMode mode = ExecutionMode::TIER_BASED;
        std::vector<std::string> filter; // Empty = run all
        bool skip_stress = false;
        bool skip_chaos = false;
        int timeout_seconds = 3600; // 1 hour total timeout
    };

    struct BenchmarkResult {
        std::string name;
        std::string tier;
        bool passed;
        double duration_seconds;
        std::string error_message;
    };

    struct SuiteResults {
        std::vector<BenchmarkResult> results;
        int total_benchmarks = 0;
        int passed = 0;
        int failed = 0;
        int skipped = 0;
        double total_duration_seconds = 0;
        bool success = false;
    };

    struct BenchmarkDef {
        std::string name;
        std::string tier;
        std::function<void(const std::string&)> runner;
        bool is_stress;
        bool is_chaos;
    };

    explicit BenchmarkSuiteRunner(const Config& config = Config())
        : config_(config) {
        InitializeBenchmarks();
    }

    SuiteResults Run() {
        SuiteResults results;
        auto start = std::chrono::steady_clock::now();

        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "  RawrXD Benchmark Suite v1.0\n";
        std::cout << "  Backend: " << config_.backend << "\n";
        std::cout << "  Mode: " << ExecutionModeToString(config_.mode) << "\n";
        std::cout << std::string(80, '=') << "\n\n";

        // Filter benchmarks
        auto benchmarks = FilterBenchmarks();
        results.total_benchmarks = static_cast<int>(benchmarks.size());

        // Execute based on mode
        switch (config_.mode) {
            case ExecutionMode::SERIAL:
                RunSerial(benchmarks, results);
                break;
            case ExecutionMode::PARALLEL:
                RunParallel(benchmarks, results);
                break;
            case ExecutionMode::TIER_BASED:
                RunTierBased(benchmarks, results);
                break;
        }

        auto end = std::chrono::steady_clock::now();
        results.total_duration_seconds = std::chrono::duration<double>(end - start).count();
        results.success = (results.failed == 0);

        PrintSummary(results);
        return results;
    }

    static void PrintSummary(const SuiteResults& results) {
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "  Benchmark Suite Summary\n";
        std::cout << std::string(80, '=') << "\n\n";

        std::cout << "  Total Benchmarks: " << results.total_benchmarks << "\n";
        std::cout << "  Passed: " << results.passed << "\n";
        std::cout << "  Failed: " << results.failed << "\n";
        std::cout << "  Skipped: " << results.skipped << "\n";
        std::cout << "  Total Duration: " << std::fixed << std::setprecision(2) 
                  << results.total_duration_seconds << " seconds\n\n";

        if (results.success) {
            std::cout << "  STATUS: ALL BENCHMARKS PASSED ✓\n";
        } else {
            std::cout << "  STATUS: SOME BENCHMARKS FAILED ✗\n";
        }

        std::cout << std::string(80, '=') << "\n";
    }

private:
    Config config_;
    std::vector<BenchmarkDef> all_benchmarks_;

    void InitializeBenchmarks() {
        // Tier 1: Core Runtime
        all_benchmarks_.push_back({"inference_tps", "Tier 1", 
            RunInferenceTPSBenchmark, false, false});
        all_benchmarks_.push_back({"context_scaling", "Tier 1", 
            RunContextScalingBenchmark, false, false});
        all_benchmarks_.push_back({"concurrent_load", "Tier 1", 
            RunConcurrentLoadBenchmark, false, false});
        all_benchmarks_.push_back({"latency_percentiles", "Tier 1", 
            RunLatencyPercentilesBenchmark, false, false});
        all_benchmarks_.push_back({"resource_monitoring", "Tier 1", 
            RunResourceMonitoringBenchmark, false, false});

        // Tier 2: Agentic
        all_benchmarks_.push_back({"planning_task", "Tier 2", 
            RunPlanningTaskBenchmark, false, false});
        all_benchmarks_.push_back({"tool_use", "Tier 2", 
            RunToolUseBenchmark, false, false});

        // Tier 3: Sovereign-Only
        all_benchmarks_.push_back({"seg_mutation", "Tier 3", 
            RunSEGMutationBenchmark, false, false});
        all_benchmarks_.push_back({"swarm_coordination", "Tier 3", 
            RunSwarmCoordinationBenchmark, false, false});
        all_benchmarks_.push_back({"autonomous_recovery", "Tier 3", 
            RunAutonomousRecoveryBenchmark, false, false});

        // Tier 4: Reliability
        all_benchmarks_.push_back({"memory_leak", "Tier 4", 
            RunMemoryLeakBenchmark, false, false});
        all_benchmarks_.push_back({"performance_drift", "Tier 4", 
            RunPerformanceDriftBenchmark, false, false});
        all_benchmarks_.push_back({"determinism", "Tier 4", 
            RunDeterminismBenchmark, false, false});

        // Workflow
        all_benchmarks_.push_back({"workflow_explain_repo", "Workflow", 
            RunWorkflowExplainRepoBenchmark, false, false});
        all_benchmarks_.push_back({"workflow_bug_fix", "Workflow", 
            RunWorkflowBugFixBenchmark, false, false});

        // Stress & Chaos (Batch 4)
        all_benchmarks_.push_back({"stress_overload", "Stress", 
            RunStressOverloadBenchmark, true, false});
        all_benchmarks_.push_back({"chaos_fault_injection", "Chaos", 
            RunChaosFaultInjectionBenchmark, false, true});
        all_benchmarks_.push_back({"degradation_curve", "Stress", 
            RunDegradationCurveBenchmark, true, false});
        all_benchmarks_.push_back({"resource_pressure", "Stress", 
            RunResourcePressureBenchmark, true, false});
        all_benchmarks_.push_back({"mutation_storm", "Chaos", 
            RunMutationStormBenchmark, false, true});
        all_benchmarks_.push_back({"swarm_overload", "Stress", 
            RunSwarmOverloadBenchmark, true, false});
    }

    std::vector<BenchmarkDef> FilterBenchmarks() {
        std::vector<BenchmarkDef> filtered;
        
        for (const auto& bench : all_benchmarks_) {
            // Skip stress if requested
            if (config_.skip_stress && bench.is_stress) {
                continue;
            }
            // Skip chaos if requested
            if (config_.skip_chaos && bench.is_chaos) {
                continue;
            }
            // Apply name filter
            if (!config_.filter.empty()) {
                bool match = false;
                for (const auto& f : config_.filter) {
                    if (bench.name.find(f) != std::string::npos) {
                        match = true;
                        break;
                    }
                }
                if (!match) continue;
            }
            filtered.push_back(bench);
        }
        
        return filtered;
    }

    void RunSerial(const std::vector<BenchmarkDef>& benchmarks, SuiteResults& results) {
        for (const auto& bench : benchmarks) {
            RunSingleBenchmark(bench, results);
        }
    }

    void RunParallel(const std::vector<BenchmarkDef>& benchmarks, SuiteResults& results) {
        // Note: In production, use std::async or thread pool
        // For now, run serial with warning
        std::cout << "  [Warning] Parallel mode not fully implemented, running serial\n";
        RunSerial(benchmarks, results);
    }

    void RunTierBased(const std::vector<BenchmarkDef>& benchmarks, SuiteResults& results) {
        // Group by tier
        std::map<std::string, std::vector<BenchmarkDef>> tier_groups;
        for (const auto& bench : benchmarks) {
            tier_groups[bench.tier].push_back(bench);
        }

        // Run in tier order
        std::vector<std::string> tier_order = {
            "Tier 1", "Tier 2", "Tier 3", "Tier 4", "Workflow", "Stress", "Chaos"
        };

        for (const auto& tier : tier_order) {
            auto it = tier_groups.find(tier);
            if (it == tier_groups.end()) continue;

            std::cout << "\n  Executing " << tier << " benchmarks...\n";
            std::cout << "  " << std::string(40, '-') << "\n";

            for (const auto& bench : it->second) {
                RunSingleBenchmark(bench, results);
            }
        }
    }

    void RunSingleBenchmark(const BenchmarkDef& bench, SuiteResults& results) {
        std::cout << "    Running " << bench.name << "... " << std::flush;
        
        BenchmarkResult result;
        result.name = bench.name;
        result.tier = bench.tier;
        
        auto start = std::chrono::steady_clock::now();
        
        try {
            bench.runner(config_.backend);
            result.passed = true;
            results.passed++;
        } catch (const std::exception& e) {
            result.passed = false;
            result.error_message = e.what();
            results.failed++;
        }
        
        auto end = std::chrono::steady_clock::now();
        result.duration_seconds = std::chrono::duration<double>(end - start).count();
        
        results.results.push_back(result);
        
        std::cout << (result.passed ? "PASSED" : "FAILED") 
                  << " (" << std::fixed << std::setprecision(2) 
                  << result.duration_seconds << "s)\n";
    }

    static const char* ExecutionModeToString(ExecutionMode mode) {
        switch (mode) {
            case ExecutionMode::SERIAL: return "serial";
            case ExecutionMode::PARALLEL: return "parallel";
            case ExecutionMode::TIER_BASED: return "tier-based";
            default: return "unknown";
        }
    }
};

// Main entry point
int RunBenchmarkSuite(int argc, char* argv[]) {
    BenchmarkSuiteRunner::Config config;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--backend" && i + 1 < argc) {
            config.backend = argv[++i];
        } else if (arg == "--serial") {
            config.mode = BenchmarkSuiteRunner::ExecutionMode::SERIAL;
        } else if (arg == "--parallel") {
            config.mode = BenchmarkSuiteRunner::ExecutionMode::PARALLEL;
        } else if (arg == "--skip-stress") {
            config.skip_stress = true;
        } else if (arg == "--skip-chaos") {
            config.skip_chaos = true;
        } else if (arg == "--filter" && i + 1 < argc) {
            config.filter.push_back(argv[++i]);
        }
    }

    BenchmarkSuiteRunner runner(config);
    auto results = runner.Run();
    
    return results.success ? 0 : 1;
}

} // namespace Benchmark
