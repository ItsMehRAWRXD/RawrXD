// benchmark_runner_main.cpp
// Batch 5: Main Benchmark Runner Entry Point
//
// Provides: CLI interface, benchmark selection, result aggregation
// Features: Filter by tier/backend, parallel execution, progress reporting

#include "benchmark_tiers.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <functional>
#include <chrono>
#include <iomanip>

// Forward declarations for all benchmark runners
namespace Benchmark {
    void RunInferenceTPSBenchmark(const std::string& backend);
    void RunContextScalingBenchmark(const std::string& backend);
    void RunConcurrentLoadBenchmark(const std::string& backend);
    void RunLatencyPercentilesBenchmark(const std::string& backend);
    void RunResourceMonitoringBenchmark(const std::string& backend);
    void RunPlanningTaskBenchmark(const std::string& backend);
    void RunToolUseBenchmark(const std::string& backend);
    void RunSegMutationBenchmark(const std::string& backend);
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
}

struct BenchmarkInfo {
    std::string name;
    std::string tier;
    std::string description;
    std::function<void(const std::string&)> runner;
    std::vector<std::string> supported_backends;
};

class BenchmarkRunner {
public:
    struct Config {
        std::string backend = "sovereign";
        std::vector<std::string> tiers;
        std::vector<std::string> benchmarks;
        bool list_only = false;
        bool verbose = false;
        int parallel_workers = 1;
        std::string output_format = "console";
        std::string output_file;
    };

    BenchmarkRunner() {
        RegisterAllBenchmarks();
    }

    int Run(int argc, char* argv[]) {
        Config config = ParseArgs(argc, argv);
        
        if (config.list_only) {
            ListBenchmarks();
            return 0;
        }

        std::cout << R"(
╔══════════════════════════════════════════════════════════════════════╗
║         RawrXD Phase D.5 Refined Benchmark Suite                   ║
║         Sovereign vs Ollama Performance Comparison                   ║
╚══════════════════════════════════════════════════════════════════════╝
)" << std::endl;

        std::cout << "Backend: " << config.backend << std::endl;
        std::cout << "Time: " << GetTimestamp() << std::endl;
        std::cout << std::string(70, '=') << std::endl;

        auto benchmarks_to_run = SelectBenchmarks(config);
        
        if (benchmarks_to_run.empty()) {
            std::cerr << "No benchmarks selected. Use --list to see available benchmarks." << std::endl;
            return 1;
        }

        int success_count = 0;
        int fail_count = 0;
        
        auto total_start = std::chrono::steady_clock::now();
        
        for (size_t i = 0; i < benchmarks_to_run.size(); ++i) {
            const auto& info = benchmarks_to_run[i];
            
            std::cout << "\n[" << (i + 1) << "/" << benchmarks_to_run.size() << "] " 
                      << info.name << std::endl;
            std::cout << std::string(70, '-') << std::endl;
            
            auto bench_start = std::chrono::steady_clock::now();
            
            try {
                info.runner(config.backend);
                success_count++;
            } catch (const std::exception& e) {
                std::cerr << "ERROR: " << e.what() << std::endl;
                fail_count++;
            }
            
            auto bench_end = std::chrono::steady_clock::now();
            auto bench_duration = std::chrono::duration_cast<std::chrono::seconds>(
                bench_end - bench_start).count();
            
            if (config.verbose) {
                std::cout << "Duration: " << bench_duration << "s" << std::endl;
            }
        }
        
        auto total_end = std::chrono::steady_clock::now();
        auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(
            total_end - total_start).count();
        
        PrintSummary(success_count, fail_count, total_duration);
        
        return fail_count > 0 ? 1 : 0;
    }

private:
    std::vector<BenchmarkInfo> benchmarks_;

    void RegisterAllBenchmarks() {
        // Tier 1: Core Runtime
        benchmarks_.push_back({"inference_tps", "tier1", "Core TPS measurement",
            Benchmark::RunInferenceTPSBenchmark, {"sovereign", "ollama"}});
        benchmarks_.push_back({"context_scaling", "tier1", "Context length scaling",
            Benchmark::RunContextScalingBenchmark, {"sovereign", "ollama"}});
        benchmarks_.push_back({"concurrent_load", "tier1", "Parallel load testing",
            Benchmark::RunConcurrentLoadBenchmark, {"sovereign", "ollama"}});
        benchmarks_.push_back({"latency_percentiles", "tier1", "Tail latency analysis",
            Benchmark::RunLatencyPercentilesBenchmark, {"sovereign", "ollama"}});
        benchmarks_.push_back({"resource_monitoring", "tier1", "Resource utilization",
            Benchmark::RunResourceMonitoringBenchmark, {"sovereign", "ollama"}});
        
        // Tier 2: Agentic
        benchmarks_.push_back({"planning_task", "tier2", "Multi-step planning",
            Benchmark::RunPlanningTaskBenchmark, {"sovereign"}});
        benchmarks_.push_back({"tool_use", "tier2", "Tool execution",
            Benchmark::RunToolUseBenchmark, {"sovereign"}});
        
        // Tier 3: Sovereign-Only
        benchmarks_.push_back({"seg_mutation", "tier3", "Graph mutation",
            Benchmark::RunSegMutationBenchmark, {"sovereign"}});
        benchmarks_.push_back({"swarm_coordination", "tier3", "Agent efficiency",
            Benchmark::RunSwarmCoordinationBenchmark, {"sovereign"}});
        benchmarks_.push_back({"autonomous_recovery", "tier3", "Failure recovery",
            Benchmark::RunAutonomousRecoveryBenchmark, {"sovereign"}});
        
        // Tier 4: Reliability
        benchmarks_.push_back({"memory_leak", "tier4", "Long-running stability",
            Benchmark::RunMemoryLeakBenchmark, {"sovereign", "ollama"}});
        benchmarks_.push_back({"performance_drift", "tier4", "Performance degradation",
            Benchmark::RunPerformanceDriftBenchmark, {"sovereign", "ollama"}});
        benchmarks_.push_back({"determinism", "tier4", "Output repeatability",
            Benchmark::RunDeterminismBenchmark, {"sovereign", "ollama"}});
        
        // Workflow
        benchmarks_.push_back({"workflow_explain_repo", "workflow", "Repository explanation",
            Benchmark::RunWorkflowExplainRepoBenchmark, {"sovereign"}});
        benchmarks_.push_back({"workflow_bug_fix", "workflow", "Bug fix cycle",
            Benchmark::RunWorkflowBugFixBenchmark, {"sovereign"}});
        
        // Stress & Chaos
        benchmarks_.push_back({"stress_overload", "stress", "Sustained maximum load",
            Benchmark::RunStressOverloadBenchmark, {"sovereign"}});
        benchmarks_.push_back({"chaos_fault_injection", "stress", "Random fault injection",
            Benchmark::RunChaosFaultInjectionBenchmark, {"sovereign"}});
        benchmarks_.push_back({"degradation_curve", "stress", "Gradual load increase",
            Benchmark::RunDegradationCurveBenchmark, {"sovereign"}});
        benchmarks_.push_back({"resource_pressure", "stress", "Resource constraints",
            Benchmark::RunResourcePressureBenchmark, {"sovereign"}});
        benchmarks_.push_back({"mutation_storm", "stress", "Rapid graph mutations",
            Benchmark::RunMutationStormBenchmark, {"sovereign"}});
        benchmarks_.push_back({"swarm_overload", "stress", "Multi-agent overload",
            Benchmark::RunSwarmOverloadBenchmark, {"sovereign"}});
    }

    Config ParseArgs(int argc, char* argv[]) {
        Config config;
        
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "--help" || arg == "-h") {
                PrintHelp();
                exit(0);
            } else if (arg == "--list" || arg == "-l") {
                config.list_only = true;
            } else if (arg == "--backend" && i + 1 < argc) {
                config.backend = argv[++i];
            } else if (arg == "--tier" && i + 1 < argc) {
                config.tiers.push_back(argv[++i]);
            } else if (arg == "--benchmark" && i + 1 < argc) {
                config.benchmarks.push_back(argv[++i]);
            } else if (arg == "--verbose" || arg == "-v") {
                config.verbose = true;
            } else if (arg == "--output" && i + 1 < argc) {
                config.output_file = argv[++i];
            } else if (arg == "--format" && i + 1 < argc) {
                config.output_format = argv[++i];
            }
        }
        
        return config;
    }

    void PrintHelp() {
        std::cout << R"(RawrXD Benchmark Runner

Usage: benchmark_runner [options]

Options:
  --help, -h              Show this help message
  --list, -l              List available benchmarks
  --backend <name>          Backend to test (sovereign|ollama) [default: sovereign]
  --tier <name>             Run benchmarks from specific tier (can be repeated)
  --benchmark <name>        Run specific benchmark (can be repeated)
  --verbose, -v             Enable verbose output
  --output <file>           Write results to file
  --format <format>         Output format (console|json|html) [default: console]

Tiers:
  tier1       Core Runtime benchmarks (5 benchmarks)
  tier2       Agentic benchmarks (2 benchmarks)
  tier3       Sovereign-Only benchmarks (3 benchmarks)
  tier4       Reliability benchmarks (3 benchmarks)
  workflow    Developer Workflow benchmarks (2 benchmarks)
  stress      Stress & Chaos benchmarks (6 benchmarks)

Examples:
  benchmark_runner --backend sovereign --tier tier1
  benchmark_runner --benchmark inference_tps --benchmark latency_percentiles
  benchmark_runner --list
)" << std::endl;
    }

    void ListBenchmarks() {
        std::cout << "Available Benchmarks:\n\n";
        
        std::map<std::string, std::vector<BenchmarkInfo>> by_tier;
        for (const auto& bench : benchmarks_) {
            by_tier[bench.tier].push_back(bench);
        }
        
        for (const auto& [tier, benches] : by_tier) {
            std::cout << "[" << tier << "]\n";
            for (const auto& bench : benches) {
                std::cout << "  " << std::left << std::setw(25) << bench.name
                          << " - " << bench.description << "\n";
                std::cout << "    Backends: ";
                for (size_t i = 0; i < bench.supported_backends.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << bench.supported_backends[i];
                }
                std::cout << "\n";
            }
            std::cout << std::endl;
        }
    }

    std::vector<BenchmarkInfo> SelectBenchmarks(const Config& config) {
        std::vector<BenchmarkInfo> selected;
        
        for (const auto& bench : benchmarks_) {
            // Filter by tier
            if (!config.tiers.empty()) {
                bool tier_match = false;
                for (const auto& tier : config.tiers) {
                    if (bench.tier == tier) {
                        tier_match = true;
                        break;
                    }
                }
                if (!tier_match) continue;
            }
            
            // Filter by specific benchmark names
            if (!config.benchmarks.empty()) {
                bool name_match = false;
                for (const auto& name : config.benchmarks) {
                    if (bench.name == name) {
                        name_match = true;
                        break;
                    }
                }
                if (!name_match) continue;
            }
            
            // Filter by backend support
            bool backend_supported = false;
            for (const auto& supported : bench.supported_backends) {
                if (supported == config.backend) {
                    backend_supported = true;
                    break;
                }
            }
            if (!backend_supported) continue;
            
            selected.push_back(bench);
        }
        
        return selected;
    }

    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    void PrintSummary(int success, int fail, int64_t duration_sec) {
        std::cout << "\n" << std::string(70, '=') << std::endl;
        std::cout << "BENCHMARK SUMMARY" << std::endl;
        std::cout << std::string(70, '=') << std::endl;
        std::cout << "Total:    " << (success + fail) << std::endl;
        std::cout << "Passed:   " << success << std::endl;
        std::cout << "Failed:   " << fail << std::endl;
        std::cout << "Duration: " << duration_sec << "s" << std::endl;
        std::cout << std::string(70, '=') << std::endl;
        
        if (fail == 0) {
            std::cout << "\n✓ All benchmarks completed successfully!" << std::endl;
        } else {
            std::cout << "\n✗ " << fail << " benchmark(s) failed!" << std::endl;
        }
    }
};

int main(int argc, char* argv[]) {
    BenchmarkRunner runner;
    return runner.Run(argc, argv);
}
