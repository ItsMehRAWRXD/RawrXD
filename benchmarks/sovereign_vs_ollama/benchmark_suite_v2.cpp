// Complete Benchmark Suite Runner
// Orchestrates all benchmarks with proper manifest, aggregation, and reporting
// Copyright (c) 2026 RawrXD Team

#include "include/benchmark_common.hpp"
#include "include/benchmark_manifest.hpp"
#include "include/benchmark_orchestrator.hpp"
#include "include/results_aggregator.hpp"
#include "include/regression_tracker.hpp"
#include "include/json_reporter.hpp"

// Benchmarks - Batch 1-3
#include "src/inference_tps_benchmark.hpp"
#include "src/agent_spawn_benchmark.hpp"
#include "src/swarm16_benchmark.hpp"
#include "src/seg_execution_benchmark.hpp"
#include "src/decision_making_benchmark.hpp"
#include "src/self_correction_benchmark.hpp"
#include "src/response_quality_benchmark.hpp"
#include "src/context_handling_benchmark.hpp"
#include "src/autonomous_runtime_benchmark.hpp"
#include "src/resource_usage_benchmark.hpp"
#include "src/stability_benchmark.hpp"
#include "src/developer_productivity_benchmark.hpp"

// Benchmarks - Batch 4 (Chaos & Stress)
#include "src/chaos_resilience_benchmark.hpp"
#include "src/stress_overload_benchmark.hpp"
#include "src/swarm_overload_benchmark.hpp"
#include "src/mutation_storm_benchmark.hpp"
#include "src/degradation_curve_benchmark.hpp"
#include "src/resource_pressure_benchmark.hpp"

#include <iostream>
#include <vector>
#include <memory>
#include <cstring>
#include <filesystem>

using namespace rawrxd::benchmark;

void PrintBanner() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                      ║\n";
    std::cout << "║     RawrXD Sovereign vs Ollama Benchmark Suite v2.0                 ║\n";
    std::cout << "║     Comprehensive Agentic/Autonomous/Swarm Performance Testing      ║\n";
    std::cout << "║                                                                      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
}

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --backend <type>         Backend: sovereign, ollama, both (default: both)\n";
    std::cout << "  --model <name>           Model name (default: phi-3-mini-Q4)\n";
    std::cout << "  --ollama-model <name>    Ollama model name (default: phi3:mini)\n";
    std::cout << "  --swarm-size <n>         Number of agents (default: 16)\n";
    std::cout << "  --warmup <n>             Warmup runs (default: 10)\n";
    std::cout << "  --runs <n>               Measured runs (default: 50)\n";
    std::cout << "  --stability-minutes <n>   Stability test duration (default: 10)\n";
    std::cout << "  --benchmarks <list>      Comma-separated list (default: all)\n";
    std::cout << "  --output <path>          Output directory (default: reports)\n";
    std::cout << "  --seed <n>               Random seed (default: 42)\n";
    std::cout << "  --temperature <f>        Temperature (default: 0.0)\n";
    std::cout << "  --check-regressions      Enable regression checking\n";
    std::cout << "  --export-csv             Export results to CSV\n";
    std::cout << "  --verbose                Enable verbose output\n";
    std::cout << "  --help                   Show this help\n";
    std::cout << "\nBenchmarks (Batch 1-3):\n";
    std::cout << "  inference_tps, agent_spawn, swarm16, seg_execution, decision_making,\n";
    std::cout << "  self_correction, response_quality, context_handling, autonomous_runtime,\n";
    std::cout << "  resource_usage, stability, developer_productivity\n";
    std::cout << "\nBenchmarks (Batch 4 - Chaos & Stress):\n";
    std::cout << "  chaos_resilience, stress_overload, swarm_overload, mutation_storm,\n";
    std::cout << "  degradation_curve, resource_pressure\n";
    std::cout << "\nSpecial:\n";
    std::cout << "  all - Run all benchmarks\n";
    std::cout << "  batch1 - Run Batch 1 (Core Performance)\n";
    std::cout << "  batch2 - Run Batch 2 (Agentic Capabilities)\n";
    std::cout << "  batch3 - Run Batch 3 (Infrastructure)\n";
    std::cout << "  batch4 - Run Batch 4 (Chaos & Stress)\n";
}

BenchmarkConfig ParseArgs(int argc, char* argv[]) {
    BenchmarkConfig config;
    
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            // Handled by orchestrator
            ++i;
        } else if (std::strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            config.model_name = argv[i + 1];
            ++i;
        } else if (std::strcmp(argv[i], "--ollama-model") == 0 && i + 1 < argc) {
            config.ollama_model = argv[i + 1];
            ++i;
        } else if (std::strcmp(argv[i], "--swarm-size") == 0 && i + 1 < argc) {
            config.swarm_size = std::atoi(argv[i + 1]);
            ++i;
        } else if (std::strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
            config.warmup_runs = std::atoi(argv[i + 1]);
            ++i;
        } else if (std::strcmp(argv[i], "--runs") == 0 && i + 1 < argc) {
            config.measured_runs = std::atoi(argv[i + 1]);
            ++i;
        } else if (std::strcmp(argv[i], "--stability-minutes") == 0 && i + 1 < argc) {
            config.stability_duration_minutes = std::atoi(argv[i + 1]);
            ++i;
        } else if (std::strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            config.output_dir = argv[i + 1];
            ++i;
        } else if (std::strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            config.seed = std::atoi(argv[i + 1]);
            ++i;
        } else if (std::strcmp(argv[i], "--temperature") == 0 && i + 1 < argc) {
            config.temperature = std::atof(argv[i + 1]);
            ++i;
        } else if (std::strcmp(argv[i], "--verbose") == 0) {
            config.verbose = true;
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            std::exit(0);
        }
    }
    
    return config;
}

std::vector<std::string> ParseBenchmarkList(const std::string& list) {
    std::vector<std::string> benchmarks;
    std::stringstream ss(list);
    std::string item;
    
    while (std::getline(ss, item, ',')) {
        // Trim whitespace
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) {
            benchmarks.push_back(item);
        }
    }
    
    return benchmarks;
}

int main(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        std::cout << "\nRunning with default settings...\n\n";
    }
    
    // Parse base configuration
    BenchmarkConfig base_config = ParseArgs(argc, argv);
    
    // Determine backends to test
    std::vector<BackendType> backends = {BackendType::SOVEREIGN, BackendType::OLLAMA};
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--backend") == 0 && i + 1 < argc) {
            if (std::strcmp(argv[i + 1], "sovereign") == 0) {
                backends = {BackendType::SOVEREIGN};
            } else if (std::strcmp(argv[i + 1], "ollama") == 0) {
                backends = {BackendType::OLLAMA};
            }
            ++i;
        }
    }
    
    // Determine benchmarks to run
    std::vector<std::string> benchmark_names;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--benchmarks") == 0 && i + 1 < argc) {
            benchmark_names = ParseBenchmarkList(argv[i + 1]);
            ++i;
        }
    }
    
    // Create orchestrator configuration
    BenchmarkOrchestrator::OrchestratorConfig orch_config;
    orch_config.backends = backends;
    orch_config.benchmark_names = benchmark_names;
    orch_config.output_directory = base_config.output_dir;
    
    // Create orchestrator
    BenchmarkOrchestrator orchestrator(orch_config);
    
    // Register all benchmarks - Batch 1-3
    orchestrator.RegisterBenchmark("inference_tps", []() { return std::make_unique<InferenceTPSBenchmark>(); });
    orchestrator.RegisterBenchmark("agent_spawn", []() { return std::make_unique<AgentSpawnBenchmark>(); });
    orchestrator.RegisterBenchmark("swarm16", []() { return std::make_unique<Swarm16Benchmark>(); });
    orchestrator.RegisterBenchmark("seg_execution", []() { return std::make_unique<SEGExecutionBenchmark>(); });
    orchestrator.RegisterBenchmark("decision_making", []() { return std::make_unique<DecisionMakingBenchmark>(); });
    orchestrator.RegisterBenchmark("self_correction", []() { return std::make_unique<SelfCorrectionBenchmark>(); });
    orchestrator.RegisterBenchmark("response_quality", []() { return std::make_unique<ResponseQualityBenchmark>(); });
    orchestrator.RegisterBenchmark("context_handling", []() { return std::make_unique<ContextHandlingBenchmark>(); });
    orchestrator.RegisterBenchmark("autonomous_runtime", []() { return std::make_unique<AutonomousRuntimeBenchmark>(); });
    orchestrator.RegisterBenchmark("resource_usage", []() { return std::make_unique<ResourceUsageBenchmark>(); });
    orchestrator.RegisterBenchmark("stability", []() { return std::make_unique<StabilityBenchmark>(); });
    orchestrator.RegisterBenchmark("developer_productivity", []() { return std::make_unique<DeveloperProductivityBenchmark>(); });
    
    // Register Batch 4 benchmarks (Chaos & Stress)
    orchestrator.RegisterBenchmark("chaos_resilience", []() { return std::make_unique<ChaosResilienceBenchmark>(); });
    orchestrator.RegisterBenchmark("stress_overload", []() { return std::make_unique<StressOverloadBenchmark>(); });
    orchestrator.RegisterBenchmark("swarm_overload", []() { return std::make_unique<SwarmOverloadBenchmark>(); });
    orchestrator.RegisterBenchmark("mutation_storm", []() { return std::make_unique<MutationStormBenchmark>(); });
    orchestrator.RegisterBenchmark("degradation_curve", []() { return std::make_unique<DegradationCurveBenchmark>(); });
    orchestrator.RegisterBenchmark("resource_pressure", []() { return std::make_unique<ResourcePressureBenchmark>(); });
    
    // Run benchmarks
    std::cout << "Starting benchmark orchestration...\n";
    std::cout << "Backends: ";
    for (auto b : backends) {
        std::cout << BackendTypeToString(b) << " ";
    }
    std::cout << "\n\n";
    
    auto result = orchestrator.RunAll(base_config);
    
    if (!result.success) {
        std::cerr << "\nSome benchmarks failed. Check logs for details.\n";
    }
    
    // Aggregate results if both backends ran
    if (backends.size() == 2) {
        std::cout << "\nGenerating comparison report...\n";
        
        ResultsAggregator aggregator;
        
        // Split results by backend
        std::vector<BenchmarkResult> sovereign_results;
        std::vector<BenchmarkResult> ollama_results;
        
        for (const auto& r : result.results) {
            if (r.backend == BackendType::SOVEREIGN) {
                sovereign_results.push_back(r);
            } else if (r.backend == BackendType::OLLAMA) {
                ollama_results.push_back(r);
            }
        }
        
        if (!sovereign_results.empty() && !ollama_results.empty()) {
            auto report = aggregator.GenerateComparisonReport(sovereign_results, ollama_results);
            
            std::string report_path = base_config.output_dir + "/comparison_report.md";
            std::ofstream file(report_path);
            if (file) {
                file << report;
                std::cout << "Comparison report saved to: " << report_path << "\n";
            }
            
            // Calculate and display composite scores
            auto sovereign_scores = aggregator.Aggregate(sovereign_results);
            auto ollama_scores = aggregator.Aggregate(ollama_results);
            
            std::cout << "\n========================================\n";
            std::cout << "COMPOSITE SCORES\n";
            std::cout << "========================================\n";
            std::cout << std::fixed << std::setprecision(1);
            std::cout << "Sovereign SIS: " << sovereign_scores.sis << "\n";
            std::cout << "Ollama SIS: " << ollama_scores.sis << "\n";
            std::cout << "Sovereign Advantage: " << ((sovereign_scores.sis - ollama_scores.sis) / ollama_scores.sis * 100) << "%\n";
            std::cout << "========================================\n";
        }
    }
    
    // Check for regressions if enabled
    bool check_regressions = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--check-regressions") == 0) {
            check_regressions = true;
            break;
        }
    }
    
    if (check_regressions) {
        std::cout << "\nChecking for regressions...\n";
        RegressionTracker tracker;
        
        for (const auto& r : result.results) {
            auto report = tracker.CheckRegressions(r);
            if (report.has_regressions) {
                std::cout << report.ToMarkdown() << "\n";
            }
        }
    }
    
    // Export to CSV if enabled
    bool export_csv = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--export-csv") == 0) {
            export_csv = true;
            break;
        }
    }
    
    if (export_csv) {
        std::cout << "\nExporting to CSV...\n";
        RegressionTracker tracker;
        std::string csv_path = base_config.output_dir + "/benchmark_history.csv";
        if (tracker.ExportToCsv(csv_path)) {
            std::cout << "CSV exported to: " << csv_path << "\n";
        }
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Benchmark Suite Complete!\n";
    std::cout << "========================================\n";
    std::cout << "Total duration: " << std::fixed << std::setprecision(1) << result.total_duration_seconds << "s\n";
    std::cout << "Benchmarks run: " << result.benchmarks_run << "\n";
    std::cout << "Passed: " << result.benchmarks_passed << "\n";
    std::cout << "Failed: " << result.benchmarks_failed << "\n";
    std::cout << "========================================\n\n";
    
    return result.success ? 0 : 1;
}
