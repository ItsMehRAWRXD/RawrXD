// Sovereign Distributed Runtime - Phase D.3
// Test Runner
// Copyright (c) 2026 RawrXD Team

#include "../SovereignDistributedRuntime.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace Sovereign::Distributed;

void PrintHeader(const std::string& title) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  " << title << "\n";
    std::cout << std::string(60, '=') << "\n";
}

void PrintResult(const DistributedTestFramework::TestResult& result) {
    std::cout << "  " << std::left << std::setw(30) << result.scenario_name;
    std::cout << " | ";
    
    if (result.passed) {
        std::cout << "\033[32mPASSED\033[0m";
    } else {
        std::cout << "\033[31mFAILED\033[0m";
    }
    
    std::cout << " | " << result.duration_ms << "ms";
    
    if (!result.error_message.empty()) {
        std::cout << " | Error: " << result.error_message;
    }
    
    std::cout << "\n";
}

void PrintBenchmarkResult(const DistributedBenchmarkAdapter::BenchmarkResult& result) {
    std::cout << "\n  Benchmark: " << result.benchmark_name << "\n";
    std::cout << "  " << std::string(50, '-') << "\n";
    std::cout << "    Total Operations:    " << result.total_operations << "\n";
    std::cout << "    Throughput:          " << std::fixed << std::setprecision(2) 
              << result.throughput_ops_per_sec << " ops/sec\n";
    std::cout << "    Avg Latency:         " << result.avg_latency_ms << " ms\n";
    std::cout << "    P99 Latency:         " << result.p99_latency_ms << " ms\n";
    std::cout << "    Consensus Count:     " << result.consensus_count << "\n";
    std::cout << "    Avg Consensus Time:  " << result.avg_consensus_time_ms << " ms\n";
    std::cout << "    Rollback Count:      " << result.rollback_count << "\n";
    std::cout << "    Node Failures:       " << result.node_failures << "\n";
    std::cout << "    Cluster Stable:      " << (result.cluster_stable ? "Yes" : "No") << "\n";
}

int main(int argc, char* argv[]) {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Sovereign Distributed Runtime - Phase D.3          ║\n";
    std::cout << "║              Distributed Test Runner                     ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════╝\n";
    
    // Parse arguments
    bool run_tests = true;
    bool run_benchmarks = true;
    bool verbose = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--tests-only") {
            run_benchmarks = false;
        } else if (arg == "--benchmarks-only") {
            run_tests = false;
        } else if (arg == "--verbose" || arg == "-v") {
            verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "\nUsage: " << argv[0] << " [options]\n";
            std::cout << "\nOptions:\n";
            std::cout << "  --tests-only        Run only tests\n";
            std::cout << "  --benchmarks-only   Run only benchmarks\n";
            std::cout << "  --verbose, -v       Enable verbose output\n";
            std::cout << "  --help, -h          Show this help\n";
            return 0;
        }
    }
    
    int total_tests = 0;
    int passed_tests = 0;
    int failed_tests = 0;
    
    // Run Tests
    if (run_tests) {
        PrintHeader("Running Distributed Tests");
        
        DistributedTestFramework framework;
        auto results = framework.RunAllScenarios();
        
        for (const auto& result : results) {
            PrintResult(result);
            total_tests++;
            if (result.passed) {
                passed_tests++;
            } else {
                failed_tests++;
            }
        }
        
        std::cout << "\n" << std::string(60, '-') << "\n";
        std::cout << "  Total: " << total_tests << " | ";
        std::cout << "\033[32mPassed: " << passed_tests << "\033[0m | ";
        std::cout << "\033[31mFailed: " << failed_tests << "\033[0m\n";
    }
    
    // Run Benchmarks
    if (run_benchmarks) {
        PrintHeader("Running Distributed Benchmarks");
        
        // Create test cluster
        auto cluster = DistributedTestFramework::CreateTestCluster(3);
        if (cluster.empty()) {
            std::cerr << "Failed to create test cluster for benchmarks\n";
            return 1;
        }
        
        // Initialize cluster
        for (auto& node : cluster) {
            if (!node->Initialize()) {
                std::cerr << "Failed to initialize node for benchmarks\n";
                return 1;
            }
        }
        
        // Join cluster
        std::vector<NodeIdentity> seed_nodes;
        for (auto& node : cluster) {
            seed_nodes.push_back(node->GetClusterTopology().GetHealthyNodes()[0]);
        }
        
        for (auto& node : cluster) {
            node->JoinCluster(seed_nodes);
        }
        
        // Run benchmark
        DistributedBenchmarkAdapter benchmark;
        DistributedBenchmarkAdapter::BenchmarkConfig bench_config;
        bench_config.benchmark_name = "DistributedConsensus";
        bench_config.duration_seconds = 10;
        bench_config.concurrent_agents = 50;
        
        std::vector<DistributedRuntime*> cluster_ptrs;
        for (auto& node : cluster) {
            cluster_ptrs.push_back(node.get());
        }
        
        auto result = benchmark.RunBenchmark(bench_config, cluster_ptrs);
        PrintBenchmarkResult(result);
        
        // Cleanup
        for (auto& node : cluster) {
            node->LeaveCluster();
            node->Shutdown();
        }
    }
    
    // Summary
    PrintHeader("Summary");
    if (run_tests) {
        std::cout << "  Tests:    " << passed_tests << "/" << total_tests << " passed\n";
    }
    if (run_benchmarks) {
        std::cout << "  Benchmarks: Completed\n";
    }
    
    std::cout << "\n" << std::string(60, '=') << "\n\n";
    
    return failed_tests > 0 ? 1 : 0;
}
