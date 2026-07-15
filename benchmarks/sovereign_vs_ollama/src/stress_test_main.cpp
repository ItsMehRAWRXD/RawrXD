// stress_test_main.cpp
// Batch 4: Stress & Chaos Test Suite Entry Point

#include "chaos_engine.hpp"
#include "workload_profiles.hpp"
#include "orchestration_telemetry.hpp"
#include <iostream>
#include <cstring>

void PrintHelp(const char* program_name) {
    std::cout << "RawrXD Stress Test Suite - Batch 4: Chaos & Resilience\n"
              << "=====================================================\n\n"
              << "Usage: " << program_name << " [options]\n\n"
              << "Stress Tests:\n"
              << "  --stress-overload         Run stress overload benchmark\n"
              << "  --swarm-overload          Run swarm overload benchmark\n"
              << "  --mutation-storm          Run mutation storm benchmark\n"
              << "  --degradation-curve       Run degradation curve benchmark\n"
              << "  --resource-pressure       Run resource pressure benchmark\n"
              << "  --chaos-resilience        Run chaos resilience benchmark\n"
              << "  --all                     Run all stress tests\n\n"
              << "Configuration:\n"
              << "  --duration SECONDS        Test duration (default: 300)\n"
              << "  --intensity LEVEL         Chaos intensity 0.0-1.0 (default: 0.5)\n"
              << "  --workload FILE           Workload profile JSON\n"
              << "  --output DIR              Output directory\n\n"
              << "Examples:\n"
              << "  " << program_name << " --all --duration 600\n"
              << "  " << program_name << " --chaos-resilience --intensity 0.8\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintHelp(argv[0]);
        return 1;
    }
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     RawrXD Stress Test Suite - Batch 4                       ║\n";
    std::cout << "║     Chaos, Resilience & Degradation Testing                  ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    // Parse arguments
    bool run_all = false;
    bool run_stress_overload = false;
    bool run_swarm_overload = false;
    bool run_mutation_storm = false;
    bool run_degradation_curve = false;
    bool run_resource_pressure = false;
    bool run_chaos_resilience = false;
    
    int duration_seconds = 300;
    double intensity = 0.5;
    std::string workload_file;
    std::string output_dir = "stress_results";
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            PrintHelp(argv[0]);
            return 0;
        }
        else if (arg == "--all") {
            run_all = true;
        }
        else if (arg == "--stress-overload") {
            run_stress_overload = true;
        }
        else if (arg == "--swarm-overload") {
            run_swarm_overload = true;
        }
        else if (arg == "--mutation-storm") {
            run_mutation_storm = true;
        }
        else if (arg == "--degradation-curve") {
            run_degradation_curve = true;
        }
        else if (arg == "--resource-pressure") {
            run_resource_pressure = true;
        }
        else if (arg == "--chaos-resilience") {
            run_chaos_resilience = true;
        }
        else if (arg == "--duration" && i + 1 < argc) {
            duration_seconds = std::stoi(argv[++i]);
        }
        else if (arg == "--intensity" && i + 1 < argc) {
            intensity = std::stod(argv[++i]);
        }
        else if (arg == "--workload" && i + 1 < argc) {
            workload_file = argv[++i];
        }
        else if (arg == "--output" && i + 1 < argc) {
            output_dir = argv[++i];
        }
    }
    
    // If no specific test selected, run all
    if (!run_stress_overload && !run_swarm_overload && !run_mutation_storm &&
        !run_degradation_curve && !run_resource_pressure && !run_chaos_resilience) {
        run_all = true;
    }
    
    if (run_all) {
        run_stress_overload = true;
        run_swarm_overload = true;
        run_mutation_storm = true;
        run_degradation_curve = true;
        run_resource_pressure = true;
        run_chaos_resilience = true;
    }
    
    std::cout << "Configuration:\n";
    std::cout << "  Duration: " << duration_seconds << " seconds\n";
    std::cout << "  Intensity: " << (intensity * 100) << "%\n";
    std::cout << "  Output: " << output_dir << "\n";
    if (!workload_file.empty()) {
        std::cout << "  Workload: " << workload_file << "\n";
    }
    std::cout << "\n";
    
    // Run selected tests
    int tests_run = 0;
    int tests_passed = 0;
    
    if (run_stress_overload) {
        std::cout << "[TEST] Stress Overload Benchmark\n";
        try {
            RunStressOverloadBenchmark("sovereign");
            tests_run++;
            tests_passed++;
            std::cout << "  Status: PASSED\n\n";
        } catch (...) {
            tests_run++;
            std::cout << "  Status: FAILED\n\n";
        }
    }
    
    if (run_swarm_overload) {
        std::cout << "[TEST] Swarm Overload Benchmark\n";
        try {
            RunSwarmOverloadBenchmark("sovereign");
            tests_run++;
            tests_passed++;
            std::cout << "  Status: PASSED\n\n";
        } catch (...) {
            tests_run++;
            std::cout << "  Status: FAILED\n\n";
        }
    }
    
    if (run_mutation_storm) {
        std::cout << "[TEST] Mutation Storm Benchmark\n";
        try {
            RunMutationStormBenchmark("sovereign");
            tests_run++;
            tests_passed++;
            std::cout << "  Status: PASSED\n\n";
        } catch (...) {
            tests_run++;
            std::cout << "  Status: FAILED\n\n";
        }
    }
    
    if (run_degradation_curve) {
        std::cout << "[TEST] Degradation Curve Benchmark\n";
        try {
            RunDegradationCurveBenchmark("sovereign");
            tests_run++;
            tests_passed++;
            std::cout << "  Status: PASSED\n\n";
        } catch (...) {
            tests_run++;
            std::cout << "  Status: FAILED\n\n";
        }
    }
    
    if (run_resource_pressure) {
        std::cout << "[TEST] Resource Pressure Benchmark\n";
        try {
            RunResourcePressureBenchmark("sovereign");
            tests_run++;
            tests_passed++;
            std::cout << "  Status: PASSED\n\n";
        } catch (...) {
            tests_run++;
            std::cout << "  Status: FAILED\n\n";
        }
    }
    
    if (run_chaos_resilience) {
        std::cout << "[TEST] Chaos Resilience Benchmark\n";
        try {
            RunChaosResilienceBenchmark("sovereign");
            tests_run++;
            tests_passed++;
            std::cout << "  Status: PASSED\n\n";
        } catch (...) {
            tests_run++;
            std::cout << "  Status: FAILED\n\n";
        }
    }
    
    // Summary
    std::cout << "══════════════════════════════════════════════════════════════\n";
    std::cout << "Stress Test Summary\n";
    std::cout << "══════════════════════════════════════════════════════════════\n";
    std::cout << "Tests run: " << tests_run << "\n";
    std::cout << "Tests passed: " << tests_passed << "\n";
    std::cout << "Success rate: " << (tests_passed * 100 / tests_run) << "%\n";
    std::cout << "\n";
    
    return (tests_passed == tests_run) ? 0 : 1;
}
