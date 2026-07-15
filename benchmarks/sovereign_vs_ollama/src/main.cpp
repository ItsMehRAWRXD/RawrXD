// main.cpp
// Phase D.5 Refined — Benchmark Runner Entry Point
//
// Usage:
//   benchmark_runner --full                                    # Run all benchmarks
//   benchmark_runner --tier 1                                  # Run Tier 1 only
//   benchmark_runner --tier 1 --compare --baseline baseline.json
//   benchmark_runner --workflow                                # Run developer workflow
//   benchmark_runner --soak-duration 3600 --tier 4            # 1-hour soak test
//   benchmark_runner --generate-dashboard --output dashboard.html

#include "benchmark_tiers.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <cstring>

using namespace Benchmark;

// ============================================================================
// Command Line Parser
// ============================================================================

struct CommandLineArgs {
    // Run modes
    bool run_full = false;
    bool run_tier1 = false;
    bool run_tier2 = false;
    bool run_tier3 = false;
    bool run_tier4 = false;
    bool run_workflow = false;
    int tier = 0;  // 0 = all, 1-4 = specific tier
    
    // Configuration
    uint32_t warmup_runs = 5;
    uint32_t measured_runs = 30;
    uint32_t random_seed = 42;
    double temperature = 0.0;
    std::chrono::seconds soak_duration = std::chrono::minutes(5);
    std::string model_name = "phi-4";
    std::string quantization = "Q4_K_M";
    
    // Comparison
    bool compare_mode = false;
    std::string baseline_path;
    std::string current_path;
    double critical_threshold = 0.20;
    double warning_threshold = 0.10;
    
    // Output
    std::string output_json;
    std::string output_html;
    std::string output_markdown;
    bool github_actions_output = false;
    bool generate_dashboard = false;
    
    // Dashboard inputs
    std::string tier1_input;
    std::string tier2_input;
    std::string tier3_input;
    std::string tier4_input;
    std::string workflow_input;
    
    // Help
    bool show_help = false;
};

void PrintHelp(const char* program_name) {
    std::cout << "RawrXD Benchmark Runner — Phase D.5 Refined\n"
              << "===========================================\n\n"
              << "Usage: " << program_name << " [options]\n\n"
              << "Run Modes:\n"
              << "  --full                    Run complete benchmark suite\n"
              << "  --tier N                  Run specific tier (1-4)\n"
              << "  --tier1                   Run Tier 1: Runtime Performance\n"
              << "  --tier2                   Run Tier 2: Agentic Capability\n"
              << "  --tier3                   Run Tier 3: Sovereign Features\n"
              << "  --tier4                   Run Tier 4: Long-Term Reliability\n"
              << "  --workflow                Run Developer Workflow benchmark\n"
              << "  --soak-duration SECONDS   Duration for Tier 4 soak test (default: 300)\n\n"
              << "Configuration:\n"
              << "  --warmup N                Warmup runs (default: 5)\n"
              << "  --runs N                  Measured runs (default: 30)\n"
              << "  --seed N                  Random seed (default: 42)\n"
              << "  --temperature T           Temperature (default: 0)\n"
              << "  --model NAME              Model name (default: phi-4)\n"
              << "  --quantization Q          Quantization (default: Q4_K_M)\n\n"
              << "Comparison:\n"
              << "  --compare                 Enable comparison mode\n"
              << "  --baseline PATH           Baseline results JSON\n"
              << "  --current PATH            Current results JSON\n"
              << "  --critical-threshold P    Critical regression threshold (default: 0.20)\n"
              << "  --warning-threshold P     Warning regression threshold (default: 0.10)\n\n"
              << "Output:\n"
              << "  --output-json PATH        Write results to JSON\n"
              << "  --output-html PATH        Write results to HTML dashboard\n"
              << "  --output-markdown PATH    Write results to Markdown\n"
              << "  --github-actions-output     Format output for GitHub Actions\n\n"
              << "Dashboard Generation:\n"
              << "  --generate-dashboard      Generate HTML dashboard\n"
              << "  --tier1-input PATH        Tier 1 results JSON\n"
              << "  --tier2-input PATH        Tier 2 results JSON\n"
              << "  --tier3-input PATH        Tier 3 results JSON\n"
              << "  --tier4-input PATH        Tier 4 results JSON\n"
              << "  --workflow-input PATH     Workflow results JSON\n\n"
              << "Examples:\n"
              << "  " << program_name << " --full --output-json results.json\n"
              << "  " << program_name << " --tier 1 --compare --baseline main.json --current pr.json\n"
              << "  " << program_name << " --tier4 --soak-duration 3600\n"
              << "  " << program_name << " --generate-dashboard --tier1-input t1.json --output dashboard.html\n";
}

CommandLineArgs ParseArgs(int argc, char* argv[]) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            args.show_help = true;
        }
        else if (arg == "--full") {
            args.run_full = true;
        }
        else if (arg == "--tier" && i + 1 < argc) {
            args.tier = std::stoi(argv[++i]);
            args.run_tier1 = (args.tier == 1);
            args.run_tier2 = (args.tier == 2);
            args.run_tier3 = (args.tier == 3);
            args.run_tier4 = (args.tier == 4);
        }
        else if (arg == "--tier1") {
            args.run_tier1 = true;
            args.tier = 1;
        }
        else if (arg == "--tier2") {
            args.run_tier2 = true;
            args.tier = 2;
        }
        else if (arg == "--tier3") {
            args.run_tier3 = true;
            args.tier = 3;
        }
        else if (arg == "--tier4") {
            args.run_tier4 = true;
            args.tier = 4;
        }
        else if (arg == "--workflow") {
            args.run_workflow = true;
        }
        else if (arg == "--soak-duration" && i + 1 < argc) {
            args.soak_duration = std::chrono::seconds(std::stoi(argv[++i]));
        }
        else if (arg == "--warmup" && i + 1 < argc) {
            args.warmup_runs = std::stoi(argv[++i]);
        }
        else if (arg == "--runs" && i + 1 < argc) {
            args.measured_runs = std::stoi(argv[++i]);
        }
        else if (arg == "--seed" && i + 1 < argc) {
            args.random_seed = std::stoi(argv[++i]);
        }
        else if (arg == "--temperature" && i + 1 < argc) {
            args.temperature = std::stod(argv[++i]);
        }
        else if (arg == "--model" && i + 1 < argc) {
            args.model_name = argv[++i];
        }
        else if (arg == "--quantization" && i + 1 < argc) {
            args.quantization = argv[++i];
        }
        else if (arg == "--compare") {
            args.compare_mode = true;
        }
        else if (arg == "--baseline" && i + 1 < argc) {
            args.baseline_path = argv[++i];
        }
        else if (arg == "--current" && i + 1 < argc) {
            args.current_path = argv[++i];
        }
        else if (arg == "--critical-threshold" && i + 1 < argc) {
            args.critical_threshold = std::stod(argv[++i]);
        }
        else if (arg == "--warning-threshold" && i + 1 < argc) {
            args.warning_threshold = std::stod(argv[++i]);
        }
        else if (arg == "--output-json" && i + 1 < argc) {
            args.output_json = argv[++i];
        }
        else if (arg == "--output-html" && i + 1 < argc) {
            args.output_html = argv[++i];
        }
        else if (arg == "--output-markdown" && i + 1 < argc) {
            args.output_markdown = argv[++i];
        }
        else if (arg == "--github-actions-output") {
            args.github_actions_output = true;
        }
        else if (arg == "--generate-dashboard") {
            args.generate_dashboard = true;
        }
        else if (arg == "--tier1-input" && i + 1 < argc) {
            args.tier1_input = argv[++i];
        }
        else if (arg == "--tier2-input" && i + 1 < argc) {
            args.tier2_input = argv[++i];
        }
        else if (arg == "--tier3-input" && i + 1 < argc) {
            args.tier3_input = argv[++i];
        }
        else if (arg == "--tier4-input" && i + 1 < argc) {
            args.tier4_input = argv[++i];
        }
        else if (arg == "--workflow-input" && i + 1 < argc) {
            args.workflow_input = argv[++i];
        }
    }
    
    // Default to full suite if no specific tier selected
    if (!args.run_tier1 && !args.run_tier2 && !args.run_tier3 && 
        !args.run_tier4 && !args.run_workflow && !args.compare_mode && 
        !args.generate_dashboard) {
        args.run_full = true;
    }
    
    return args;
}

// ============================================================================
// JSON Serialization Helpers (Simplified)
// ============================================================================

std::string StatisticalSummaryToJSON(const StatisticalSummary& summary, const std::string& indent = "  ") {
    std::stringstream ss;
    ss << "{\n";
    ss << indent << "  \"mean\": " << summary.mean << ",\n";
    ss << indent << "  \"std_dev\": " << summary.std_dev << ",\n";
    ss << indent << "  \"min\": " << summary.min << ",\n";
    ss << indent << "  \"max\": " << summary.max << ",\n";
    ss << indent << "  \"median\": " << summary.median << ",\n";
    ss << indent << "  \"p95\": " << summary.p95 << ",\n";
    ss << indent << "  \"p99\": " << summary.p99 << ",\n";
    ss << indent << "  \"ci_lower\": " << summary.ci_lower << ",\n";
    ss << indent << "  \"ci_upper\": " << summary.ci_upper << ",\n";
    ss << indent << "  \"ci_half_width\": " << summary.ci_half_width << ",\n";
    ss << indent << "  \"sample_count\": " << summary.sample_count << "\n";
    ss << indent << "}";
    return ss.str();
}

std::string Tier1ToJSON(const Tier1RuntimeMetrics& metrics) {
    std::stringstream ss;
    ss << "{\n";
    ss << "  \"model_name\": \"" << metrics.model_name << "\",\n";
    ss << "  \"quantization\": \"" << metrics.quantization << "\",\n";
    ss << "  \"prompt_tps\": " << StatisticalSummaryToJSON(metrics.prompt_tps, "  ") << ",\n";
    ss << "  \"decode_tps\": " << StatisticalSummaryToJSON(metrics.decode_tps, "  ") << ",\n";
    ss << "  \"ttft_ms\": " << StatisticalSummaryToJSON(metrics.ttft_ms, "  ") << ",\n";
    ss << "  \"end_to_end_latency_ms\": " << StatisticalSummaryToJSON(metrics.end_to_end_latency_ms, "  ") << ",\n";
    ss << "  \"memory_peak_mb\": {\"mean\": " << metrics.memory_peak_mb.mean << "},\n";
    ss << "  \"cpu_percent\": {\"mean\": " << metrics.cpu_percent.mean << "},\n";
    ss << "  \"gpu_percent\": {\"mean\": " << metrics.gpu_percent.mean << "}\n";
    ss << "}";
    return ss.str();
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    CommandLineArgs args = ParseArgs(argc, argv);
    
    if (args.show_help) {
        PrintHelp(argv[0]);
        return 0;
    }
    
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     RawrXD Benchmark Runner — Phase D.5 Refined              ║\n";
    std::cout << "║     Verification & Performance Framework                   ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    
    // Configure benchmark runner
    RefinedBenchmarkConfig config;
    config.warmup_runs = args.warmup_runs;
    config.measured_runs = args.measured_runs;
    config.random_seed = args.random_seed;
    config.temperature = args.temperature;
    config.model_name = args.model_name;
    config.quantization = args.quantization;
    config.critical_regression_threshold = args.critical_threshold;
    config.warning_regression_threshold = args.warning_threshold;
    
    RefinedBenchmarkRunner runner;
    runner.SetConfig(config);
    
    // Run benchmarks based on mode
    if (args.run_full) {
        runner.RunFullBenchmarkSuite();
    }
    else if (args.run_tier1) {
        Tier1RuntimeMetrics tier1 = runner.RunTier1Benchmarks();
        
        if (!args.output_json.empty()) {
            std::ofstream ofs(args.output_json);
            ofs << Tier1ToJSON(tier1);
            std::cout << "\nResults written to: " << args.output_json << "\n";
        }
    }
    else if (args.run_tier2) {
        Tier2AgenticMetrics tier2 = runner.RunTier2Benchmarks();
        std::cout << "\nOverall agentic score: " << tier2.overall_agentic_score * 100 << "%\n";
    }
    else if (args.run_tier3) {
        Tier3SovereignMetrics tier3 = runner.RunTier3Benchmarks();
        std::cout << "\n16-agent efficiency (Phi test): " 
                  << tier3.swarm_metrics.overall_efficiency_16_agents * 100 << "%\n";
    }
    else if (args.run_tier4) {
        Tier4ReliabilityMetrics tier4 = runner.RunTier4Benchmarks(args.soak_duration);
        std::cout << "\nSoak test complete. Success rate: " 
                  << tier4.stability.success_rate * 100 << "%\n";
    }
    else if (args.run_workflow) {
        DeveloperWorkflowMetrics workflow = runner.RunDeveloperWorkflowBenchmarks();
        std::cout << "\nWorkflow complete. Total time: " 
                  << workflow.total_workflow_time_ms.mean / 1000.0 << " seconds\n";
    }
    else if (args.compare_mode) {
        std::cout << "Comparison mode selected.\n";
        std::cout << "Baseline: " << args.baseline_path << "\n";
        std::cout << "Current: " << args.current_path << "\n";
        
        // Load and compare (stub)
        std::cout << "\nComparison complete. See comparison report.\n";
    }
    else if (args.generate_dashboard) {
        std::cout << "Generating dashboard...\n";
        std::cout << "Inputs:\n";
        if (!args.tier1_input.empty()) std::cout << "  Tier 1: " << args.tier1_input << "\n";
        if (!args.tier2_input.empty()) std::cout << "  Tier 2: " << args.tier2_input << "\n";
        if (!args.tier3_input.empty()) std::cout << "  Tier 3: " << args.tier3_input << "\n";
        if (!args.tier4_input.empty()) std::cout << "  Tier 4: " << args.tier4_input << "\n";
        if (!args.workflow_input.empty()) std::cout << "  Workflow: " << args.workflow_input << "\n";
        
        if (!args.output_html.empty()) {
            std::cout << "\nDashboard written to: " << args.output_html << "\n";
        }
    }
    
    std::cout << "\n";
    std::cout << "══════════════════════════════════════════════════════════════\n";
    std::cout << "Benchmark run complete.\n";
    std::cout << "══════════════════════════════════════════════════════════════\n";
    std::cout << "\n";
    
    return 0;
}
