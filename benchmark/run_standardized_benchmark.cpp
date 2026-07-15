/**
 * @file run_standardized_benchmark.cpp
 * @brief Standardized Benchmark Runner
 *
 * Command-line tool for running reproducible benchmarks.
 *
 * @copyright RawrXD 2026
 */

#include "standardized_benchmark.hpp"
#include <iostream>
#include <string>
#include <cstdlib>

using namespace rawrxd::benchmark;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " [options] \u003cmodel_path\u003e\n\n";
    std::cout << "Options:\n";
    std::cout << "  --prompt \u003ctext\u003e       Prompt text (default: \"The quick brown fox...\")\n";
    std::cout << "  --tokens \u003cn\u003e          Number of tokens to generate (default: 100)\n";
    std::cout << "  --iterations \u003cn\u003e    Number of benchmark iterations (default: 10)\n";
    std::cout << "  --warmup \u003cn\u003e        Warmup iterations (default: 3)\n";
    std::cout << "  --temperature \u003ct\u003e    Sampling temperature (default: 1.0)\n";
    std::cout << "  --top-k \u003ck\u003e          Top-k sampling (default: 40)\n";
    std::cout << "  --seed \u003cs\u003e          Random seed for reproducibility (default: 42)\n";
    std::cout << "  --output \u003cfile\u003e     Output file (default: benchmark_results.json)\n";
    std::cout << "  --format \u003cformat\u003e   Output format: json, console (default: json)\n";
    std::cout << "  --quick              Quick benchmark (5 iterations, 50 tokens)\n";
    std::cout << "  --help               Show this help\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    BenchmarkConfig config;
    std::string model_path;
    
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        } else if (arg == "--prompt" && i + 1 < argc) {
            config.prompt = argv[++i];
        } else if (arg == "--tokens" && i + 1 < argc) {
            config.max_tokens = std::atoi(argv[++i]);
        } else if (arg == "--iterations" && i + 1 < argc) {
            config.benchmark_iterations = std::atoi(argv[++i]);
        } else if (arg == "--warmup" && i + 1 < argc) {
            config.warmup_iterations = std::atoi(argv[++i]);
        } else if (arg == "--temperature" && i + 1 < argc) {
            config.temperature = std::atof(argv[++i]);
        } else if (arg == "--top-k" && i + 1 < argc) {
            config.top_k = std::atoi(argv[++i]);
        } else if (arg == "--seed" && i + 1 < argc) {
            config.seed = std::atoi(argv[++i]);
        } else if (arg == "--output" && i + 1 < argc) {
            config.output_file = argv[++i];
        } else if (arg == "--format" && i + 1 < argc) {
            config.output_format = argv[++i];
        } else if (arg == "--quick") {
            config.benchmark_iterations = 5;
            config.max_tokens = 50;
        } else if (arg[0] != '-') {
            model_path = arg;
        }
    }
    
    if (model_path.empty()) {
        std::cerr << "Error: No model path specified\n";
        PrintUsage(argv[0]);
        return 1;
    }
    
    config.model_path = model_path;
    
    // Show configuration
    std::cout << "========================================\n";
    std::cout << "RawrXD Standardized Benchmark\n";
    std::cout << "========================================\n\n";
    std::cout << "Configuration:\n";
    std::cout << "  Model: " << config.model_path << "\n";
    std::cout << "  Prompt: \"" << config.prompt.substr(0, 50) << "...\"\n";
    std::cout << "  Tokens: " << config.max_tokens << "\n";
    std::cout << "  Iterations: " << config.benchmark_iterations << "\n";
    std::cout << "  Warmup: " << config.warmup_iterations << "\n";
    std::cout << "  Temperature: " << config.temperature << "\n";
    std::cout << "  Top-k: " << config.top_k << "\n";
    std::cout << "  Seed: " << config.seed << "\n";
    std::cout << "  Output: " << config.output_file << "\n";
    std::cout << "\nEstimated duration: " << EstimateDuration(config) << "\n\n";
    
    // Run benchmark
    StandardizedBenchmark benchmark(config);
    auto results = benchmark.Run();
    
    // Output results
    if (config.output_format == "json") {
        if (benchmark.ExportJSON(config.output_file)) {
            std::cout << "Results exported to: " << config.output_file << "\n";
        } else {
            std::cerr << "Failed to export results\n";
        }
    }
    
    // Always print console report
    std::cout << "\n" << benchmark.GenerateReport() << "\n";
    
    return results.passed ? 0 : 1;
}
