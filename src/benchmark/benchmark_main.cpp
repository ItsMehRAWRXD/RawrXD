/**
 * @file benchmark_main.cpp
 * @brief RawrXD-Benchmark Executable Entry Point
 * @version 1.0.0
 * 
 * Standalone benchmark executable that links directly to MASM loader
 * without IDE overhead. Measures T-P-O (Time-Per-Operation) metrics.
 * 
 * Usage:
 *   RawrXD-Benchmark.exe [options]
 *   RawrXD-Benchmark.exe --mode cold_start --model model.gguf
 *   RawrXD-Benchmark.exe --mode dequant --type Q4_0 --iterations 1000000
 *   RawrXD-Benchmark.exe --mode all --output results.csv
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#include "benchmark_harness.h"
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace RawrXD::Benchmark;

// ============================================================================
// COMMAND LINE ARGUMENTS
// ============================================================================

struct CommandLineArgs {
    TestMode mode = TestMode::ALL;
    QuantType quantType = QuantType::Q4_0;
    std::string modelPath;
    std::string outputPath = "benchmark_results.csv";
    uint64_t iterations = 1000;
    uint64_t warmupIterations = 10;
    uint32_t seqLen = 1024;
    uint32_t headDim = 128;
    uint64_t cacheSizeMB = 512;
    bool verbose = false;
    bool compareBaseline = false;
    std::string baselinePath;
};

// ============================================================================
// COMMAND LINE PARSING
// ============================================================================

void PrintUsage(const char* programName) {
    std::cout << R"(
RawrXD-Benchmark: High-Performance Inference Benchmark
Version 1.0.0 | MASM-Accelerated | T-P-O Metrics

USAGE:
  )" << programName << R"( [OPTIONS]

MODES:
  --mode cold_start       Measure GGUF cold start latency
  --mode dequant          Measure dequantization kernel throughput
  --mode attention        Measure attention matrix multiplication
  --mode kv_cache         Measure KV-cache random access
  --mode token_gen        Measure end-to-end token generation
  --mode all              Run all benchmarks (default)

OPTIONS:
  --model <path>          Path to GGUF model file
  --type <Q4_0|Q4_1|Q8_0> Quantization type for dequant benchmark
  --iterations <n>        Number of benchmark iterations (default: 1000)
  --warmup <n>            Warmup iterations before measurement (default: 10)
  --output <path>         Output file for results (default: benchmark_results.csv)
  --seq-len <n>           Sequence length for attention benchmark (default: 1024)
  --head-dim <n>          Head dimension for attention benchmark (default: 128)
  --cache-size <mb>       Cache size for KV-cache benchmark (default: 512)
  --compare <path>        Compare against baseline results file
  --verbose               Enable verbose output
  --help                  Show this help message

EXAMPLES:
  # Cold start benchmark
  )" << programName << R"( --mode cold_start --model model.gguf

  # Dequantization throughput (1 million iterations)
  )" << programName << R"( --mode dequant --type Q4_0 --iterations 1000000

  # Full benchmark suite with comparison
  )" << programName << R"( --mode all --model model.gguf --compare baseline.csv

METRICS CAPTURED:
  - Cold Start Latency: Time to map GGUF + parse headers (ms)
  - Kernel Throughput: GB/s for dequantization operations
  - Attention Latency: μs for matrix multiplication
  - KV-Cache Access: Random read/write latency (ns)
  - Token Generation: Tokens per second end-to-end

)";
}

CommandLineArgs ParseCommandLine(int argc, char* argv[]) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            exit(0);
        }
        else if (arg == "--mode" && i + 1 < argc) {
            std::string mode = argv[++i];
            if (mode == "cold_start") args.mode = TestMode::COLD_START;
            else if (mode == "dequant") args.mode = TestMode::KERNEL_DEQUANT;
            else if (mode == "attention") args.mode = TestMode::KERNEL_ATTENTION;
            else if (mode == "kv_cache") args.mode = TestMode::KV_CACHE_ACCESS;
            else if (mode == "token_gen") args.mode = TestMode::END_TO_END_TOKEN;
            else if (mode == "all") args.mode = TestMode::ALL;
            else {
                std::cerr << "Error: Unknown mode: " << mode << std::endl;
                exit(1);
            }
        }
        else if (arg == "--model" && i + 1 < argc) {
            args.modelPath = argv[++i];
        }
        else if (arg == "--type" && i + 1 < argc) {
            std::string type = argv[++i];
            if (type == "Q4_0") args.quantType = QuantType::Q4_0;
            else if (type == "Q4_1") args.quantType = QuantType::Q4_1;
            else if (type == "Q5_0") args.quantType = QuantType::Q5_0;
            else if (type == "Q5_1") args.quantType = QuantType::Q5_1;
            else if (type == "Q8_0") args.quantType = QuantType::Q8_0;
            else if (type == "F16") args.quantType = QuantType::F16;
            else if (type == "F32") args.quantType = QuantType::F32;
            else {
                std::cerr << "Error: Unknown quantization type: " << type << std::endl;
                exit(1);
            }
        }
        else if (arg == "--iterations" && i + 1 < argc) {
            args.iterations = std::stoull(argv[++i]);
        }
        else if (arg == "--warmup" && i + 1 < argc) {
            args.warmupIterations = std::stoull(argv[++i]);
        }
        else if (arg == "--output" && i + 1 < argc) {
            args.outputPath = argv[++i];
        }
        else if (arg == "--seq-len" && i + 1 < argc) {
            args.seqLen = std::stoul(argv[++i]);
        }
        else if (arg == "--head-dim" && i + 1 < argc) {
            args.headDim = std::stoul(argv[++i]);
        }
        else if (arg == "--cache-size" && i + 1 < argc) {
            args.cacheSizeMB = std::stoull(argv[++i]);
        }
        else if (arg == "--compare" && i + 1 < argc) {
            args.compareBaseline = true;
            args.baselinePath = argv[++i];
        }
        else if (arg == "--verbose" || arg == "-v") {
            args.verbose = true;
        }
        else {
            std::cerr << "Error: Unknown argument: " << arg << std::endl;
            PrintUsage(argv[0]);
            exit(1);
        }
    }
    
    return args;
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main(int argc, char* argv[]) {
    // Set console output to UTF-8 on Windows
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    #endif
    
    // Print banner
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║           RawrXD-Benchmark v1.0.0 - Performance Harness          ║
║                                                                  ║
║     MASM-Accelerated Inference | T-P-O Metrics | Zero Stubs      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

)";
    
    // Parse command line
    CommandLineArgs args = ParseCommandLine(argc, argv);
    
    // Validate required arguments
    if ((args.mode == TestMode::COLD_START || args.mode == TestMode::END_TO_END_TOKEN) 
        && args.modelPath.empty()) {
        std::cerr << "Error: --model required for cold_start and token_gen modes" << std::endl;
        return 1;
    }
    
    // Configure benchmark harness
    BenchmarkConfig config;
    config.warmupIterations = args.warmupIterations;
    config.benchmarkIterations = args.iterations;
    config.enableProfiling = args.verbose;
    if (!args.modelPath.empty()) {
        config.modelPaths.push_back(args.modelPath);
    }
    
    // Initialize harness
    BenchmarkHarness harness;
    if (!harness.Initialize(config)) {
        std::cerr << "Error: Failed to initialize benchmark harness" << std::endl;
        return 1;
    }
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Mode: " << [args]() {
        switch (args.mode) {
            case TestMode::COLD_START: return "Cold Start";
            case TestMode::KERNEL_DEQUANT: return "Dequantization Kernel";
            case TestMode::KERNEL_ATTENTION: return "Attention";
            case TestMode::KV_CACHE_ACCESS: return "KV-Cache Access";
            case TestMode::END_TO_END_TOKEN: return "Token Generation";
            case TestMode::ALL: return "All Tests";
            default: return "Unknown";
        }
    }() << std::endl;
    std::cout << "  Iterations: " << args.iterations << std::endl;
    std::cout << "  Warmup: " << args.warmupIterations << std::endl;
    if (!args.modelPath.empty()) {
        std::cout << "  Model: " << args.modelPath << std::endl;
    }
    std::cout << std::endl;
    
    // Run benchmarks based on mode
    std::vector<BenchmarkResult> results;
    
    switch (args.mode) {
        case TestMode::COLD_START: {
            std::cout << "Running cold start benchmark..." << std::endl;
            results.push_back(harness.RunColdStart(args.modelPath));
            break;
        }
        case TestMode::KERNEL_DEQUANT: {
            std::cout << "Running dequantization benchmark..." << std::endl;
            results.push_back(harness.RunDequantBenchmark(args.quantType, args.iterations));
            break;
        }
        case TestMode::KERNEL_ATTENTION: {
            std::cout << "Running attention benchmark..." << std::endl;
            results.push_back(harness.RunAttentionBenchmark(args.seqLen, args.headDim));
            break;
        }
        case TestMode::KV_CACHE_ACCESS: {
            std::cout << "Running KV-cache benchmark..." << std::endl;
            results.push_back(harness.RunKVCacheBenchmark(args.cacheSizeMB, args.iterations));
            break;
        }
        case TestMode::END_TO_END_TOKEN: {
            std::cout << "Running token generation benchmark..." << std::endl;
            results.push_back(harness.RunTokenGeneration(args.modelPath, 100));
            break;
        }
        case TestMode::ALL: {
            std::cout << "Running full benchmark suite..." << std::endl;
            results = harness.RunAllBenchmarks();
            break;
        }
    }
    
    // Print and export results
    std::cout << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << "                         BENCHMARK RESULTS                         " << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << std::endl;
    
    for (auto& result : results) {
        result.PrintResults();
        
        // Export to CSV
        std::string outputFile = args.outputPath;
        if (results.size() > 1) {
            // Append test name for multiple results
            size_t dotPos = outputFile.find_last_of('.');
            if (dotPos != std::string::npos) {
                outputFile.insert(dotPos, "_" + result.testName);
            }
        }
        result.ExportToCSV(outputFile);
        std::cout << "  Exported to: " << outputFile << std::endl;
        
        // Compare to baseline if requested
        if (args.compareBaseline) {
            std::cout << std::endl;
            std::string comparison = harness.CompareToBaseline(result, args.baselinePath);
            std::cout << comparison << std::endl;
        }
        
        std::cout << std::endl;
    }
    
    // Shutdown harness
    harness.Shutdown();
    
    std::cout << "═══════════════════════════════════════════════════════════════════" << std::endl;
    std::cout << "                    Benchmark Complete                             " << std::endl;
    std::cout << "═══════════════════════════════════════════════════════════════════" << std::endl;
    
    return 0;
}
