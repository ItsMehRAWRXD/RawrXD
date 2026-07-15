// ============================================================================
// Benchmark Runner - End-to-End Performance Testing
// ============================================================================
// Usage: run_benchmark.exe [--model <path>] [--tokens <n>] [--iterations <n>]
// ============================================================================

#include "end_to_end_benchmark.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>

using namespace RawrXD::Benchmark;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --model <path>         Path to GGUF model (default: mock)\n";
    std::cout << "  --tokenizer <path>     Path to tokenizer (default: mock)\n";
    std::cout << "  --tokens <n>             Max tokens to generate (default: 256)\n";
    std::cout << "  --prompt-tokens <n>      Number of prompt tokens (default: 32)\n";
    std::cout << "  --iterations <n>         Benchmark iterations (default: 10)\n";
    std::cout << "  --warmup <n>             Warmup iterations (default: 3)\n";
    std::cout << "  --no-speculative         Disable speculative decoding\n";
    std::cout << "  --draft-tokens <n>       Draft tokens for speculative (default: 4)\n";
    std::cout << "  --output <path>          Output file for results (JSON)\n";
    std::cout << "  --hardware               Show hardware info and exit\n";
    std::cout << "  --help                   Show this help\n";
}

int main(int argc, char* argv[]) {
    // Parse arguments
    BenchmarkConfig config;
    std::string output_path;
    bool show_hardware = false;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        } else if (arg == "--hardware") {
            show_hardware = true;
        } else if (arg == "--model" && i + 1 < argc) {
            config.model_path = argv[++i];
        } else if (arg == "--tokenizer" && i + 1 < argc) {
            config.tokenizer_path = argv[++i];
        } else if (arg == "--tokens" && i + 1 < argc) {
            config.max_tokens = std::stoi(argv[++i]);
        } else if (arg == "--prompt-tokens" && i + 1 < argc) {
            config.prompt_tokens = std::stoi(argv[++i]);
        } else if (arg == "--iterations" && i + 1 < argc) {
            config.benchmark_iterations = std::stoi(argv[++i]);
        } else if (arg == "--warmup" && i + 1 < argc) {
            config.warmup_iterations = std::stoi(argv[++i]);
        } else if (arg == "--no-speculative") {
            config.use_speculative = false;
        } else if (arg == "--draft-tokens" && i + 1 < argc) {
            config.draft_tokens = std::stoi(argv[++i]);
        } else if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }
    
    // Show hardware info if requested
    if (show_hardware) {
        std::cout << "========================================\n";
        std::cout << "Hardware Detection\n";
        std::cout << "========================================\n\n";
        
        auto hw = DetectHardware();
        std::cout << "CPU Features:\n";
        std::cout << "  Cores: " << hw.num_cores << "\n";
        std::cout << "  Threads: " << hw.num_threads << "\n";
        std::cout << "  AVX512: " << (hw.has_avx512 ? "Yes" : "No") << "\n";
        std::cout << "  AVX2: " << (hw.has_avx2 ? "Yes" : "No") << "\n";
        std::cout << "  FMA: " << (hw.has_fma ? "Yes" : "No") << "\n\n";
        
        std::cout << "Cache Hierarchy:\n";
        std::cout << "  L1: " << (hw.l1_cache_size / 1024) << " KB\n";
        std::cout << "  L2: " << (hw.l2_cache_size / 1024) << " KB\n";
        std::cout << "  L3: " << (hw.l3_cache_size / (1024 * 1024)) << " MB\n\n";
        
        std::cout << "Memory:\n";
        std::cout << "  Total: " << (hw.memory_size / (1024ULL * 1024 * 1024)) << " GB\n\n";
        
        std::cout << "Estimated Performance:\n";
        std::cout << "  Max GFLOPS: " << hw.estimated_max_gflops << "\n";
        
        // Estimate for common model sizes
        std::cout << "\nTheoretical Throughput:\n";
        std::cout << "  7B model (4096 hidden, 32 layers): " 
                  << EstimateTheoreticalThroughput(hw, 4096, 32, 32) << " tok/s\n";
        std::cout << "  13B model (5120 hidden, 40 layers): " 
                  << EstimateTheoreticalThroughput(hw, 5120, 40, 40) << " tok/s\n";
        std::cout << "  70B model (8192 hidden, 80 layers): " 
                  << EstimateTheoreticalThroughput(hw, 8192, 80, 64) << " tok/s\n";
        
        return 0;
    }
    
    // Print benchmark header
    std::cout << "========================================\n";
    std::cout << "RawrXD End-to-End Benchmark\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Configuration:\n";
    std::cout << "  Model: " << (config.model_path.empty() ? "(mock)" : config.model_path) << "\n";
    std::cout << "  Max tokens: " << config.max_tokens << "\n";
    std::cout << "  Iterations: " << config.benchmark_iterations << "\n";
    std::cout << "  Warmup: " << config.warmup_iterations << "\n";
    std::cout << "  Speculative: " << (config.use_speculative ? "enabled" : "disabled") << "\n";
    if (config.use_speculative) {
        std::cout << "  Draft tokens: " << config.draft_tokens << "\n";
    }
    std::cout << "\n";
    
    // Initialize benchmark
    EndToEndBenchmark benchmark;
    
    // Set progress callback
    benchmark.SetProgressCallback([](uint32_t current, uint32_t total) {
        std::cout << "\r  Progress: " << current << "/" << total << " tokens";
        std::cout.flush();
    });
    
    std::cout << "Initializing...\n";
    if (!benchmark.Initialize(config)) {
        std::cerr << "Failed to initialize: " << benchmark.GetLastError() << "\n";
        return 1;
    }
    
    // Run benchmark
    std::cout << "Running benchmark...\n";
    auto results = benchmark.Run();
    
    std::cout << "\n\n";
    std::cout << results.Summary();
    
    // Performance analysis
    auto hw = DetectHardware();
    auto analysis = AnalyzePerformance(results, hw);
    
    std::cout << "Performance Analysis:\n";
    std::cout << "  Achieved vs theoretical: " 
              << std::fixed << std::setprecision(1) 
              << analysis.achieved_vs_theoretical_percent << "%\n";
    std::cout << "  Bottleneck: " << analysis.bottleneck_analysis << "\n\n";
    
    if (!analysis.recommendations.empty()) {
        std::cout << "Recommendations:\n";
        for (const auto& rec : analysis.recommendations) {
            std::cout << "  - " << rec << "\n";
        }
        std::cout << "\n";
    }
    
    // Save results if requested
    if (!output_path.empty()) {
        std::ofstream ofs(output_path);
        if (ofs) {
            ofs << results.ToJson();
            std::cout << "Results saved to: " << output_path << "\n";
        } else {
            std::cerr << "Failed to save results to: " << output_path << "\n";
        }
    }
    
    return 0;
}
