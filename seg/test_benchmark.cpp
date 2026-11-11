// ============================================================================
// Benchmark Test Runner
// ============================================================================
// Run performance benchmarks to establish baseline
// ============================================================================

#include "benchmark_suite.hpp"
#include <iostream>

using namespace SEG;

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Performance Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Parse command line
    std::string model_path = "d:/models/ministral3_q4_0.gguf";
    if (argc > 1) {
        model_path = argv[1];
    }
    
    std::cout << "Model: " << model_path << std::endl;
    std::cout << std::endl;
    
    // Configure benchmark
    BenchmarkConfig config;
    config.model_path = model_path;
    config.iterations = 3;
    config.max_tokens = 20;
    config.warmup_tokens = 5;
    
    // Run benchmark
    BenchmarkRunner runner(config);
    BenchmarkResults results = runner.Run();
    
    // Print detailed report
    runner.PrintReport();
    
    // Export results
    runner.ExportCSV("benchmark_results.csv");
    runner.ExportJSON("benchmark_results.json");
    
    // Compare with reference
    std::cout << "\n========================================" << std::endl;
    std::cout << "Next Steps:" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (results.tokens_per_sec < 1.0) {
        std::cout << "1. Implement AVX-512 kernels for MatMul" << std::endl;
        std::cout << "2. Integrate FlashAttention v2" << std::endl;
        std::cout << "3. Profile to identify bottlenecks" << std::endl;
    } else if (results.tokens_per_sec < 10.0) {
        std::cout << "1. Optimize attention computation" << std::endl;
        std::cout << "2. Add multi-threading across heads" << std::endl;
    } else {
        std::cout << "Performance is good! Consider:" << std::endl;
        std::cout << "1. Quantization (Q4_K, Q8_0)" << std::endl;
        std::cout << "2. Batch inference" << std::endl;
    }
    
    return 0;
}
