// ============================================================================
// Test Program for GPU-Accelerated Transformer
// ============================================================================

#include "transformer_gpu_complete.hpp"
#include <iostream>
#include <vector>

using namespace transformer_gpu;

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "GPU Transformer Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // Initialize transformer
    TransformerGPU model;
    std::string shaderPath = "d:/rawrxd/src/inference/shaders";
    
    std::cout << "Initializing transformer..." << std::endl;
    if (!model.Initialize("", shaderPath)) {
        std::cerr << "Failed to initialize model" << std::endl;
        return 1;
    }

    // Create prompt
    std::vector<int> prompt = {1, 2, 3, 4, 5}; // Token IDs
    
    std::cout << std::endl;
    std::cout << "Running benchmark..." << std::endl;
    std::cout << "  Prompt size: " << prompt.size() << " tokens" << std::endl;
    std::cout << "  Generating: 10 tokens" << std::endl;
    std::cout << std::endl;

    // Benchmark
    PerformanceMetrics metrics = BenchmarkTransformer(model, prompt, 10);

    // Results
    std::cout << "========================================" << std::endl;
    std::cout << "Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "  Tokens generated: " << metrics.total_tokens << std::endl;
    std::cout << "  Layers processed: " << metrics.total_layers << std::endl;
    std::cout << std::endl;
    std::cout << "  Tokens/sec: " << metrics.tokens_per_second << std::endl;
    std::cout << "  Time/token: " << metrics.time_per_token_ms << " ms" << std::endl;
    std::cout << "  Time/layer: " << metrics.time_per_layer_us << " us" << std::endl;
    std::cout << std::endl;

    // Status
    if (metrics.tokens_per_second >= 150.0) {
        std::cout << "✅ TARGET ACHIEVED: 150+ tok/s" << std::endl;
    } else if (metrics.tokens_per_second >= 100.0) {
        std::cout << "✅ GOOD: 100+ tok/s" << std::endl;
    } else {
        std::cout << "⚠ NEEDS OPTIMIZATION: " << metrics.tokens_per_second << " tok/s" << std::endl;
    }

    // Cleanup
    model.Cleanup();

    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Test complete" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
