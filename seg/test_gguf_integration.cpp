// ============================================================================
// GGUF Transformer Integration Test
// Tests tight coupling between GGUF loader and Transformer Runtime
// ============================================================================

#include "gguf_transformer_integration.hpp"
#include <iostream>
#include <chrono>
#include <algorithm>

using namespace transformer;

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " <gguf_file> [command]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  info       - Show model info (default)\n";
    std::cout << "  layers     - Load and verify all layer weights\n";
    std::cout << "  inference  - Run inference test\n";
    std::cout << "  bench      - Benchmark layer loading\n";
}

int cmdInfo(const std::string& path) {
    std::cout << "========================================\n";
    std::cout << "GGUF Model Info\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Loading: " << path << "\n\n";
    
    auto model = LoadModelFromGGUF(path);
    
    if (!model.Validate()) {
        std::cerr << "ERROR: Model validation failed\n";
        return 1;
    }
    
    model.PrintInfo();
    
    return 0;
}

int cmdLayers(const std::string& path) {
    std::cout << "========================================\n";
    std::cout << "Layer Weights Verification\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Loading: " << path << "\n\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    auto model = LoadModelFromGGUF(path);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    if (!model.Validate()) {
        std::cerr << "ERROR: Model validation failed\n";
        return 1;
    }
    
    std::cout << "Loaded in " << duration.count() << " ms\n\n";
    
    // Verify each layer
    std::cout << "Verifying layers...\n";
    for (size_t i = 0; i < model.layer_weights.size(); i++) {
        const auto& w = model.layer_weights[i];
        std::cout << "Layer " << i << ":\n";
        std::cout << "  Q proj: " << (w.q_proj.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  K proj: " << (w.k_proj.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  V proj: " << (w.v_proj.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  O proj: " << (w.o_proj.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  Gate:   " << (w.gate_proj.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  Up:     " << (w.up_proj.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  Down:   " << (w.down_proj.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  In norm: " << (w.input_layernorm.empty() ? "MISSING" : "OK") << "\n";
        std::cout << "  Post norm: " << (w.post_attn_layernorm.empty() ? "MISSING" : "OK") << "\n";
    }
    
    return 0;
}

int cmdInference(const std::string& path) {
    std::cout << "========================================\n";
    std::cout << "Inference Test\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Loading model from: " << path << "\n";
    
    GGUFTransformerRuntime runtime;
    if (!runtime.InitializeFromGGUF(path)) {
        std::cerr << "ERROR: Failed to initialize runtime\n";
        return 1;
    }
    
    std::cout << "Model loaded successfully!\n\n";
    
    // Run a simple inference test
    std::vector<uint32_t> prompt = {1, 2, 3}; // Dummy tokens
    
    std::cout << "Running inference with " << prompt.size() << " token prompt...\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    auto output = runtime.Generate(prompt, 10, 0.8f, 0.9f);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "Generated " << output.size() << " tokens in " << duration.count() << " ms\n";
    std::cout << "Tokens/sec: " << (output.size() * 1000.0 / duration.count()) << "\n";
    
    return 0;
}

int cmdBenchmark(const std::string& path) {
    std::cout << "========================================\n";
    std::cout << "Loading Benchmark\n";
    std::cout << "========================================\n\n";
    
    std::cout << "File: " << path << "\n\n";
    
    // Run multiple times
    const int iterations = 5;
    std::vector<double> times;
    
    for (int i = 0; i < iterations; i++) {
        auto start = std::chrono::high_resolution_clock::now();
        auto model = LoadModelFromGGUF(path);
        auto end = std::chrono::high_resolution_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        times.push_back(duration.count());
        
        std::cout << "Run " << (i + 1) << ": " << duration.count() << " ms\n";
    }
    
    // Calculate stats
    double avg = 0;
    for (auto t : times) avg += t;
    avg /= times.size();
    
    double min_time = *std::min_element(times.begin(), times.end());
    double max_time = *std::max_element(times.begin(), times.end());
    
    std::cout << "\nStatistics:\n";
    std::cout << "  Average: " << avg << " ms\n";
    std::cout << "  Min: " << min_time << " ms\n";
    std::cout << "  Max: " << max_time << " ms\n";
    
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }
    
    std::string path = argv[1];
    std::string command = (argc > 2) ? argv[2] : "info";
    
    if (command == "info") {
        return cmdInfo(path);
    } else if (command == "layers") {
        return cmdLayers(path);
    } else if (command == "inference") {
        return cmdInference(path);
    } else if (command == "bench") {
        return cmdBenchmark(path);
    } else {
        std::cerr << "Unknown command: " << command << "\n";
        printUsage(argv[0]);
        return 1;
    }
}
