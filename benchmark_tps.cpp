// TPS Benchmark: Measure actual inference throughput
#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>
#include "src/quantization/quantized_model.hpp"
#include "src/quantization/gguf_loader.hpp"

using namespace rawrxd::quantization;

int main(int argc, char* argv[]) {
    std::cout << "=== RawrXD TPS Benchmark ===" << std::endl;
    std::cout << "Target: 131+ tok/s (CPU) → 500+ tok/s (GPU) → 600+ tok/s (Medusa)" << std::endl;
    std::cout << std::endl;
    
    const char* modelPath = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    
    // Load model
    std::cout << "[1/3] Loading model..." << std::endl;
    auto load_start = std::chrono::high_resolution_clock::now();
    
    GGUFModelLoader loader;
    if (!loader.Load(modelPath)) {
        std::cerr << "Failed to load GGUF" << std::endl;
        return 1;
    }
    
    QuantizedModel model;
    QuantizedModelConfig config;
    config.mode = QuantizationMode::Q4_0;
    config.num_layers = loader.GetConfig().block_count;
    config.hidden_size = loader.GetConfig().embedding_length;
    config.vocab_size = loader.GetConfig().vocab_size;
    config.num_heads = loader.GetConfig().head_count;
    config.num_kv_heads = loader.GetConfig().head_count_kv;
    config.intermediate_size = loader.GetConfig().feed_forward_length;
    config.max_seq_length = 32768;
    
    if (!model.Initialize(config) || !model.LoadFromGGUF(modelPath)) {
        std::cerr << "Failed to initialize/load model" << std::endl;
        return 1;
    }
    
    auto load_end = std::chrono::high_resolution_clock::now();
    double load_time = std::chrono::duration<double>(load_end - load_start).count();
    std::cout << "      Loaded in " << load_time << "s" << std::endl;
    
    // Warmup
    std::cout << "[2/3] Warming up..." << std::endl;
    std::vector<int32_t> warmup = {1, 2, 3};
    std::vector<float> logits;
    for (int i = 0; i < 3; i++) {
        model.Forward(warmup, logits, 1, warmup.size());
    }
    std::cout << "      Warmup complete" << std::endl;
    
    // Benchmark
    std::cout << "[3/3] Benchmarking..." << std::endl;
    std::cout << std::endl;
    
    std::vector<size_t> seq_lengths = {1, 8, 16, 32, 64, 128};
    
    for (size_t seq_len : seq_lengths) {
        std::vector<int32_t> tokens(seq_len);
        for (size_t i = 0; i < seq_len; i++) tokens[i] = (i % 1000) + 1;
        
        // Run multiple iterations for accurate timing
        int iterations = (seq_len <= 8) ? 10 : 3;
        double total_ms = 0;
        
        for (int iter = 0; iter < iterations; iter++) {
            auto start = std::chrono::high_resolution_clock::now();
            model.Forward(tokens, logits, 1, seq_len);
            auto end = std::chrono::high_resolution_clock::now();
            total_ms += std::chrono::duration<double, std::milli>(end - start).count();
        }
        
        double avg_ms = total_ms / iterations;
        double tokens_per_sec = (seq_len / avg_ms) * 1000.0;
        double ms_per_token = avg_ms / seq_len;
        
        std::cout << "  Seq " << seq_len << ": "
                  << avg_ms << " ms, "
                  << tokens_per_sec << " tok/s, "
                  << ms_per_token << " ms/tok"
                  << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "=== Results ===" << std::endl;
    std::cout << model.GetModelInfo() << std::endl;
    
    return 0;
}
