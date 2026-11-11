// Benchmark: Measure actual inference throughput
#include <iostream>
#include <chrono>
#include <vector>
#include <math>
#include "src/quantization/quantized_model.hpp"
#include "src/quantization/gguf_loader.hpp"

using namespace rawrxd::quantization;

int main(int argc, char* argv[]) {
    std::cout << "=== RawrXD Inference Benchmark ===" << std::endl;
    std::cout << "Target: 131+ tok/s (CPU) → 500+ tok/s (GPU) → 600+ tok/s (Medusa)" << std::endl;
    std::cout << "Model: ministral3 Q4_0 (24 layers, 1024 hidden, 131072 vocab)" << std::endl;
    std::cout << "Context: 32K supported" << std::endl;
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
    
    if (!model.Initialize(config)) {
        std::cerr << "Failed to initialize model" << std::endl;
        return 1;
    }
    
    if (!model.LoadFromGGUF(modelPath)) {
        std::cerr << "Failed to load weights" << std::endl;
        return 1;
    }
    
    auto load_end = std::chrono::high_resolution_clock::now();
    double load_time = std::chrono::duration<double>(load_end - load_start).count();
    std::cout << "      Loaded in " << load_time << "s" << std::endl;
    
    // Warmup
    std::cout << "[2/3] Warming up..." << std::endl;
    std::vector<int32_t> warmup_tokens = {1, 2, 3};
    std::vector<float> warmup_logits;
    for (int i = 0; i < 3; i++) {
        model.Forward(warmup_tokens, warmup_logits, 1, warmup_tokens.size());
    }
    std::cout << "      Warmup complete" << std::endl;
    
    // Benchmark
    std::cout << "[3/3] Benchmarking..." << std::endl;
    std::cout << std::endl;
    
    // Test different sequence lengths
    std::vector<size_t> seq_lengths = {1, 8, 16, 32, 64, 128};
    
    for (size_t seq_len : seq_lengths) {
        std::vector<int32_t> tokens(seq_len);
        for (size_t i = 0; i < seq_len; i++) tokens[i] = (i % 1000) + 1;
        
        std::vector<float> logits;
        
        // Single forward pass
        auto start = std::chrono::high_resolution_clock::now();
        bool success = model.Forward(tokens, logits, 1, seq_len);
        auto end = std::chrono::high_resolution_clock::now();
        
        if (!success) {
            std::cerr << "Forward failed for seq_len=" << seq_len << std::endl;
            continue;
        }
        
        double duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double tokens_per_sec = (seq_len / duration_ms) * 1000.0;
        double ms_per_token = duration_ms / seq_len;
        
        std::cout << "  Seq " << seq_len << ": "
                  << duration_ms << " ms, "
                  << tokens_per_sec << " tok/s, "
                  << ms_per_token << " ms/tok"
                  << std::endl;
    }
    
    // Summary
    std::cout << std::endl;
    std::cout << "=== Results ===" << std::endl;
    std::cout << model.GetModelInfo() << std::endl;
    std::cout << std::endl;
    std::cout << "Next steps for 131+ tok/s:" << std::endl;
    std::cout << "  1. AVX2/AVX512 kernels for MatMul" << std::endl;
    std::cout << "  2. FlashAttention for O(n) memory" << std::endl;
    std::cout << "  3. GPU Vulkan compute shaders" << std::endl;
    std::cout << "  4. Medusa speculative decoding" << std::endl;
    
    return 0;
}
