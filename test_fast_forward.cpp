// Fast test: Load model and do minimal forward pass
#include <iostream>
#include <chrono>
#include "src/quantization/quantized_model.hpp"
#include "src/quantization/gguf_loader.hpp"

using namespace rawrxd::quantization;

int main(int argc, char* argv[]) {
    std::cout << "=== Fast Forward Test ===" << std::endl;
    
    const char* modelPath = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    std::cout << "Model: " << modelPath << std::endl;
    
    // Step 1: Validate GGUF
    std::cout << "Step 1: Validating GGUF..." << std::endl;
    if (!GGUFModelLoader::IsValidGGUF(modelPath)) {
        std::cerr << "Invalid GGUF" << std::endl;
        return 1;
    }
    std::cout << "  OK" << std::endl;
    
    // Step 2: Load metadata
    std::cout << "Step 2: Loading metadata..." << std::endl;
    GGUFModelLoader loader;
    if (!loader.Load(modelPath)) {
        std::cerr << "Failed to load metadata" << std::endl;
        return 1;
    }
    std::cout << "  OK - " << loader.GetConfig().block_count << " layers" << std::endl;
    
    // Step 3: Initialize model
    std::cout << "Step 3: Initializing model..." << std::endl;
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
        std::cerr << "Failed to initialize" << std::endl;
        return 1;
    }
    std::cout << "  OK" << std::endl;
    
    // Step 4: Load weights
    std::cout << "Step 4: Loading weights..." << std::endl;
    if (!model.LoadFromGGUF(modelPath)) {
        std::cerr << "Failed to load weights" << std::endl;
        return 1;
    }
    std::cout << "  OK" << std::endl;
    
    // Step 5: Fast forward pass - just embedding lookup + single layer
    std::cout << "Step 5: Fast forward pass (embedding only)..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<int32_t> tokens = {1};  // Single token
    std::vector<float> logits;
    
    // Use batch_size=1, seq_len=1 for speed
    if (!model.Forward(tokens, logits, 1, 1)) {
        std::cerr << "Forward failed" << std::endl;
        return 1;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    std::cout << "  OK - " << logits.size() << " logits" << std::endl;
    std::cout << "  Time: " << duration << " ms" << std::endl;
    
    // Calculate tokens/sec
    double tokens_per_sec = 1000.0 / duration;
    std::cout << "  Throughput: " << tokens_per_sec << " tok/s" << std::endl;
    
    // Step 6: Model info
    std::cout << "\n=== Model Info ===" << std::endl;
    std::cout << model.GetModelInfo() << std::endl;
    
    std::cout << "\n=== SUCCESS ===" << std::endl;
    return 0;
}
