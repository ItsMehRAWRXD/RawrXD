// Minimal Pipeline Test - Step by step debugging
#include <iostream>
#include <vector>

#include "src/quantization/quantized_model.hpp"
#include "src/quantization/gguf_loader.hpp"

using namespace rawrxd::quantization;

int main(int argc, char* argv[]) {
    std::cout << "=== Minimal Pipeline Test ===" << std::endl;
    
    const char* modelPath = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    std::cout << "Model: " << modelPath << std::endl;
    
    // Step 1: Check if file exists
    std::cout << "Step 1: Checking file..." << std::endl;
    if (!GGUFModelLoader::IsValidGGUF(modelPath)) {
        std::cerr << "  Not a valid GGUF file" << std::endl;
        return 1;
    }
    std::cout << "  OK: Valid GGUF" << std::endl;
    
    // Step 2: Load metadata
    std::cout << "Step 2: Loading metadata..." << std::endl;
    GGUFModelLoader loader;
    if (!loader.Load(modelPath)) {
        std::cerr << "  Failed to load GGUF" << std::endl;
        return 1;
    }
    std::cout << "  OK: Metadata loaded" << std::endl;
    
    const auto& config = loader.GetConfig();
    std::cout << "  Architecture: " << config.architecture << std::endl;
    std::cout << "  Layers: " << config.block_count << std::endl;
    std::cout << "  Hidden: " << config.embedding_length << std::endl;
    std::cout << "  Vocab: " << config.vocab_size << std::endl;
    
    // Step 3: Initialize model
    std::cout << "Step 3: Initializing model..." << std::endl;
    QuantizedModel model;
    QuantizedModelConfig qcfg;
    qcfg.mode = QuantizationMode::Q4_0;
    qcfg.num_layers = config.block_count > 0 ? config.block_count : 28;
    qcfg.hidden_size = config.embedding_length > 0 ? config.embedding_length : 3072;
    qcfg.vocab_size = config.vocab_size > 0 ? config.vocab_size : 128256;
    qcfg.num_heads = config.head_count > 0 ? config.head_count : 24;
    qcfg.num_kv_heads = config.head_count_kv > 0 ? config.head_count_kv : 8;
    qcfg.intermediate_size = config.feed_forward_length > 0 ? config.feed_forward_length : 8192;
    qcfg.max_seq_length = 32768;
    
    if (!model.Initialize(qcfg)) {
        std::cerr << "  Failed to initialize model" << std::endl;
        return 1;
    }
    std::cout << "  OK: Model initialized" << std::endl;
    
    // Step 4: Load weights (this is where it might crash)
    std::cout << "Step 4: Loading weights..." << std::endl;
    if (!model.LoadFromGGUF(modelPath)) {
        std::cerr << "  Warning: Failed to load weights (continuing with synthetic)" << std::endl;
    } else {
        std::cout << "  OK: Weights loaded" << std::endl;
    }
    
    // Step 5: Test forward pass
    std::cout << "Step 5: Testing forward pass..." << std::endl;
    std::vector<int32_t> tokens = {1, 2, 3, 4, 5};
    std::vector<float> logits;
    
    if (!model.Forward(tokens, logits, 1, tokens.size())) {
        std::cerr << "  Forward pass failed" << std::endl;
        return 1;
    }
    std::cout << "  OK: Forward pass complete, " << logits.size() << " logits" << std::endl;
    
    // Step 6: Generate token
    std::cout << "Step 6: Generating token..." << std::endl;
    int32_t nextToken = model.GenerateNextToken(tokens, 1.0f, 40);
    std::cout << "  Generated token: " << nextToken << std::endl;
    
    std::cout << std::endl << "=== All Steps Complete ===" << std::endl;
    return 0;
}
