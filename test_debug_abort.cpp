// Debug Test: Find where abort() is called
#include <iostream>
#include <csignal>

// Custom abort handler
void abort_handler(int sig) {
    std::cerr << "\n*** ABORT CAUGHT ***" << std::endl;
    std::cerr << "Signal: " << sig << std::endl;
    exit(1);
}

#include "src/quantization/quantized_model.hpp"
#include "src/quantization/gguf_loader.hpp"

using namespace rawrxd::quantization;

int main(int argc, char* argv[]) {
    // Install signal handler
    signal(SIGABRT, abort_handler);
    signal(SIGSEGV, abort_handler);
    
    std::cout << "=== Debug Abort Test ===" << std::endl;
    
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
    
    // Step 3: Initialize model with correct dimensions from GGUF
    std::cout << "Step 3: Initializing model..." << std::endl;
    QuantizedModel model;
    QuantizedModelConfig config;
    config.mode = QuantizationMode::Q4_0;
    // Use dimensions from GGUF metadata
    config.num_layers = loader.GetConfig().block_count;  // 24
    config.hidden_size = loader.GetConfig().embedding_length;  // 1024
    config.vocab_size = loader.GetConfig().vocab_size;  // 131072
    config.num_heads = loader.GetConfig().head_count;  // 16
    config.num_kv_heads = loader.GetConfig().head_count_kv;  // 16
    config.intermediate_size = loader.GetConfig().feed_forward_length;  // 8192
    config.max_seq_length = 32768;
    
    if (!model.Initialize(config)) {
        std::cerr << "Failed to initialize" << std::endl;
        return 1;
    }
    std::cout << "  OK" << std::endl;
    
    // Step 4: Try to load weights (this is where it might abort)
    std::cout << "Step 4: Loading weights..." << std::endl;
    std::cout << "  About to call LoadFromGGUF..." << std::endl;
    
    bool loaded = model.LoadFromGGUF(modelPath);
    
    std::cout << "  LoadFromGGUF returned: " << (loaded ? "true" : "false") << std::endl;
    
    // Step 5: Forward pass
    std::cout << "Step 5: Forward pass..." << std::endl;
    std::vector<int32_t> tokens = {1, 2, 3};
    std::vector<float> logits;
    
    if (!model.Forward(tokens, logits, 1, tokens.size())) {
        std::cerr << "Forward failed" << std::endl;
        return 1;
    }
    std::cout << "  OK - " << logits.size() << " logits" << std::endl;
    
    std::cout << "\n=== SUCCESS ===" << std::endl;
    return 0;
}
