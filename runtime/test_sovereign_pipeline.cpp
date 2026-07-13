// ============================================================================
// test_sovereign_pipeline.cpp - Test End-to-End Sovereign Inference
// ============================================================================

#include "sovereign_inference_pipeline.hpp"
#include <iostream>
#include <cstring>

using namespace RawrXD::Runtime;

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <tokenizer.json> <model.gguf> [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --prompt \"text\"     Prompt text (default: 'Hello, world!')" << std::endl;
    std::cout << "  --max-tokens N      Max tokens to generate (default: 50)" << std::endl;
    std::cout << "  --temperature T     Sampling temperature (default: 0.8)" << std::endl;
    std::cout << "  --top-k K           Top-k sampling (default: 40)" << std::endl;
    std::cout << "  --info              Show model info and exit" << std::endl;
    std::cout << "  --count-tokens      Count tokens in prompt and exit" << std::endl;
}

void TokenCallback(uint32_t token_id, const std::string& token_text, void* user_data) {
    (void)token_id;
    (void)user_data;
    std::cout << token_text << std::flush;
}

int main(int argc, char* argv[]) {
    std::cout << "=== Sovereign Inference Pipeline Test ===" << std::endl;
    std::cout << std::endl;
    
    if (argc < 3) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::string tokenizer_path = argv[1];
    std::string model_path = argv[2];
    
    // Default options
    std::string prompt = "Hello, world!";
    size_t max_tokens = 50;
    float temperature = 0.8f;
    int top_k = 40;
    bool show_info = false;
    bool count_tokens = false;
    
    // Parse arguments
    for (int i = 3; i < argc; ++i) {
        if (std::strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
            prompt = argv[++i];
        } else if (std::strcmp(argv[i], "--max-tokens") == 0 && i + 1 < argc) {
            max_tokens = std::stoul(argv[++i]);
        } else if (std::strcmp(argv[i], "--temperature") == 0 && i + 1 < argc) {
            temperature = std::stof(argv[++i]);
        } else if (std::strcmp(argv[i], "--top-k") == 0 && i + 1 < argc) {
            top_k = std::stoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--info") == 0) {
            show_info = true;
        } else if (std::strcmp(argv[i], "--count-tokens") == 0) {
            count_tokens = true;
        }
    }
    
    // Initialize pipeline
    std::cout << "Initializing pipeline..." << std::endl;
    std::cout << "  Tokenizer: " << tokenizer_path << std::endl;
    std::cout << "  Model: " << model_path << std::endl;
    std::cout << std::endl;
    
    SovereignInferencePipeline pipeline;
    if (!pipeline.Initialize(tokenizer_path, model_path)) {
        std::cout << "Failed to initialize pipeline" << std::endl;
        return 1;
    }
    
    std::cout << "Pipeline initialized successfully!" << std::endl;
    std::cout << "  " << pipeline.GetModelInfo() << std::endl;
    std::cout << "  Vocab size: " << pipeline.GetVocabSize() << std::endl;
    std::cout << std::endl;
    
    // Handle info mode
    if (show_info) {
        return 0;
    }
    
    // Handle count-tokens mode
    if (count_tokens) {
        size_t token_count = pipeline.CountTokens(prompt);
        std::cout << "Prompt token count: " << token_count << std::endl;
        return 0;
    }
    
    // Generate
    std::cout << "Prompt: " << prompt << std::endl;
    std::cout << std::endl;
    std::cout << "Generating (max " << max_tokens << " tokens)..." << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    GenerationConfig config;
    config.max_new_tokens = max_tokens;
    config.temperature = temperature;
    config.top_k = top_k;
    config.add_bos = true;
    config.add_eos = false;
    
    std::string output = pipeline.Generate(prompt, config);
    
    std::cout << output << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    std::cout << std::endl;
    std::cout << "Generation complete!" << std::endl;
    
    return 0;
}
