/**
 * @file generate_cli.cpp
 * @brief Unified CLI for token generation - uses GenerationBouncer
 * 
 * Usage: RawrXD-Generate.exe --model model.gguf --prompt "Hello" --tokens 50
 */

#include "runtime/GenerationBouncer.hpp"
#include <iostream>
#include <string>
#include <cstring>

void PrintUsage() {
    std::cout << "Usage: RawrXD-Generate.exe [options]\n"
              << "Options:\n"
              << "  --model <path>     Path to GGUF model file\n"
              << "  --prompt <text>    Input prompt\n"
              << "  --tokens <n>       Max tokens to generate (default: 256)\n"
              << "  --temp <float>     Temperature (default: 0.7)\n"
              << "  --top-p <float>    Top-p (default: 0.9)\n"
              << "  --top-k <int>      Top-k (default: 40)\n"
              << "  --stream           Enable streaming output\n"
              << "  --help             Show this help\n";
}

int main(int argc, char* argv[]) {
    std::string modelPath;
    std::string prompt;
    int maxTokens = 256;
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    bool streaming = false;
    
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            modelPath = argv[++i];
        } else if (std::strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
            prompt = argv[++i];
        } else if (std::strcmp(argv[i], "--tokens") == 0 && i + 1 < argc) {
            maxTokens = std::stoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--temp") == 0 && i + 1 < argc) {
            temperature = std::stof(argv[++i]);
        } else if (std::strcmp(argv[i], "--top-p") == 0 && i + 1 < argc) {
            topP = std::stof(argv[++i]);
        } else if (std::strcmp(argv[i], "--top-k") == 0 && i + 1 < argc) {
            topK = std::stoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--stream") == 0) {
            streaming = true;
        } else if (std::strcmp(argv[i], "--help") == 0) {
            PrintUsage();
            return 0;
        }
    }
    
    if (modelPath.empty() || prompt.empty()) {
        std::cerr << "Error: --model and --prompt are required\n";
        PrintUsage();
        return 1;
    }
    
    std::cout << "[RawrXD-Generate] Loading model: " << modelPath << std::endl;
    
    RawrXD::GenerationBouncer bouncer;
    
    if (!bouncer.Initialize(modelPath)) {
        std::cerr << "[RawrXD-Generate] Failed to load model\n";
        return 1;
    }
    
    RawrXD::GenerationRequest req;
    req.prompt = prompt;
    req.max_tokens = maxTokens;
    req.temperature = temperature;
    req.top_p = topP;
    req.top_k = topK;
    req.stream = streaming;
    
    std::cout << "[RawrXD-Generate] Generating response...\n" << std::endl;
    std::cout << "Prompt: " << prompt << "\n" << std::endl;
    
    if (streaming) {
        req.on_token = [](const std::string& text) {
            std::cout << text << std::flush;
        };
        
        auto result = bouncer.GenerateStreaming(req);
        
        std::cout << "\n\n[Generation Complete]" << std::endl;
        std::cout << "Tokens: " << result.tokens_generated << std::endl;
        std::cout << "TPS: " << result.tokens_per_second << std::endl;
        std::cout << "TTFT: " << result.time_to_first_token_ms << " ms" << std::endl;
    } else {
        auto result = bouncer.Generate(req);
        
        if (result.success) {
            std::cout << "\n[Generated Text]" << std::endl;
            std::cout << result.text << std::endl;
            std::cout << "\n[Statistics]" << std::endl;
            std::cout << "Tokens: " << result.tokens_generated << std::endl;
            std::cout << "TPS: " << result.tokens_per_second << std::endl;
            std::cout << "TTFT: " << result.time_to_first_token_ms << " ms" << std::endl;
        } else {
            std::cerr << "[Error] " << result.error << std::endl;
            return 1;
        }
    }
    
    bouncer.Shutdown();
    return 0;
}
