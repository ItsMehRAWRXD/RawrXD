/**
 * @file rawrxd_generate.cpp
 * @brief CLI Entry Point - Unified Generation Command
 * 
 * Single command-line interface for text generation:
 *   RawrXD.exe --generate --model model.gguf --prompt "Hello" --tokens 100
 * 
 * Replaces all fragmented CLI entry points with canonical bouncer.
 * 
 * @copyright RawrXD 2026
 */

#include "runtime/GenerationBouncer.hpp"
#include <iostream>
#include <string>
#include <cstring>

void PrintUsage(const char* program) {
    std::cout << "RawrXD Generation CLI\n";
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --model <path>      Path to GGUF model file (required)\n";
    std::cout << "  --prompt <text>     Input prompt (required)\n";
    std::cout << "  --tokens <n>        Max tokens to generate (default: 256)\n";
    std::cout << "  --temp <float>      Sampling temperature (default: 0.7)\n";
    std::cout << "  --top-p <float>     Top-p sampling (default: 0.9)\n";
    std::cout << "  --top-k <n>         Top-k sampling (default: 40)\n";
    std::cout << "  --stream            Enable streaming output\n";
    std::cout << "  --help              Show this help message\n\n";
    std::cout << "Example:\n";
    std::cout << "  " << program << " --model phi-3.gguf --prompt \"Explain AI\" --tokens 100\n";
}

struct CLIArgs {
    std::string model_path;
    std::string prompt;
    int max_tokens = 256;
    float temperature = 0.7f;
    float top_p = 0.9f;
    int top_k = 40;
    bool stream = false;
    bool help = false;
};

bool ParseArgs(int argc, char* argv[], CLIArgs& args) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--model" && i + 1 < argc) {
            args.model_path = argv[++i];
        } else if (arg == "--prompt" && i + 1 < argc) {
            args.prompt = argv[++i];
        } else if (arg == "--tokens" && i + 1 < argc) {
            args.max_tokens = std::stoi(argv[++i]);
        } else if (arg == "--temp" && i + 1 < argc) {
            args.temperature = std::stof(argv[++i]);
        } else if (arg == "--top-p" && i + 1 < argc) {
            args.top_p = std::stof(argv[++i]);
        } else if (arg == "--top-k" && i + 1 < argc) {
            args.top_k = std::stoi(argv[++i]);
        } else if (arg == "--stream") {
            args.stream = true;
        } else if (arg == "--help" || arg == "-h") {
            args.help = true;
        }
    }
    return true;
}

int main(int argc, char* argv[]) {
    CLIArgs args;
    if (!ParseArgs(argc, argv, args)) {
        std::cerr << "Error: Failed to parse arguments\n";
        PrintUsage(argv[0]);
        return 1;
    }

    if (args.help) {
        PrintUsage(argv[0]);
        return 0;
    }

    if (args.model_path.empty()) {
        std::cerr << "Error: --model is required\n";
        PrintUsage(argv[0]);
        return 1;
    }

    if (args.prompt.empty()) {
        std::cerr << "Error: --prompt is required\n";
        PrintUsage(argv[0]);
        return 1;
    }

    std::cout << "[RawrXD] Loading model: " << args.model_path << "\n";
    
    RawrXD::GenerationBouncer bouncer;
    if (!bouncer.Initialize(args.model_path)) {
        std::cerr << "Error: Failed to load model\n";
        return 1;
    }

    auto stats = bouncer.GetModelStats();
    std::cout << "[RawrXD] Model: " << stats.model_type 
              << " (" << stats.num_parameters / 1000000 << "M params, "
              << stats.num_layers << " layers)\n";

    RawrXD::GenerationRequest req;
    req.prompt = args.prompt;
    req.max_tokens = args.max_tokens;
    req.temperature = args.temperature;
    req.top_p = args.top_p;
    req.top_k = args.top_k;
    req.stream = args.stream;

    if (args.stream) {
        std::cout << "\n[Streaming]\n";
        req.on_token = [](const std::string& token) {
            std::cout << token << std::flush;
        };
    }

    std::cout << "\n[Generating]\n";
    auto result = bouncer.Generate(req);

    if (!result.success) {
        std::cerr << "Error: " << result.error << "\n";
        return 1;
    }

    if (!args.stream) {
        std::cout << result.text << "\n";
    }

    std::cout << "\n[Metrics]\n";
    std::cout << "  Tokens: " << result.tokens_generated << "\n";
    std::cout << "  TPS: " << result.tokens_per_second << "\n";
    std::cout << "  TTFT: " << result.time_to_first_token_ms << " ms\n";

    return 0;
}
