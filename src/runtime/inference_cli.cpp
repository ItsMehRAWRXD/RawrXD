/**
 * @file inference_cli.cpp
 * @brief RawrXD Inference CLI - Complete Pipeline Integration
 *
 * End-to-end inference: GGUF → Tokens → Embeddings → Inference → Text
 * Zero external dependencies. Pure C++17.
 *
 * @copyright RawrXD 2026
 */

#include "inference_engine.hpp"
#include "embedding_lookup.hpp"
#include "tokenizer_runtime.h"
#include "../model/model_context.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include <csignal>

using namespace rawrxd::runtime;
using namespace rawrxd::model;

// ============================================================================
// CLI Configuration
// ============================================================================

struct CLIConfig {
    std::string model_path;
    std::string prompt;
    std::string mode = "generate";  // generate, chat, benchmark
    
    // Generation parameters
    uint32_t max_tokens = 256;
    float temperature = 0.8f;
    float top_p = 0.95f;
    uint32_t top_k = 40;
    float repetition_penalty = 1.0f;
    
    // I/O options
    bool streaming = true;
    bool verbose = false;
    bool benchmark = false;
    
    // Parse from command line
    static CLIConfig Parse(int argc, char* argv[]);
    void PrintHelp() const;
};

CLIConfig CLIConfig::Parse(int argc, char* argv[]) {
    CLIConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            config.PrintHelp();
            std::exit(0);
        } else if (arg == "-m" || arg == "--model") {
            if (++i < argc) config.model_path = argv[i];
        } else if (arg == "-p" || arg == "--prompt") {
            if (++i < argc) config.prompt = argv[i];
        } else if (arg == "--mode") {
            if (++i < argc) config.mode = argv[i];
        } else if (arg == "-n" || arg == "--max-tokens") {
            if (++i < argc) config.max_tokens = std::stoul(argv[i]);
        } else if (arg == "-t" || arg == "--temperature") {
            if (++i < argc) config.temperature = std::stof(argv[i]);
        } else if (arg == "--top-p") {
            if (++i < argc) config.top_p = std::stof(argv[i]);
        } else if (arg == "--top-k") {
            if (++i < argc) config.top_k = std::stoul(argv[i]);
        } else if (arg == "--repeat-penalty") {
            if (++i < argc) config.repetition_penalty = std::stof(argv[i]);
        } else if (arg == "--no-stream") {
            config.streaming = false;
        } else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--benchmark") {
            config.benchmark = true;
        } else if (arg[0] != '-') {
            // Positional argument: prompt
            config.prompt = arg;
        }
    }
    
    return config;
}

void CLIConfig::PrintHelp() const {
    std::cout << "RawrXD Inference CLI - Complete Pipeline C1-C4\n"
              << "=============================================\n\n"
              << "Usage: inference_cli [options] [prompt]\n\n"
              << "Options:\n"
              << "  -m, --model PATH         GGUF model path (required)\n"
              << "  -p, --prompt TEXT        Input prompt\n"
              << "      --mode MODE          Mode: generate, chat, benchmark\n"
              << "  -n, --max-tokens N       Max tokens to generate (default: 256)\n"
              << "  -t, --temperature T      Sampling temperature (default: 0.8)\n"
              << "      --top-p P            Top-p sampling (default: 0.95)\n"
              << "      --top-k K            Top-k sampling (default: 40)\n"
              << "      --repeat-penalty P   Repetition penalty (default: 1.0)\n"
              << "      --no-stream          Disable streaming output\n"
              << "      --benchmark          Run benchmark mode\n"
              << "  -v, --verbose            Verbose output\n"
              << "  -h, --help               Show this help\n\n"
              << "Examples:\n"
              << "  inference_cli -m model.gguf -p \"Hello world\"\n"
              << "  inference_cli -m model.gguf --benchmark\n"
              << "  inference_cli -m model.gguf --mode chat\n";
}

// ============================================================================
// Pipeline Integration
// ============================================================================

class InferencePipeline {
public:
    bool Initialize(const std::string& model_path, bool verbose = false);
    std::string Generate(const std::string& prompt, const InferenceConfig& config);
    void GenerateStreaming(const std::string& prompt, const InferenceConfig& config);
    
    const InferenceTelemetry& GetLastTelemetry() const { return last_telemetry_; }
    bool IsInitialized() const { return initialized_; }
    const std::string& GetLastError() const { return last_error_; }
    
    // Component access for advanced usage
    const ModelContext& GetModel() const { return model_; }
    const Tokenizer& GetTokenizer() const { return tokenizer_; }
    const EmbeddingLookup& GetEmbeddingLookup() const { return embedding_lookup_; }
    const InferenceEngine& GetEngine() const { return engine_; }
    
private:
    bool initialized_ = false;
    std::string last_error_;
    InferenceTelemetry last_telemetry_;
    
    ModelContext model_;
    Tokenizer tokenizer_;
    EmbeddingLookup embedding_lookup_;
    InferenceEngine engine_;
};

bool InferencePipeline::Initialize(const std::string& model_path, bool verbose) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    // C1: Load Model
    if (verbose) std::cout << "[C1] Loading model: " << model_path << std::endl;
    
    if (!model_.LoadFromFile(model_path)) {
        last_error_ = "Failed to load model: " + model_path;
        return false;
    }
    
    const auto& arch = model_.GetArchitecture();
    if (verbose) {
        std::cout << "[C1] Model loaded:\n"
                  << "     Type: " << arch.type << "\n"
                  << "     Vocab: " << arch.vocab_size << "\n"
                  << "     Layers: " << arch.layer_count << "\n"
                  << "     Hidden: " << arch.embedding_dim << "\n"
                  << "     Context: " << arch.context_length << std::endl;
    }
    
    // C2: Initialize Tokenizer
    if (verbose) std::cout << "[C2] Initializing tokenizer..." << std::endl;
    
    if (!tokenizer_.Load(model_)) {
        last_error_ = "Failed to initialize tokenizer";
        return false;
    }
    
    if (verbose) {
        std::cout << "[C2] Tokenizer ready: " << tokenizer_.VocabularySize() << " tokens\n"
                  << "     BOS: " << tokenizer_.BosToken() << " EOS: " << tokenizer_.EosToken() << std::endl;
    }
    
    // C3: Initialize Embedding Lookup
    if (verbose) std::cout << "[C3] Initializing embedding lookup..." << std::endl;
    
    if (!embedding_lookup_.Initialize(model_)) {
        // Non-fatal: embeddings may not be available yet
        if (verbose) std::cout << "[C3] Warning: " << embedding_lookup_.GetLastError() << std::endl;
    } else if (verbose) {
        std::cout << "[C3] Embedding lookup ready: " << embedding_lookup_.GetVocabSize() 
                  << " × " << embedding_lookup_.GetEmbeddingDim() << std::endl;
    }
    
    // C4: Initialize Inference Engine
    if (verbose) std::cout << "[C4] Initializing inference engine..." << std::endl;
    
    if (!engine_.Initialize(model_)) {
        last_error_ = "Failed to initialize inference engine: " + engine_.GetLastError();
        return false;
    }
    
    if (verbose) {
        std::cout << "[C4] Inference engine ready:\n"
                  << "     Layers: " << engine_.GetNumLayers() << "\n"
                  << "     Heads: " << engine_.GetNumHeads() << "\n"
                  << "     Head dim: " << engine_.GetHeadDim() << std::endl;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    double init_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    
    if (verbose) std::cout << "Pipeline initialized in " << std::fixed << std::setprecision(2) << init_ms << " ms" << std::endl;
    
    initialized_ = true;
    return true;
}

std::string InferencePipeline::Generate(const std::string& prompt, const InferenceConfig& config) {
    if (!initialized_) {
        last_error_ = "Pipeline not initialized";
        return "";
    }
    
    // C2: Tokenize
    auto tokens = tokenizer_.Encode(prompt);
    
    // C3: Get embeddings (if available, otherwise engine handles it)
    std::vector<uint32_t> input_tokens(tokens.begin(), tokens.end());
    
    // C4: Generate
    auto output_tokens = engine_.GenerateTokens(input_tokens, config);
    
    // C2: Decode
    std::vector<TokenId> output_tokens_int(output_tokens.begin(), output_tokens.end());
    std::string output = tokenizer_.Decode(output_tokens_int);
    
    last_telemetry_ = engine_.GetLastTelemetry();
    return output;
}

void InferencePipeline::GenerateStreaming(const std::string& prompt, const InferenceConfig& config) {
    if (!initialized_) {
        std::cerr << "Error: Pipeline not initialized" << std::endl;
        return;
    }
    
    // C2: Tokenize
    auto tokens = tokenizer_.Encode(prompt);
    std::vector<uint32_t> input_tokens(tokens.begin(), tokens.end());
    
    // C3+C4: Generate with streaming
    engine_.GenerateStreaming(prompt, 
        [this](uint32_t token_id, const std::string& token_text, bool is_last) {
            std::cout << token_text << std::flush;
        },
        config);
    
    std::cout << std::endl;
    last_telemetry_ = engine_.GetLastTelemetry();
}

// ============================================================================
// Benchmark Mode
// ============================================================================

void RunBenchmark(InferencePipeline& pipeline, const CLIConfig& cli_config) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Benchmark Mode" << std::endl;
    std::cout << "========================================\n" << std::endl;
    
    InferenceConfig config;
    config.max_tokens = 100;
    config.temperature = 0.8f;
    config.deterministic = true;  // For reproducibility
    
    std::vector<std::string> prompts = {
        "The quick brown fox",
        "In the beginning",
        "Once upon a time",
        "The future of AI",
        "To be or not to be"
    };
    
    double total_time_ms = 0.0;
    size_t total_tokens = 0;
    
    for (size_t i = 0; i < prompts.size(); ++i) {
        std::cout << "[" << (i + 1) << "/" << prompts.size() << "] \"" << prompts[i] << "\"... " << std::flush;
        
        auto start = std::chrono::high_resolution_clock::now();
        auto output = pipeline.Generate(prompts[i], config);
        auto end = std::chrono::high_resolution_clock::now();
        
        double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
        const auto& telemetry = pipeline.GetLastTelemetry();
        
        total_time_ms += elapsed;
        total_tokens += telemetry.tokens_generated;
        
        std::cout << telemetry.tokens_generated << " tokens, "
                  << std::fixed << std::setprecision(1) << telemetry.tokens_per_second << " t/s"
                  << std::endl;
    }
    
    double avg_tps = (total_tokens * 1000.0) / total_time_ms;
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Benchmark Results" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Total tokens: " << total_tokens << std::endl;
    std::cout << "Total time: " << std::fixed << std::setprecision(2) << total_time_ms << " ms" << std::endl;
    std::cout << "Average speed: " << std::setprecision(1) << avg_tps << " tokens/sec" << std::endl;
}

// ============================================================================
// Chat Mode
// ============================================================================

void RunChatMode(InferencePipeline& pipeline, const CLIConfig& cli_config) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "RawrXD Chat Mode" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Type 'exit' or 'quit' to end the session.\n" << std::endl;
    
    InferenceConfig config;
    config.max_tokens = cli_config.max_tokens;
    config.temperature = cli_config.temperature;
    config.top_p = cli_config.top_p;
    config.top_k = cli_config.top_k;
    config.repetition_penalty = cli_config.repetition_penalty;
    
    std::string conversation;
    
    while (true) {
        std::cout << "\nYou: ";
        std::string input;
        std::getline(std::cin, input);
        
        if (input == "exit" || input == "quit") {
            break;
        }
        
        if (input.empty()) {
            continue;
        }
        
        // Build prompt with conversation history
        std::string prompt = conversation + "User: " + input + "\nAssistant: ";
        
        std::cout << "Assistant: " << std::flush;
        
        // Generate response
        auto response = pipeline.Generate(prompt, config);
        std::cout << response << std::endl;
        
        // Update conversation
        conversation += "User: " + input + "\nAssistant: " + response + "\n\n";
        
        // Show telemetry if verbose
        if (cli_config.verbose) {
            const auto& telemetry = pipeline.GetLastTelemetry();
            std::cout << "[" << telemetry.tokens_generated << " tokens, "
                      << std::fixed << std::setprecision(1) << telemetry.tokens_per_second << " t/s]"
                      << std::endl;
        }
    }
    
    std::cout << "\nGoodbye!" << std::endl;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    CLIConfig config = CLIConfig::Parse(argc, argv);
    
    if (config.model_path.empty()) {
        std::cerr << "Error: Model path required. Use -m or --model." << std::endl;
        config.PrintHelp();
        return 1;
    }
    
    std::cout << "RawrXD Inference CLI - Pipeline C1-C4 Integration" << std::endl;
    std::cout << "================================================\n" << std::endl;
    
    // Initialize pipeline
    InferencePipeline pipeline;
    if (!pipeline.Initialize(config.model_path, config.verbose)) {
        std::cerr << "Error: " << pipeline.GetLastError() << std::endl;
        return 1;
    }
    
    // Route to mode
    if (config.mode == "benchmark" || config.benchmark) {
        RunBenchmark(pipeline, config);
    } else if (config.mode == "chat") {
        RunChatMode(pipeline, config);
    } else {
        // Generate mode
        if (config.prompt.empty()) {
            std::cerr << "Error: Prompt required. Use -p or --prompt." << std::endl;
            return 1;
        }
        
        InferenceConfig inf_config;
        inf_config.max_tokens = config.max_tokens;
        inf_config.temperature = config.temperature;
        inf_config.top_p = config.top_p;
        inf_config.top_k = config.top_k;
        inf_config.repetition_penalty = config.repetition_penalty;
        inf_config.streaming = config.streaming;
        
        std::cout << "Prompt: \"" << config.prompt << "\"\n" << std::endl;
        std::cout << "Output: \"" << std::flush;
        
        auto output = pipeline.Generate(config.prompt, inf_config);
        std::cout << output << "\"\n" << std::endl;
        
        // Show telemetry
        const auto& telemetry = pipeline.GetLastTelemetry();
        std::cout << "\n" << telemetry.Summary() << std::endl;
    }
    
    return 0;
}
