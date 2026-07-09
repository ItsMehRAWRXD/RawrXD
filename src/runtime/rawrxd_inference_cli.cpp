/**
 * @file rawrxd_inference_cli.cpp
 * @brief RawrXD Inference CLI - Complete C1-C4 Integration
 *
 * End-to-end inference: GGUF → Tokens → Embeddings → Inference → Text
 *
 * @copyright RawrXD 2026
 */

#include "../model/model_context.h"
#include "tokenizer_runtime.h"
#include "embedding_lookup.hpp"
#include "inference_engine.hpp"
#include "gguf_weight_loader.hpp"

#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#endif

using namespace rawrxd::runtime;
using namespace rawrxd::model;

// ============================================================================
// CLI Configuration
// ============================================================================

struct CLIConfig {
    std::string model_path;
    std::string prompt = "Hello, how are you?";
    uint32_t max_tokens = 100;
    float temperature = 0.8f;
    float top_p = 0.95f;
    uint32_t top_k = 40;
    bool verbose = false;
    bool streaming = false;
    bool use_weights = true;  // Use real weights vs synthetic
};

// ============================================================================
// Signal Handling
// ============================================================================

static volatile bool g_interrupted = false;

#ifdef _WIN32
BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        g_interrupted = true;
        std::cerr << "\nInterrupted by user. Exiting gracefully...\n";
        return TRUE;
    }
    return FALSE;
}
#else
void SignalHandler(int signal) {
    if (signal == SIGINT) {
        g_interrupted = true;
        std::cerr << "\nInterrupted by user. Exiting gracefully...\n";
    }
}
#endif

// ============================================================================
// Help
// ============================================================================

void PrintHelp(const char* program_name) {
    std::cout << "RawrXD Inference CLI - Complete C1-C4 Pipeline\n"
              << "=============================================\n\n"
              << "Usage: " << program_name << " [options]\n\n"
              << "Options:\n"
              << "  -m, --model PATH       Path to GGUF model file (required)\n"
              << "  -p, --prompt TEXT      Input prompt (default: \"Hello, how are you?\")\n"
              << "  -n, --max-tokens N     Maximum tokens to generate (default: 100)\n"
              << "  -t, --temperature T    Sampling temperature (default: 0.8)\n"
              << "  --top-p P              Top-p (nucleus) sampling (default: 0.95)\n"
              << "  --top-k K              Top-k sampling (default: 40)\n"
              << "  --synthetic            Use synthetic weights instead of loading from GGUF\n"
              << "  --streaming            Enable streaming output\n"
              << "  -v, --verbose          Verbose output\n"
              << "  -h, --help             Show this help\n\n"
              << "Examples:\n"
              << "  " << program_name << " -m model.gguf -p \"What is AI?\"\n"
              << "  " << program_name << " -m model.gguf -n 50 -t 0.6\n"
              << "  " << program_name << " -m model.gguf --streaming\n";
}

// ============================================================================
// Argument Parsing
// ============================================================================

CLIConfig ParseArgs(int argc, char* argv[]) {
    CLIConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            PrintHelp(argv[0]);
            exit(0);
        }
        else if ((arg == "-m" || arg == "--model") && i + 1 < argc) {
            config.model_path = argv[++i];
        }
        else if ((arg == "-p" || arg == "--prompt") && i + 1 < argc) {
            config.prompt = argv[++i];
        }
        else if ((arg == "-n" || arg == "--max-tokens") && i + 1 < argc) {
            config.max_tokens = static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if ((arg == "-t" || arg == "--temperature") && i + 1 < argc) {
            config.temperature = std::stof(argv[++i]);
        }
        else if (arg == "--top-p" && i + 1 < argc) {
            config.top_p = std::stof(argv[++i]);
        }
        else if (arg == "--top-k" && i + 1 < argc) {
            config.top_k = static_cast<uint32_t>(std::stoul(argv[++i]));
        }
        else if (arg == "--synthetic") {
            config.use_weights = false;
        }
        else if (arg == "--streaming") {
            config.streaming = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            config.verbose = true;
        }
        else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            PrintHelp(argv[0]);
            exit(1);
        }
    }
    
    return config;
}

// ============================================================================
// Main Inference Pipeline
// ============================================================================

int RunInference(const CLIConfig& config) {
    std::cout << "========================================\n";
    std::cout << "RawrXD Inference CLI - C1-C4 Pipeline\n";
    std::cout << "========================================\n\n";
    
    // Validate config
    if (config.model_path.empty()) {
        std::cerr << "Error: Model path required (-m PATH)\n\n";
        PrintHelp("rawrxd_inference_cli");
        return 1;
    }
    
    auto total_start = std::chrono::high_resolution_clock::now();
    
    // ========================================================================
    // C1: Model Loading (GGUF ingestion)
    // ========================================================================
    std::cout << "[C1] Loading model from GGUF...\n";
    
    ModelContext model;
    if (!model.LoadFromFile(config.model_path)) {
        std::cerr << "Failed to load model: " << config.model_path << "\n";
        return 1;
    }
    
    const auto& arch = model.GetArchitecture();
    std::cout << "  Model: " << arch.type << "\n";
    std::cout << "  Vocab size: " << arch.vocab_size << "\n";
    std::cout << "  Layers: " << arch.layer_count << "\n";
    std::cout << "  Embedding dim: " << arch.embedding_dim << "\n";
    std::cout << "  Context length: " << arch.context_length << "\n";
    std::cout << "  Quantization: " << arch.quantization_type << "\n";
    std::cout << "  Tensors: " << model.GetTensorCount() << "\n\n";
    
    // ========================================================================
    // Weight Loading (if enabled)
    // ========================================================================
    std::unique_ptr<TransformerWeights> weights;
    
    if (config.use_weights) {
        std::cout << "[C1b] Loading transformer weights...\n";
        
        auto weight_start = std::chrono::high_resolution_clock::now();
        
        std::string weight_error;
        auto progress_callback = [](const LoadingProgress& progress) {
            std::cout << "  Progress: " << progress.loaded_tensors << "/" << progress.total_tensors
                      << " tensors (" << std::fixed << std::setprecision(1) << progress.GetPercentComplete()
                      << "%)\r" << std::flush;
        };
        
        weights = LoadTransformerWeights(config.model_path, &weight_error, progress_callback);
        
        auto weight_end = std::chrono::high_resolution_clock::now();
        double weight_time = std::chrono::duration<double, std::milli>(weight_end - weight_start).count();
        
        if (weights) {
            std::cout << "\n  Loaded " << weights->GetLayerCount() << " layers\n";
            std::cout << "  Total size: " << weights->GetTotalSizeBytes() / (1024 * 1024) << " MB\n";
            std::cout << "  Time: " << std::fixed << std::setprecision(2) << weight_time << " ms\n\n";
        } else {
            std::cout << "  Warning: Could not load weights: " << weight_error << "\n";
            std::cout << "  Falling back to synthetic weights\n\n";
        }
    }
    
    // ========================================================================
    // C2: Tokenization
    // ========================================================================
    std::cout << "[C2] Tokenizing prompt...\n";
    
    Tokenizer tokenizer;
    if (!tokenizer.Load(model)) {
        std::cerr << "Failed to initialize tokenizer\n";
        return 1;
    }
    
    auto tokens = tokenizer.Encode(config.prompt);
    
    std::cout << "  Prompt: \"" << config.prompt << "\"\n";
    std::cout << "  Tokens: " << tokens.size() << " [";
    for (size_t i = 0; i < std::min(tokens.size(), size_t(10)); ++i) {
        if (i > 0) std::cout << " ";
        std::cout << tokens[i];
    }
    if (tokens.size() > 10) std::cout << " ...";
    std::cout << "]\n\n";
    
    // ========================================================================
    // C3: Embedding Lookup
    // ========================================================================
    std::cout << "[C3] Looking up embeddings...\n";
    
    EmbeddingLookup embedding_lookup;
    if (!embedding_lookup.Initialize(model)) {
        std::cerr << "Failed to initialize embedding lookup: " << embedding_lookup.GetLastError() << "\n";
        return 1;
    }
    
    std::vector<uint32_t> token_ids(tokens.begin(), tokens.end());
    EmbeddingTelemetry emb_telemetry;
    auto embeddings = embedding_lookup.GetEmbeddingsWithTelemetry(token_ids, &emb_telemetry);
    
    std::cout << "  Tokens: " << emb_telemetry.token_count << "\n";
    std::cout << "  Dimension: " << emb_telemetry.embedding_dim << "\n";
    std::cout << "  Time: " << std::fixed << std::setprecision(3) << emb_telemetry.lookup_ms << " ms\n";
    std::cout << "  Bytes read: " << emb_telemetry.bytes_read << "\n\n";
    
    // ========================================================================
    // C4: Inference
    // ========================================================================
    std::cout << "[C4] Running inference...\n";
    
    InferenceEngine engine;
    if (!engine.Initialize(model)) {
        std::cerr << "Failed to initialize inference engine: " << engine.GetLastError() << "\n";
        return 1;
    }
    
    // Configure generation
    InferenceConfig inf_config;
    inf_config.max_tokens = config.max_tokens;
    inf_config.temperature = config.temperature;
    inf_config.top_p = config.top_p;
    inf_config.top_k = config.top_k;
    inf_config.streaming = config.streaming;
    
    std::cout << "  Generation config:\n";
    std::cout << "    Max tokens: " << inf_config.max_tokens << "\n";
    std::cout << "    Temperature: " << inf_config.temperature << "\n";
    std::cout << "    Top-p: " << inf_config.top_p << "\n";
    std::cout << "    Top-k: " << inf_config.top_k << "\n\n";
    
    std::cout << "  Generating...\n";
    std::cout << "  Output: \"";
    std::cout.flush();
    
    // Generate
    std::vector<uint32_t> output_tokens;
    
    if (config.streaming) {
        // Streaming generation
        auto token_callback = [](uint32_t token_id, const std::string& token_text, bool is_last) {
            std::cout << token_text << std::flush;
            if (is_last) std::cout << "\"\n";
        };
        
        engine.GenerateStreaming(config.prompt, token_callback, inf_config);
    } else {
        // Batch generation
        output_tokens = engine.GenerateFromEmbeddings(embeddings, inf_config);
        
        // Decode tokens
        std::vector<TokenId> output_tokens_int(output_tokens.begin(), output_tokens.end());
        std::string output_text = tokenizer.Decode(output_tokens_int);
        
        std::cout << output_text << "\"\n";
    }
    
    // ========================================================================
    // Telemetry Summary
    // ========================================================================
    const auto& inf_telemetry = engine.GetLastTelemetry();
    
    std::cout << "\n----------------------------------------\n";
    std::cout << "Telemetry Summary\n";
    std::cout << "----------------------------------------\n";
    std::cout << "  Tokens generated: " << inf_telemetry.tokens_generated << "\n";
    std::cout << "  Prompt tokens: " << inf_telemetry.tokens_prompt << "\n";
    std::cout << "  Time to first token: " << std::fixed << std::setprecision(2) 
              << inf_telemetry.time_to_first_token_ms << " ms\n";
    std::cout << "  Total time: " << inf_telemetry.total_time_ms << " ms\n";
    std::cout << "  Tokens/sec: " << std::setprecision(1) << inf_telemetry.tokens_per_second << "\n";
    std::cout << "  Layers processed: " << inf_telemetry.layers_processed << "\n";
    
    auto total_end = std::chrono::high_resolution_clock::now();
    double total_time = std::chrono::duration<double, std::milli>(total_end - total_start).count();
    std::cout << "  Total pipeline time: " << total_time << " ms\n";
    std::cout << "----------------------------------------\n";
    
    return 0;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    // Set up signal handling
#ifdef _WIN32
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
#else
    std::signal(SIGINT, SignalHandler);
#endif
    
    // Parse arguments
    CLIConfig config = ParseArgs(argc, argv);
    
    // Run inference
    try {
        return RunInference(config);
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
