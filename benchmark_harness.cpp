/**
 * @file benchmark_harness.cpp
 * @brief RawrXD End-to-End Benchmark Harness
 *
 * Comprehensive benchmarking for C1-C4 pipeline with telemetry.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <algorithm>

// Include RawrXD components
#include "src/model/model_context.h"
#include "src/runtime/tokenizer_runtime.h"
#include "src/inference/transformer_layer.h"

using namespace rawrxd;

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchmarkConfig {
    std::string model_path;
    std::string prompt;
    uint32_t max_tokens = 64;
    uint32_t warmup_tokens = 10;
    uint32_t benchmark_tokens = 50;
    float temperature = 0.8f;
    uint32_t top_k = 40;
    bool verbose = true;
    bool dump_telemetry = true;
};

// ============================================================================
// Telemetry Structure
// ============================================================================

struct LayerTelemetry {
    double rms_norm_ms = 0.0;
    double attention_ms = 0.0;
    double ffn_ms = 0.0;
    double total_ms = 0.0;
};

struct BenchmarkResult {
    bool success = false;
    std::string error_message;
    
    // Model info
    std::string model_name;
    uint32_t vocab_size = 0;
    uint32_t hidden_size = 0;
    uint32_t num_layers = 0;
    uint32_t num_heads = 0;
    uint32_t num_kv_heads = 0;
    uint32_t context_length = 0;
    
    // Timing
    double load_time_ms = 0.0;
    double tokenize_time_ms = 0.0;
    double warmup_time_ms = 0.0;
    double inference_time_ms = 0.0;
    double total_time_ms = 0.0;
    
    // Throughput
    double tokens_per_second = 0.0;
    double ms_per_token = 0.0;
    double prompt_tokens_per_sec = 0.0;
    
    // Token counts
    uint32_t prompt_tokens = 0;
    uint32_t generated_tokens = 0;
    
    // Memory
    size_t peak_memory_mb = 0;
    size_t model_size_mb = 0;
    
    // Generated text
    std::string generated_text;
    
    // Per-layer telemetry (if available)
    std::vector<LayerTelemetry> layer_times;
};

// ============================================================================
// Memory Usage (Windows)
// ============================================================================

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>

size_t GetCurrentMemoryUsageMB() {
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize / (1024 * 1024);
    }
    return 0;
}
#else
size_t GetCurrentMemoryUsageMB() { return 0; }
#endif

// ============================================================================
// Benchmark Runner
// ============================================================================

class BenchmarkRunner {
public:
    BenchmarkResult Run(const BenchmarkConfig& config) {
        BenchmarkResult result;
        auto start_total = std::chrono::steady_clock::now();
        
        std::cout << "========================================\n";
        std::cout << "RawrXD End-to-End Benchmark\n";
        std::cout << "========================================\n\n";
        
        // Step 1: Load Model (C1)
        std::cout << "[1/5] Loading model: " << config.model_path << "\n";
        auto start = std::chrono::steady_clock::now();
        
        auto model_ctx = std::make_unique<model::ModelContext>();
        if (!model_ctx->LoadFromFile(config.model_path)) {
            result.error_message = "Failed to load model from: " + config.model_path;
            std::cerr << "ERROR: " << result.error_message << "\n";
            return result;
        }
        
        auto end = std::chrono::steady_clock::now();
        result.load_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        // Extract model info
        const auto& arch = model_ctx->GetArchitecture();
        result.model_name = model_ctx->GetMetadata("general.name");
        if (result.model_name.empty()) result.model_name = "Unknown";
        result.vocab_size = arch.vocab_size;
        result.hidden_size = arch.embedding_dim;
        result.num_layers = arch.layer_count;
        result.num_heads = arch.head_count;
        result.num_kv_heads = arch.kv_head_count;
        result.context_length = arch.context_length;
        
        // Estimate model size from file
        std::ifstream file(config.model_path, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            result.model_size_mb = static_cast<size_t>(file.tellg()) / (1024 * 1024);
            file.close();
        }
        
        std::cout << "  Model: " << result.model_name << "\n";
        std::cout << "  Vocab: " << result.vocab_size << ", Hidden: " << result.hidden_size << "\n";
        std::cout << "  Layers: " << result.num_layers << ", Heads: " << result.num_heads << "\n";
        std::cout << "  Model size: " << result.model_size_mb << " MB\n";
        std::cout << "  Load time: " << std::fixed << std::setprecision(2) << result.load_time_ms << " ms\n\n";
        
        // Step 2: Create Tokenizer (C2)
        std::cout << "[2/5] Initializing tokenizer...\n";
        start = std::chrono::steady_clock::now();
        
        auto tokenizer = runtime::TokenizerFactory::FromModel(*model_ctx);
        if (!tokenizer) {
            result.error_message = "Failed to create tokenizer";
            std::cerr << "ERROR: " << result.error_message << "\n";
            return result;
        }
        
        end = std::chrono::steady_clock::now();
        result.tokenize_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        // Tokenize prompt
        auto tokens = tokenizer->Encode(config.prompt);
        result.prompt_tokens = static_cast<uint32_t>(tokens.size());
        result.prompt_tokens_per_sec = result.prompt_tokens / (result.tokenize_time_ms / 1000.0);
        
        std::cout << "  Prompt: \"" << config.prompt << "\"\n";
        std::cout << "  Tokens: " << result.prompt_tokens << "\n";
        std::cout << "  Tokenize time: " << std::fixed << std::setprecision(2) << result.tokenize_time_ms << " ms\n";
        std::cout << "  Prompt tok/sec: " << std::fixed << std::setprecision(2) << result.prompt_tokens_per_sec << "\n\n";
        
        // Step 3: Initialize Transformer (C3-C4)
        std::cout << "[3/5] Initializing transformer...\n";
        
        inference::TransformerModel model;
        if (!model.Load(config.model_path)) {
            result.error_message = "Failed to initialize transformer (likely std::bad_alloc on large model)";
            std::cerr << "ERROR: " << result.error_message << "\n";
            std::cerr << "  Note: Current implementation allocates full weight matrices.\n";
            std::cerr << "  For large models, use a smaller model or implement quantized loading.\n";
            return result;
        }
        
        std::cout << "  Transformer initialized successfully\n\n";
        
        // Step 4: Warmup
        std::cout << "[4/5] Warmup (" << config.warmup_tokens << " tokens)...\n";
        start = std::chrono::steady_clock::now();
        
        std::vector<uint32_t> all_tokens;
        all_tokens.reserve(tokens.size() + config.warmup_tokens);
        for (auto t : tokens) {
            all_tokens.push_back(static_cast<uint32_t>(t));
        }
        
        for (uint32_t i = 0; i < config.warmup_tokens && i < config.max_tokens; ++i) {
            auto next_token = model.GenerateNextToken(all_tokens, config.temperature, config.top_k);
            if (next_token == 0) break;
            all_tokens.push_back(next_token);
        }
        
        end = std::chrono::steady_clock::now();
        result.warmup_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        
        std::cout << "  Warmup complete: " << std::fixed << std::setprecision(2) << result.warmup_time_ms << " ms\n\n";
        
        // Step 5: Benchmark
        std::cout << "[5/5] Benchmarking (" << config.benchmark_tokens << " tokens)...\n";
        start = std::chrono::steady_clock::now();
        
        size_t mem_before = GetCurrentMemoryUsageMB();
        uint32_t tokens_generated = 0;
        
        for (uint32_t i = 0; i < config.benchmark_tokens && all_tokens.size() < config.max_tokens; ++i) {
            auto next_token = model.GenerateNextToken(all_tokens, config.temperature, config.top_k);
            if (next_token == 0) break;
            all_tokens.push_back(next_token);
            tokens_generated++;
        }
        
        end = std::chrono::steady_clock::now();
        result.inference_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result.peak_memory_mb = GetCurrentMemoryUsageMB();
        if (result.peak_memory_mb > mem_before) {
            result.peak_memory_mb -= mem_before;
        }
        
        result.generated_tokens = tokens_generated;
        result.ms_per_token = result.inference_time_ms / tokens_generated;
        result.tokens_per_second = tokens_generated / (result.inference_time_ms / 1000.0);
        
        // Decode generated tokens
        std::vector<runtime::TokenId> generated_tokens_int;
        for (size_t i = tokens.size(); i < all_tokens.size(); ++i) {
            generated_tokens_int.push_back(static_cast<runtime::TokenId>(all_tokens[i]));
        }
        result.generated_text = tokenizer->Decode(generated_tokens_int);
        
        std::cout << "  Generated " << tokens_generated << " tokens\n";
        std::cout << "  Inference time: " << std::fixed << std::setprecision(2) << result.inference_time_ms << " ms\n";
        std::cout << "  Tokens/sec: " << std::fixed << std::setprecision(2) << result.tokens_per_second << "\n";
        std::cout << "  ms/token: " << std::fixed << std::setprecision(2) << result.ms_per_token << "\n";
        std::cout << "  Memory delta: " << result.peak_memory_mb << " MB\n\n";
        
        // Total time
        auto end_total = std::chrono::steady_clock::now();
        result.total_time_ms = std::chrono::duration<double, std::milli>(end_total - start_total).count();
        result.success = true;
        
        // Print summary
        PrintSummary(result);
        
        // Dump telemetry if requested
        if (config.dump_telemetry) {
            DumpTelemetry(result, config);
        }
        
        return result;
    }
    
private:
    void PrintSummary(const BenchmarkResult& result) {
        std::cout << "========================================\n";
        std::cout << "BENCHMARK SUMMARY\n";
        std::cout << "========================================\n";
        std::cout << "Model: " << result.model_name << "\n";
        std::cout << "Architecture: " << result.num_layers << " layers, " 
                  << result.hidden_size << " hidden, " 
                  << result.num_heads << " heads\n";
        std::cout << "----------------------------------------\n";
        std::cout << "TIMING BREAKDOWN:\n";
        std::cout << "  Model load:     " << std::setw(10) << std::fixed << std::setprecision(2) << result.load_time_ms << " ms\n";
        std::cout << "  Tokenization:   " << std::setw(10) << result.tokenize_time_ms << " ms\n";
        std::cout << "  Warmup:         " << std::setw(10) << result.warmup_time_ms << " ms\n";
        std::cout << "  Inference:      " << std::setw(10) << result.inference_time_ms << " ms\n";
        std::cout << "  TOTAL:          " << std::setw(10) << result.total_time_ms << " ms\n";
        std::cout << "----------------------------------------\n";
        std::cout << "THROUGHPUT:\n";
        std::cout << "  Prompt tokens:  " << std::setw(10) << result.prompt_tokens << "\n";
        std::cout << "  Generated:      " << std::setw(10) << result.generated_tokens << " tokens\n";
        std::cout << "  Tokens/sec:     " << std::setw(10) << std::fixed << std::setprecision(2) << result.tokens_per_second << "\n";
        std::cout << "  ms/token:       " << std::setw(10) << std::fixed << std::setprecision(2) << result.ms_per_token << "\n";
        std::cout << "----------------------------------------\n";
        std::cout << "MEMORY:\n";
        std::cout << "  Model size:     " << std::setw(10) << result.model_size_mb << " MB\n";
        std::cout << "  Peak working:   " << std::setw(10) << result.peak_memory_mb << " MB\n";
        std::cout << "----------------------------------------\n";
        std::cout << "OUTPUT:\n";
        std::cout << "  \"" << result.generated_text << "\"\n";
        std::cout << "========================================\n";
    }
    
    void DumpTelemetry(const BenchmarkResult& result, const BenchmarkConfig& config) {
        std::string filename = "benchmark_" + GetTimestamp() + ".json";
        std::ofstream file(filename);
        
        if (!file.is_open()) {
            std::cerr << "Warning: Could not write telemetry to " << filename << "\n";
            return;
        }
        
        file << "{\n";
        file << "  \"timestamp\": \"" << GetTimestamp() << "\",\n";
        file << "  \"model_path\": \"" << EscapeJson(config.model_path) << "\",\n";
        file << "  \"model_name\": \"" << EscapeJson(result.model_name) << "\",\n";
        file << "  \"architecture\": {\n";
        file << "    \"vocab_size\": " << result.vocab_size << ",\n";
        file << "    \"hidden_size\": " << result.hidden_size << ",\n";
        file << "    \"num_layers\": " << result.num_layers << ",\n";
        file << "    \"num_heads\": " << result.num_heads << ",\n";
        file << "    \"num_kv_heads\": " << result.num_kv_heads << ",\n";
        file << "    \"context_length\": " << result.context_length << "\n";
        file << "  },\n";
        file << "  \"timing\": {\n";
        file << "    \"load_ms\": " << result.load_time_ms << ",\n";
        file << "    \"tokenize_ms\": " << result.tokenize_time_ms << ",\n";
        file << "    \"warmup_ms\": " << result.warmup_time_ms << ",\n";
        file << "    \"inference_ms\": " << result.inference_time_ms << ",\n";
        file << "    \"total_ms\": " << result.total_time_ms << "\n";
        file << "  },\n";
        file << "  \"throughput\": {\n";
        file << "    \"prompt_tokens\": " << result.prompt_tokens << ",\n";
        file << "    \"generated_tokens\": " << result.generated_tokens << ",\n";
        file << "    \"tokens_per_second\": " << result.tokens_per_second << ",\n";
        file << "    \"ms_per_token\": " << result.ms_per_token << ",\n";
        file << "    \"prompt_tok_per_sec\": " << result.prompt_tokens_per_sec << "\n";
        file << "  },\n";
        file << "  \"memory\": {\n";
        file << "    \"model_size_mb\": " << result.model_size_mb << ",\n";
        file << "    \"peak_working_mb\": " << result.peak_memory_mb << "\n";
        file << "  },\n";
        file << "  \"output\": \"" << EscapeJson(result.generated_text) << "\",\n";
        file << "  \"success\": " << (result.success ? "true" : "false") << "\n";
        file << "}\n";
        
        file.close();
        std::cout << "Telemetry written to: " << filename << "\n";
    }
    
    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S");
        return ss.str();
    }
    
    std::string EscapeJson(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c;
            }
        }
        return result;
    }
};

// ============================================================================
// Main Entry Point
// ============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " <model.gguf> [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --prompt <text>       Prompt text (default: \"Hello\")\n";
    std::cout << "  --max-tokens <n>    Maximum tokens to generate (default: 64)\n";
    std::cout << "  --warmup <n>        Warmup token count (default: 10)\n";
    std::cout << "  --benchmark <n>       Benchmark token count (default: 50)\n";
    std::cout << "  --temperature <t>     Sampling temperature (default: 0.8)\n";
    std::cout << "  --top-k <k>         Top-k sampling (default: 40)\n";
    std::cout << "  --quiet             Minimal output\n";
    std::cout << "  --no-telemetry      Don't dump telemetry JSON\n";
    std::cout << "\nExample:\n";
    std::cout << "  " << program << " model.gguf --prompt \"Hello world\" --max-tokens 100\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    BenchmarkConfig config;
    config.model_path = argv[1];
    
    // Parse arguments
    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--prompt" && i + 1 < argc) {
            config.prompt = argv[++i];
        } else if (arg == "--max-tokens" && i + 1 < argc) {
            config.max_tokens = std::stoul(argv[++i]);
        } else if (arg == "--warmup" && i + 1 < argc) {
            config.warmup_tokens = std::stoul(argv[++i]);
        } else if (arg == "--benchmark" && i + 1 < argc) {
            config.benchmark_tokens = std::stoul(argv[++i]);
        } else if (arg == "--temperature" && i + 1 < argc) {
            config.temperature = std::stof(argv[++i]);
        } else if (arg == "--top-k" && i + 1 < argc) {
            config.top_k = std::stoul(argv[++i]);
        } else if (arg == "--quiet") {
            config.verbose = false;
        } else if (arg == "--no-telemetry") {
            config.dump_telemetry = false;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    // Run benchmark
    BenchmarkRunner runner;
    auto result = runner.Run(config);
    
    return result.success ? 0 : 1;
}
