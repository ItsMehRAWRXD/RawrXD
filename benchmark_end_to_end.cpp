// ============================================================================
// End-to-End Benchmark - Full Pipeline Performance Test
// ============================================================================
// Tests the complete optimized inference pipeline with real models
// ============================================================================

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <numeric>
#include <cmath>

// Include the optimized pipeline components
#include "src/inference/autoregressive_generator.hpp"
#include "src/inference/sampling.hpp"
#include "src/gateway/seg_gateway.hpp"
#include "src/runtime/streaming_gguf_loader_v2.hpp"

using namespace RawrXD;
using namespace RawrXD::Inference;

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    std::string model_path;
    std::string prompt;
    uint32_t max_tokens = 128;
    uint32_t warmup_tokens = 10;
    uint32_t benchmark_runs = 3;
    bool use_flash_attention = true;
    bool use_avx512 = true;
    bool use_speculative = true;
    float temperature = 0.8f;
    int top_k = 40;
    float top_p = 0.95f;
};

// ============================================================================
// Performance Metrics
// ============================================================================
struct PerformanceMetrics {
    // Timing (ms)
    double model_load_ms = 0.0;
    double tokenizer_ms = 0.0;
    double prefill_ms = 0.0;
    double generation_ms = 0.0;
    double total_ms = 0.0;
    
    // Throughput
    double tokens_per_second = 0.0;
    double prompt_tokens_per_second = 0.0;
    double time_to_first_token_ms = 0.0;
    
    // Memory
    size_t peak_memory_mb = 0;
    size_t model_size_mb = 0;
    size_t kv_cache_mb = 0;
    
    // Generation stats
    uint32_t prompt_tokens = 0;
    uint32_t generated_tokens = 0;
    uint32_t total_tokens = 0;
    
    // Latency breakdown
    double embedding_lookup_ms = 0.0;
    double transformer_layer_ms = 0.0;
    double attention_ms = 0.0;
    double ffn_ms = 0.0;
    double sampling_ms = 0.0;
    
    // Optimization stats
    double flash_attention_speedup = 0.0;
    double avx512_speedup = 0.0;
    double speculative_speedup = 0.0;
    uint32_t accepted_draft_tokens = 0;
    uint32_t total_draft_tokens = 0;
};

// ============================================================================
// Benchmark Runner
// ============================================================================
class EndToEndBenchmark {
public:
    EndToEndBenchmark(const BenchmarkConfig& config) : config_(config) {}
    
    PerformanceMetrics Run() {
        PerformanceMetrics metrics;
        
        std::cout << "========================================" << std::endl;
        std::cout << "End-to-End Benchmark" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Model: " << config_.model_path << std::endl;
        std::cout << "Prompt: \"" << config_.prompt << "\"" << std::endl;
        std::cout << "Max tokens: " << config_.max_tokens << std::endl;
        std::cout << "FlashAttention: " << (config_.use_flash_attention ? "ON" : "OFF") << std::endl;
        std::cout << "AVX512: " << (config_.use_avx512 ? "ON" : "OFF") << std::endl;
        std::cout << "Speculative: " << (config_.use_speculative ? "ON" : "OFF") << std::endl;
        std::cout << std::endl;
        
        // Phase 1: Model Loading
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!LoadModel()) {
            std::cerr << "Failed to load model" << std::endl;
            return metrics;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        metrics.model_load_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        std::cout << "✓ Model loaded in " << metrics.model_load_ms << " ms" << std::endl;
        
        // Phase 2: Tokenization
        t0 = std::chrono::high_resolution_clock::now();
        auto tokens = TokenizePrompt();
        t1 = std::chrono::high_resolution_clock::now();
        metrics.tokenizer_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        metrics.prompt_tokens = tokens.size();
        std::cout << "✓ Tokenized " << metrics.prompt_tokens << " tokens in " 
                  << metrics.tokenizer_ms << " ms" << std::endl;
        
        // Phase 3: Warmup
        std::cout << "\nWarmup (" << config_.warmup_tokens << " tokens)..." << std::endl;
        WarmupGeneration(config_.warmup_tokens);
        
        // Phase 4: Benchmark Runs
        std::cout << "\nRunning benchmark (" << config_.benchmark_runs << " iterations)..." << std::endl;
        std::vector<double> tokens_per_sec_runs;
        
        for (uint32_t run = 0; run < config_.benchmark_runs; run++) {
            std::cout << "  Run " << (run + 1) << "/" << config_.benchmark_runs << ": ";
            
            auto run_metrics = RunSingleGeneration();
            tokens_per_sec_runs.push_back(run_metrics.tokens_per_second);
            
            std::cout << std::fixed << std::setprecision(2) 
                      << run_metrics.tokens_per_second << " tok/s" << std::endl;
        }
        
        // Calculate averages
        metrics.tokens_per_second = std::accumulate(tokens_per_sec_runs.begin(), 
                                                     tokens_per_sec_runs.end(), 0.0) 
                                     / tokens_per_sec_runs.size();
        
        // Calculate statistics
        double variance = 0.0;
        for (double tps : tokens_per_sec_runs) {
            variance += std::pow(tps - metrics.tokens_per_second, 2);
        }
        variance /= tokens_per_sec_runs.size();
        double stddev = std::sqrt(variance);
        
        // Phase 5: Report Results
        std::cout << "\n========================================" << std::endl;
        std::cout << "Benchmark Results" << std::endl;
        std::cout << "========================================" << std::endl;
        
        std::cout << "\n--- Timing Breakdown ---" << std::endl;
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "Model Load:       " << std::setw(10) << metrics.model_load_ms << " ms" << std::endl;
        std::cout << "Tokenization:     " << std::setw(10) << metrics.tokenizer_ms << " ms" << std::endl;
        std::cout << "Prefill:          " << std::setw(10) << metrics.prefill_ms << " ms" << std::endl;
        std::cout << "Generation:       " << std::setw(10) << metrics.generation_ms << " ms" << std::endl;
        std::cout << "Total:            " << std::setw(10) << metrics.total_ms << " ms" << std::endl;
        
        std::cout << "\n--- Throughput ---" << std::endl;
        std::cout << "Tokens/sec:       " << std::setw(10) << metrics.tokens_per_second << " tok/s" << std::endl;
        std::cout << "Std Dev:          " << std::setw(10) << stddev << " tok/s" << std::endl;
        std::cout << "Prompt tok/s:     " << std::setw(10) << metrics.prompt_tokens_per_second << " tok/s" << std::endl;
        std::cout << "Time to 1st:      " << std::setw(10) << metrics.time_to_first_token_ms << " ms" << std::endl;
        
        std::cout << "\n--- Generation Stats ---" << std::endl;
        std::cout << "Prompt tokens:    " << std::setw(10) << metrics.prompt_tokens << std::endl;
        std::cout << "Generated tokens: " << std::setw(10) << metrics.generated_tokens << std::endl;
        std::cout << "Total tokens:     " << std::setw(10) << metrics.total_tokens << std::endl;
        
        std::cout << "\n--- Memory Usage ---" << std::endl;
        std::cout << "Model size:       " << std::setw(10) << metrics.model_size_mb << " MB" << std::endl;
        std::cout << "KV cache:         " << std::setw(10) << metrics.kv_cache_mb << " MB" << std::endl;
        std::cout << "Peak memory:      " << std::setw(10) << metrics.peak_memory_mb << " MB" << std::endl;
        
        if (config_.use_speculative) {
            std::cout << "\n--- Speculative Decoding ---" << std::endl;
            double acceptance_rate = metrics.total_draft_tokens > 0 
                ? (100.0 * metrics.accepted_draft_tokens / metrics.total_draft_tokens)
                : 0.0;
            std::cout << "Draft acceptance: " << std::setw(10) << acceptance_rate << "%" << std::endl;
            std::cout << "Speedup:          " << std::setw(10) << metrics.speculative_speedup << "x" << std::endl;
        }
        
        std::cout << "\n========================================" << std::endl;
        
        // Save results to file
        SaveResults(metrics, tokens_per_sec_runs);
        
        return metrics;
    }
    
private:
    BenchmarkConfig config_;
    std::unique_ptr<Runtime::StreamingGGUFLoader> loader_;
    std::unique_ptr<AutoregressiveGenerator> generator_;
    
    bool LoadModel() {
        loader_ = std::make_unique<Runtime::StreamingGGUFLoader>();
        if (!loader_->Open(config_.model_path)) {
            return false;
        }
        
        // Create generator with optimized config
        TransformerConfig tconfig;
        tconfig.hidden_size = 4096;
        tconfig.num_heads = 32;
        tconfig.num_kv_heads = 8;
        tconfig.head_dim = 128;
        tconfig.intermediate_size = 14336;
        tconfig.num_layers = 34;
        tconfig.rms_norm_eps = 1e-5f;
        
        GenerationConfig gconfig;
        gconfig.max_tokens = config_.max_tokens;
        gconfig.temperature = config_.temperature;
        gconfig.top_k = config_.top_k;
        gconfig.top_p = config_.top_p;
        
        generator_ = std::make_unique<AutoregressiveGenerator>(tconfig, gconfig);
        
        return generator_->Initialize(*loader_, std::make_unique<ASCIITokenizer>());
    }
    
    std::vector<int> TokenizePrompt() {
        ASCIITokenizer tokenizer;
        return tokenizer.Encode(config_.prompt);
    }
    
    void WarmupGeneration(uint32_t num_tokens) {
        // Generate a few tokens to warm up caches
        GenerationConfig warmup_config;
        warmup_config.max_tokens = num_tokens;
        warmup_config.temperature = 0.8f;
        
        // Run warmup
        auto _ = generator_->Generate("Hello");
    }
    
    PerformanceMetrics RunSingleGeneration() {
        PerformanceMetrics metrics;
        
        auto t0 = std::chrono::high_resolution_clock::now();
        
        // Generate text
        std::string output = generator_->Generate(config_.prompt);
        
        auto t1 = std::chrono::high_resolution_clock::now();
        auto total_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        
        // Get stats from generator
        auto stats = generator_->GetStats();
        
        metrics.generation_ms = total_ms;
        metrics.generated_tokens = stats.tokens_generated;
        metrics.total_tokens = stats.prompt_tokens + stats.tokens_generated;
        metrics.tokens_per_second = stats.tokens_per_second;
        metrics.time_to_first_token_ms = total_ms / stats.tokens_generated;
        
        return metrics;
    }
    
    void SaveResults(const PerformanceMetrics& metrics, 
                     const std::vector<double>& tokens_per_sec_runs) {
        std::ofstream out("benchmark_results.json");
        out << "{\n";
        out << "  \"model_path\": \"" << config_.model_path << "\",\n";
        out << "  \"prompt\": \"" << config_.prompt << "\",\n";
        out << "  \"max_tokens\": " << config_.max_tokens << ",\n";
        out << "  \"use_flash_attention\": " << (config_.use_flash_attention ? "true" : "false") << ",\n";
        out << "  \"use_avx512\": " << (config_.use_avx512 ? "true" : "false") << ",\n";
        out << "  \"use_speculative\": " << (config_.use_speculative ? "true" : "false") << ",\n";
        out << "  \"results\": {\n";
        out << "    \"model_load_ms\": " << metrics.model_load_ms << ",\n";
        out << "    \"tokenizer_ms\": " << metrics.tokenizer_ms << ",\n";
        out << "    \"tokens_per_second\": " << metrics.tokens_per_second << ",\n";
        out << "    \"prompt_tokens\": " << metrics.prompt_tokens << ",\n";
        out << "    \"generated_tokens\": " << metrics.generated_tokens << ",\n";
        out << "    \"model_size_mb\": " << metrics.model_size_mb << ",\n";
        out << "    \"peak_memory_mb\": " << metrics.peak_memory_mb << "\n";
        out << "  },\n";
        out << "  \"runs\": [";
        for (size_t i = 0; i < tokens_per_sec_runs.size(); i++) {
            if (i > 0) out << ", ";
            out << tokens_per_sec_runs[i];
        }
        out << "]\n";
        out << "}\n";
        
        std::cout << "\nResults saved to benchmark_results.json" << std::endl;
    }
};

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    BenchmarkConfig config;
    
    // Parse command line arguments
    if (argc > 1) {
        config.model_path = argv[1];
    } else {
        // Default to ministral3 if available
        config.model_path = "D:\\ministral3_q4_0.gguf";
    }
    
    if (argc > 2) {
        config.prompt = argv[2];
    } else {
        config.prompt = "Hello, how are you today?";
    }
    
    if (argc > 3) {
        config.max_tokens = std::stoi(argv[3]);
    }
    
    // Check if model exists
    std::ifstream check(config.model_path);
    if (!check.good()) {
        std::cerr << "Model not found: " << config.model_path << std::endl;
        std::cerr << "Usage: " << argv[0] << " <model_path> [prompt] [max_tokens]" << std::endl;
        return 1;
    }
    
    // Run benchmark
    EndToEndBenchmark benchmark(config);
    auto metrics = benchmark.Run();
    
    // Return success if we got reasonable performance
    if (metrics.tokens_per_second > 0) {
        std::cout << "\n✓ Benchmark completed successfully!" << std::endl;
        return 0;
    } else {
        std::cerr << "\n✗ Benchmark failed" << std::endl;
        return 1;
    }
}
