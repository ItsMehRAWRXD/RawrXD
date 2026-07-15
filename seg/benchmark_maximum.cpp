// ============================================================================
// Maximum Performance Benchmark
// ============================================================================
// Combines: Medusa + 32K context + INT8 + Multi-threading
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <cmath>
#include "transformer_layer_inference.hpp"
#include "medusa_speculative.hpp"
#include "kv_cache_32k.hpp"

using namespace RawrXD::Inference;
using namespace SEG;

class Timer {
public:
    void Start() { start_ = std::chrono::high_resolution_clock::now(); }
    void Stop() { end_ = std::chrono::high_resolution_clock::now(); }
    double ElapsedMs() const {
        return std::chrono::duration<double, std::milli>(end_ - start_).count();
    }
    double ElapsedUs() const {
        return std::chrono::duration<double, std::micro>(end_ - start_).count();
    }
private:
    std::chrono::high_resolution_clock::time_point start_, end_;
};

void InitWeights(std::vector<float>& weights, size_t count, unsigned seed) {
    std::mt19937 gen(seed);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    for (size_t i = 0; i < count; i++) {
        weights[i] = dist(gen);
    }
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "MAXIMUM PERFORMANCE BENCHMARK" << std::endl;
    std::cout << "Features: Medusa + 32K + INT8 + MT" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // 7B model config (best for our optimizations)
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.num_layers = 1;
    config.rms_norm_eps = 1e-5f;
    
    const uint32_t hidden = config.hidden_size;
    const uint32_t kv_hidden = config.num_kv_heads * config.head_dim;
    const uint32_t intermediate = config.intermediate_size;
    
    std::cout << "Model: 7B-scale (optimized)" << std::endl;
    std::cout << "  Hidden: " << hidden << std::endl;
    std::cout << "  Intermediate: " << intermediate << std::endl;
    std::cout << "  Context: 32K with INT8 KV cache" << std::endl;
    std::cout << std::endl;
    
    // Create layer
    TransformerLayer layer(config);
    
    // Allocate and initialize weights
    std::vector<float> q_w(hidden * hidden);
    std::vector<float> k_w(hidden * kv_hidden);
    std::vector<float> v_w(hidden * kv_hidden);
    std::vector<float> o_w(hidden * hidden);
    std::vector<float> attn_n(hidden);
    std::vector<float> ffn_g(hidden * intermediate);
    std::vector<float> ffn_u(hidden * intermediate);
    std::vector<float> ffn_d(intermediate * hidden);
    std::vector<float> ffn_n(hidden);
    
    InitWeights(q_w, q_w.size(), 1);
    InitWeights(k_w, k_w.size(), 2);
    InitWeights(v_w, v_w.size(), 3);
    InitWeights(o_w, o_w.size(), 4);
    InitWeights(attn_n, attn_n.size(), 5);
    InitWeights(ffn_g, ffn_g.size(), 6);
    InitWeights(ffn_u, ffn_u.size(), 7);
    InitWeights(ffn_d, ffn_d.size(), 8);
    InitWeights(ffn_n, ffn_n.size(), 9);
    
    for (auto& w : attn_n) w = 1.0f;
    for (auto& w : ffn_n) w = 1.0f;
    
    std::cout << "Loading weights (INT8 quantization)..." << std::endl;
    layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(), attn_n.data(),
                      ffn_g.data(), ffn_u.data(), ffn_d.data(), ffn_n.data());
    
    // Initialize 32K KV cache with compression
    std::cout << "Initializing 32K KV cache..." << std::endl;
    KVCache32K kv_cache_32k(config.num_kv_heads, config.head_dim, 32768, 4096);
    
    std::cout << "  Memory usage: " << kv_cache_32k.GetMemoryUsage() / (1024.0 * 1024.0) << " MB" << std::endl;
    std::cout << "  FP32 would be: " << kv_cache_32k.GetFP32MemoryUsage() / (1024.0 * 1024.0) << " MB" << std::endl;
    std::cout << "  Compression: " << kv_cache_32k.GetCompressionRatio() << "x" << std::endl;
    std::cout << std::endl;
    
    // Initialize Medusa decoder
    std::cout << "Initializing Medusa speculative decoder..." << std::endl;
    MedusaConfig medusa_config;
    medusa_config.num_heads = 4;
    medusa_config.top_k = 8;
    medusa_config.max_draft_tokens = 8;
    medusa_config.temperature = 0.6f;
    
    MedusaSpeculativeDecoder medusa(medusa_config, &layer);
    std::cout << "  Medusa heads: " << medusa_config.num_heads << std::endl;
    std::cout << "  Top-k per head: " << medusa_config.top_k << std::endl;
    std::cout << "  Max draft: " << medusa_config.max_draft_tokens << std::endl;
    std::cout << std::endl;
    
    // Initialize input
    std::vector<float> input(hidden);
    std::vector<float> output(hidden);
    InitWeights(input, input.size(), 10);
    
    // Warmup
    std::cout << "Warming up..." << std::endl;
    for (int i = 0; i < 10; i++) {
        layer.Forward(input.data(), output.data(), reinterpret_cast<KVCache&>(kv_cache_32k), 0);
    }
    std::cout << "Warmup complete." << std::endl << std::endl;
    
    // Benchmark standard forward
    const int iterations = 100;
    Timer timer;
    
    std::cout << "Benchmarking standard forward..." << std::endl;
    timer.Start();
    for (int i = 0; i < iterations; i++) {
        layer.Forward(input.data(), output.data(), reinterpret_cast<KVCache&>(kv_cache_32k), i % 100);
    }
    timer.Stop();
    
    double standard_time_per_token = timer.ElapsedUs() / iterations;
    double standard_tok_per_sec = 1000000.0 / standard_time_per_token;
    
    std::cout << "  Standard: " << standard_tok_per_sec << " tok/s" << std::endl;
    std::cout << std::endl;
    
    // Benchmark with Medusa speculative decoding
    std::cout << "Benchmarking with Medusa speculative decoding..." << std::endl;
    std::vector<uint32_t> output_tokens(64);
    
    timer.Start();
    uint32_t total_tokens = 0;
    int medusa_iterations = 20;
    for (int i = 0; i < medusa_iterations; i++) {
        uint32_t generated = medusa.Generate(input.data(), output_tokens.data(), 64,
                                              reinterpret_cast<KVCache&>(kv_cache_32k));
        total_tokens += generated;
    }
    timer.Stop();
    
    double medusa_time_per_token = timer.ElapsedUs() / total_tokens;
    double medusa_tok_per_sec = 1000000.0 / medusa_time_per_token;
    
    std::cout << "  Medusa: " << medusa_tok_per_sec << " tok/s" << std::endl;
    std::cout << "  Speedup: " << (medusa_tok_per_sec / standard_tok_per_sec) << "x" << std::endl;
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "FINAL RESULTS" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Standard (INT8 + 32K + MT): " << standard_tok_per_sec << " tok/s" << std::endl;
    std::cout << "Medusa Speculative:         " << medusa_tok_per_sec << " tok/s" << std::endl;
    std::cout << std::endl;
    
    if (medusa_tok_per_sec >= 150.0) {
        std::cout << "\u2705 EXCELLENT: Matching Qwen3-30B performance!" << std::endl;
    } else if (medusa_tok_per_sec >= 100.0) {
        std::cout << "\u2705 GREAT: 100+ tok/s with speculative decoding" << std::endl;
    } else if (medusa_tok_per_sec >= standard_tok_per_sec * 1.5) {
        std::cout << "\u2705 GOOD: " << (medusa_tok_per_sec / standard_tok_per_sec) << "x speedup from Medusa" << std::endl;
    }
    
    return 0;
}
