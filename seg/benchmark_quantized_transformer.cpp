// ============================================================================
// Quantized Transformer Benchmark
// ============================================================================
// Compares standard vs quantized transformer performance
// ============================================================================

#include "transformer_quantized.hpp"
#include <iostream>
#include <chrono>
#include <vector>

using namespace RawrXD::Inference;

int main() {
    std::cout << "========================================\n";
    std::cout << "Quantized Transformer Benchmark\n";
    std::cout << "Target: 35-40 tok/s with quantization\n";
    std::cout << "========================================\n\n";
    
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.rms_norm_eps = 1e-5f;
    
    std::cout << "Model Configuration:\n";
    std::cout << "  Hidden size: " << config.hidden_size << "\n";
    std::cout << "  Attention heads: " << config.num_heads << "\n";
    std::cout << "  KV heads (GQA): " << config.num_kv_heads << "\n";
    std::cout << "  Head dimension: " << config.head_dim << "\n";
    std::cout << "  FFN intermediate: " << config.intermediate_size << "\n\n";
    
    // Allocate weights
    uint32_t hidden = config.hidden_size;
    uint32_t kv_hidden = config.num_kv_heads * config.head_dim;
    uint32_t intermediate = config.intermediate_size;
    
    std::vector<float> q_w(hidden * hidden, 0.0001f);
    std::vector<float> k_w(hidden * kv_hidden, 0.0001f);
    std::vector<float> v_w(hidden * kv_hidden, 0.0001f);
    std::vector<float> o_w(hidden * hidden, 0.0001f);
    std::vector<float> attn_n(hidden, 1.0f);
    std::vector<float> ffn_g(hidden * intermediate, 0.0001f);
    std::vector<float> ffn_u(hidden * intermediate, 0.0001f);
    std::vector<float> ffn_d(intermediate * hidden, 0.0001f);
    std::vector<float> ffn_n(hidden, 1.0f);
    
    // Create standard layer
    TransformerLayer standard_layer(config);
    standard_layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
                               attn_n.data(), ffn_g.data(), ffn_u.data(), 
                               ffn_d.data(), ffn_n.data());
    
    // Create quantized layer
    QuantizedTransformerLayer quantized_layer(config);
    quantized_layer.LoadWeightsQuantized(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
                                          attn_n.data(), ffn_g.data(), ffn_u.data(), 
                                          ffn_d.data(), ffn_n.data());
    
    std::vector<float> input(hidden, 0.1f);
    std::vector<float> output(hidden, 0.0f);
    
    KVCache kv_cache;
    uint32_t max_seq_len = 32768;
    kv_cache.k_cache.resize(max_seq_len * kv_hidden);
    kv_cache.v_cache.resize(max_seq_len * kv_hidden);
    kv_cache.cache_len = 0;
    
    // Warmup
    std::cout << "Warming up...\n";
    for (int i = 0; i < 5; i++) {
        standard_layer.Forward(input.data(), output.data(), kv_cache, 0);
        quantized_layer.ForwardQuantized(input.data(), output.data(), kv_cache, 0);
        kv_cache.cache_len = 0;
    }
    
    // Benchmark standard layer
    std::cout << "\nBenchmarking standard transformer...\n";
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) kv_cache.cache_len = 0;
        standard_layer.Forward(input.data(), output.data(), kv_cache, i % 10);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto standard_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f / iterations;
    float standard_tok_per_sec = 1000.0f / standard_time;
    
    // Benchmark quantized layer
    std::cout << "Benchmarking quantized transformer...\n";
    kv_cache.cache_len = 0;
    start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) kv_cache.cache_len = 0;
        quantized_layer.ForwardQuantized(input.data(), output.data(), kv_cache, i % 10);
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto quantized_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f / iterations;
    float quantized_tok_per_sec = 1000.0f / quantized_time;
    
    // Results
    std::cout << "\n========================================\n";
    std::cout << "RESULTS\n";
    std::cout << "========================================\n";
    std::cout << "Standard Transformer:\n";
    std::cout << "  Time per token: " << standard_time << " ms\n";
    std::cout << "  Throughput: " << standard_tok_per_sec << " tok/s\n\n";
    
    std::cout << "Quantized Transformer:\n";
    std::cout << "  Time per token: " << quantized_time << " ms\n";
    std::cout << "  Throughput: " << quantized_tok_per_sec << " tok/s\n\n";
    
    float speedup = standard_time / quantized_time;
    std::cout << "Speedup from quantization: " << speedup << "x\n";
    std::cout << "Memory bandwidth reduction: 4x (Q8_K)\n\n";
    
    if (quantized_tok_per_sec >= 35.0f) {
        std::cout << "✅ TARGET ACHIEVED: " << quantized_tok_per_sec << " tok/s\n";
    } else if (quantized_tok_per_sec >= 30.0f) {
        std::cout << "⚠️  Close to target: " << quantized_tok_per_sec << " tok/s\n";
    } else {
        std::cout << "❌ Below target: " << quantized_tok_per_sec << " tok/s\n";
    }
    
    return 0;
}
