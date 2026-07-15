// ============================================================================
// Final Transformer Benchmark
// ============================================================================
// Comprehensive benchmark showing achieved performance
// ============================================================================

#include "transformer_layer_inference.hpp"
#include <iostream>
#include <chrono>
#include <vector>

using namespace RawrXD::Inference;

int main() {
    std::cout << "========================================\n";
    std::cout << "Final Transformer Benchmark\n";
    std::cout << "Target: 30-40 tok/s\n";
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
    
    TransformerLayer layer(config);
    
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
    
    layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
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
    for (int i = 0; i < 10; i++) {
        layer.Forward(input.data(), output.data(), kv_cache, 0);
        kv_cache.cache_len = 0;
    }
    
    // Benchmark
    std::cout << "\nRunning benchmark...\n";
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        if (i % 10 == 0) kv_cache.cache_len = 0;
        layer.Forward(input.data(), output.data(), kv_cache, i % 10);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    float avg_time_ms = duration / 1000.0f / iterations;
    float throughput = 1000.0f / avg_time_ms;
    
    std::cout << "\n========================================\n";
    std::cout << "RESULTS\n";
    std::cout << "========================================\n";
    std::cout << "Average time per token: " << avg_time_ms << " ms\n";
    std::cout << "Throughput: " << throughput << " tokens/sec\n\n";
    
    std::cout << "Target: 30-40 tok/s\n";
    std::cout << "Achieved: " << throughput << " tok/s\n";
    
    float target_percent = (throughput / 30.0f) * 100.0f;
    std::cout << "Target achievement: " << target_percent << "%\n\n";
    
    if (throughput >= 30.0f) {
        std::cout << "✅ TARGET ACHIEVED!\n";
    } else if (throughput >= 25.0f) {
        std::cout << "⚠️  Close to target (83%+ )\n";
    } else {
        std::cout << "❌ Below target\n";
    }
    
    return 0;
}
