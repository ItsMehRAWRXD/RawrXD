// ============================================================================
// FFN Benchmark - Measure Feed-Forward Network Performance
// ============================================================================

#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include "transformer_layer_inference.hpp"

using namespace RawrXD::Inference;

int main() {
    std::cout << "========================================\n";
    std::cout << "FFN Performance Benchmark\n";
    std::cout << "========================================\n\n";
    
    // Config matching actual LLM (e.g., Llama-3.2-3B)
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;  // This is the FFN bottleneck
    config.rms_norm_eps = 1e-5f;
    
    std::cout << "Model Configuration:\n";
    std::cout << "  Hidden Size: " << config.hidden_size << "\n";
    std::cout << "  Intermediate Size: " << config.intermediate_size << "\n";
    std::cout << "  FFN Expansion: " << (config.intermediate_size / config.hidden_size) << "x\n\n";
    
    TransformerLayer layer(config);
    
    uint32_t hidden = config.hidden_size;
    uint32_t kv_hidden = config.num_kv_heads * config.head_dim;
    uint32_t intermediate = config.intermediate_size;
    
    // Allocate weights (small values for stability)
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
    
    std::vector<float> input(hidden, 0.01f);
    std::vector<float> output(hidden, 0.0f);
    
    KVCache kv_cache;
    kv_cache.k_cache.resize(128 * kv_hidden);
    kv_cache.v_cache.resize(128 * kv_hidden);
    kv_cache.cache_len = 0;
    
    std::cout << "Running benchmark...\n";
    std::cout << "(This represents the FFN bottleneck from baseline)\n\n";
    
    // Warmup
    std::cout << "Warming up...\n";
    for (int i = 0; i < 5; i++) {
        layer.Forward(input.data(), output.data(), kv_cache, 0);
    }
    
    // Benchmark
    uint32_t iterations = 50;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < iterations; i++) {
        // Reset cache periodically
        if (i % 10 == 0) {
            kv_cache.cache_len = 0;
            kv_cache.k_cache.assign(128 * kv_hidden, 0.0f);
            kv_cache.v_cache.assign(128 * kv_hidden, 0.0f);
        }
        layer.Forward(input.data(), output.data(), kv_cache, i % 10);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    float avgTimeMs = duration.count() / static_cast<float>(iterations);
    float tokensPerSec = 1000.0f / avgTimeMs;
    
    std::cout << "\nResults:\n";
    std::cout << "  Iterations: " << iterations << "\n";
    std::cout << "  Total time: " << duration.count() << " ms\n";
    std::cout << "  Avg time per token: " << avgTimeMs << " ms\n";
    std::cout << "  Throughput: " << tokensPerSec << " tokens/sec\n\n";
    
    // Compare to baseline
    float baselineTimeMs = 15015.0f / 128.0f;  // From BENCHMARK_BASELINE.md: 15015ms for 128 tokens
    float speedup = baselineTimeMs / avgTimeMs;
    
    std::cout << "Comparison to Baseline:\n";
    std::cout << "  Baseline: ~" << baselineTimeMs << " ms/token\n";
    std::cout << "  Current:  " << avgTimeMs << " ms/token\n";
    std::cout << "  Speedup:  " << speedup << "x\n\n";
    
    // Calculate FLOPs
    // FFN FLOPs per token: 2 * hidden * intermediate (gate) + 2 * hidden * intermediate (up) + 2 * intermediate * hidden (down)
    // = 2 * hidden * intermediate * 3 = 6 * hidden * intermediate
    uint64_t ffn_flops = 6ULL * hidden * intermediate;
    // Attention FLOPs (simplified): 2 * hidden^2 * 4 (Q,K,V,O projections)
    uint64_t attn_flops = 8ULL * hidden * hidden;
    uint64_t total_flops = ffn_flops + attn_flops;
    
    float gflops = (total_flops / 1e9f) / (avgTimeMs / 1000.0f);
    
    std::cout << "Compute Analysis:\n";
    std::cout << "  FFN FLOPs/token:   " << (ffn_flops / 1e6f) << " MFLOPs\n";
    std::cout << "  Attn FLOPs/token:  " << (attn_flops / 1e6f) << " MFLOPs\n";
    std::cout << "  Total FLOPs/token: " << (total_flops / 1e6f) << " MFLOPs\n";
    std::cout << "  Compute:           " << gflops << " GFLOP/s\n\n";
    
    std::cout << "========================================\n";
    std::cout << "Benchmark Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
