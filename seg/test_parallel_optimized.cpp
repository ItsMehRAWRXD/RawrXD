// ============================================================================
// Optimized Parallel Transformer Test
// ============================================================================

#include "thread_pool.hpp"
#include "transformer_layer_parallel.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>

using namespace RawrXD::Inference;

int main() {
    std::cout << "========================================\n";
    std::cout << "Optimized Parallel Transformer Test\n";
    std::cout << "========================================\n\n";
    
    // Configuration matching a typical model
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.rms_norm_eps = 1e-5f;
    
    std::cout << "Configuration:\n";
    std::cout << "  Hidden: " << config.hidden_size << "\n";
    std::cout << "  Heads: " << config.num_heads << "\n";
    std::cout << "  KV Heads: " << config.num_kv_heads << "\n";
    std::cout << "  Head Dim: " << config.head_dim << "\n";
    std::cout << "  Intermediate: " << config.intermediate_size << "\n\n";
    
    // Test with different thread counts
    std::vector<size_t> thread_counts = {1, 2, 4, 8, 16};
    
    for (size_t tc : thread_counts) {
        if (tc > ThreadPool::HardwareConcurrency()) continue;
        
        std::cout << "--- Testing with " << tc << " threads ---\n";
        
        // Create parallel layer with specific thread count
        ParallelTransformerLayer layer(config);
        layer.SetNumThreads(tc);
        
        // Allocate weights (small values for stability)
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
        
        // Prepare input and output
        std::vector<float> input(hidden, 0.1f);
        std::vector<float> output(hidden, 0.0f);
        
        // Prepare KV cache
        KVCache kv_cache;
        uint32_t max_seq_len = 32768;
        kv_cache.k_cache.resize(max_seq_len * kv_hidden);
        kv_cache.v_cache.resize(max_seq_len * kv_hidden);
        kv_cache.cache_len = 0;
        
        // Warmup
        for (int i = 0; i < 3; i++) {
            layer.ForwardParallel(input.data(), output.data(), kv_cache, 0);
            kv_cache.cache_len = 0;
        }
        
        // Benchmark
        uint32_t iterations = 20;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (uint32_t i = 0; i < iterations; i++) {
            if (i % 5 == 0) kv_cache.cache_len = 0;
            layer.ForwardParallel(input.data(), output.data(), kv_cache, i % 5);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        float avgTimeMs = duration.count() / static_cast<float>(iterations) / 1000.0f;
        float tokensPerSec = 1000.0f / avgTimeMs;
        
        std::cout << "  Avg time per token: " << avgTimeMs << " ms\n";
        std::cout << "  Throughput: " << tokensPerSec << " tokens/sec\n\n";
    }
    
    std::cout << "Done!\n";
    return 0;
}
