// ============================================================================
// Test Multi-threaded Transformer Layer
// ============================================================================

#include "transformer_layer_parallel.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>

using namespace RawrXD::Inference;

int main() {
    std::cout << "========================================\n";
    std::cout << "Multi-threaded Transformer Test\n";
    std::cout << "========================================\n\n";
    
    // Configuration matching a typical model
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.rms_norm_eps = 1e-5f;
    // Using default max sequence length of 32768
    
    std::cout << "Configuration:\n";
    std::cout << "  Hidden: " << config.hidden_size << "\n";
    std::cout << "  Heads: " << config.num_heads << "\n";
    std::cout << "  KV Heads: " << config.num_kv_heads << "\n";
    std::cout << "  Head Dim: " << config.head_dim << "\n";
    std::cout << "  Intermediate: " << config.intermediate_size << "\n\n";
    
    // Create parallel layer
    ParallelTransformerLayer layer(config);
    
    std::cout << "Thread pool initialized with " << layer.GetNumThreads() << " threads\n\n";
    
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
    
    std::cout << "Running benchmark...\n\n";
    
    // Warmup
    std::cout << "Warming up...\n";
    for (int i = 0; i < 5; i++) {
        layer.ForwardParallel(input.data(), output.data(), kv_cache, 0);
        kv_cache.cache_len = 0;
    }
    
    // Benchmark parallel forward pass
    uint32_t iterations = 50;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < iterations; i++) {
        // Reset cache periodically
        if (i % 10 == 0) kv_cache.cache_len = 0;
        layer.ForwardParallel(input.data(), output.data(), kv_cache, i % 10);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    float avgTimeMs = duration.count() / static_cast<float>(iterations) / 1000.0f;
    float tokensPerSec = 1000.0f / avgTimeMs;
    
    std::cout << "\nResults (Parallel):\n";
    std::cout << "  Iterations: " << iterations << "\n";
    std::cout << "  Total time: " << duration.count() / 1000.0f << " ms\n";
    std::cout << "  Avg time per token: " << avgTimeMs << " ms\n";
    std::cout << "  Throughput: " << tokensPerSec << " tokens/sec\n\n";
    
    // Compare to sequential baseline
    std::cout << "Comparing to sequential baseline...\n";
    
    TransformerLayer seq_layer(config);
    seq_layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
                          attn_n.data(), ffn_g.data(), ffn_u.data(), 
                          ffn_d.data(), ffn_n.data());
    
    // Warmup sequential
    for (int i = 0; i < 5; i++) {
        seq_layer.Forward(input.data(), output.data(), kv_cache, 0);
        kv_cache.cache_len = 0;
    }
    
    // Benchmark sequential
    start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < iterations; i++) {
        if (i % 10 == 0) kv_cache.cache_len = 0;
        seq_layer.Forward(input.data(), output.data(), kv_cache, i % 10);
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto seq_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    float seqAvgTimeMs = seq_duration.count() / static_cast<float>(iterations) / 1000.0f;
    float seqTokensPerSec = 1000.0f / seqAvgTimeMs;
    
    std::cout << "\nResults (Sequential):\n";
    std::cout << "  Avg time per token: " << seqAvgTimeMs << " ms\n";
    std::cout << "  Throughput: " << seqTokensPerSec << " tokens/sec\n\n";
    
    // Speedup
    float speedup = seqAvgTimeMs / avgTimeMs;
    std::cout << "Speedup: " << speedup << "x\n\n";
    
    // Test with different thread counts
    std::cout << "Testing different thread counts:\n";
    std::vector<size_t> thread_counts = {1, 2, 4, 8, 16};
    
    for (size_t tc : thread_counts) {
        if (tc > ThreadPool::HardwareConcurrency()) continue;
        
        layer.SetNumThreads(tc);
        
        // Warmup
        for (int i = 0; i < 3; i++) {
            layer.ForwardParallel(input.data(), output.data(), kv_cache, 0);
            kv_cache.cache_len = 0;
        }
        
        // Benchmark
        start = std::chrono::high_resolution_clock::now();
        for (uint32_t i = 0; i < 20; i++) {
            if (i % 5 == 0) kv_cache.cache_len = 0;
            layer.ForwardParallel(input.data(), output.data(), kv_cache, i % 5);
        }
        end = std::chrono::high_resolution_clock::now();
        auto dur = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        float tpt = 1000.0f / (dur.count() / 20.0f / 1000.0f);
        
        std::cout << "  " << tc << " threads: " << tpt << " tokens/sec\n";
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Test Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
