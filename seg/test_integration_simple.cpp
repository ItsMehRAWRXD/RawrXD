// ============================================================================
// Simple Integration Test for AVX-512 Transformer
// ============================================================================

#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include "transformer_layer_inference.hpp"

using namespace RawrXD::Inference;

int main() {
    std::cout << "========================================\n";
    std::cout << "AVX-512 Transformer Integration Test\n";
    std::cout << "========================================\n\n";
    
    // Config matching typical LLM dimensions
    TransformerConfig config;
    config.hidden_size = 512;
    config.num_heads = 8;
    config.num_kv_heads = 4;
    config.head_dim = 64;
    config.intermediate_size = 1024;
    config.rms_norm_eps = 1e-5f;
    
    std::cout << "Config:\n";
    std::cout << "  Hidden: " << config.hidden_size << "\n";
    std::cout << "  Heads: " << config.num_heads << "\n";
    std::cout << "  KV Heads: " << config.num_kv_heads << "\n";
    std::cout << "  Head Dim: " << config.head_dim << "\n";
    std::cout << "  Intermediate: " << config.intermediate_size << "\n\n";
    
    // Create layer
    TransformerLayer layer(config);
    std::cout << "✓ Layer created\n";
    
    // Allocate and initialize weights
    uint32_t hidden = config.hidden_size;
    uint32_t kv_hidden = config.num_kv_heads * config.head_dim;
    uint32_t intermediate = config.intermediate_size;
    
    std::vector<float> q_w(hidden * hidden, 0.001f);
    std::vector<float> k_w(hidden * kv_hidden, 0.001f);
    std::vector<float> v_w(hidden * kv_hidden, 0.001f);
    std::vector<float> o_w(hidden * hidden, 0.001f);
    std::vector<float> attn_n(hidden, 1.0f);
    std::vector<float> ffn_g(hidden * intermediate, 0.001f);
    std::vector<float> ffn_u(hidden * intermediate, 0.001f);
    std::vector<float> ffn_d(intermediate * hidden, 0.001f);
    std::vector<float> ffn_n(hidden, 1.0f);
    
    // Load weights
    layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
                      attn_n.data(), ffn_g.data(), ffn_u.data(), 
                      ffn_d.data(), ffn_n.data());
    std::cout << "✓ Weights loaded\n";
    
    // Prepare input and output
    std::vector<float> input(hidden, 0.1f);
    std::vector<float> output(hidden, 0.0f);
    
    // Prepare KV cache
    KVCache kv_cache;
    kv_cache.k_cache.resize(32 * kv_hidden);
    kv_cache.v_cache.resize(32 * kv_hidden);
    kv_cache.cache_len = 0;
    
    std::cout << "\nRunning forward pass tests...\n";
    
    // Test 1: Single forward pass
    std::cout << "\nTest 1: Single forward pass\n";
    bool success = layer.Forward(input.data(), output.data(), kv_cache, 0);
    if (!success) {
        std::cout << "  ✗ Forward pass failed\n";
        return 1;
    }
    
    // Check output is not all zeros
    float sum = 0.0f;
    for (float v : output) sum += std::abs(v);
    std::cout << "  ✓ Forward pass complete\n";
    std::cout << "  Output L1 norm: " << sum << "\n";
    
    if (sum < 1e-10f) {
        std::cout << "  ✗ Output is all zeros - possible error\n";
        return 1;
    }
    
    // Test 2: Multiple positions
    std::cout << "\nTest 2: Multiple positions\n";
    for (uint32_t pos = 1; pos < 5; pos++) {
        success = layer.Forward(input.data(), output.data(), kv_cache, pos);
        if (!success) {
            std::cout << "  ✗ Forward pass at position " << pos << " failed\n";
            return 1;
        }
    }
    std::cout << "  ✓ Forward pass at 5 positions complete\n";
    std::cout << "  Cache length: " << kv_cache.cache_len << "\n";
    
    // Test 3: Benchmark
    std::cout << "\nTest 3: Performance benchmark\n";
    
    // Reset cache
    kv_cache.cache_len = 0;
    
    // Warmup
    for (int i = 0; i < 10; i++) {
        layer.Forward(input.data(), output.data(), kv_cache, 0);
    }
    
    // Benchmark
    uint32_t iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < iterations; i++) {
        // Reset cache periodically to avoid it growing too large
        if (i % 10 == 0) kv_cache.cache_len = 0;
        layer.Forward(input.data(), output.data(), kv_cache, i % 10);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    float avgTime = duration.count() / static_cast<float>(iterations);
    float tokensPerSec = 1000000.0f / avgTime;
    
    std::cout << "  " << iterations << " iterations\n";
    std::cout << "  Total time: " << duration.count() / 1000.0f << " ms\n";
    std::cout << "  Avg time: " << avgTime << " us\n";
    std::cout << "  Throughput: " << tokensPerSec << " tokens/sec\n";
    
    std::cout << "\n========================================\n";
    std::cout << "All tests passed!\n";
    std::cout << "========================================\n";
    
    return 0;
}
