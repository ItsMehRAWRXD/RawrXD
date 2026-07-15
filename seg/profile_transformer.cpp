// ============================================================================
// Transformer Profiling Tool
// ============================================================================
// Breaks down time spent in each component
// ============================================================================

#include "transformer_layer_inference.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>

using namespace RawrXD::Inference;

struct ProfileResult {
    const char* name;
    float time_ms;
    float percentage;
};

class TransformerProfiler {
public:
    std::vector<ProfileResult> results;
    
    void Print() {
        std::cout << "\n=== Transformer Profile ===\n";
        float total = 0;
        for (const auto& r : results) {
            total += r.time_ms;
        }
        
        for (auto& r : results) {
            r.percentage = (r.time_ms / total) * 100.0f;
            std::cout << r.name << ": " << r.time_ms << " ms (" << r.percentage << "%)\n";
        }
        std::cout << "Total: " << total << " ms\n";
        std::cout << "Throughput: " << (1000.0f / total) << " tok/s\n\n";
    }
};

int main() {
    std::cout << "========================================\n";
    std::cout << "Transformer Profiling\n";
    std::cout << "========================================\n\n";
    
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.rms_norm_eps = 1e-5f;
    
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
    
    // Profile individual components
    TransformerProfiler profiler;
    
    // Profile full forward pass
    auto start = std::chrono::high_resolution_clock::now();
    const int iterations = 50;
    for (int i = 0; i < iterations; i++) {
        layer.Forward(input.data(), output.data(), kv_cache, i % 10);
        if (i % 10 == 9) kv_cache.cache_len = 0;
    }
    auto end = std::chrono::high_resolution_clock::now();
    float total_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f / iterations;
    
    std::cout << "\nFull forward pass: " << total_time << " ms/token\n";
    std::cout << "Throughput: " << (1000.0f / total_time) << " tok/s\n";
    
    // Estimate component breakdown based on operation counts
    // These are approximations based on FLOPS:
    // - QKV projections: 3 * hidden * hidden = 3 * 4096 * 4096 = 50.3M FLOPs
    // - Attention scores: num_heads * seq_len * head_dim = 32 * 10 * 128 = 41K FLOPs (small!)
    // - Attention output: num_heads * head_dim * seq_len = 41K FLOPs
    // - Output projection: hidden * hidden = 16.8M FLOPs
    // - FFN gate/up: 2 * hidden * intermediate = 2 * 4096 * 14336 = 117.4M FLOPs
    // - FFN down: intermediate * hidden = 58.7M FLOPs
    // Total MatMul: ~243M FLOPs per token
    
    std::cout << "\n=== Estimated Component Breakdown ===\n";
    std::cout << "Based on operation counts:\n";
    float total_flops = 243.0f; // Million FLOPs
    
    std::cout << "QKV Projections: ~50M FLOPs (" << (50.0f/total_flops*100) << "%)\n";
    std::cout << "Attention Compute: ~0.1M FLOPs (negligible)\n";
    std::cout << "Output Projection: ~17M FLOPs (" << (17.0f/total_flops*100) << "%)\n";
    std::cout << "FFN Gate+Up: ~117M FLOPs (" << (117.0f/total_flops*100) << "%)\n";
    std::cout << "FFN Down: ~59M FLOPs (" << (59.0f/total_flops*100) << "%)\n";
    
    std::cout << "\n=== Bottleneck Analysis ===\n";
    std::cout << "1. FFN MatMul dominates: ~72% of compute\n";
    std::cout << "2. Attention is memory-bound, not compute-bound\n";
    std::cout << "3. Large matrices (4096x14336) benefit from tiling\n";
    
    std::cout << "\n=== Optimization Opportunities ===\n";
    std::cout << "1. Flash Attention: Reduce memory bandwidth for attention\n";
    std::cout << "2. Tiled MatMul: Better cache utilization for FFN\n";
    std::cout << "3. Weight quantization: Reduce memory bandwidth\n";
    std::cout << "4. Kernel fusion: Combine RMSNorm + MatMul\n";
    
    return 0;
}
