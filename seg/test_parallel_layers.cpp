// ============================================================================
// Parallel Layer Processing Test
// ============================================================================
// Instead of parallelizing within a layer, parallelize across multiple layers
// for multi-token generation or batch processing
// ============================================================================

#include "thread_pool.hpp"
#include "transformer_layer_inference.hpp"
#include <iostream>
#include <chrono>
#include <vector>

using namespace RawrXD::Inference;

int main() {
    std::cout << "========================================\n";
    std::cout << "Parallel Layer Processing Test\n";
    std::cout << "Strategy: Parallelize across layers\n";
    std::cout << "========================================\n\n";
    
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.rms_norm_eps = 1e-5f;
    
    // Create multiple transformer layers
    const int num_layers = 4;
    std::vector<std::unique_ptr<TransformerLayer>> layers;
    
    for (int i = 0; i < num_layers; i++) {
        layers.push_back(std::make_unique<TransformerLayer>(config));
    }
    
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
    
    for (auto& layer : layers) {
        layer->LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(),
                          attn_n.data(), ffn_g.data(), ffn_u.data(), 
                          ffn_d.data(), ffn_n.data());
    }
    
    // Prepare inputs/outputs for each layer
    std::vector<std::vector<float>> inputs(num_layers, std::vector<float>(hidden, 0.1f));
    std::vector<std::vector<float>> outputs(num_layers, std::vector<float>(hidden, 0.0f));
    std::vector<KVCache> kv_caches(num_layers);
    uint32_t max_seq_len = 32768;
    
    for (auto& cache : kv_caches) {
        cache.k_cache.resize(max_seq_len * kv_hidden);
        cache.v_cache.resize(max_seq_len * kv_hidden);
        cache.cache_len = 0;
    }
    
    std::cout << "Testing " << num_layers << " layers\n\n";
    
    // Sequential baseline
    std::cout << "Sequential execution (all layers)...\n";
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < num_layers; i++) {
        layers[i]->Forward(inputs[i].data(), outputs[i].data(), kv_caches[i], 0);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto seq_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f;
    std::cout << "  Time: " << seq_time << " ms\n";
    std::cout << "  Per layer: " << seq_time / num_layers << " ms\n\n";
    
    // Parallel execution across layers
    std::cout << "Parallel execution (layers in parallel)...\n";
    ThreadPool pool;
    pool.Initialize(num_layers);
    
    // Reset KV caches
    for (auto& cache : kv_caches) {
        cache.cache_len = 0;
    }
    
    start = std::chrono::high_resolution_clock::now();
    
    std::vector<std::future<bool>> futures;
    for (int i = 0; i < num_layers; i++) {
        futures.push_back(pool.Submit([&, i]() {
            return layers[i]->Forward(inputs[i].data(), outputs[i].data(), kv_caches[i], 0);
        }));
    }
    
    for (auto& f : futures) {
        f.get();
    }
    
    end = std::chrono::high_resolution_clock::now();
    auto par_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f;
    float speedup = seq_time / par_time;
    
    std::cout << "  Time: " << par_time << " ms\n";
    std::cout << "  Speedup: " << speedup << "x\n\n";
    
    // Test with different thread counts
    std::cout << "Testing different thread counts:\n";
    std::vector<size_t> thread_counts = {1, 2, 4};
    
    for (size_t tc : thread_counts) {
        if (tc > num_layers) continue;
        
        pool.Shutdown();
        pool.Initialize(tc);
        
        // Reset KV caches
        for (auto& cache : kv_caches) {
            cache.cache_len = 0;
        }
        
        // Warmup
        for (int w = 0; w < 2; w++) {
            std::vector<std::future<bool>> wfutures;
            for (int i = 0; i < num_layers; i++) {
                wfutures.push_back(pool.Submit([&, i]() {
                    return layers[i]->Forward(inputs[i].data(), outputs[i].data(), kv_caches[i], 0);
                }));
            }
            for (auto& f : wfutures) f.get();
            for (auto& cache : kv_caches) cache.cache_len = 0;
        }
        
        // Benchmark
        start = std::chrono::high_resolution_clock::now();
        
        std::vector<std::future<bool>> bfutures;
        for (int i = 0; i < num_layers; i++) {
            bfutures.push_back(pool.Submit([&, i]() {
                return layers[i]->Forward(inputs[i].data(), outputs[i].data(), kv_caches[i], 0);
            }));
        }
        
        for (auto& f : bfutures) {
            f.get();
        }
        
        end = std::chrono::high_resolution_clock::now();
        auto time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0f;
        float sp = seq_time / time;
        
        std::cout << "  " << tc << " threads: " << time << " ms, speedup: " << sp << "x\n";
    }
    
    std::cout << "\nDone!\n";
    return 0;
}
