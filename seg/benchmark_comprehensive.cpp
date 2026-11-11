// ============================================================================
// Comprehensive Transformer Benchmark
// ============================================================================
// Runs multiple iterations and reports statistics
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <cmath>
#include <algorithm>
#include <numeric>
#include "transformer_layer_inference.hpp"

using namespace RawrXD::Inference;

// High-resolution timer
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

// Initialize weights with random values
void InitWeights(std::vector<float>& weights, size_t count, unsigned seed) {
    std::mt19937 gen(seed);
    std::normal_distribution<float> dist(0.0f, 0.02f);
    for (size_t i = 0; i < count; i++) {
        weights[i] = dist(gen);
    }
}

// Compute statistics
struct Stats {
    double min, max, mean, median, stddev;
};

Stats ComputeStats(const std::vector<double>& values) {
    Stats stats;
    stats.min = *std::min_element(values.begin(), values.end());
    stats.max = *std::max_element(values.begin(), values.end());
    
    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    stats.mean = sum / values.size();
    
    std::vector<double> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    stats.median = sorted[sorted.size() / 2];
    
    double sq_sum = 0.0;
    for (double v : values) {
        sq_sum += (v - stats.mean) * (v - stats.mean);
    }
    stats.stddev = std::sqrt(sq_sum / values.size());
    
    return stats;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Comprehensive Transformer Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Configuration matching Qwen2.5-7B
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
    
    std::cout << "Model Configuration:" << std::endl;
    std::cout << "  Hidden size: " << hidden << std::endl;
    std::cout << "  Num heads: " << config.num_heads << std::endl;
    std::cout << "  Num KV heads: " << config.num_kv_heads << " (GQA)" << std::endl;
    std::cout << "  Head dim: " << config.head_dim << std::endl;
    std::cout << "  Intermediate size: " << intermediate << std::endl;
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
    
    layer.LoadWeights(q_w.data(), k_w.data(), v_w.data(), o_w.data(), attn_n.data(),
                      ffn_g.data(), ffn_u.data(), ffn_d.data(), ffn_n.data());
    
    // Initialize input and KV cache
    std::vector<float> input(hidden);
    std::vector<float> output(hidden);
    InitWeights(input, input.size(), 10);
    
    KVCache kv_cache;
    kv_cache.k_cache.resize(2048 * kv_hidden);
    kv_cache.v_cache.resize(2048 * kv_hidden);
    kv_cache.cache_len = 0;
    
    // Warmup
    std::cout << "Warming up..." << std::endl;
    for (int i = 0; i < 20; i++) {
        layer.Forward(input.data(), output.data(), kv_cache, 0);
    }
    std::cout << "Warmup complete." << std::endl << std::endl;
    
    // Benchmark with multiple runs
    const int runs = 10;
    const int iterations_per_run = 50;
    std::vector<double> throughputs;
    Timer timer;
    
    std::cout << "Running " << runs << " benchmark rounds..." << std::endl;
    for (int run = 0; run < runs; run++) {
        timer.Start();
        for (int i = 0; i < iterations_per_run; i++) {
            layer.Forward(input.data(), output.data(), kv_cache, i % 100);
        }
        timer.Stop();
        
        double time_per_token_us = timer.ElapsedUs() / iterations_per_run;
        double tok_per_sec = 1000000.0 / time_per_token_us;
        throughputs.push_back(tok_per_sec);
        
        std::cout << "  Run " << (run + 1) << ": " << tok_per_sec << " tok/s" << std::endl;
    }
    std::cout << std::endl;
    
    // Compute statistics
    Stats stats = ComputeStats(throughputs);
    
    std::cout << "========================================" << std::endl;
    std::cout << "Performance Statistics" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "  Min:    " << stats.min << " tok/s" << std::endl;
    std::cout << "  Max:    " << stats.max << " tok/s" << std::endl;
    std::cout << "  Mean:   " << stats.mean << " tok/s" << std::endl;
    std::cout << "  Median: " << stats.median << " tok/s" << std::endl;
    std::cout << "  StdDev: " << stats.stddev << " tok/s" << std::endl;
    std::cout << std::endl;
    
    std::cout << "========================================" << std::endl;
    std::cout << "Result" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Average Throughput: " << stats.mean << " tok/s" << std::endl;
    std::cout << std::endl;
    
    if (stats.mean >= 50.0) {
        std::cout << "\u2705 Excellent: " << stats.mean << " tok/s >= 50 tok/s" << std::endl;
    } else if (stats.mean >= 40.0) {
        std::cout << "\u2705 Target achieved: " << stats.mean << " tok/s >= 40 tok/s" << std::endl;
    } else if (stats.mean >= 37.0) {
        std::cout << "\u2705 Baseline maintained: " << stats.mean << " tok/s >= 37 tok/s" << std::endl;
    } else {
        std::cout << "\u26a0 Below baseline: " << stats.mean << " tok/s < 37 tok/s" << std::endl;
    }
    
    return 0;
}
