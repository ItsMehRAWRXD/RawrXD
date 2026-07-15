// ============================================================================
// Quick Comparison: Optimized vs Baseline
// ============================================================================
// Fast benchmark comparing KV cache + multi-threading optimizations
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>
#include <cmath>

#include "../runtime/kv_cache_optimized.hpp"
#include "../../rawrxd/src/kernels/avx2_kernels.hpp"
#include "../../rawrxd/src/kernels/avx512_kernels.hpp"

using namespace RawrXD::Runtime;
using namespace rawrxd::kernels;

// ============================================================================
// Benchmark Config
// ============================================================================

struct Config {
    uint32_t num_layers = 24;
    uint32_t num_heads = 32;
    uint32_t head_dim = 64;
    uint32_t hidden_size = 2048;
    uint32_t seq_len = 128;
    uint32_t gen_tokens = 32;  // Reduced for speed
    uint32_t iters = 3;
};

// ============================================================================
// Baseline: Simple KV Cache
// ============================================================================

class SimpleKVCache {
public:
    std::vector<float> k_cache;
    std::vector<float> v_cache;
    uint32_t num_heads = 0, head_dim = 0, max_seq = 0;
    
    void Init(uint32_t heads, uint32_t dim, uint32_t max_seq_len) {
        num_heads = heads;
        head_dim = dim;
        max_seq = max_seq_len;
        k_cache.resize(heads * max_seq_len * dim);
        v_cache.resize(heads * max_seq_len * dim);
    }
    
    float* GetK(uint32_t head, uint32_t pos) {
        return &k_cache[(head * max_seq + pos) * head_dim];
    }
    
    float* GetV(uint32_t head, uint32_t pos) {
        return &v_cache[(head * max_seq + pos) * head_dim];
    }
};

// ============================================================================
// Benchmark Functions
// ============================================================================

double BenchBaseline(const Config& cfg) {
    SimpleKVCache cache;
    cache.Init(cfg.num_heads, cfg.head_dim, cfg.seq_len + cfg.gen_tokens);
    
    std::vector<float> query(cfg.head_dim, 0.01f);
    std::vector<float> output(cfg.head_dim, 0.0f);
    std::vector<float> scores(cfg.seq_len + cfg.gen_tokens);
    
    // Warmup
    for (uint32_t h = 0; h < cfg.num_heads; ++h) {
        volatile float* ptr = cache.GetK(h, 0);
        (void)ptr;
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < cfg.iters; ++iter) {
        for (uint32_t token = 0; token < cfg.gen_tokens; ++token) {
            uint32_t current_len = cfg.seq_len + token;
            
            for (uint32_t layer = 0; layer < cfg.num_layers; ++layer) {
                for (uint32_t h = 0; h < cfg.num_heads; ++h) {
                    // Compute attention scores
                    for (uint32_t pos = 0; pos < current_len; ++pos) {
                        float* k = cache.GetK(h, pos);
                        scores[pos] = 0.0f;
                        for (uint32_t d = 0; d < cfg.head_dim; ++d) {
                            scores[pos] += query[d] * k[d];
                        }
                        scores[pos] /= std::sqrt(static_cast<float>(cfg.head_dim));
                    }
                    
                    // Softmax
                    float max_score = scores[0];
                    for (uint32_t pos = 1; pos < current_len; ++pos) {
                        if (scores[pos] > max_score) max_score = scores[pos];
                    }
                    
                    float sum = 0.0f;
                    for (uint32_t pos = 0; pos < current_len; ++pos) {
                        scores[pos] = std::exp(scores[pos] - max_score);
                        sum += scores[pos];
                    }
                    for (uint32_t pos = 0; pos < current_len; ++pos) {
                        scores[pos] /= sum;
                    }
                    
                    // Weighted sum
                    std::memset(output.data(), 0, cfg.head_dim * sizeof(float));
                    for (uint32_t pos = 0; pos < current_len; ++pos) {
                        float* v = cache.GetV(h, pos);
                        for (uint32_t d = 0; d < cfg.head_dim; ++d) {
                            output[d] += v[d] * scores[pos];
                        }
                    }
                }
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return duration.count() / 1000.0 / cfg.iters;
}

double BenchOptimized(const Config& cfg) {
    OptimizedKVCache cache;
    OptimizedKVCache::Config cache_cfg;
    cache_cfg.num_layers = 1;
    cache_cfg.num_heads = cfg.num_heads;
    cache_cfg.head_dim = cfg.head_dim;
    cache_cfg.max_seq_len = cfg.seq_len + cfg.gen_tokens;
    cache_cfg.batch_size = 1;
    
    if (!cache.Initialize(cache_cfg)) {
        return -1.0;
    }
    
    std::vector<float> query(cfg.head_dim, 0.01f);
    std::vector<float> output(cfg.head_dim, 0.0f);
    std::vector<float> scores(cfg.seq_len + cfg.gen_tokens);
    
    // Warmup
    for (uint32_t h = 0; h < cfg.num_heads; ++h) {
        volatile float* ptr = cache.GetK(0, h, 0);
        (void)ptr;
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < cfg.iters; ++iter) {
        for (uint32_t token = 0; token < cfg.gen_tokens; ++token) {
            uint32_t current_len = cfg.seq_len + token;
            
            // Parallelize across layers and heads
            for (uint32_t layer = 0; layer < cfg.num_layers; ++layer) {
                uint32_t num_threads = std::min(
                    static_cast<uint32_t>(std::thread::hardware_concurrency()),
                    cfg.num_heads);
                uint32_t heads_per_thread = cfg.num_heads / num_threads;
                
                std::vector<std::thread> threads;
                
                auto worker = [&](uint32_t h_start, uint32_t h_end) {
                    std::vector<float> local_scores(cfg.seq_len + cfg.gen_tokens);
                    std::vector<float> local_output(cfg.head_dim);
                    
                    for (uint32_t h = h_start; h < h_end; ++h) {
                        // Compute attention scores with prefetching
                        for (uint32_t pos = 0; pos < current_len; ++pos) {
                            float* k = cache.GetK(0, h, pos);
                            
                            // Prefetch next K
                            if (pos + 16 < current_len) {
                                cache.PrefetchK(0, h, pos + 16, 4);
                            }
                            
                            local_scores[pos] = KernelDispatch::VecDotF32(
                                query.data(), k, cfg.head_dim);
                            local_scores[pos] /= std::sqrt(static_cast<float>(cfg.head_dim));
                        }
                        
                        // Softmax using kernel
                        KernelDispatch::SoftmaxF32(
                            local_scores.data(), local_scores.data(), current_len);
                        
                        // Weighted sum with prefetching
                        std::memset(local_output.data(), 0, cfg.head_dim * sizeof(float));
                        for (uint32_t pos = 0; pos < current_len; ++pos) {
                            float* v = cache.GetV(0, h, pos);
                            
                            if (pos + 16 < current_len) {
                                cache.PrefetchV(0, h, pos + 16, 4);
                            }
                            
                            for (uint32_t d = 0; d < cfg.head_dim; ++d) {
                                local_output[d] += v[d] * local_scores[pos];
                            }
                        }
                    }
                };
                
                // Launch threads
                for (uint32_t t = 0; t < num_threads; ++t) {
                    uint32_t h_start = t * heads_per_thread;
                    uint32_t h_end = (t == num_threads - 1) ? cfg.num_heads : (t + 1) * heads_per_thread;
                    threads.emplace_back(worker, h_start, h_end);
                }
                
                for (auto& t : threads) {
                    t.join();
                }
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return duration.count() / 1000.0 / cfg.iters;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Quick Optimized Transformer Benchmark\n";
    std::cout << "========================================\n\n";
    
    CPUFeatures::Print();
    std::cout << "\n";
    
    Config cfg;
    std::cout << "Config: " << cfg.num_layers << " layers, " << cfg.num_heads << " heads, "
              << cfg.seq_len << " prompt + " << cfg.gen_tokens << " gen tokens\n";
    std::cout << "Threads: " << std::thread::hardware_concurrency() << "\n\n";
    
    std::cout << "Running baseline (single-threaded)...\n";
    double baseline_time = BenchBaseline(cfg);
    double baseline_tok_s = cfg.gen_tokens / baseline_time;
    std::cout << "  Time: " << std::fixed << std::setprecision(2) << baseline_time << " s\n";
    std::cout << "  Throughput: " << std::setprecision(1) << baseline_tok_s << " tok/s\n\n";
    
    std::cout << "Running optimized (SoA + multi-threaded)...\n";
    double opt_time = BenchOptimized(cfg);
    double opt_tok_s = cfg.gen_tokens / opt_time;
    std::cout << "  Time: " << std::fixed << std::setprecision(2) << opt_time << " s\n";
    std::cout << "  Throughput: " << std::setprecision(1) << opt_tok_s << " tok/s\n\n";
    
    // Summary
    std::cout << "========================================\n";
    std::cout << "Results\n";
    std::cout << "========================================\n";
    
    double speedup = baseline_time / opt_time;
    std::cout << "Speedup: " << std::setprecision(2) << speedup << "x\n";
    std::cout << "Baseline: " << std::setprecision(1) << baseline_tok_s << " tok/s\n";
    std::cout << "Optimized: " << std::setprecision(1) << opt_tok_s << " tok/s\n\n";
    
    if (opt_tok_s >= 30.0) {
        std::cout << "✓ TARGET ACHIEVED: 30+ tok/s\n";
    } else if (opt_tok_s >= 20.0) {
        std::cout << "⚠ Close to target: 20+ tok/s (need 30+)\n";
    } else {
        std::cout << "✗ Below target: " << std::setprecision(1) << opt_tok_s << " tok/s\n";
    }
    
    std::cout << "\n========================================\n";
    
    return 0;
}
