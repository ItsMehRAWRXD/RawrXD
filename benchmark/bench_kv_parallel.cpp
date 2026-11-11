// ============================================================================
// Benchmark: KV Cache Optimization + Parallel Attention
// ============================================================================
// Tests the impact of:
// 1. SoA KV cache layout
// 2. Prefetching
// 3. Multi-threaded attention
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <thread>

#include "../runtime/kv_cache_optimized.hpp"
#include "../kernels/avx2_kernels.hpp"
#include "../kernels/avx512_kernels.hpp"

using namespace RawrXD::Runtime;
using namespace rawrxd::kernels;

// ============================================================================
// Benchmark Configurations
// ============================================================================

struct BenchConfig {
    uint32_t num_layers = 24;
    uint32_t num_heads = 32;
    uint32_t head_dim = 64;
    uint32_t seq_len = 128;
    uint32_t batch_size = 1;
    uint32_t iterations = 100;
};

// ============================================================================
// Baseline: Simple KV Cache (AoS layout)
// ============================================================================

class BaselineKVCache {
public:
    std::vector<float> k_cache;
    std::vector<float> v_cache;
    
    void Init(uint32_t layers, uint32_t heads, uint32_t seq, uint32_t dim) {
        k_cache.resize(layers * heads * seq * dim);
        v_cache.resize(layers * heads * seq * dim);
    }
    
    float* GetK(uint32_t layer, uint32_t head, uint32_t pos, uint32_t dim) {
        return &k_cache[((layer * 32 + head) * 128 + pos) * dim];
    }
};

// ============================================================================
// Benchmark Functions
// ============================================================================

double BenchBaselineKV(const BenchConfig& config) {
    BaselineKVCache cache;
    cache.Init(config.num_layers, config.num_heads, config.seq_len, config.head_dim);
    
    // Warmup
    for (uint32_t l = 0; l < config.num_layers; ++l) {
        for (uint32_t h = 0; h < config.num_heads; ++h) {
            volatile float* ptr = cache.GetK(l, h, 0, config.head_dim);
            (void)ptr;
        }
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.iterations; ++iter) {
        for (uint32_t l = 0; l < config.num_layers; ++l) {
            for (uint32_t h = 0; h < config.num_heads; ++h) {
                for (uint32_t s = 0; s < config.seq_len; ++s) {
                    volatile float* ptr = cache.GetK(l, h, s, config.head_dim);
                    // Touch memory
                    for (uint32_t d = 0; d < config.head_dim; d += 16) {
                        (void)ptr[d];
                    }
                }
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    return duration.count() / 1000.0 / config.iterations; // ms per iteration
}

double BenchOptimizedKV(const BenchConfig& config) {
    OptimizedKVCache cache;
    OptimizedKVCache::Config cache_config;
    cache_config.num_layers = config.num_layers;
    cache_config.num_heads = config.num_heads;
    cache_config.head_dim = config.head_dim;
    cache_config.max_seq_len = config.seq_len;
    cache_config.batch_size = config.batch_size;
    
    if (!cache.Initialize(cache_config)) {
        return -1.0;
    }
    
    // Warmup
    for (uint32_t l = 0; l < config.num_layers; ++l) {
        for (uint32_t h = 0; h < config.num_heads; ++h) {
            volatile float* ptr = cache.GetK(l, h, 0);
            (void)ptr;
        }
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.iterations; ++iter) {
        for (uint32_t l = 0; l < config.num_layers; ++l) {
            for (uint32_t h = 0; h < config.num_heads; ++h) {
                // Use block access for better locality
                float* k_block = cache.GetKBlock(l, h, 0, config.seq_len);
                
                // Touch memory with prefetching
                for (uint32_t s = 0; s < config.seq_len; s += 16) {
                    cache.PrefetchK(l, h, s + 16, 4);
                    
                    // Touch current block
                    for (uint32_t d = 0; d < config.head_dim; d += 16) {
                        (void)k_block[s * config.head_dim + d];
                    }
                }
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    return duration.count() / 1000.0 / config.iterations;
}

double BenchParallelAttention(const BenchConfig& config) {
    // Create work items for parallel processing
    std::vector<ParallelAttention::WorkItem> items;
    items.reserve(config.num_heads);
    
    // Mock data
    std::vector<float> query(config.head_dim, 0.01f);
    std::vector<float> output(config.head_dim, 0.0f);
    
    for (uint32_t h = 0; h < config.num_heads; ++h) {
        ParallelAttention::WorkItem item;
        item.layer = 0;
        item.head_start = h;
        item.head_end = h + 1;
        item.seq_len = config.seq_len;
        item.query = query.data();
        item.key_cache = nullptr;  // Would be real cache
        item.value_cache = nullptr;
        item.output = output.data();
        items.push_back(item);
    }
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Run parallel attention (simplified - just thread spawn overhead)
    for (uint32_t iter = 0; iter < config.iterations; ++iter) {
        uint32_t threads_used = ParallelAttention::ComputeAttentionParallel(
            items.data(), items.size(), 0);
        (void)threads_used;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    return duration.count() / 1000.0 / config.iterations;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "KV Cache + Parallel Attention Benchmark\n";
    std::cout << "========================================\n\n";
    
    // Print CPU features
    CPUFeatures::Print();
    std::cout << "\n";
    
    BenchConfig config;
    config.num_layers = 24;
    config.num_heads = 32;
    config.head_dim = 64;
    config.seq_len = 128;
    config.iterations = 50;
    
    std::cout << "Configuration:\n";
    std::cout << "  Layers: " << config.num_layers << "\n";
    std::cout << "  Heads: " << config.num_heads << "\n";
    std::cout << "  Head dim: " << config.head_dim << "\n";
    std::cout << "  Seq len: " << config.seq_len << "\n";
    std::cout << "  Iterations: " << config.iterations << "\n\n";
    
    // Run benchmarks
    std::cout << "Running benchmarks...\n\n";
    
    std::cout << "1. Baseline KV Cache (AoS layout):\n";
    double baseline_time = BenchBaselineKV(config);
    std::cout << "   Time: " << std::fixed << std::setprecision(2) << baseline_time << " ms\n";
    std::cout << "   Throughput: " << std::setprecision(1) 
              << (config.num_layers * config.num_heads * config.seq_len / (baseline_time / 1000.0)) 
              << " accesses/sec\n\n";
    
    std::cout << "2. Optimized KV Cache (SoA layout + prefetch):\n";
    double optimized_time = BenchOptimizedKV(config);
    if (optimized_time > 0) {
        std::cout << "   Time: " << std::fixed << std::setprecision(2) << optimized_time << " ms\n";
        std::cout << "   Throughput: " << std::setprecision(1)
                  << (config.num_layers * config.num_heads * config.seq_len / (optimized_time / 1000.0))
                  << " accesses/sec\n";
        double speedup = baseline_time / optimized_time;
        std::cout << "   Speedup: " << std::setprecision(2) << speedup << "x\n\n";
    } else {
        std::cout << "   FAILED\n\n";
    }
    
    std::cout << "3. Parallel Attention (thread spawn):\n";
    double parallel_time = BenchParallelAttention(config);
    std::cout << "   Time: " << std::fixed << std::setprecision(2) << parallel_time << " ms\n";
    std::cout << "   Overhead: " << std::setprecision(2) << parallel_time << " ms for " 
              << config.num_heads << " heads\n\n";
    
    // Summary
    std::cout << "========================================\n";
    std::cout << "Summary\n";
    std::cout << "========================================\n";
    
    if (optimized_time > 0) {
        double kv_speedup = baseline_time / optimized_time;
        std::cout << "KV Cache Speedup: " << std::setprecision(2) << kv_speedup << "x\n";
        
        if (kv_speedup > 1.2) {
            std::cout << "✓ SoA layout + prefetching is effective\n";
        } else {
            std::cout << "⚠ Limited benefit from SoA on this workload\n";
        }
    }
    
    std::cout << "\nRecommendations:\n";
    if (optimized_time > 0 && baseline_time / optimized_time > 1.2) {
        std::cout << "  1. Use OptimizedKVCache in transformer layers\n";
        std::cout << "  2. Enable prefetching for attention kernels\n";
    }
    std::cout << "  3. Parallelize attention across heads (" << std::thread::hardware_concurrency() 
              << " threads available)\n";
    std::cout << "  4. Profile actual attention computation with MASM telemetry\n";
    
    std::cout << "\n========================================\n";
    
    return 0;
}
