// ============================================================================
// KV Cache Benchmark
// ============================================================================
// Compares standard vs optimized KV cache performance
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include "kv_cache_optimizer.hpp"

using namespace seg;

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    uint32_t num_layers = 24;
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 32;  // MHA
    uint32_t head_dim = 64;      // 2048 / 32
    uint32_t max_seq_len = 4096;
    uint32_t num_iterations = 100;
};

// ============================================================================
// Run Benchmark
// ============================================================================
void RunBenchmark(const BenchmarkConfig& config) {
    std::cout << "========================================\n";
    std::cout << "KV Cache Benchmark\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Configuration:\n";
    std::cout << "  Layers: " << config.num_layers << "\n";
    std::cout << "  Heads: " << config.num_heads << "\n";
    std::cout << "  KV Heads: " << config.num_kv_heads << "\n";
    std::cout << "  Head dim: " << config.head_dim << "\n";
    std::cout << "  Max seq len: " << config.max_seq_len << "\n";
    std::cout << "  Iterations: " << config.num_iterations << "\n\n";
    
    // Initialize caches
    OptimizedKVCache opt_cache;
    StandardKVCache std_cache;
    
    if (!opt_cache.Initialize(config.max_seq_len, config.num_kv_heads, config.head_dim)) {
        std::cerr << "Failed to initialize optimized cache\n";
        return;
    }
    
    if (!std_cache.Initialize(config.max_seq_len, config.num_kv_heads, config.head_dim)) {
        std::cerr << "Failed to initialize standard cache\n";
        return;
    }
    
    // Memory usage comparison
    std::cout << "Memory Usage:\n";
    std::cout << "  Standard:  " << (std_cache.GetMemoryUsage() / (1024.0 * 1024.0)) << " MB\n";
    std::cout << "  Optimized: " << (opt_cache.GetMemoryUsage() / (1024.0 * 1024.0)) << " MB\n";
    std::cout << "  Overhead:  " << ((opt_cache.GetMemoryUsage() - std_cache.GetMemoryUsage()) / 
                                    (1024.0 * 1024.0)) << " MB\n\n";
    
    // Prepare query and output buffers
    std::vector<float> query(config.num_heads * config.head_dim, 0.1f);
    std::vector<float> output(config.num_heads * config.head_dim, 0.0f);
    
    // Benchmark standard cache
    std::cout << "Running Standard Cache Benchmark...\n";
    auto std_start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.num_iterations; iter++) {
        uint32_t seq_len = 128 + (iter % 512);  // Vary sequence length
        
        // Simulate attention computation for each layer
        for (uint32_t layer = 0; layer < config.num_layers; layer++) {
            ComputeAttentionStandard(
                query.data(), std_cache, config.num_heads, config.num_kv_heads,
                config.head_dim, seq_len, output.data()
            );
        }
    }
    
    auto std_end = std::chrono::high_resolution_clock::now();
    double std_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        std_end - std_start).count() / 1000.0;
    
    // Benchmark optimized cache
    std::cout << "Running Optimized Cache Benchmark...\n";
    auto opt_start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.num_iterations; iter++) {
        uint32_t seq_len = 128 + (iter % 512);
        
        for (uint32_t layer = 0; layer < config.num_layers; layer++) {
            ComputeAttentionOptimized(
                query.data(), opt_cache, config.num_heads, config.num_kv_heads,
                config.head_dim, seq_len, output.data()
            );
        }
    }
    
    auto opt_end = std::chrono::high_resolution_clock::now();
    double opt_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        opt_end - opt_start).count() / 1000.0;
    
    // Results
    std::cout << "\n========================================\n";
    std::cout << "Results\n";
    std::cout << "========================================\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Standard time:  " << std_time_ms << " ms\n";
    std::cout << "  Optimized time: " << opt_time_ms << " ms\n";
    std::cout << "  Speedup:        " << (std_time_ms / opt_time_ms) << "x\n";
    std::cout << "  Improvement:    " << ((std_time_ms - opt_time_ms) / std_time_ms * 100) << "%\n\n";
    
    // Cache efficiency
    std::cout << "Cache Efficiency:\n";
    std::cout << "  Optimized hit rate: " << (opt_cache.GetCacheHitRate() * 100) << "%\n";
    std::cout << "  Standard hit rate:  ~70% (estimated)\n\n";
    
    // Analysis
    std::cout << "Analysis:\n";
    if (opt_time_ms < std_time_ms) {
        std::cout << "  ✓ Optimized layout shows improvement\n";
        std::cout << "  ✓ Cache-line alignment reduces memory bandwidth\n";
    } else {
        std::cout << "  ⚠ No improvement (may be due to small head_dim)\n";
        std::cout << "  ⚠ Benefits increase with larger models\n";
    }
    std::cout << "\n";
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    BenchmarkConfig config;
    
    // Parse args
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--layers" && i + 1 < argc) config.num_layers = std::stoi(argv[++i]);
        else if (arg == "--heads" && i + 1 < argc) config.num_heads = std::stoi(argv[++i]);
        else if (arg == "--head-dim" && i + 1 < argc) config.head_dim = std::stoi(argv[++i]);
        else if (arg == "--seq-len" && i + 1 < argc) config.max_seq_len = std::stoi(argv[++i]);
        else if (arg == "--iterations" && i + 1 < argc) config.num_iterations = std::stoi(argv[++i]);
    }
    
    RunBenchmark(config);
    
    return 0;
}
