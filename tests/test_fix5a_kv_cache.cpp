//=============================================================================
// Fix 5A Validation Test: KV Cache Layout Rewrite
// Verifies 64-byte alignment and 2x performance gain
//=============================================================================

#include "memory/RawrXD_KVCache_Layout.hpp"
#include "runtime/RawrXD_DeterministicPerformance.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <cmath>

using namespace RawrXD::Memory;
using namespace RawrXD::Runtime;

//=============================================================================
// Alignment Validation
//=============================================================================
bool ValidateAlignment(const KVCacheConfig& config) {
    std::cout << "[ALIGNMENT CHECK] Validating 64-byte alignment..." << std::endl;
    
    OptimizedKVCache cache(config);
    
    // Check each token starts at 64-byte boundary
    for (uint32_t t = 0; t < std::min(config.max_seq_len, 100u); ++t) {
        float* k = cache.GetK(t, 0);
        if ((uintptr_t)k % 64 != 0) {
            std::cerr << "  FAILED: Token " << t << " K not 64-byte aligned (offset: " 
                      << ((uintptr_t)k % 64) << ")" << std::endl;
            return false;
        }
        
        // Verify K and V are contiguous
        float* v = cache.GetV(t, 0);
        float* expected_v = k + config.head_dim;
        if (v != expected_v) {
            std::cerr << "  FAILED: K and V not contiguous for token " << t << std::endl;
            return false;
        }
    }
    
    std::cout << "  PASSED: All tokens 64-byte aligned, K/V contiguous" << std::endl;
    return true;
}

//=============================================================================
// Cache Performance Microbenchmark
//=============================================================================
double BenchmarkCacheAccess(OptimizedKVCache& cache, const KVCacheConfig& config, 
                            uint32_t seq_len, uint32_t num_iterations = 1000) {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> token_dist(0, seq_len - 1);
    std::uniform_int_distribution<uint32_t> head_dist(0, config.num_heads - 1);
    
    // Warmup
    volatile float sum = 0;
    for (int i = 0; i < 100; ++i) {
        uint32_t t = token_dist(rng);
        uint32_t h = head_dist(rng);
        float* k = cache.GetK(t, h);
        if (k) {
            for (uint32_t d = 0; d < config.head_dim; ++d) {
                sum += k[d];
            }
        }
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < num_iterations; ++iter) {
        // Simulate attention pattern: sequential token access
        for (uint32_t t = 0; t < seq_len; ++t) {
            for (uint32_t h = 0; h < config.num_heads; ++h) {
                float* k = cache.GetK(t, h);
                float* v = cache.GetV(t, h);
                if (k && v) {
                    // Dot product simulation
                    float dot = 0;
                    for (uint32_t d = 0; d < config.head_dim; d += 16) {
                        dot += k[d] * v[d];
                    }
                    sum += dot;
                }
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Calculate tokens per second
    double total_tokens = static_cast<double>(seq_len * config.num_heads * num_iterations);
    double seconds = duration.count() / 1e6;
    double tps = total_tokens / seconds;
    
    return tps;
}

//=============================================================================
// Legacy Layout Benchmark (for comparison)
//=============================================================================
double BenchmarkLegacyAccess(LegacyKVCache& cache, const KVCacheConfig& config,
                             uint32_t seq_len, uint32_t num_iterations = 1000) {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<uint32_t> token_dist(0, seq_len - 1);
    std::uniform_int_distribution<uint32_t> head_dist(0, config.num_heads - 1);
    
    // Warmup
    volatile float sum = 0;
    for (int i = 0; i < 100; ++i) {
        uint32_t t = token_dist(rng);
        uint32_t h = head_dist(rng);
        float* k = cache.GetK(t, h);
        if (k) {
            for (uint32_t d = 0; d < config.head_dim; ++d) {
                sum += k[d];
            }
        }
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < num_iterations; ++iter) {
        for (uint32_t t = 0; t < seq_len; ++t) {
            for (uint32_t h = 0; h < config.num_heads; ++h) {
                float* k = cache.GetK(t, h);
                float* v = cache.GetV(t, h);
                if (k && v) {
                    float dot = 0;
                    for (uint32_t d = 0; d < config.head_dim; d += 16) {
                        dot += k[d] * v[d];
                    }
                    sum += dot;
                }
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    double total_tokens = static_cast<double>(seq_len * config.num_heads * num_iterations);
    double seconds = duration.count() / 1e6;
    double tps = total_tokens / seconds;
    
    return tps;
}

//=============================================================================
// Main Test
//=============================================================================
int main(int argc, char* argv[]) {
    std::cout << "=================================================================" << std::endl;
    std::cout << "Fix 5A: KV Cache Layout Rewrite Validation" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << std::endl;
    
    // Initialize deterministic mode
    if (!DeterministicPerformanceManager::Initialize(argc, const_cast<const char**>(argv))) {
        std::cerr << "ERROR: Failed to initialize deterministic mode" << std::endl;
        return 1;
    }
    
    // Configuration
    KVCacheConfig config;
    config.num_heads = 32;
    config.head_dim = 128;
    config.max_seq_len = 4096;
    config.window_size = 2048;
    
    std::cout << "Configuration:" << std::endl;
    std::cout << "  Heads: " << config.num_heads << std::endl;
    std::cout << "  Head Dim: " << config.head_dim << std::endl;
    std::cout << "  Max Seq Len: " << config.max_seq_len << std::endl;
    std::cout << "  Window Size: " << config.window_size << std::endl;
    std::cout << std::endl;
    
    // Check alignment
    size_t raw_token = config.num_heads * 2 * config.head_dim * sizeof(float);
    size_t aligned_token = config.GetTokenStride();
    std::cout << "Token Stride: " << aligned_token << " bytes (raw: " << raw_token 
              << ", padding: " << (aligned_token - raw_token) << ")" << std::endl;
    std::cout << "Alignment: " << (config.IsAligned() ? "PERFECT" : "PADDED") << std::endl;
    std::cout << std::endl;
    
    // Test 1: Alignment validation
    if (!ValidateAlignment(config)) {
        return 1;
    }
    std::cout << std::endl;
    
    // Test 2: Performance comparison
    std::cout << "[PERFORMANCE BENCHMARK] Running cache access patterns..." << std::endl;
    
    OptimizedKVCache optimized(config);
    LegacyKVCache legacy(config);
    
    // Initialize with test data
    for (uint32_t t = 0; t < 100; ++t) {
        for (uint32_t h = 0; h < config.num_heads; ++h) {
            float* k = optimized.GetK(t, h);
            float* v = optimized.GetV(t, h);
            if (k && v) {
                for (uint32_t d = 0; d < config.head_dim; ++d) {
                    k[d] = static_cast<float>(d) / config.head_dim;
                    v[d] = static_cast<float>(d) / config.head_dim;
                }
            }
        }
    }
    
    // Benchmark at different sequence lengths
    std::vector<uint32_t> seq_lengths = {512, 1024, 2048, 4096};
    
    std::cout << std::endl;
    std::cout << "Sequence Length | Optimized TPS | Legacy TPS | Speedup" << std::endl;
    std::cout << "----------------|---------------|------------|--------" << std::endl;
    
    double total_speedup = 0;
    int num_tests = 0;
    
    for (uint32_t seq_len : seq_lengths) {
        double opt_tps = BenchmarkCacheAccess(optimized, config, seq_len, 100);
        double leg_tps = BenchmarkLegacyAccess(legacy, config, seq_len, 100);
        double speedup = opt_tps / leg_tps;
        
        std::cout << std::setw(15) << seq_len << " | "
                  << std::setw(13) << std::fixed << std::setprecision(0) << opt_tps << " | "
                  << std::setw(10) << std::fixed << std::setprecision(0) << leg_tps << " | "
                  << std::setw(6) << std::fixed << std::setprecision(2) << speedup << "x" << std::endl;
        
        total_speedup += speedup;
        num_tests++;
    }
    
    double avg_speedup = total_speedup / num_tests;
    std::cout << "----------------|---------------|------------|--------" << std::endl;
    std::cout << "Average Speedup: " << std::fixed << std::setprecision(2) << avg_speedup << "x" << std::endl;
    std::cout << std::endl;
    
    // Test 3: Layout info
    std::string info;
    optimized.GetLayoutInfo(info);
    std::cout << info << std::endl;
    
    // Validation
    bool passed = true;
    
    if (avg_speedup < 1.5) {
        std::cerr << "WARNING: Speedup (" << avg_speedup << "x) below expected 2x target" << std::endl;
        passed = false;
    }
    
    if (!config.IsAligned()) {
        std::cerr << "WARNING: Token alignment not optimal" << std::endl;
        passed = false;
    }
    
    std::cout << "=================================================================" << std::endl;
    std::cout << "Fix 5A Validation: " << (passed ? "PASSED" : "WARNING") << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    return passed ? 0 : 1;
}
