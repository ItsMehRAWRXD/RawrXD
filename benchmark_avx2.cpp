// ============================================================================
// AVX2 Performance Benchmark
// Measure actual tokens/sec with optimized kernels
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include "src/kernels/avx2_gemm.hpp"
#include "src/kernels/optimized_transformer.hpp"

using namespace rawrxd::kernels;

// ============================================================================
// Benchmark GEMM Performance
// ============================================================================
void BenchmarkGEMM() {
    std::cout << "\n=== AVX2 GEMM Benchmark ===" << std::endl;
    
    // Test different matrix sizes
    std::vector<std::tuple<size_t, size_t, size_t>> test_sizes = {
        {1024, 1024, 1024},    // Square matrices
        {2048, 1024, 1024},    // Wide
        {1024, 2048, 1024},    // Tall
        {4096, 1024, 1024},    // Very wide (like attention)
    };
    
    for (const auto& [M, N, K] : test_sizes) {
        // Allocate aligned memory
        float* A = (float*)_aligned_malloc(M * K * sizeof(float), 32);
        float* B = (float*)_aligned_malloc(K * N * sizeof(float), 32);
        float* C = (float*)_aligned_malloc(M * N * sizeof(float), 32);
        
        // Initialize with random data
        std::mt19937 rng(42);
        std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
        
        for (size_t i = 0; i < M * K; i++) A[i] = dist(rng);
        for (size_t i = 0; i < K * N; i++) B[i] = dist(rng);
        
        // Warmup
        for (int i = 0; i < 5; i++) {
            AVX2_Gemm_F32_F32(A, B, C, M, N, K, true);
        }
        
        // Benchmark
        const int iterations = 20;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; i++) {
            AVX2_Gemm_F32_F32(A, B, C, M, N, K, true);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double time_ms = std::chrono::duration<double, std::milli>(end - start).count() / iterations;
        
        // Calculate performance
        double ops = 2.0 * M * N * K;  // Multiply-adds
        double gflops = (ops / 1e9) / (time_ms / 1000.0);
        double bytes = (M * K + K * N + M * N) * sizeof(float);
        double bandwidth_gbps = (bytes / 1e9) / (time_ms / 1000.0);
        
        std::cout << "  [" << M << "x" << K << "] @ [" << K << "x" << N << "]" << std::endl;
        std::cout << "    Time: " << time_ms << " ms" << std::endl;
        std::cout << "    Performance: " << gflops << " GFLOPS" << std::endl;
        std::cout << "    Bandwidth: " << bandwidth_gbps << " GB/s" << std::endl;
        
        _aligned_free(A);
        _aligned_free(B);
        _aligned_free(C);
    }
}

// ============================================================================
// Benchmark Transformer Layer
// ============================================================================
void BenchmarkTransformerLayer() {
    std::cout << "\n=== Transformer Layer Benchmark ===" << std::endl;
    
    // Config matching ministral3
    OptimizedTransformerConfig config;
    config.hidden_size = 1024;
    config.num_heads = 16;
    config.num_kv_heads = 16;
    config.head_dim = 64;
    config.intermediate_size = 8192;
    config.max_seq_len = 32768;
    
    // Initialize layer weights with random data
    OptimizedLayerWeights weights;
    weights.hidden_size = config.hidden_size;
    weights.intermediate_size = config.intermediate_size;
    weights.num_heads = config.num_heads;
    weights.head_dim = config.head_dim;
    
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-0.1f, 0.1f);
    
    // Allocate and initialize weights
    weights.q_proj.resize(config.hidden_size * config.hidden_size);
    weights.k_proj.resize(config.hidden_size * config.num_kv_heads * config.head_dim);
    weights.v_proj.resize(config.hidden_size * config.num_kv_heads * config.head_dim);
    weights.o_proj.resize(config.hidden_size * config.hidden_size);
    weights.gate_proj.resize(config.hidden_size * config.intermediate_size);
    weights.up_proj.resize(config.hidden_size * config.intermediate_size);
    weights.down_proj.resize(config.intermediate_size * config.hidden_size);
    weights.input_layernorm.resize(config.hidden_size, 1.0f);
    weights.post_attention_layernorm.resize(config.hidden_size, 1.0f);
    
    for (auto& w : weights.q_proj) w = dist(rng);
    for (auto& w : weights.k_proj) w = dist(rng);
    for (auto& w : weights.v_proj) w = dist(rng);
    for (auto& w : weights.o_proj) w = dist(rng);
    for (auto& w : weights.gate_proj) w = dist(rng);
    for (auto& w : weights.up_proj) w = dist(rng);
    for (auto& w : weights.down_proj) w = dist(rng);
    
    // Initialize layer
    OptimizedTransformerLayer layer;
    if (!layer.Initialize(weights, config)) {
        std::cerr << "Failed to initialize layer" << std::endl;
        return;
    }
    
    // Initialize KV cache
    SREMKVCache kv_cache;
    kv_cache.Initialize(1, config.max_seq_len, config.num_kv_heads, config.head_dim);
    
    // Test different sequence lengths
    std::vector<size_t> seq_lengths = {1, 8, 32, 128, 512};
    
    for (size_t seq_len : seq_lengths) {
        // Allocate input/output
        std::vector<float> input(seq_len * config.hidden_size);
        std::vector<float> output(seq_len * config.hidden_size);
        
        for (auto& v : input) v = dist(rng);
        
        // Warmup
        for (int i = 0; i < 3; i++) {
            layer.Forward(input.data(), output.data(), 1, seq_len, &kv_cache, 0);
            kv_cache.Clear();
        }
        
        // Benchmark
        const int iterations = 10;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < iterations; i++) {
            layer.Forward(input.data(), output.data(), 1, seq_len, &kv_cache, 0);
            kv_cache.Clear();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double time_ms = std::chrono::duration<double, std::milli>(end - start).count() / iterations;
        
        double tokens_per_sec = (seq_len * 1000.0) / time_ms;
        
        std::cout << "  Seq len: " << seq_len << std::endl;
        std::cout << "    Time: " << time_ms << " ms" << std::endl;
        std::cout << "    Throughput: " << tokens_per_sec << " tok/s" << std::endl;
        std::cout << "    Attention: " << layer.GetAttentionTimeMs() << " ms" << std::endl;
        std::cout << "    FFN: " << layer.GetFfnTimeMs() << " ms" << std::endl;
    }
}

// ============================================================================
// Full Model Simulation
// ============================================================================
void SimulateFullModel() {
    std::cout << "\n=== Full Model Simulation (24 layers) ===" << std::endl;
    
    // Config matching ministral3
    OptimizedTransformerConfig config;
    config.hidden_size = 1024;
    config.num_heads = 16;
    config.num_kv_heads = 16;
    config.head_dim = 64;
    config.intermediate_size = 8192;
    config.max_seq_len = 32768;
    
    const size_t num_layers = 24;
    const size_t vocab_size = 131072;
    
    // Initialize embeddings
    std::vector<float> embeddings(vocab_size * config.hidden_size);
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-0.1f, 0.1f);
    for (auto& e : embeddings) e = dist(rng);
    
    // Initialize output norm and LM head
    std::vector<float> output_norm(config.hidden_size, 1.0f);
    std::vector<float> lm_head(vocab_size * config.hidden_size);
    for (auto& w : lm_head) w = dist(rng);
    
    // Test single token generation
    std::cout << "  Testing single token generation..." << std::endl;
    
    int32_t token_id = 1;
    std::vector<float> hidden(config.hidden_size);
    std::vector<float> logits(vocab_size);
    
    // Embedding lookup
    std::copy(&embeddings[token_id * config.hidden_size],
              &embeddings[(token_id + 1) * config.hidden_size],
              hidden.begin());
    
    // Simulate 24 layers (just timing, not actual computation)
    auto start = std::chrono::high_resolution_clock::now();
    
    // This would be the actual layer computation
    // For now, just estimate based on single layer benchmark
    double estimated_layer_time_ms = 5.0;  // From previous benchmark
    double total_time_ms = estimated_layer_time_ms * num_layers;
    
    // Add overhead for embedding lookup, norm, LM head
    total_time_ms += 2.0;
    
    auto end = std::chrono::high_resolution_clock::now();
    double actual_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Estimate tokens/sec
    double tokens_per_sec = 1000.0 / total_time_ms;
    
    std::cout << "    Estimated time per token: " << total_time_ms << " ms" << std::endl;
    std::cout << "    Estimated throughput: " << tokens_per_sec << " tok/s" << std::endl;
    std::cout << "    Target (131 tok/s): " << (tokens_per_sec >= 131 ? "✓ MET" : "✗ NEEDS OPTIMIZATION") << std::endl;
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD AVX2 Performance Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    
    // Check AVX2 support
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    bool hasAVX2 = (cpuInfo[2] & (1 << 28)) != 0;  // Check OSXSAVE
    if (hasAVX2) {
        __cpuid(cpuInfo, 7);
        hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;  // Check AVX2 bit
    }
    
    std::cout << "AVX2 Support: " << (hasAVX2 ? "YES" : "NO") << std::endl;
    
    if (!hasAVX2) {
        std::cerr << "AVX2 not supported! Cannot run benchmark." << std::endl;
        return 1;
    }
    
    // Run benchmarks
    BenchmarkGEMM();
    BenchmarkTransformerLayer();
    SimulateFullModel();
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Benchmark Complete" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return 0;
}
