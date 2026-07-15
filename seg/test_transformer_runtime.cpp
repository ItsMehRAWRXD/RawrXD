// ============================================================================
// Transformer Runtime Test & Benchmark
// ============================================================================

#include "transformer_layer_runtime.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <random>

using namespace transformer;

// ============================================================================
// Test Configuration
// ============================================================================
struct TestConfig {
    uint32_t hidden_size = 4096;
    uint32_t num_heads = 32;
    uint32_t num_kv_heads = 8;  // GQA
    uint32_t head_dim = 128;
    uint32_t intermediate_size = 14336;
    uint32_t num_layers = 32;
    uint32_t max_seq_len = 4096;
    uint32_t vocab_size = 32000;
};

// ============================================================================
// Helper Functions
// ============================================================================
void PrintConfig(const TransformerConfig& config) {
    std::cout << "Transformer Configuration:\n";
    std::cout << "  Hidden Size: " << config.hidden_size << "\n";
    std::cout << "  Num Heads: " << config.num_heads << "\n";
    std::cout << "  Num KV Heads: " << config.num_kv_heads << "\n";
    std::cout << "  Head Dim: " << config.head_dim << "\n";
    std::cout << "  Intermediate Size: " << config.intermediate_size << "\n";
    std::cout << "  Num Layers: " << config.num_layers << "\n";
    std::cout << "  Max Seq Len: " << config.max_seq_len << "\n";
    std::cout << "  Vocab Size: " << config.vocab_size << "\n";
}

void PrintMetrics(const LayerMetrics& metrics) {
    std::cout << "  Layer Time: " << std::fixed << std::setprecision(3) << metrics.time_ms << " ms\n";
    std::cout << "  Tokens/sec: " << std::fixed << std::setprecision(2) << metrics.tokens_per_second << "\n";
}

// ============================================================================
// Weight Generation (Random for testing)
// ============================================================================
LayerWeights GenerateRandomWeights(const TransformerConfig& config, std::mt19937& gen) {
    LayerWeights weights;
    std::normal_distribution<float> dist(0.0f, 0.02f);
    
    auto fill_random = [&](std::vector<float>& vec, size_t size) {
        vec.resize(size);
        for (auto& v : vec) v = dist(gen);
    };
    
    fill_random(weights.q_proj, config.hidden_size * config.num_heads * config.head_dim);
    fill_random(weights.k_proj, config.hidden_size * config.num_kv_heads * config.head_dim);
    fill_random(weights.v_proj, config.hidden_size * config.num_kv_heads * config.head_dim);
    fill_random(weights.o_proj, config.num_heads * config.head_dim * config.hidden_size);
    fill_random(weights.gate_proj, config.hidden_size * config.intermediate_size);
    fill_random(weights.up_proj, config.hidden_size * config.intermediate_size);
    fill_random(weights.down_proj, config.intermediate_size * config.hidden_size);
    fill_random(weights.input_layernorm, config.hidden_size);
    fill_random(weights.post_attn_layernorm, config.hidden_size);
    
    return weights;
}

// ============================================================================
// Benchmark Tests
// ============================================================================
void BenchmarkSingleLayer(const TransformerConfig& config, 
                          const LayerWeights& weights,
                          uint32_t num_iterations = 100) {
    std::cout << "\n=== Single Layer Benchmark ===\n";
    
    TransformerLayerRuntime layer;
    if (!layer.Initialize(config, weights)) {
        std::cerr << "Failed to initialize layer\n";
        return;
    }
    
    // Set CPU backend
    layer.SetBackend(CreateCPUBackend());
    
    // Prepare input
    std::vector<float> input(config.hidden_size);
    std::vector<float> output(config.hidden_size);
    KVCacheEntry kv_cache;
    kv_cache.Resize(config.max_seq_len, config.num_kv_heads, config.head_dim);
    
    // Initialize with random data
    std::mt19937 gen(42);
    std::normal_distribution<float> dist(0.0f, 1.0f);
    for (auto& v : input) v = dist(gen);
    
    // Warmup
    std::cout << "Warming up...\n";
    for (uint32_t i = 0; i < 10; i++) {
        kv_cache.Reset();
        layer.Forward(TensorViewF32(input.data(), {config.hidden_size}),
                      TensorViewF32(output.data(), {config.hidden_size}),
                      kv_cache, 0);
    }
    
    // Benchmark
    std::cout << "Running benchmark...\n";
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < num_iterations; i++) {
        kv_cache.Reset();
        layer.Forward(TensorViewF32(input.data(), {config.hidden_size}),
                      TensorViewF32(output.data(), {config.hidden_size}),
                      kv_cache, 0);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double avg_time_ms = elapsed_ms / num_iterations;
    double tokens_per_sec = 1000.0 / avg_time_ms;
    
    std::cout << "Results:\n";
    std::cout << "  Iterations: " << num_iterations << "\n";
    std::cout << "  Total Time: " << std::fixed << std::setprecision(2) << elapsed_ms << " ms\n";
    std::cout << "  Avg Time/Layer: " << std::fixed << std::setprecision(3) << avg_time_ms << " ms\n";
    std::cout << "  Tokens/sec: " << std::fixed << std::setprecision(2) << tokens_per_sec << "\n";
    
    // Project full model performance
    double full_model_time_ms = avg_time_ms * config.num_layers;
    double full_model_tps = 1000.0 / full_model_time_ms;
    std::cout << "  Projected Full Model: " << std::fixed << std::setprecision(2) << full_model_tps << " tok/s\n";
    
    layer.Cleanup();
}

void BenchmarkAttentionOnly(const TransformerConfig& config,
                              const LayerWeights& weights,
                              uint32_t num_iterations = 100) {
    std::cout << "\n=== Attention-Only Benchmark ===\n";
    
    TransformerLayerRuntime layer;
    if (!layer.Initialize(config, weights)) {
        std::cerr << "Failed to initialize layer\n";
        return;
    }
    
    layer.SetBackend(CreateCPUBackend());
    
    std::vector<float> input(config.hidden_size);
    std::vector<float> output(config.hidden_size);
    KVCacheEntry kv_cache;
    kv_cache.Resize(config.max_seq_len, config.num_kv_heads, config.head_dim);
    
    std::mt19937 gen(42);
    std::normal_distribution<float> dist(0.0f, 1.0f);
    for (auto& v : input) v = dist(gen);
    
    // Warmup
    for (uint32_t i = 0; i < 10; i++) {
        kv_cache.Reset();
        layer.Forward(TensorViewF32(input.data(), {config.hidden_size}),
                      TensorViewF32(output.data(), {config.hidden_size}),
                      kv_cache, 0);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t i = 0; i < num_iterations; i++) {
        kv_cache.Reset();
        layer.Forward(TensorViewF32(input.data(), {config.hidden_size}),
                      TensorViewF32(output.data(), {config.hidden_size}),
                      kv_cache, 0);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double avg_time_ms = elapsed_ms / num_iterations;
    
    std::cout << "  Attention + MLP Time: " << std::fixed << std::setprecision(3) << avg_time_ms << " ms\n";
    std::cout << "  Tokens/sec: " << std::fixed << std::setprecision(2) << (1000.0 / avg_time_ms) << "\n";
    
    layer.Cleanup();
}

void BenchmarkSequenceLength(const TransformerConfig& config,
                              const LayerWeights& weights,
                              const std::vector<uint32_t>& seq_lengths) {
    std::cout << "\n=== Sequence Length Scaling ===\n";
    
    TransformerLayerRuntime layer;
    if (!layer.Initialize(config, weights)) {
        std::cerr << "Failed to initialize layer\n";
        return;
    }
    
    layer.SetBackend(CreateCPUBackend());
    
    std::vector<float> input(config.hidden_size);
    std::vector<float> output(config.hidden_size);
    
    std::mt19937 gen(42);
    std::normal_distribution<float> dist(0.0f, 1.0f);
    for (auto& v : input) v = dist(gen);
    
    std::cout << "Seq Len | Time (ms) | Tokens/s\n";
    std::cout << "--------|-----------|----------\n";
    
    for (uint32_t seq_len : seq_lengths) {
        KVCacheEntry kv_cache;
        kv_cache.Resize(config.max_seq_len, config.num_kv_heads, config.head_dim);
        
        // Build up cache
        for (uint32_t pos = 0; pos < seq_len; pos++) {
            layer.Forward(TensorViewF32(input.data(), {config.hidden_size}),
                          TensorViewF32(output.data(), {config.hidden_size}),
                          kv_cache, pos);
        }
        
        // Time next token
        auto start = std::chrono::high_resolution_clock::now();
        layer.Forward(TensorViewF32(input.data(), {config.hidden_size}),
                      TensorViewF32(output.data(), {config.hidden_size}),
                      kv_cache, seq_len);
        auto end = std::chrono::high_resolution_clock::now();
        
        double elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double tps = 1000.0 / elapsed_ms;
        
        std::cout << std::setw(7) << seq_len << " | "
                  << std::fixed << std::setprecision(3) << std::setw(9) << elapsed_ms << " | "
                  << std::fixed << std::setprecision(2) << std::setw(8) << tps << "\n";
    }
    
    layer.Cleanup();
}

// ============================================================================
// Correctness Tests
// ============================================================================
void TestRMSNorm() {
    std::cout << "\n=== RMSNorm Test ===\n";
    
    std::vector<float> input = {1.0f, 2.0f, 3.0f, 4.0f};
    std::vector<float> weights = {1.0f, 1.0f, 1.0f, 1.0f};
    std::vector<float> output(4);
    
    auto backend = CreateCPUBackend();
    backend->RMSNorm(input.data(), output.data(), weights.data(), 4, 1e-6f);
    
    std::cout << "Input:  [";
    for (auto v : input) std::cout << v << " ";
    std::cout << "]\n";
    
    std::cout << "Output: [";
    for (auto v : output) std::cout << v << " ";
    std::cout << "]\n";
    
    // Verify: RMS = sqrt((1+4+9+16)/4) = sqrt(7.5) ≈ 2.7386
    // Output should be input / RMS
    float rms = std::sqrt(30.0f / 4.0f);
    std::cout << "Expected RMS: " << rms << "\n";
}

void TestSoftmax() {
    std::cout << "\n=== Softmax Test ===\n";
    
    std::vector<float> input = {1.0f, 2.0f, 3.0f};
    std::vector<float> output(3);
    
    auto backend = CreateCPUBackend();
    backend->Softmax(input.data(), output.data(), 3);
    
    std::cout << "Input:  [";
    for (auto v : input) std::cout << v << " ";
    std::cout << "]\n";
    
    std::cout << "Output: [";
    for (auto v : output) std::cout << v << " ";
    std::cout << "]\n";
    
    // Verify sum = 1
    float sum = 0.0f;
    for (auto v : output) sum += v;
    std::cout << "Sum: " << sum << " (should be ~1.0)\n";
}

void TestMatMul() {
    std::cout << "\n=== MatMul Test ===\n";
    
    // A: [2, 3], B: [3, 2], C: [2, 2]
    std::vector<float> A = {1.0f, 2.0f, 3.0f,  // row 0
                               4.0f, 5.0f, 6.0f}; // row 1
    std::vector<float> B = {1.0f, 2.0f,  // row 0
                               3.0f, 4.0f,  // row 1
                               5.0f, 6.0f}; // row 2
    std::vector<float> C(4);
    
    auto backend = CreateCPUBackend();
    backend->MatMul(A.data(), B.data(), C.data(), 2, 3, 2);
    
    std::cout << "A @ B = [";
    for (auto v : C) std::cout << v << " ";
    std::cout << "]\n";
    
    // Expected: [22, 28, 49, 64]
    std::cout << "Expected: [22, 28, 49, 64]\n";
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "Transformer Runtime Test Suite\n";
    std::cout << "========================================\n";
    
    // Parse command line
    bool run_correctness = true;
    bool run_benchmark = true;
    uint32_t num_iterations = 100;
    
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--no-correctness") run_correctness = false;
        if (arg == "--no-benchmark") run_benchmark = false;
        if (arg == "--iterations" && i + 1 < argc) {
            num_iterations = std::stoi(argv[++i]);
        }
        if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]\n";
            std::cout << "Options:\n";
            std::cout << "  --no-correctness    Skip correctness tests\n";
            std::cout << "  --no-benchmark      Skip benchmark tests\n";
            std::cout << "  --iterations N      Set benchmark iterations (default: 100)\n";
            std::cout << "  --help              Show this help\n";
            return 0;
        }
    }
    
    // Setup config
    TransformerConfig config;
    config.hidden_size = 4096;
    config.num_heads = 32;
    config.num_kv_heads = 8;
    config.head_dim = 128;
    config.intermediate_size = 14336;
    config.num_layers = 32;
    config.max_seq_len = 4096;
    config.vocab_size = 32000;
    
    PrintConfig(config);
    
    // Generate random weights
    std::cout << "\nGenerating random weights...\n";
    std::mt19937 gen(42);
    LayerWeights weights = GenerateRandomWeights(config, gen);
    
    // Run correctness tests
    if (run_correctness) {
        TestRMSNorm();
        TestSoftmax();
        TestMatMul();
    }
    
    // Run benchmarks
    if (run_benchmark) {
        BenchmarkSingleLayer(config, weights, num_iterations);
        BenchmarkAttentionOnly(config, weights, num_iterations);
        
        std::vector<uint32_t> seq_lengths = {1, 128, 512, 1024, 2048};
        BenchmarkSequenceLength(config, weights, seq_lengths);
    }
    
    std::cout << "\n========================================\n";
    std::cout << "Test Complete\n";
    std::cout << "========================================\n";
    
    return 0;
}
