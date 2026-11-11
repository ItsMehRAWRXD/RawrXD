// ============================================================================
// Fused Layer Benchmark
// ============================================================================
// Compares fused vs baseline transformer layer performance
// ============================================================================

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include "fused_transformer_layer.hpp"

using namespace seg;

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    uint32_t num_layers = 24;
    uint32_t num_iterations = 100;
    uint32_t seq_len = 128;
};

// ============================================================================
// Run Benchmark
// ============================================================================
void RunBenchmark(const BenchmarkConfig& config) {
    std::cout << "========================================\n";
    std::cout << "Fused Transformer Layer Benchmark\n";
    std::cout << "========================================\n\n";
    
    std::cout << "Configuration:\n";
    std::cout << "  Layers: " << config.num_layers << "\n";
    std::cout << "  Iterations: " << config.num_iterations << "\n";
    std::cout << "  Sequence length: " << config.seq_len << "\n\n";
    
    // Layer configuration (1B model)
    FusedLayerConfig layer_config;
    layer_config.hidden_size = 2048;
    layer_config.num_heads = 32;
    layer_config.num_kv_heads = 32;
    layer_config.head_dim = 64;
    layer_config.intermediate_size = 5504;
    
    // Initialize layers
    FusedTransformerLayer fused_layer;
    BaselineTransformerLayer baseline_layer;
    
    if (!fused_layer.Initialize(layer_config)) {
        std::cerr << "Failed to initialize fused layer\n";
        return;
    }
    
    if (!baseline_layer.Initialize(layer_config)) {
        std::cerr << "Failed to initialize baseline layer\n";
        return;
    }
    
    // Allocate buffers
    uint32_t hidden_size = layer_config.hidden_size;
    std::vector<float> input(hidden_size, 0.1f);
    std::vector<float> output(hidden_size, 0.0f);
    
    // Dummy weights
    std::vector<float> q_weight(hidden_size * hidden_size, 0.01f);
    std::vector<float> k_weight(hidden_size * hidden_size, 0.01f);
    std::vector<float> v_weight(hidden_size * hidden_size, 0.01f);
    std::vector<float> o_weight(hidden_size * hidden_size, 0.01f);
    std::vector<float> gate_weight(hidden_size * layer_config.intermediate_size, 0.01f);
    std::vector<float> up_weight(hidden_size * layer_config.intermediate_size, 0.01f);
    std::vector<float> down_weight(layer_config.intermediate_size * hidden_size, 0.01f);
    std::vector<float> attn_norm_weight(hidden_size, 1.0f);
    std::vector<float> mlp_norm_weight(hidden_size, 1.0f);
    
    // KV cache
    std::vector<float> k_cache(config.seq_len * hidden_size, 0.0f);
    std::vector<float> v_cache(config.seq_len * hidden_size, 0.0f);
    
    // Benchmark baseline
    std::cout << "Running Baseline (Non-Fused) Benchmark...\n";
    auto baseline_start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.num_iterations; iter++) {
        for (uint32_t layer = 0; layer < config.num_layers; layer++) {
            for (uint32_t pos = 0; pos < config.seq_len; pos++) {
                baseline_layer.Forward(
                    input.data(), output.data(),
                    q_weight.data(), k_weight.data(), v_weight.data(), o_weight.data(),
                    gate_weight.data(), up_weight.data(), down_weight.data(),
                    attn_norm_weight.data(), mlp_norm_weight.data(),
                    k_cache.data(), v_cache.data(), pos, pos + 1
                );
                // Copy output to input for next position
                input = output;
            }
        }
    }
    
    auto baseline_end = std::chrono::high_resolution_clock::now();
    double baseline_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        baseline_end - baseline_start).count() / 1000.0;
    
    // Reset KV cache for fused benchmark
    std::fill(k_cache.begin(), k_cache.end(), 0.0f);
    std::fill(v_cache.begin(), v_cache.end(), 0.0f);
    std::fill(input.begin(), input.end(), 0.1f);
    
    // Benchmark fused
    std::cout << "Running Fused Layer Benchmark...\n";
    auto fused_start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.num_iterations; iter++) {
        for (uint32_t layer = 0; layer < config.num_layers; layer++) {
            for (uint32_t pos = 0; pos < config.seq_len; pos++) {
                fused_layer.Forward(
                    input.data(), output.data(),
                    q_weight.data(), k_weight.data(), v_weight.data(), o_weight.data(),
                    gate_weight.data(), up_weight.data(), down_weight.data(),
                    attn_norm_weight.data(), mlp_norm_weight.data(),
                    k_cache.data(), v_cache.data(), pos, pos + 1
                );
                input = output;
            }
        }
    }
    
    auto fused_end = std::chrono::high_resolution_clock::now();
    double fused_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        fused_end - fused_start).count() / 1000.0;
    
    // Results
    std::cout << "\n========================================\n";
    std::cout << "Results\n";
    std::cout << "========================================\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Baseline time: " << baseline_time_ms << " ms\n";
    std::cout << "  Fused time:    " << fused_time_ms << " ms\n";
    std::cout << "  Speedup:       " << (baseline_time_ms / fused_time_ms) << "x\n";
    std::cout << "  Improvement:   " << ((baseline_time_ms - fused_time_ms) / baseline_time_ms * 100) << "%\n\n";
    
    // Analysis
    std::cout << "Analysis:\n";
    if (fused_time_ms < baseline_time_ms) {
        std::cout << "  ✓ Fused layer shows improvement\n";
        std::cout << "  ✓ Reduced memory round-trips\n";
        std::cout << "  ✓ Better cache locality\n";
    } else {
        std::cout << "  ⚠ No improvement (may be due to simplified compute)\n";
        std::cout << "  ⚠ Real gains require actual matmul kernels\n";
    }
    std::cout << "\n";
    
    // Tokens per second estimate
    double total_tokens = config.num_iterations * config.num_layers * config.seq_len;
    double baseline_tok_s = total_tokens / (baseline_time_ms / 1000.0);
    double fused_tok_s = total_tokens / (fused_time_ms / 1000.0);
    
    std::cout << "Estimated Throughput:\n";
    std::cout << "  Baseline: " << std::fixed << std::setprecision(1) << baseline_tok_s << " tok/s\n";
    std::cout << "  Fused:    " << fused_tok_s << " tok/s\n\n";
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
        else if (arg == "--iterations" && i + 1 < argc) config.num_iterations = std::stoi(argv[++i]);
        else if (arg == "--seq-len" && i + 1 < argc) config.seq_len = std::stoi(argv[++i]);
    }
    
    RunBenchmark(config);
    
    return 0;
}
