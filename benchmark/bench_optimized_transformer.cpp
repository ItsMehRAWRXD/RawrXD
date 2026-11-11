// ============================================================================
// Benchmark: Optimized Transformer vs Baseline
// ============================================================================
// Compares:
// 1. Baseline transformer (AoS KV cache, single-threaded)
// 2. Optimized transformer (SoA KV cache, multi-threaded)
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <cstring>

#include "../runtime/transformer_layer_optimized.hpp"
#include "../../rawrxd/src/kernels/avx2_kernels.hpp"
#include "../../rawrxd/src/kernels/avx512_kernels.hpp"

using namespace RawrXD::Runtime;
using namespace rawrxd::kernels;

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchConfig {
    // Model config (1B parameters)
    uint32_t num_layers = 24;
    uint32_t num_heads = 32;
    uint32_t head_dim = 64;
    uint32_t hidden_size = 2048;
    uint32_t intermediate_size = 5504;
    uint32_t vocab_size = 32000;
    uint32_t max_seq_len = 2048;
    
    // Benchmark config
    uint32_t prompt_len = 128;
    uint32_t gen_tokens = 64;
    uint32_t warmup_iters = 5;
    uint32_t benchmark_iters = 10;
};

// ============================================================================
// Weight Generation (Random for benchmarking)
// ============================================================================

void GenerateRandomWeights(float* weights, size_t count, float scale = 0.01f) {
    // Simple deterministic random for reproducibility
    for (size_t i = 0; i < count; ++i) {
        weights[i] = scale * (static_cast<float>((i * 1103515245 + 12345) & 0x7FFF) / 32768.0f - 0.5f);
    }
}

// ============================================================================
// Baseline Transformer (Simplified)
// ============================================================================

class BaselineTransformerLayer {
public:
    struct Config {
        uint32_t hidden_size = 2048;
        uint32_t num_heads = 32;
        uint32_t head_dim = 64;
        uint32_t intermediate_size = 5504;
    };

    void Init(const Config& cfg) {
        config = cfg;
        // Simple AoS cache
        kv_cache.resize(2 * config.num_heads * 2048 * config.head_dim);
    }

    void Forward(const float* input, const float* weights, float* output,
                 uint32_t seq_len, uint32_t current_len) {
        // Simplified - just do matmul for timing
        using namespace rawrxd::kernels;
        
        // Q projection
        KernelDispatch::MatMulF32(input, weights, output, 
                                   seq_len, config.hidden_size, config.hidden_size);
        
        // Simulate attention computation
        std::vector<float> scores(2048);
        std::vector<float> attn_out(config.hidden_size);
        
        for (uint32_t h = 0; h < config.num_heads; ++h) {
            // Compute scores (simplified)
            for (uint32_t pos = 0; pos < current_len + seq_len; ++pos) {
                scores[pos] = 0.0f;
                for (uint32_t d = 0; d < config.head_dim; ++d) {
                    scores[pos] += input[h * config.head_dim + d] * 0.01f;
                }
            }
            
            // Softmax
            SoftmaxF32(scores.data(), scores.data(), current_len + seq_len);
            
            // Weighted sum
            for (uint32_t d = 0; d < config.head_dim; ++d) {
                attn_out[h * config.head_dim + d] = 0.0f;
                for (uint32_t pos = 0; pos < current_len + seq_len; ++pos) {
                    attn_out[h * config.head_dim + d] += scores[pos] * 0.01f;
                }
            }
        }
        
        // Output projection
        KernelDispatch::MatMulF32(attn_out.data(), weights, output,
                                   seq_len, config.hidden_size, config.hidden_size);
    }

private:
    Config config;
    std::vector<float> kv_cache;
};

// ============================================================================
// Benchmark Functions
// ============================================================================

double BenchBaselineTransformer(const BenchConfig& config) {
    BaselineTransformerLayer::Config layer_cfg;
    layer_cfg.hidden_size = config.hidden_size;
    layer_cfg.num_heads = config.num_heads;
    layer_cfg.head_dim = config.head_dim;
    layer_cfg.intermediate_size = config.intermediate_size;
    
    std::vector<BaselineTransformerLayer> layers(config.num_layers);
    for (auto& layer : layers) {
        layer.Init(layer_cfg);
    }
    
    // Allocate weights and buffers
    std::vector<float> weights(config.hidden_size * config.hidden_size);
    std::vector<float> input(config.hidden_size);
    std::vector<float> output(config.hidden_size);
    
    GenerateRandomWeights(weights.data(), weights.size());
    GenerateRandomWeights(input.data(), input.size());
    
    // Warmup
    for (uint32_t w = 0; w < config.warmup_iters; ++w) {
        for (auto& layer : layers) {
            layer.Forward(input.data(), weights.data(), output.data(), 1, w);
        }
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.benchmark_iters; ++iter) {
        for (uint32_t token = 0; token < config.gen_tokens; ++token) {
            for (auto& layer : layers) {
                layer.Forward(input.data(), weights.data(), output.data(), 1, 
                             config.prompt_len + token);
            }
            std::swap(input, output);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return duration.count() / 1000.0 / config.benchmark_iters; // seconds per iteration
}

double BenchOptimizedTransformer(const BenchConfig& config) {
    TransformerConfig tf_config;
    tf_config.num_layers = config.num_layers;
    tf_config.num_heads = config.num_heads;
    tf_config.head_dim = config.head_dim;
    tf_config.hidden_size = config.hidden_size;
    tf_config.intermediate_size = config.intermediate_size;
    tf_config.vocab_size = config.vocab_size;
    tf_config.max_seq_len = config.max_seq_len;
    
    OptimizedTransformerModel model;
    if (!model.Initialize(tf_config)) {
        return -1.0;
    }
    
    // Allocate weights
    size_t embedding_size = config.vocab_size * config.hidden_size;
    size_t output_size = config.hidden_size * config.vocab_size;
    size_t layer_weights_size = 7 * config.hidden_size * config.hidden_size + 
                                   2 * config.hidden_size * config.intermediate_size +
                                   config.intermediate_size * config.hidden_size;
    
    std::vector<float> embedding_weights(embedding_size);
    std::vector<float> output_weights(output_size);
    std::vector<float> layer_weights(layer_weights_size * config.num_layers);
    
    GenerateRandomWeights(embedding_weights.data(), embedding_size);
    GenerateRandomWeights(output_weights.data(), output_size);
    GenerateRandomWeights(layer_weights.data(), layer_weights_size * config.num_layers);
    
    // Input tokens
    std::vector<int32_t> input_tokens(config.prompt_len);
    for (uint32_t i = 0; i < config.prompt_len; ++i) {
        input_tokens[i] = i % config.vocab_size;
    }
    
    std::vector<float> logits(config.vocab_size);
    
    // Warmup
    for (uint32_t w = 0; w < config.warmup_iters; ++w) {
        model.Reset();
        model.Forward(input_tokens.data(), embedding_weights.data(), 
                       output_weights.data(), layer_weights.data(),
                       logits.data(), config.prompt_len);
    }
    
    // Benchmark
    auto start = std::chrono::high_resolution_clock::now();
    
    for (uint32_t iter = 0; iter < config.benchmark_iters; ++iter) {
        model.Reset();
        
        // Prompt processing
        model.Forward(input_tokens.data(), embedding_weights.data(),
                       output_weights.data(), layer_weights.data(),
                       logits.data(), config.prompt_len);
        
        // Token generation
        int32_t next_token = static_cast<int32_t>(logits[0] * 1000) % config.vocab_size;
        for (uint32_t token = 0; token < config.gen_tokens; ++token) {
            model.Forward(&next_token, embedding_weights.data(),
                          output_weights.data(), layer_weights.data(),
                          logits.data(), 1);
            next_token = static_cast<int32_t>(logits[0] * 1000) % config.vocab_size;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    return duration.count() / 1000.0 / config.benchmark_iters;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================\n";
    std::cout << "Optimized Transformer Benchmark\n";
    std::cout << "========================================\n\n";
    
    // Print CPU features
    CPUFeatures::Print();
    std::cout << "\n";
    
    BenchConfig config;
    
    std::cout << "Model Configuration:\n";
    std::cout << "  Layers: " << config.num_layers << "\n";
    std::cout << "  Heads: " << config.num_heads << "\n";
    std::cout << "  Hidden size: " << config.hidden_size << "\n";
    std::cout << "  Intermediate: " << config.intermediate_size << "\n";
    std::cout << "  Vocab: " << config.vocab_size << "\n";
    std::cout << "\nBenchmark Configuration:\n";
    std::cout << "  Prompt length: " << config.prompt_len << "\n";
    std::cout << "  Generation tokens: " << config.gen_tokens << "\n";
    std::cout << "  Warmup iterations: " << config.warmup_iters << "\n";
    std::cout << "  Benchmark iterations: " << config.benchmark_iters << "\n\n";
    
    std::cout << "Running benchmarks...\n\n";
    
    // Baseline
    std::cout << "1. Baseline Transformer (AoS, single-threaded):\n";
    double baseline_time = BenchBaselineTransformer(config);
    if (baseline_time > 0) {
        double baseline_tok_s = config.gen_tokens / baseline_time;
        std::cout << "   Time: " << std::fixed << std::setprecision(2) << baseline_time << " s\n";
        std::cout << "   Throughput: " << std::setprecision(1) << baseline_tok_s << " tok/s\n\n";
    } else {
        std::cout << "   FAILED\n\n";
    }
    
    // Optimized
    std::cout << "2. Optimized Transformer (SoA, multi-threaded):\n";
    double optimized_time = BenchOptimizedTransformer(config);
    if (optimized_time > 0) {
        double optimized_tok_s = config.gen_tokens / optimized_time;
        std::cout << "   Time: " << std::fixed << std::setprecision(2) << optimized_time << " s\n";
        std::cout << "   Throughput: " << std::setprecision(1) << optimized_tok_s << " tok/s\n";
        
        if (baseline_time > 0) {
            double speedup = baseline_time / optimized_time;
            std::cout << "   Speedup: " << std::setprecision(2) << speedup << "x\n\n";
        }
    } else {
        std::cout << "   FAILED\n\n";
    }
    
    // Summary
    std::cout << "========================================\n";
    std::cout << "Summary\n";
    std::cout << "========================================\n";
    
    if (baseline_time > 0 && optimized_time > 0) {
        double speedup = baseline_time / optimized_time;
        double tok_s = config.gen_tokens / optimized_time;
        
        std::cout << "Speedup: " << std::setprecision(2) << speedup << "x\n";
        std::cout << "Throughput: " << std::setprecision(1) << tok_s << " tok/s\n\n";
        
        if (tok_s >= 30.0) {
            std::cout << "✓ TARGET ACHIEVED: 30+ tok/s\n";
        } else if (tok_s >= 20.0) {
            std::cout << "⚠ Close to target: 20+ tok/s (need 30+)\n";
        } else {
            std::cout << "✗ Below target: " << std::setprecision(1) << tok_s << " tok/s\n";
            std::cout << "  Consider: quantization (Q4_0/Q8_0), larger batching,\n";
            std::cout << "            or FlashAttention-style tiling\n";
        }
    }
    
    std::cout << "\n========================================\n";
    
    return 0;
}
