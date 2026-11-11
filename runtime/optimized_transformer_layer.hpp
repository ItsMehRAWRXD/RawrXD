// ============================================================================
// optimized_transformer_layer.hpp - FlashAttention-Integrated Transformer Layer
// ============================================================================
// Replaces the standard attention in TransformerLayerRuntime with FlashAttention.
// Maintains the same interface but uses optimized kernels internally.
//
// Usage:
//   OptimizedTransformerLayer layer;
//   layer.BindLayer(...);  // Same as before
//   layer.Forward(...);  // Uses FlashAttention internally
// ============================================================================

#pragma once

#include "transformer_layer_runtime.hpp"
#include "flash_attention.hpp"
#include "quantized_matmul.hpp"

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Optimized Transformer Layer
// ============================================================================
class OptimizedTransformerLayer : public TransformerLayerRuntime {
public:
    OptimizedTransformerLayer();
    ~OptimizedTransformerLayer() override;
    
    // Override Forward to use FlashAttention
    bool Forward(const float* input,
                 uint32_t seqLen,
                 uint32_t position,
                 float* output,
                 float* keyCache,
                 float* valueCache,
                 uint32_t maxSeqLen) const override;
    
    // Initialize FlashAttention (call after BindLayer)
    bool InitializeFlashAttention();
    
    // Check if FlashAttention is available
    bool HasFlashAttention() const { return m_flash_attn_initialized; }
    
    // Get performance stats
    struct PerfStats {
        uint64_t total_cycles = 0;
        uint64_t qkv_cycles = 0;
        uint64_t attention_cycles = 0;
        uint64_t mlp_cycles = 0;
        uint32_t tokens_processed = 0;
        
        float GetTokensPerSecond(float cpu_ghz = 3.0f) const {
            if (total_cycles == 0 || tokens_processed == 0) return 0.0f;
            float seconds = total_cycles / (cpu_ghz * 1e9f);
            return tokens_processed / seconds;
        }
    };
    
    const PerfStats& GetPerfStats() const { return m_perf_stats; }
    void ResetPerfStats() { m_perf_stats = PerfStats(); }

private:
    mutable FlashAttention m_flash_attention;
    mutable bool m_flash_attn_initialized = false;
    mutable PerfStats m_perf_stats;
    
    // Optimized kernels
    bool ComputeQKVOptimized(
        const float* normed_input,
        float* q_out,
        float* k_out,
        float* v_out,
        uint64_t* cycles_out
    ) const;
    
    bool ComputeAttentionOptimized(
        const float* q,
        const float* k_cache,
        const float* v_cache,
        uint32_t seq_len,
        float* output,
        uint64_t* cycles_out
    ) const;
    
    bool ComputeMLPOptimized(
        const float* normed_input,
        float* output,
        uint64_t* cycles_out
    ) const;
};

// ============================================================================
// Optimized Transformer Model
// ============================================================================
class OptimizedTransformerModel : public TransformerModelRuntime {
public:
    OptimizedTransformerModel();
    ~OptimizedTransformerModel() override;
    
    // Override to create optimized layers
    bool Initialize(const std::vector<TransformerLayerConfig>& layerConfigs) override;
    
    // Forward with optimization
    bool Forward(const float* input, uint32_t seqLen, uint32_t position, float* output) override;
    
    // Get aggregated performance stats
    struct ModelPerfStats {
        uint64_t total_cycles = 0;
        uint64_t total_tokens = 0;
        float avg_tokens_per_sec = 0.0f;
        float peak_memory_mb = 0.0f;
    };
    
    ModelPerfStats GetModelPerfStats() const;
    void ResetModelPerfStats();

private:
    std::vector<std::unique_ptr<OptimizedTransformerLayer>> m_optimized_layers;
    mutable ModelPerfStats m_model_stats;
};

// ============================================================================
// Performance Benchmarking
// ============================================================================
class TransformerBenchmark {
public:
    struct Config {
        uint32_t warmup_iterations = 10;
        uint32_t benchmark_iterations = 100;
        bool profile_attention = true;
        bool profile_mlp = true;
        bool profile_qkv = true;
    };
    
    struct Results {
        float avg_latency_ms = 0.0f;
        float min_latency_ms = 0.0f;
        float max_latency_ms = 0.0f;
        float throughput_tokens_per_sec = 0.0f;
        float memory_bandwidth_gbps = 0.0f;
        
        // Breakdown
        float qkv_percent = 0.0f;
        float attention_percent = 0.0f;
        float mlp_percent = 0.0f;
    };
    
    static Results RunBenchmark(
        const OptimizedTransformerModel& model,
        const Config& config
    );
    
    static void PrintResults(const Results& results);
};

} // namespace Runtime
} // namespace RawrXD
