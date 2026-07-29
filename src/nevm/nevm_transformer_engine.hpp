//============================================================================
// nevm_transformer_engine.hpp
// RawrXD N-EVM Complete Transformer Execution Engine
// Executes full transformer using only virtual tensor ABI + MMU
//============================================================================

#pragma once

#include "nevm_v2.hpp"
#include "nevm_kernels.hpp"
#include "nevm_prefetch.hpp"

namespace RawrXD {
namespace NEVM {

//============================================================================
// Transformer Execution Engine
// Executes complete transformer without traditional tensor runtime
//============================================================================

class TransformerEngine {
public:
    struct Config {
        // Model architecture
        uint32_t num_layers;
        uint32_t hidden_dim;
        uint32_t num_heads;
        uint32_t head_dim;
        uint32_t ffn_dim;
        uint32_t vocab_size;
        uint32_t max_seq_len;
        
        // Execution
        uint32_t batch_size;
        PrecisionMode default_precision;
        bool use_flash_attention;
        bool use_kv_cache;
        
        // Memory
        size_t kv_cache_size;      // Per-layer KV cache allocation
    };
    
    TransformerEngine(NEVM_v2* vm, const Config& config);
    ~TransformerEngine();
    
    // Initialize with model
    bool Initialize(GGUF_PassthroughLoader* loader);
    
    // Execute complete forward pass
    // input_tokens: [batch, seq_len]
    // output_logits: [batch, seq_len, vocab_size]
    bool Forward(const int32_t* input_tokens,
                  float* output_logits,
                  uint32_t seq_len);
    
    // Execute single layer (for debugging/profiling)
    bool ExecuteLayer(uint32_t layer_id,
                       const float* input,
                       float* output,
                       uint32_t seq_len);
    
    // Generation mode (autoregressive)
    // input_token: single token [batch, 1]
    // kv_cache: maintained across calls
    bool GenerateStep(const int32_t* input_token,
                       float* output_logits,
                       uint32_t current_pos);
    
    // Reset KV cache
    void ResetKVCache();
    
    // Statistics
    struct ExecutionStats {
        uint64_t total_cycles;
        uint64_t memory_cycles;
        uint64_t compute_cycles;
        uint64_t prefetch_cycles;
        uint64_t stall_cycles;
        
        uint32_t precision_switches;
        uint32_t format_upgrades;
        uint32_t format_downgrades;
        
        float avg_layer_latency_ms;
        float memory_pressure;
        size_t working_set_bytes;
    };
    ExecutionStats GetExecutionStats() const;
    void ResetExecutionStats();
    
private:
    NEVM_v2* vm_;
    Config config_;
    GGUF_PassthroughLoader* loader_;
    
    // Buffers (allocated once, reused)
    struct LayerBuffers {
        std::vector<float> residual;
        std::vector<float> normalized;
        std::vector<float> qkv;
        std::vector<float> attention;
        std::vector<float> ffn;
        std::vector<float> softmax;
    };
    LayerBuffers buffers_;
    
    // KV cache
    struct KVCache {
        std::vector<float> k_cache;  // [layers, batch, heads, max_seq, head_dim]
        std::vector<float> v_cache;
        uint32_t current_len;
    };
    KVCache kv_cache_;
    
    // RoPE tables
    std::vector<float> rope_sin_;
    std::vector<float> rope_cos_;
    
    // Execution state
    ExecutionStats stats_;
    uint64_t execution_start_tick_;
    
    // Private methods
    bool AllocateBuffers();
    bool InitializeKVCache();
    bool PrecomputeRoPE();
    
    // Layer execution with virtual tensor ABI
    bool ExecuteAttentionLayer(uint32_t layer_id,
                                const float* input,
                                float* output,
                                uint32_t seq_len,
                                uint32_t cache_pos = 0);
    
    bool ExecuteFFNLayer(uint32_t layer_id,
                         const float* input,
                         float* output,
                         uint32_t seq_len);
    
    // Virtual tensor access
    VirtualTensorAddress GetWeightAddress(uint32_t layer_id,
                                           const std::string& weight_name);
    
    // Precision management
    PrecisionMode SelectLayerPrecision(uint32_t layer_id,
                                        const std::string& op_type);
    
    // Pre-fetch coordination
    void PrefetchNextLayer(uint32_t current_layer);
    void PrefetchWeights(uint32_t layer_id, PrecisionMode precision);
};

//============================================================================
// Validation: NEVM executes complete layer without bypass
//============================================================================

class TransformerValidation {
public:
    // Verify that execution uses only virtual tensor ABI
    static bool ValidateVirtualABI(TransformerEngine* engine,
                                    uint32_t test_layer);
    
    // Verify no direct tensor access
    static bool ValidateNoDirectTensorAccess(TransformerEngine* engine);
    
    // Verify MMU is used for all memory operations
    static bool ValidateMMUUsage(TransformerEngine* engine);
    
    // Full validation suite
    static bool RunValidationSuite(NEVM_v2* vm, 
                                    GGUF_PassthroughLoader* loader,
                                    const TransformerEngine::Config& config);
};

//============================================================================
// Benchmark: Compare NEVM vs traditional execution
//============================================================================

class TransformerBenchmark {
public:
    struct Result {
        float nevms_time_ms;
        float traditional_time_ms;
        float speedup;
        size_t nevms_memory_bytes;
        size_t traditional_memory_bytes;
        float memory_reduction;
    };
    
    static Result RunBenchmark(NEVM_v2* vm,
                                  GGUF_PassthroughLoader* loader,
                                  const TransformerEngine::Config& config,
                                  uint32_t num_iterations = 10);
};

} // namespace NEVM
} // namespace RawrXD
