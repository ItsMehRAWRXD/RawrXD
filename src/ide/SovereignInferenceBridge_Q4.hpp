/*===========================================================================
 * SovereignInferenceBridge_Q4.hpp
 * 
 * Q4_K_M integration for SovereignInferenceBridge
 * 
 * This header provides the production inference path:
 *   SovereignInferenceBridge -> Deep2Bridge_Quantized -> Q4_K_M Kernels
 * 
 * Replaces scalar dequantization with optimized MASM kernels
 *===========================================================================*/

#pragma once

#include "SovereignInferenceBridge.h"
#include "../bridge/Deep2Bridge_Quantized.hpp"

// Forward declarations
struct SIB_Internal;

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * Q4_K_M Model State Extension
 * Extended model info for quantized models
 *===========================================================================*/
struct SIB_Q4ModelState {
    // Original model info
    SIB_ModelInfo base_info;
    
    // Quantization-specific data
    int gguf_quant_type;                    // GGUF file_type value
    RawrXD::Bridge::QuantizedLayerType quant_type;
    
    // Weight handles for transformer layers
    // Each layer has: Q, K, V projections, O projection, FFN weights
    struct LayerWeights {
        RawrXD::Bridge::QuantizedWeightHandle q_proj;
        RawrXD::Bridge::QuantizedWeightHandle k_proj;
        RawrXD::Bridge::QuantizedWeightHandle v_proj;
        RawrXD::Bridge::QuantizedWeightHandle o_proj;
        RawrXD::Bridge::QuantizedWeightHandle gate_proj;
        RawrXD::Bridge::QuantizedWeightHandle up_proj;
        RawrXD::Bridge::QuantizedWeightHandle down_proj;
        bool initialized = false;
    };
    
    // Array of layer weights (size = num_layers)
    std::vector<LayerWeights> layers;
    
    // Token embedding
    RawrXD::Bridge::QuantizedWeightHandle token_embed;
    
    // Output head
    RawrXD::Bridge::QuantizedWeightHandle output_head;
    
    // KV cache (allocated separately, not quantized)
    float* k_cache = nullptr;
    float* v_cache = nullptr;
    size_t cache_seq_len = 0;
    size_t cache_batch_size = 0;
    
    // Performance tracking
    uint64_t total_tokens_generated = 0;
    uint64_t total_inference_time_us = 0;
    double avg_tps = 0.0;
};

/*===========================================================================
 * Q4_K_M Inference Context
 * Runtime state for quantized inference
 *===========================================================================*/
class SIB_Q4InferenceContext {
public:
    SIB_Q4InferenceContext() = default;
    ~SIB_Q4InferenceContext();
    
    // Non-copyable
    SIB_Q4InferenceContext(const SIB_Q4InferenceContext&) = delete;
    SIB_Q4InferenceContext& operator=(const SIB_Q4InferenceContext&) = delete;
    
    // Initialize from loaded model
    bool Initialize(const SIB_Q4ModelState& model_state);
    
    // Run one transformer layer
    // input: Input tensor (hidden_dim)
    // output: Output tensor (hidden_dim)
    // layer_idx: Layer index (0 to num_layers-1)
    // position: Token position in sequence (for RoPE)
    bool RunTransformerLayer(
        const float* input,
        float* output,
        int layer_idx,
        int position
    );
    
    // Run complete forward pass (all layers)
    // token_ids: Input token IDs
    // num_tokens: Number of input tokens
    // output_logits: Output logits (vocab_size)
    bool Forward(
        const int* token_ids,
        int num_tokens,
        float* output_logits
    );
    
    // Generate next token
    // Uses KV cache for efficient generation
    int GenerateNextToken(
        const int* prompt_tokens,
        int num_prompt_tokens,
        float temperature,
        int top_k
    );
    
    // KV cache management
    void ClearKVCache();
    void ResizeKVCache(size_t seq_len, size_t batch_size);
    
    // Performance
    double GetAverageTPS() const;
    void ResetPerformanceStats();

private:
    // Layer implementations
    bool RunAttention_Q4KM(
        const float* input,
        float* output,
        int layer_idx,
        int position
    );
    
    bool RunFFN_Q4KM(
        const float* input,
        float* output,
        int layer_idx
    );
    
    // Scratch buffers (aligned for AVX2/AVX-512)
    float* scratch_buffer_ = nullptr;
    float* temp_buffer_ = nullptr;
    float* attn_buffer_ = nullptr;
    size_t buffer_size_ = 0;
    
    // Model reference
    const SIB_Q4ModelState* model_ = nullptr;
    
    // Quantized linear layers (one per weight tensor)
    std::vector<RawrXD::Bridge::Deep2QuantizedLinear> q_layers_;
    std::vector<RawrXD::Bridge::Deep2QuantizedLinear> k_layers_;
    std::vector<RawrXD::Bridge::Deep2QuantizedLinear> v_layers_;
    std::vector<RawrXD::Bridge::Deep2QuantizedLinear> o_layers_;
    std::vector<RawrXD::Bridge::Deep2QuantizedLinear> gate_layers_;
    std::vector<RawrXD::Bridge::Deep2QuantizedLinear> up_layers_;
    std::vector<RawrXD::Bridge::Deep2QuantizedLinear> down_layers_;
    
    // Performance
    uint64_t inference_count_ = 0;
    uint64_t total_cycles_ = 0;
};

/*===========================================================================
 * Integration API
 * Connects to existing SovereignInferenceBridge
 *===========================================================================*/

/**
 * Initialize Q4_K_M support in SovereignInferenceBridge
 * Called from SIB_Initialize when Q4_K_M model is detected
 */
bool SIB_Q4_Initialize(void);

/**
 * Load Q4_K_M model weights from GGUF
 * Called from SIB_LoadModel after GGUF validation
 */
bool SIB_Q4_LoadModel(
    const WCHAR* gguf_path,
    const SIB_ModelInfo* model_info,
    int gguf_quant_type
);

/**
 * Run Q4_K_M inference
 * Called from SIB_RequestCompletion for quantized models
 */
bool SIB_Q4_RunInference(
    const int* input_tokens,
    int num_tokens,
    SIB_CompletionResult* result
);

/**
 * Check if Q4_K_M kernels are available
 */
bool SIB_Q4_IsAvailable(void);

/**
 * Get Q4_K_M kernel version string
 */
const char* SIB_Q4_GetKernelVersion(void);

/**
 * Convert quantization type to string
 */
const char* SIB_Q4_QuantTypeToString(int gguf_quant_type);

} // namespace IDE
} // namespace RawrXD
