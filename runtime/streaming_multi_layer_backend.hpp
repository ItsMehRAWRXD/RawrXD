// ============================================================================
// streaming_multi_layer_backend.hpp - Multi-Layer Streaming Inference Backend
// ============================================================================
// Executes transformer inference with on-demand layer loading.
// Suitable for models larger than available RAM (70B+ on consumer hardware).
//
// Architecture:
//   Token ID
//      ↓
//   Embedding Lookup (mmap'd)
//      ↓
//   For each layer:
//      Load layer weights → Execute → Unload
//      ↓
//   Output Projection (mmap'd)
//      ↓
//   Logits
//
// Memory footprint: ~1 layer + embeddings + output weights
// ============================================================================

#pragma once

#include "streaming_gguf_loader.hpp"
#include "streaming_layer_registry.hpp"
#include "transformer_layer_runtime.hpp"
#include "telemetry_ids.hpp"
#include <vector>
#include <cstdint>
#include <cmath>

namespace RawrXD {
namespace Runtime {

// Forward declaration
class KVCache;

// ============================================================================
// StreamingMultiLayerBackend - Memory-efficient inference for large models
// ============================================================================
class StreamingMultiLayerBackend {
public:
    StreamingMultiLayerBackend();
    ~StreamingMultiLayerBackend();

    // Initialize from streaming loader
    // Discovers model architecture and prepares for inference
    bool Initialize(StreamingGGUFLoader& loader);

    // Execute single token through the model
    // position_id: current position in sequence (for RoPE)
    // logits_out: output buffer [vocab_size]
    bool ExecuteToken(
        uint32_t token_id,
        uint32_t position_id,
        float* logits_out
    );

    // Generate tokens from prompt
    // prompt_tokens: input token IDs
    // output_tokens: generated token IDs (appended)
    // max_new_tokens: maximum tokens to generate
    // temperature: sampling temperature (1.0 = greedy)
    // top_k: top-k sampling (0 = disabled)
    bool Generate(
        const std::vector<uint32_t>& prompt_tokens,
        std::vector<uint32_t>& output_tokens,
        size_t max_new_tokens,
        float temperature = 1.0f,
        int top_k = 40
    );

    // Reset internal state (KV cache, position counter)
    void Reset();

    // Get model properties
    uint32_t GetVocabSize() const { return m_vocab_size; }
    uint32_t GetNumLayers() const { return m_num_layers; }
    uint32_t GetHiddenSize() const { return m_hidden_size; }
    uint32_t GetNumHeads() const { return m_num_heads; }
    uint32_t GetMaxSeqLen() const { return m_max_seq_len; }

    // Check if initialized
    bool IsInitialized() const { return m_initialized; }

    // Buffer access for SEG integration
    float* GetLogitsBuffer() { return m_logits; }
    size_t GetLogitsBytes() const { return sizeof(m_logits); }

private:
    // Components
    StreamingLayerRegistry m_registry;
    std::unique_ptr<KVCache> m_kv_cache;

    // Model configuration
    uint32_t m_hidden_size = 0;
    uint32_t m_num_layers = 0;
    uint32_t m_num_heads = 0;
    uint32_t m_num_kv_heads = 0;
    uint32_t m_head_dim = 0;
    uint32_t m_intermediate_size = 0;
    uint32_t m_vocab_size = 0;
    uint32_t m_max_seq_len = 0;
    bool m_initialized = false;

    // Model tensors (mmap'd, always resident)
    TensorView m_token_embeddings;   // [vocab_size, hidden_size]
    TensorView m_output_norm;        // [hidden_size]
    TensorView m_output_weight;      // [vocab_size, hidden_size]

    // Working buffers (aligned for SIMD)
    alignas(64) float m_hidden[8192];      // Current hidden state
    alignas(64) float m_next_hidden[8192]; // Next hidden state
    alignas(64) float m_normed[8192];      // Normalized hidden
    alignas(64) float m_qkv[24576];       // QKV concatenated [3 * max_hidden]
    alignas(64) float m_attn_out[8192];   // Attention output
    alignas(64) float m_mlp_out[8192];     // MLP output
    alignas(64) float m_logits[128000];    // Output logits

    // Internal methods
    bool LoadModelTensors(StreamingGGUFLoader& loader);
    bool EmbeddingLookup(uint32_t token_id, float* out);
    bool OutputProjection(const float* hidden, float* logits);
    bool ExecuteLayer(uint32_t layer_idx, uint32_t position);
    
    // Transformer operations
    void RMSNorm(const float* input, const TensorView& weight, float* output, uint32_t size);
    void ProjectQKV(const float* input, const LayerWeights& weights, float* q_out, float* k_out, float* v_out);
    void AttentionMultiHead(const float* query, const KVCache& cache, uint32_t position, float* output);
    void MLPForward(const float* input, const LayerWeights& weights, float* output);
    void MatMulRow(const TensorView& weight, const float* input, float* output, uint32_t out_dim, uint32_t in_dim);
    float SiLU(float x) { return x / (1.0f + expf(-x)); }
    
    // Sampling
    int32_t SampleToken(const float* logits, float temperature, int top_k);
    int32_t GreedySample(const float* logits);
    int32_t TopKSample(const float* logits, int k, float temperature);
    
    // Softmax for sampling
    void Softmax(float* data, uint32_t size);
};

} // namespace Runtime
} // namespace RawrXD
