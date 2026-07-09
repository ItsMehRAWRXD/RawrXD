#pragma once
// ============================================================================
// C4: Transformer Forward Pass
// ============================================================================
// Single forward pass through transformer layers via SEG
// Input: Embeddings [seq_len x hidden_size]
// Output: Logits [seq_len x vocab_size]
// ============================================================================

#include "seg_runtime.hpp"
#include "seg_graph.hpp"
#include "seg_executor.hpp"
#include <cstdint>
#include <vector>
#include <memory>

// Include TensorView definition
#include "../runtime/tensor_view.hpp"

using RawrXD::Runtime::TensorView;

namespace seg {

// Transformer layer configuration
struct TransformerConfig {
    uint32_t hidden_size = 3072;      // Model dimension
    uint32_t num_layers = 32;         // Number of transformer layers
    uint32_t num_heads = 32;          // Number of attention heads
    uint32_t num_kv_heads = 32;       // Number of KV heads (GQA)
    uint32_t head_dim = 96;           // Dimension per head (hidden_size / num_heads)
    uint32_t intermediate_size = 8192; // MLP intermediate dimension
    uint32_t vocab_size = 32000;      // Vocabulary size
    float rms_norm_eps = 1e-5f;       // RMSNorm epsilon
    float rope_theta = 10000.0f;      // RoPE base frequency
    uint32_t max_position = 4096;     // Maximum sequence length
};

// Layer weights for a single transformer layer
struct LayerWeights {
    // Attention
    TensorView input_norm;      // [hidden_size] - RMSNorm before attention
    TensorView q_proj;          // [hidden_size, hidden_size]
    TensorView k_proj;          // [hidden_size, num_kv_heads * head_dim]
    TensorView v_proj;          // [hidden_size, num_kv_heads * head_dim]
    TensorView o_proj;          // [hidden_size, hidden_size]
    
    // MLP
    TensorView post_norm;       // [hidden_size] - RMSNorm after attention
    TensorView gate_proj;       // [hidden_size, intermediate_size]
    TensorView up_proj;         // [hidden_size, intermediate_size]
    TensorView down_proj;       // [intermediate_size, hidden_size]
};

// Model weights (all layers + embeddings + output)
struct ModelWeights {
    // Token embeddings
    TensorView token_embeddings;  // [vocab_size, hidden_size]
    
    // Output
    TensorView output_norm;         // [hidden_size]
    TensorView output_weight;       // [hidden_size, vocab_size]
    
    // Per-layer weights
    std::vector<LayerWeights> layers;
};

// KV cache for attention
struct KVCache {
    std::vector<float> key_cache;   // [max_seq, num_kv_heads, head_dim]
    std::vector<float> value_cache; // [max_seq, num_kv_heads, head_dim]
    uint32_t current_seq_len = 0;
    uint32_t max_seq_len = 0;
    
    bool Initialize(uint32_t max_seq, uint32_t num_kv_heads, uint32_t head_dim);
    void Reset();
};

// ============================================================================
// TransformerForward - Single forward pass through transformer
// ============================================================================
class TransformerForward {
public:
    TransformerForward();
    ~TransformerForward();
    
    // Initialize with model configuration and weights
    bool Initialize(
        const TransformerConfig& config,
        const ModelWeights& weights,
        Executor& executor
    );
    
    // Single forward pass
    // Input: embeddings [seq_len x hidden_size]
    // Output: logits [seq_len x vocab_size]
    bool Forward(
        const float* embeddings,      // [seq_len x hidden_size]
        uint32_t seq_len,
        uint32_t position,            // Starting position (for RoPE)
        float* logits,                // [seq_len x vocab_size] output
        KVCache* kv_cache = nullptr   // Optional KV cache for incremental
    );
    
    // Forward with new KV cache (for first call)
    bool ForwardWithNewCache(
        const float* embeddings,
        uint32_t seq_len,
        float* logits
    );
    
    // Forward with existing cache (for incremental generation)
    bool ForwardWithCache(
        const float* embedding,       // Single token embedding
        uint32_t position,
        float* logits,
        KVCache& kv_cache
    );
    
    // State queries
    bool IsInitialized() const { return initialized_; }
    const TransformerConfig& GetConfig() const { return config_; }
    uint32_t GetNumLayers() const { return config_.num_layers; }

private:
    TransformerConfig config_;
    ModelWeights weights_;
    Executor* executor_ = nullptr;
    bool initialized_ = false;
    
    // Internal KV cache (if not provided externally)
    std::unique_ptr<KVCache> internal_cache_;
    
    // Layer computation
    bool ComputeLayer(
        uint32_t layer_idx,
        const float* input,
        uint32_t seq_len,
        uint32_t position,
        float* output,
        KVCache& kv_cache
    );
    
    // Attention computation
    bool ComputeAttention(
        const float* query,
        const float* key,
        const float* value,
        uint32_t seq_len,
        uint32_t num_heads,
        uint32_t num_kv_heads,
        uint32_t head_dim,
        float* output,
        KVCache& kv_cache
    );
    
    // MLP computation
    bool ComputeMLP(
        const float* input,
        float* output,
        uint32_t hidden_size,
        uint32_t intermediate_size
    );
    
    // RMSNorm
    void ComputeRMSNorm(
        const float* input,
        float* output,
        const TensorView& weight,
        uint32_t size,
        float eps
    );
    
    // RoPE (Rotary Position Embedding)
    void ApplyRoPE(
        float* query,
        float* key,
        uint32_t seq_len,
        uint32_t num_heads,
        uint32_t num_kv_heads,
        uint32_t head_dim,
        uint32_t position,
        float theta
    );
    
    // Matrix multiplication
    void ComputeMatMul(
        const float* A,
        const TensorView& B,
        float* C,
        uint32_t M,
        uint32_t N,
        uint32_t K
    );
    
    // SiLU activation
    void ComputeSiLU(const float* input, float* output, uint32_t size);
    
    // Softmax
    void ComputeSoftmax(float* data, uint32_t size);
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Create transformer graph in SEG
std::unique_ptr<Graph> CreateTransformerGraph(
    const TransformerConfig& config,
    const ModelWeights& weights
);

// Execute transformer via SEG executor
bool ExecuteTransformer(
    Executor& executor,
    Graph& graph,
    const float* input_embeddings,
    uint32_t seq_len,
    float* output_logits
);

} // namespace seg
