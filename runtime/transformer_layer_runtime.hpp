// ============================================================================
// TransformerLayerRuntime.hpp - Tensor-backed Transformer Block
// ============================================================================
// This is the first real layer built around the TensorView abstraction.
// No GGUF knowledge exists inside - only TensorView::Read(row, col) operations.
//
// Architecture:
//   Token ID
//      ↓
//   Embedding TensorView lookup
//      ↓
//   RMSNorm
//      ↓
//   Attention (Q/K/V/O projections via TensorView)
//      ↓
//   MLP (Gate/Up/Down projections via TensorView)
//      ↓
//   Output Projection TensorView
//      ↓
//   Logits
//
// Critical invariant: Everything above TensorView can evolve, but the compute
// layer needs a stable contract. This ABI is frozen.
// ============================================================================

#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <string>

#include "tensor_view.hpp"

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Layer Configuration (frozen ABI)
// ============================================================================
struct TransformerLayerConfig {
    uint32_t hiddenSize = 0;        // Model dimension (e.g., 4096)
    uint32_t numHeads = 0;          // Number of attention heads
    uint32_t numKVHeads = 0;        // Number of KV heads (GQA/MQA)
    uint32_t headDim = 0;           // Dimension per head (hiddenSize / numHeads)
    uint32_t intermediateSize = 0;  // MLP intermediate dimension
    float rmsNormEps = 1e-5f;       // RMSNorm epsilon
    
    // RoPE (Rotary Position Embedding) parameters
    float ropeTheta = 10000.0f;     // Base for rotary embeddings
    uint32_t maxPosition = 8192;    // Maximum sequence length
    
    bool useGQA = false;            // Grouped Query Attention
    bool useMQA = false;            // Multi-Query Attention
};

// ============================================================================
// Tensor-backed Transformer Layer
// ============================================================================
// Each projection is a TensorView that provides dequantized access to weights.
// The layer consumes only TensorView::Read() - no knowledge of GGUF, quantization,
// or file offsets.
// ============================================================================
class TransformerLayerRuntime {
public:
    TransformerLayerRuntime() = default;
    ~TransformerLayerRuntime() = default;
    
    // Disable copy, enable move
    TransformerLayerRuntime(const TransformerLayerRuntime&) = delete;
    TransformerLayerRuntime& operator=(const TransformerLayerRuntime&) = delete;
    TransformerLayerRuntime(TransformerLayerRuntime&&) = default;
    TransformerLayerRuntime& operator=(TransformerLayerRuntime&&) = default;
    
    // ------------------------------------------------------------------------
    // Layer Binding - Attach TensorViews for all projections
    // ------------------------------------------------------------------------
    bool BindLayer(uint32_t layerIndex,
                   const TensorView& inputNorm,      // [hidden_size]
                   const TensorView& qProj,          // [hidden_size, hidden_size]
                   const TensorView& kProj,          // [hidden_size, num_kv_heads * head_dim]
                   const TensorView& vProj,          // [hidden_size, num_kv_heads * head_dim]
                   const TensorView& oProj,          // [hidden_size, hidden_size]
                   const TensorView& postNorm,       // [hidden_size]
                   const TensorView& gateProj,       // [hidden_size, intermediate_size]
                   const TensorView& upProj,         // [hidden_size, intermediate_size]
                   const TensorView& downProj);      // [intermediate_size, hidden_size]
    
    // ------------------------------------------------------------------------
    // Forward Pass - Single token through the transformer layer
    // ------------------------------------------------------------------------
    // Input:  hidden state [hidden_size] from previous layer
    // Output: hidden state [hidden_size] after this layer
    //
    // KV Cache: External KV cache management (caller provides cache slots)
    // ------------------------------------------------------------------------
    bool Forward(const float* input,           // [hidden_size]
                 uint32_t seqLen,               // Current sequence length
                 uint32_t position,             // Current position (for RoPE)
                 float* output,                 // [hidden_size] output
                 float* keyCache,               // [max_seq, num_kv_heads, head_dim]
                 float* valueCache,             // [max_seq, num_kv_heads, head_dim]
                 uint32_t maxSeqLen) const;     // Maximum cache length
    
    // ------------------------------------------------------------------------
    // State Queries
    // ------------------------------------------------------------------------
    bool IsBound() const { return m_isBound; }
    uint32_t GetLayerIndex() const { return m_layerIndex; }
    const TransformerLayerConfig& GetConfig() const { return m_config; }
    
    // Validate tensor shapes match configuration
    bool ValidateTensors() const;
    
private:
    // Layer configuration (frozen at bind time)
    TransformerLayerConfig m_config;
    uint32_t m_layerIndex = 0;
    bool m_isBound = false;
    
    // TensorViews - these provide dequantized access to weights
    // Attention projections
    const TensorView* m_inputNorm = nullptr;   // RMSNorm before attention
    const TensorView* m_qProj = nullptr;       // Query projection
    const TensorView* m_kProj = nullptr;       // Key projection
    const TensorView* m_vProj = nullptr;       // Value projection
    const TensorView* m_oProj = nullptr;       // Output projection
    
    // MLP projections
    const TensorView* m_postNorm = nullptr;    // RMSNorm after attention
    const TensorView* m_gateProj = nullptr;    // Gate projection (SiLU)
    const TensorView* m_upProj = nullptr;      // Up projection
    const TensorView* m_downProj = nullptr;    // Down projection
    
    // ------------------------------------------------------------------------
    // Internal Compute Kernels (pure math, no TensorView knowledge)
    // ------------------------------------------------------------------------
    void ComputeRMSNorm(const float* input, float* output, uint32_t size, float eps) const;
    void ComputeMatMul(const float* A, const float* B, float* C,
                       uint32_t M, uint32_t N, uint32_t K) const;
    void ComputeAttention(const float* query, const float* key, const float* value,
                          float* output, uint32_t seqLen, uint32_t numHeads,
                          uint32_t numKVHeads, uint32_t headDim) const;
    void ApplyRoPE(float* query, float* key, uint32_t numHeads, uint32_t numKVHeads,
                   uint32_t headDim, uint32_t position, float theta) const;
    void ComputeSiLU(const float* input, float* output, uint32_t size) const;
    void ComputeSoftmax(float* data, uint32_t size) const;
    void AccumulateResidual(const float* residual, float* output, uint32_t size) const;
    
    // TensorView read helpers
    bool ReadWeightMatrix(const TensorView& view, float* output, 
                          uint32_t rows, uint32_t cols) const;
    bool ReadWeightVector(const TensorView& view, float* output,
                          uint32_t size) const;
};

// ============================================================================
// Full Model Runtime - Stack of transformer layers
// ============================================================================
class TransformerModelRuntime {
public:
    TransformerModelRuntime() = default;
    ~TransformerModelRuntime() = default;
    
    // Build model from TensorView registry
    bool Initialize(const std::vector<TransformerLayerConfig>& layerConfigs);
    
    // Bind a layer's tensors
    bool BindLayer(uint32_t layerIndex,
                   const TensorView& inputNorm,
                   const TensorView& qProj, const TensorView& kProj,
                   const TensorView& vProj, const TensorView& oProj,
                   const TensorView& postNorm,
                   const TensorView& gateProj, const TensorView& upProj,
                   const TensorView& downProj);
    
    // Full forward pass through all layers
    bool Forward(const float* input, uint32_t seqLen, uint32_t position,
                 float* output);
    
    // Token embedding lookup (via TensorView)
    bool EmbedToken(uint32_t tokenId, float* embedding);
    
    // Output projection to logits (via TensorView)
    bool ProjectToLogits(const float* hidden, float* logits);
    
    // State queries
    bool IsInitialized() const { return m_initialized; }
    uint32_t GetNumLayers() const { return static_cast<uint32_t>(m_layers.size()); }
    
    // Set embedding and output projection tensors
    void SetTokenEmbeddings(const TensorView& embeddings) { m_tokenEmbeddings = &embeddings; }
    void SetOutputNorm(const TensorView& norm) { m_outputNorm = &norm; }
    void SetOutputWeight(const TensorView& weight) { m_outputWeight = &weight; }
    
private:
    std::vector<std::unique_ptr<TransformerLayerRuntime>> m_layers;
    bool m_initialized = false;
    
    // Model-level tensors
    const TensorView* m_tokenEmbeddings = nullptr;  // [vocab_size, hidden_size]
    const TensorView* m_outputNorm = nullptr;       // [hidden_size]
    const TensorView* m_outputWeight = nullptr;       // [vocab_size, hidden_size]
    
    // KV Cache (allocated per model)
    std::vector<float> m_keyCache;
    std::vector<float> m_valueCache;
    uint32_t m_maxSeqLen = 0;
    uint32_t m_numKVHeads = 0;
    uint32_t m_headDim = 0;
};

} // namespace Runtime
} // namespace RawrXD
