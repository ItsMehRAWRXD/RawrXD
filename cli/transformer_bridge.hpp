#pragma once
// ============================================================================
// Transformer Bridge — Connect NativeBackend to TransformerLayerRuntime
// ============================================================================
// Purpose: Bridge between CLI NativeBackend and runtime transformer layers
// Handles: TensorView creation from ModelContext, KV cache management
// ============================================================================

#include "model_context.hpp"
#include "kv_cache.hpp"
#include "../runtime/transformer_layer_runtime.hpp"
#include "../runtime/tensor_view.hpp"
#include <memory>
#include <vector>

namespace RawrXD {
namespace CLI {

// Bridge between CLI ModelContext and Runtime TransformerLayerRuntime
class TransformerBridge {
public:
    TransformerBridge();
    ~TransformerBridge();

    // Initialize from ModelContext
    // Extracts architecture and binds all layer tensors
    bool Initialize(const ModelContext& modelContext);

    // Execute single token through full transformer stack
    // tokenId: input token ID
    // position: position in sequence (for RoPE)
    // seqLen: current sequence length
    // logits: output logits [vocab_size]
    bool ExecuteToken(
        uint32_t tokenId,
        uint32_t position,
        uint32_t seqLen,
        float* logits
    );

    // Reset KV cache (for new sequence)
    void ResetCache();

    // State queries
    bool IsInitialized() const { return m_initialized; }
    uint32_t GetNumLayers() const;
    uint32_t GetHiddenSize() const;
    uint32_t GetVocabSize() const;

    // Telemetry
    struct Telemetry {
        uint64_t embeddingTimeUs = 0;
        uint64_t attentionTimeUs = 0;
        uint64_t mlpTimeUs = 0;
        uint64_t totalTimeUs = 0;
        uint32_t cacheHits = 0;
        uint32_t cacheMisses = 0;
    };
    Telemetry GetLastTelemetry() const { return m_telemetry; }

private:
    bool m_initialized = false;

    // Runtime model
    std::unique_ptr<Runtime::TransformerModelRuntime> m_modelRuntime;

    // KV cache for autoregressive generation
    std::unique_ptr<KVCache> m_kvCache;

    // Model dimensions
    uint32_t m_hiddenSize = 0;
    uint32_t m_numHeads = 0;
    uint32_t m_numKVHeads = 0;
    uint32_t m_headDim = 0;
    uint32_t m_numLayers = 0;
    uint32_t m_vocabSize = 0;
    uint32_t m_maxSeqLen = 0;

    // Telemetry
    Telemetry m_telemetry;

    // Helper: Create TensorView from ModelContext tensor
    Runtime::TensorView CreateTensorView(
        const ModelContext& ctx,
        const std::string& tensorName
    ) const;

    // Helper: Bind all layers from ModelContext
    bool BindAllLayers(const ModelContext& ctx);
};

} // namespace CLI
} // namespace RawrXD
