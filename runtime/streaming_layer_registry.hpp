#pragma once
#include "streaming_gguf_loader.hpp"
#include "tensor_view.hpp"
#include <cstdint>
#include <string>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// LayerWeights - All weights for a single transformer layer
// ============================================================================
struct LayerWeights {
    // Attention weights
    TensorView attn_q;
    TensorView attn_k;
    TensorView attn_v;
    TensorView attn_output;
    
    // MLP weights
    TensorView ffn_gate;
    TensorView ffn_up;
    TensorView ffn_down;
    
    // Normalization
    TensorView attn_norm;
    TensorView ffn_norm;
    
    bool IsValid() const {
        return attn_q.IsValid() && attn_k.IsValid() && attn_v.IsValid() &&
               attn_output.IsValid() && ffn_gate.IsValid() && ffn_up.IsValid() &&
               ffn_down.IsValid() && attn_norm.IsValid() && ffn_norm.IsValid();
    }
    
    void Clear() {
        attn_q = TensorView();
        attn_k = TensorView();
        attn_v = TensorView();
        attn_output = TensorView();
        ffn_gate = TensorView();
        ffn_up = TensorView();
        ffn_down = TensorView();
        attn_norm = TensorView();
        ffn_norm = TensorView();
    }
};

// ============================================================================
// StreamingLayerRegistry - Manages layer weights with on-demand loading
// ============================================================================
// Loads one layer at a time to minimize memory footprint.
// For 70B models, this keeps memory usage to ~1 layer instead of all 80.
// ============================================================================
class StreamingLayerRegistry {
public:
    StreamingLayerRegistry();
    ~StreamingLayerRegistry();
    
    // Initialize from loader - discovers number of layers
    bool Initialize(StreamingGGUFLoader& loader);
    
    // Get number of transformer layers
    uint32_t GetNumLayers() const { return m_num_layers; }
    
    // Load a specific layer's weights (unloads previous)
    bool LoadLayer(uint32_t layer_idx);
    
    // Unload current layer to free memory
    void UnloadLayer();
    
    // Check if a layer is currently loaded
    bool IsLayerLoaded() const { return m_loaded_layer != UINT32_MAX; }
    uint32_t GetLoadedLayer() const { return m_loaded_layer; }
    
    // Access current layer weights
    const LayerWeights& GetCurrentWeights() const { return m_current; }
    
    // Get specific weight by name pattern (for custom access)
    TensorView GetWeight(const std::string& name_pattern);
    
private:
    StreamingGGUFLoader* m_loader = nullptr;
    uint32_t m_num_layers = 0;
    uint32_t m_loaded_layer = UINT32_MAX;
    LayerWeights m_current;
    
    // Helper to construct tensor name
    std::string MakeTensorName(uint32_t layer_idx, const char* suffix);
    
    // Load a single weight tensor
    TensorView LoadWeight(const std::string& name);
};

} // namespace Runtime
} // namespace RawrXD
