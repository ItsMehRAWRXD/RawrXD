// ============================================================================
// ModelBinder.hpp - Connect GGUF Registry to Transformer Layers
// ============================================================================
// This is the bridge between ingestion and compute:
//   GGUF File → Tensor Registry → ModelBinder → TransformerLayerRuntime
//
// The ModelBinder:
// 1. Reads tensor names from GGUF metadata
// 2. Looks up TensorViews in the registry
// 3. Binds them to TransformerLayerRuntime projections
// 4. Validates shapes match configuration
// ============================================================================

#pragma once

#include "transformer_layer_runtime.hpp"
#include "tensor_view.hpp"
#include <string>
#include <vector>
#include <map>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Model Architecture Configuration
// ============================================================================
struct ModelArchitectureConfig {
    std::string name;              // Model name (e.g., "phi3-mini", "qwen2.5")
    std::string arch;              // Architecture type (e.g., "llama", "qwen2")
    
    uint32_t vocabSize = 0;
    uint32_t hiddenSize = 0;
    uint32_t numLayers = 0;
    uint32_t numHeads = 0;
    uint32_t numKVHeads = 0;
    uint32_t intermediateSize = 0;
    uint32_t maxPosition = 0;
    
    float rmsNormEps = 1e-5f;
    float ropeTheta = 10000.0f;
    
    // Tensor naming conventions (vary by architecture)
    std::string tokenEmbdPattern = "token_embd.weight";
    std::string outputNormPattern = "output_norm.weight";
    std::string outputWeightPattern = "output.weight";
    
    // Layer tensor patterns (with {layer} placeholder)
    std::string inputNormPattern = "blk.{layer}.attn_norm.weight";
    std::string qProjPattern = "blk.{layer}.attn_q.weight";
    std::string kProjPattern = "blk.{layer}.attn_k.weight";
    std::string vProjPattern = "blk.{layer}.attn_v.weight";
    std::string oProjPattern = "blk.{layer}.attn_output.weight";
    std::string postNormPattern = "blk.{layer}.ffn_norm.weight";
    std::string gateProjPattern = "blk.{layer}.ffn_gate.weight";
    std::string upProjPattern = "blk.{layer}.ffn_up.weight";
    std::string downProjPattern = "blk.{layer}.ffn_down.weight";
};

// ============================================================================
// Binding Result
// ============================================================================
struct LayerBindingResult {
    bool success = false;
    uint32_t layerIndex = 0;
    std::string errorMessage;
    
    // Which tensors were bound
    bool inputNormBound = false;
    bool qProjBound = false;
    bool kProjBound = false;
    bool vProjBound = false;
    bool oProjBound = false;
    bool postNormBound = false;
    bool gateProjBound = false;
    bool upProjBound = false;
    bool downProjBound = false;
    
    uint32_t GetBoundCount() const {
        return (inputNormBound ? 1 : 0) +
               (qProjBound ? 1 : 0) +
               (kProjBound ? 1 : 0) +
               (vProjBound ? 1 : 0) +
               (oProjBound ? 1 : 0) +
               (postNormBound ? 1 : 0) +
               (gateProjBound ? 1 : 0) +
               (upProjBound ? 1 : 0) +
               (downProjBound ? 1 : 0);
    }
};

// ============================================================================
// Model Binder
// ============================================================================
class ModelBinder {
public:
    ModelBinder() = default;
    ~ModelBinder() = default;
    
    // Initialize with architecture configuration
    bool Initialize(const ModelArchitectureConfig& config);
    
    // Bind all layers from tensor registry
    bool BindModel(const TensorRegistry& registry);
    
    // Bind a specific layer
    LayerBindingResult BindLayer(uint32_t layerIndex, const TensorRegistry& registry);
    
    // Get bound model runtime
    TransformerModelRuntime* GetModel() { return &m_model; }
    const TransformerModelRuntime* GetModel() const { return &m_model; }
    
    // Get binding results
    const std::vector<LayerBindingResult>& GetBindingResults() const { return m_bindingResults; }
    
    // Statistics
    uint32_t GetNumBoundLayers() const;
    uint32_t GetNumMissingTensors() const;
    
    // Validation
    bool ValidateBinding() const;
    std::string GetBindingReport() const;
    
private:
    ModelArchitectureConfig m_config;
    TransformerModelRuntime m_model;
    std::vector<LayerBindingResult> m_bindingResults;
    bool m_initialized = false;
    
    // Helper methods
    std::string FormatLayerPattern(const std::string& pattern, uint32_t layerIndex) const;
    const TensorView* LookupTensor(const TensorRegistry& registry, const std::string& name) const;
    bool ValidateTensorShape(const TensorView& tensor, const std::vector<uint32_t>& expectedShape) const;
};

// ============================================================================
// Architecture Presets
// ============================================================================
namespace ArchitecturePresets {
    ModelArchitectureConfig Phi3Mini();
    ModelArchitectureConfig Qwen2_5(uint32_t sizeCode = 7);  // 0.5B, 1.5B, 3B, 7B, 14B, 32B, 72B
    ModelArchitectureConfig Llama3(uint32_t sizeCode = 8);   // 8B, 70B, etc.
    ModelArchitectureConfig TinyLlama();
}

} // namespace Runtime
} // namespace RawrXD
