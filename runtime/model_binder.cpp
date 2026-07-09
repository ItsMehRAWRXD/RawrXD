// ============================================================================
// ModelBinder.cpp - Connect GGUF Registry to Transformer Layers
// ============================================================================

#include "model_binder.hpp"
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Architecture Presets
// ============================================================================
namespace ArchitecturePresets {

ModelArchitectureConfig Phi3Mini() {
    ModelArchitectureConfig config;
    config.name = "phi3-mini";
    config.arch = "phi3";
    config.vocabSize = 32064;
    config.hiddenSize = 3072;
    config.numLayers = 32;
    config.numHeads = 32;
    config.numKVHeads = 32;  // MHA
    config.intermediateSize = 8192;
    config.maxPosition = 4096;
    config.rmsNormEps = 1e-5f;
    config.ropeTheta = 10000.0f;
    
    // Phi-3 uses llama.cpp naming convention
    config.tokenEmbdPattern = "token_embd.weight";
    config.outputNormPattern = "output_norm.weight";
    config.outputWeightPattern = "output.weight";
    config.inputNormPattern = "blk.{layer}.attn_norm.weight";
    config.qProjPattern = "blk.{layer}.attn_q.weight";
    config.kProjPattern = "blk.{layer}.attn_k.weight";
    config.vProjPattern = "blk.{layer}.attn_v.weight";
    config.oProjPattern = "blk.{layer}.attn_output.weight";
    config.postNormPattern = "blk.{layer}.ffn_norm.weight";
    config.gateProjPattern = "blk.{layer}.ffn_gate.weight";
    config.upProjPattern = "blk.{layer}.ffn_up.weight";
    config.downProjPattern = "blk.{layer}.ffn_down.weight";
    
    return config;
}

ModelArchitectureConfig Qwen2_5(uint32_t sizeCode) {
    ModelArchitectureConfig config;
    config.name = "qwen2.5-" + std::to_string(sizeCode) + "b";
    config.arch = "qwen2";
    config.ropeTheta = 1000000.0f;  // Qwen uses 1M
    config.rmsNormEps = 1e-6f;
    
    // Size-specific configurations
    switch (sizeCode) {
        case 0:  // 0.5B
            config.vocabSize = 151936;
            config.hiddenSize = 896;
            config.numLayers = 24;
            config.numHeads = 14;
            config.numKVHeads = 2;  // GQA
            config.intermediateSize = 4864;
            config.maxPosition = 32768;
            break;
        case 1:  // 1.5B
            config.vocabSize = 151936;
            config.hiddenSize = 1536;
            config.numLayers = 28;
            config.numHeads = 12;
            config.numKVHeads = 2;
            config.intermediateSize = 8960;
            config.maxPosition = 32768;
            break;
        case 3:  // 3B
            config.vocabSize = 151936;
            config.hiddenSize = 2048;
            config.numLayers = 36;
            config.numHeads = 16;
            config.numKVHeads = 2;
            config.intermediateSize = 11008;
            config.maxPosition = 32768;
            break;
        case 7:  // 7B
            config.vocabSize = 152064;
            config.hiddenSize = 3584;
            config.numLayers = 28;
            config.numHeads = 28;
            config.numKVHeads = 4;
            config.intermediateSize = 18944;
            config.maxPosition = 131072;
            break;
        case 14:  // 14B
            config.vocabSize = 152064;
            config.hiddenSize = 5120;
            config.numLayers = 48;
            config.numHeads = 40;
            config.numKVHeads = 8;
            config.intermediateSize = 13824;
            config.maxPosition = 131072;
            break;
        case 32:  // 32B
            config.vocabSize = 152064;
            config.hiddenSize = 5120;
            config.numLayers = 64;
            config.numHeads = 40;
            config.numKVHeads = 8;
            config.intermediateSize = 27648;
            config.maxPosition = 131072;
            break;
        case 72:  // 72B
            config.vocabSize = 152064;
            config.hiddenSize = 8192;
            config.numLayers = 80;
            config.numHeads = 64;
            config.numKVHeads = 8;
            config.intermediateSize = 29568;
            config.maxPosition = 131072;
            break;
        default:
            // Default to 7B
            config.vocabSize = 152064;
            config.hiddenSize = 3584;
            config.numLayers = 28;
            config.numHeads = 28;
            config.numKVHeads = 4;
            config.intermediateSize = 18944;
            config.maxPosition = 131072;
            break;
    }
    
    // Qwen uses llama.cpp naming
    config.tokenEmbdPattern = "token_embd.weight";
    config.outputNormPattern = "output_norm.weight";
    config.outputWeightPattern = "output.weight";
    config.inputNormPattern = "blk.{layer}.attn_norm.weight";
    config.qProjPattern = "blk.{layer}.attn_q.weight";
    config.kProjPattern = "blk.{layer}.attn_k.weight";
    config.vProjPattern = "blk.{layer}.attn_v.weight";
    config.oProjPattern = "blk.{layer}.attn_output.weight";
    config.postNormPattern = "blk.{layer}.ffn_norm.weight";
    config.gateProjPattern = "blk.{layer}.ffn_gate.weight";
    config.upProjPattern = "blk.{layer}.ffn_up.weight";
    config.downProjPattern = "blk.{layer}.ffn_down.weight";
    
    return config;
}

ModelArchitectureConfig Llama3(uint32_t sizeCode) {
    ModelArchitectureConfig config;
    config.name = "llama3-" + std::to_string(sizeCode) + "b";
    config.arch = "llama";
    config.ropeTheta = 500000.0f;  // Llama 3 uses 500K
    config.rmsNormEps = 1e-5f;
    
    switch (sizeCode) {
        case 8:
            config.vocabSize = 128256;
            config.hiddenSize = 4096;
            config.numLayers = 32;
            config.numHeads = 32;
            config.numKVHeads = 8;  // GQA
            config.intermediateSize = 14336;
            config.maxPosition = 8192;
            break;
        case 70:
            config.vocabSize = 128256;
            config.hiddenSize = 8192;
            config.numLayers = 80;
            config.numHeads = 64;
            config.numKVHeads = 8;
            config.intermediateSize = 28672;
            config.maxPosition = 8192;
            break;
        default:
            // Default to 8B
            config.vocabSize = 128256;
            config.hiddenSize = 4096;
            config.numLayers = 32;
            config.numHeads = 32;
            config.numKVHeads = 8;
            config.intermediateSize = 14336;
            config.maxPosition = 8192;
            break;
    }
    
    config.tokenEmbdPattern = "token_embd.weight";
    config.outputNormPattern = "output_norm.weight";
    config.outputWeightPattern = "output.weight";
    config.inputNormPattern = "blk.{layer}.attn_norm.weight";
    config.qProjPattern = "blk.{layer}.attn_q.weight";
    config.kProjPattern = "blk.{layer}.attn_k.weight";
    config.vProjPattern = "blk.{layer}.attn_v.weight";
    config.oProjPattern = "blk.{layer}.attn_output.weight";
    config.postNormPattern = "blk.{layer}.ffn_norm.weight";
    config.gateProjPattern = "blk.{layer}.ffn_gate.weight";
    config.upProjPattern = "blk.{layer}.ffn_up.weight";
    config.downProjPattern = "blk.{layer}.ffn_down.weight";
    
    return config;
}

ModelArchitectureConfig TinyLlama() {
    ModelArchitectureConfig config;
    config.name = "tinyllama";
    config.arch = "llama";
    config.vocabSize = 32000;
    config.hiddenSize = 2048;
    config.numLayers = 22;
    config.numHeads = 32;
    config.numKVHeads = 4;  // GQA
    config.intermediateSize = 5632;
    config.maxPosition = 2048;
    config.rmsNormEps = 1e-5f;
    config.ropeTheta = 10000.0f;
    
    config.tokenEmbdPattern = "token_embd.weight";
    config.outputNormPattern = "output_norm.weight";
    config.outputWeightPattern = "output.weight";
    config.inputNormPattern = "blk.{layer}.attn_norm.weight";
    config.qProjPattern = "blk.{layer}.attn_q.weight";
    config.kProjPattern = "blk.{layer}.attn_k.weight";
    config.vProjPattern = "blk.{layer}.attn_v.weight";
    config.oProjPattern = "blk.{layer}.attn_output.weight";
    config.postNormPattern = "blk.{layer}.ffn_norm.weight";
    config.gateProjPattern = "blk.{layer}.ffn_gate.weight";
    config.upProjPattern = "blk.{layer}.ffn_up.weight";
    config.downProjPattern = "blk.{layer}.ffn_down.weight";
    
    return config;
}

} // namespace ArchitecturePresets

// ============================================================================
// ModelBinder Implementation
// ============================================================================
bool ModelBinder::Initialize(const ModelArchitectureConfig& config) {
    m_config = config;
    m_bindingResults.clear();
    
    // Initialize model with layer configs
    std::vector<TransformerLayerConfig> layerConfigs;
    for (uint32_t i = 0; i < config.numLayers; ++i) {
        TransformerLayerConfig layerConfig;
        layerConfig.hiddenSize = config.hiddenSize;
        layerConfig.numHeads = config.numHeads;
        layerConfig.numKVHeads = config.numKVHeads;
        layerConfig.headDim = config.hiddenSize / config.numHeads;
        layerConfig.intermediateSize = config.intermediateSize;
        layerConfig.rmsNormEps = config.rmsNormEps;
        layerConfig.ropeTheta = config.ropeTheta;
        layerConfig.maxPosition = config.maxPosition;
        layerConfig.useGQA = (config.numKVHeads != config.numHeads);
        layerConfig.useMQA = (config.numKVHeads == 1);
        layerConfigs.push_back(layerConfig);
    }
    
    m_initialized = m_model.Initialize(layerConfigs);
    return m_initialized;
}

bool ModelBinder::BindModel(const TensorRegistry& registry) {
    if (!m_initialized) {
        return false;
    }
    
    m_bindingResults.clear();
    
    // Bind token embeddings
    const TensorView* tokenEmbd = LookupTensor(registry, m_config.tokenEmbdPattern);
    if (tokenEmbd) {
        m_model.SetTokenEmbeddings(*tokenEmbd);
    }
    
    // Bind output norm
    const TensorView* outputNorm = LookupTensor(registry, m_config.outputNormPattern);
    if (outputNorm) {
        m_model.SetOutputNorm(*outputNorm);
    }
    
    // Bind output weight
    const TensorView* outputWeight = LookupTensor(registry, m_config.outputWeightPattern);
    if (outputWeight) {
        m_model.SetOutputWeight(*outputWeight);
    }
    
    // Bind each layer
    for (uint32_t layerIdx = 0; layerIdx < m_config.numLayers; ++layerIdx) {
        LayerBindingResult result = BindLayer(layerIdx, registry);
        m_bindingResults.push_back(result);
    }
    
    return ValidateBinding();
}

LayerBindingResult ModelBinder::BindLayer(uint32_t layerIndex, const TensorRegistry& registry) {
    LayerBindingResult result;
    result.layerIndex = layerIndex;
    
    // Look up all tensors for this layer
    const TensorView* inputNorm = LookupTensor(registry, FormatLayerPattern(m_config.inputNormPattern, layerIndex));
    const TensorView* qProj = LookupTensor(registry, FormatLayerPattern(m_config.qProjPattern, layerIndex));
    const TensorView* kProj = LookupTensor(registry, FormatLayerPattern(m_config.kProjPattern, layerIndex));
    const TensorView* vProj = LookupTensor(registry, FormatLayerPattern(m_config.vProjPattern, layerIndex));
    const TensorView* oProj = LookupTensor(registry, FormatLayerPattern(m_config.oProjPattern, layerIndex));
    const TensorView* postNorm = LookupTensor(registry, FormatLayerPattern(m_config.postNormPattern, layerIndex));
    const TensorView* gateProj = LookupTensor(registry, FormatLayerPattern(m_config.gateProjPattern, layerIndex));
    const TensorView* upProj = LookupTensor(registry, FormatLayerPattern(m_config.upProjPattern, layerIndex));
    const TensorView* downProj = LookupTensor(registry, FormatLayerPattern(m_config.downProjPattern, layerIndex));
    
    // Track which tensors were found
    result.inputNormBound = (inputNorm != nullptr && inputNorm->IsValid());
    result.qProjBound = (qProj != nullptr && qProj->IsValid());
    result.kProjBound = (kProj != nullptr && kProj->IsValid());
    result.vProjBound = (vProj != nullptr && vProj->IsValid());
    result.oProjBound = (oProj != nullptr && oProj->IsValid());
    result.postNormBound = (postNorm != nullptr && postNorm->IsValid());
    result.gateProjBound = (gateProj != nullptr && gateProj->IsValid());
    result.upProjBound = (upProj != nullptr && upProj->IsValid());
    result.downProjBound = (downProj != nullptr && downProj->IsValid());
    
    // Check if all required tensors are present
    if (!result.inputNormBound || !result.qProjBound || !result.kProjBound ||
        !result.vProjBound || !result.oProjBound || !result.postNormBound ||
        !result.gateProjBound || !result.upProjBound || !result.downProjBound) {
        result.success = false;
        
        // Build error message
        std::stringstream ss;
        ss << "Missing tensors: ";
        if (!result.inputNormBound) ss << "input_norm ";
        if (!result.qProjBound) ss << "q_proj ";
        if (!result.kProjBound) ss << "k_proj ";
        if (!result.vProjBound) ss << "v_proj ";
        if (!result.oProjBound) ss << "o_proj ";
        if (!result.postNormBound) ss << "post_norm ";
        if (!result.gateProjBound) ss << "gate_proj ";
        if (!result.upProjBound) ss << "up_proj ";
        if (!result.downProjBound) ss << "down_proj ";
        result.errorMessage = ss.str();
        
        return result;
    }
    
    // Bind the layer
    result.success = m_model.BindLayer(layerIndex, *inputNorm, *qProj, *kProj, *vProj, *oProj,
                                       *postNorm, *gateProj, *upProj, *downProj);
    
    if (!result.success) {
        result.errorMessage = "BindLayer failed";
    }
    
    return result;
}

uint32_t ModelBinder::GetNumBoundLayers() const {
    uint32_t count = 0;
    for (const auto& result : m_bindingResults) {
        if (result.success) ++count;
    }
    return count;
}

uint32_t ModelBinder::GetNumMissingTensors() const {
    uint32_t missing = 0;
    for (const auto& result : m_bindingResults) {
        missing += (9 - result.GetBoundCount());  // 9 tensors per layer
    }
    return missing;
}

bool ModelBinder::ValidateBinding() const {
    if (!m_initialized) return false;
    if (m_bindingResults.size() != m_config.numLayers) return false;
    
    for (const auto& result : m_bindingResults) {
        if (!result.success) return false;
    }
    
    return m_model.IsInitialized();
}

std::string ModelBinder::GetBindingReport() const {
    std::stringstream ss;
    ss << "=== Model Binding Report ===" << std::endl;
    ss << "Model: " << m_config.name << std::endl;
    ss << "Architecture: " << m_config.arch << std::endl;
    ss << "Layers: " << m_config.numLayers << std::endl;
    ss << "Hidden Size: " << m_config.hiddenSize << std::endl;
    ss << "Heads: " << m_config.numHeads << " (KV: " << m_config.numKVHeads << ")" << std::endl;
    ss << std::endl;
    
    uint32_t boundLayers = GetNumBoundLayers();
    ss << "Bound Layers: " << boundLayers << "/" << m_config.numLayers << std::endl;
    
    if (boundLayers < m_config.numLayers) {
        ss << "\nFailed Layers:" << std::endl;
        for (const auto& result : m_bindingResults) {
            if (!result.success) {
                ss << "  Layer " << result.layerIndex << ": " << result.errorMessage << std::endl;
            }
        }
    }
    
    return ss.str();
}

std::string ModelBinder::FormatLayerPattern(const std::string& pattern, uint32_t layerIndex) const {
    std::string result = pattern;
    size_t pos = result.find("{layer}");
    if (pos != std::string::npos) {
        result.replace(pos, 7, std::to_string(layerIndex));
    }
    return result;
}

const TensorView* ModelBinder::LookupTensor(const TensorRegistry& registry, const std::string& name) const {
    const TensorData* data = registry.Find(name);
    if (data) {
        // Return a pointer to a view - this is safe because registry owns the data
        static thread_local TensorView view;
        view = TensorView(data);
        return &view;
    }
    return nullptr;
}

bool ModelBinder::ValidateTensorShape(const TensorView& tensor, const std::vector<uint32_t>& expectedShape) const {
    if (!tensor.IsValid()) return false;
    
    if (expectedShape.size() == 1) {
        return tensor.Rows() == expectedShape[0] || tensor.Cols() == expectedShape[0];
    } else if (expectedShape.size() == 2) {
        return tensor.Rows() == expectedShape[0] && tensor.Cols() == expectedShape[1];
    }
    
    return false;
}

} // namespace Runtime
} // namespace RawrXD
