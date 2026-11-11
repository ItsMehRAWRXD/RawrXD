// ============================================================================
// Streaming Layer Registry Implementation
// ============================================================================

#include "streaming_layer_registry.hpp"
#include <iostream>
#include <sstream>

namespace RawrXD {
namespace Runtime {

StreamingLayerRegistry::StreamingLayerRegistry() = default;

StreamingLayerRegistry::~StreamingLayerRegistry() {
    UnloadLayer();
}

bool StreamingLayerRegistry::Initialize(StreamingGGUFLoader& loader) {
    m_loader = &loader;
    m_num_layers = 0;
    m_loaded_layer = UINT32_MAX;
    
    // Discover number of layers by scanning for blk.N patterns
    // Build index first for fast name lookup
    if (!m_loader->BuildIndex()) {
        std::cerr << "[LayerRegistry] Failed to build index" << std::endl;
        return false;
    }
    
    // Count layers by looking for blk.N.attn_q.weight patterns
    uint32_t max_layer = 0;
    bool found = true;
    
    while (found) {
        std::string name = MakeTensorName(max_layer, "attn_q.weight");
        TensorInfo info;
        found = m_loader->SeekToTensor(name, info);
        if (found) {
            max_layer++;
        }
    }
    
    m_num_layers = max_layer;
    
    std::cout << "[LayerRegistry] Discovered " << m_num_layers << " layers" << std::endl;
    
    return m_num_layers > 0;
}

std::string StreamingLayerRegistry::MakeTensorName(uint32_t layer_idx, const char* suffix) {
    std::ostringstream oss;
    oss << "blk." << layer_idx << "." << suffix;
    return oss.str();
}

TensorView StreamingLayerRegistry::LoadWeight(const std::string& name) {
    if (!m_loader) return TensorView();
    
    TensorInfo info;
    if (!m_loader->SeekToTensor(name, info)) {
        std::cerr << "[LayerRegistry] Weight not found: " << name << std::endl;
        return TensorView();
    }
    
    // Create mmap-backed TensorView
    TensorView::MmapInfo mmapInfo;
    mmapInfo.base = nullptr;  // Will be set by MapTensor
    mmapInfo.fileOffset = m_loader->GetTensorDataOffset();
    mmapInfo.tensorOffset = info.offset;
    mmapInfo.dataSize = info.size;
    mmapInfo.type = static_cast<GGMLType>(info.type);
    mmapInfo.shape = info.shape;
    
    // Memory map the tensor
    MmappedTensor mmapTensor = m_loader->MapTensor(info);
    if (!mmapTensor.IsValid()) {
        std::cerr << "[LayerRegistry] Failed to mmap: " << name << std::endl;
        return TensorView();
    }
    
    // Update base pointer
    mmapInfo.base = mmapTensor.data;
    
    // Note: We don't store the MmappedTensor here - the TensorView
    // points into the mapped region. The loader maintains the mapping.
    // In a real implementation, you'd want to manage mapping lifetime.
    
    return TensorView(mmapInfo);
}

bool StreamingLayerRegistry::LoadLayer(uint32_t layer_idx) {
    if (!m_loader || layer_idx >= m_num_layers) {
        return false;
    }
    
    // Unload previous layer
    if (m_loaded_layer != UINT32_MAX) {
        UnloadLayer();
    }
    
    std::cout << "[LayerRegistry] Loading layer " << layer_idx << std::endl;
    
    // Load all weights for this layer
    m_current.attn_q = LoadWeight(MakeTensorName(layer_idx, "attn_q.weight"));
    m_current.attn_k = LoadWeight(MakeTensorName(layer_idx, "attn_k.weight"));
    m_current.attn_v = LoadWeight(MakeTensorName(layer_idx, "attn_v.weight"));
    m_current.attn_output = LoadWeight(MakeTensorName(layer_idx, "attn_output.weight"));
    
    m_current.ffn_gate = LoadWeight(MakeTensorName(layer_idx, "ffn_gate.weight"));
    m_current.ffn_up = LoadWeight(MakeTensorName(layer_idx, "ffn_up.weight"));
    m_current.ffn_down = LoadWeight(MakeTensorName(layer_idx, "ffn_down.weight"));
    
    m_current.attn_norm = LoadWeight(MakeTensorName(layer_idx, "attn_norm.weight"));
    m_current.ffn_norm = LoadWeight(MakeTensorName(layer_idx, "ffn_norm.weight"));
    
    if (!m_current.IsValid()) {
        std::cerr << "[LayerRegistry] Failed to load all weights for layer " << layer_idx << std::endl;
        UnloadLayer();
        return false;
    }
    
    m_loaded_layer = layer_idx;
    
    std::cout << "[LayerRegistry] Layer " << layer_idx << " loaded successfully" << std::endl;
    return true;
}

void StreamingLayerRegistry::UnloadLayer() {
    if (m_loaded_layer == UINT32_MAX) return;
    
    std::cout << "[LayerRegistry] Unloading layer " << m_loaded_layer << std::endl;
    
    // Clear current weights
    m_current.Clear();
    m_loaded_layer = UINT32_MAX;
    
    // Note: In a real implementation, you'd also unmap the memory here
}

TensorView StreamingLayerRegistry::GetWeight(const std::string& name_pattern) {
    if (!m_loader) return TensorView();
    return LoadWeight(name_pattern);
}

} // namespace Runtime
} // namespace RawrXD
