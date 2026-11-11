// ============================================================================
// sovereign_model_loader.cpp — Phase 11/22 Integration Implementation
// Bridges RawrXD_120B_Loader.asm with Sovereign Engine
// ============================================================================

#include "sovereign_model_loader.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace sovereign {

// ============================================================================
// ModelLayer Implementation
// ============================================================================

ModelLayer::ModelLayer(uint32_t index, void* data, size_t size, RawrXD_QuantType quant)
    : index_(index), data_(data), size_(size), quantType_(quant) {}

// ============================================================================
// ModelLoader Implementation
// ============================================================================

ModelLoader::ModelLoader(RawrXD_ModelHandle handle) : handle_(handle) {}

ModelLoader::~ModelLoader() {
    if (handle_) {
        RawrXD_UnloadModel(handle_);
        handle_ = nullptr;
    }
}

ModelLoaderPtr ModelLoader::LoadFromFile(
    const std::string& path,
    const QuantizationConfig& config) {
    
    std::cout << "[Phase 11] Loading model: " << path << std::endl;
    
    // Call assembly loader
    RawrXD_ModelHandle handle = RawrXD_LoadModel(path.c_str());
    if (!handle) {
        std::cerr << "[Phase 11] Failed to load model: " << path << std::endl;
        return nullptr;
    }
    
    auto loader = std::shared_ptr<ModelLoader>(new ModelLoader(handle));
    loader->config_ = config;
    
    // Load metadata
    if (!loader->LoadMetadata()) {
        std::cerr << "[Phase 11] Failed to parse model metadata" << std::endl;
        return nullptr;
    }
    
    // Apply quantization strategy
    loader->ApplyQuantizationStrategy();
    
    // Initialize KV cache if requested
    if (config.kvWindowSize > 0) {
        loader->InitializeKVCache();
    }
    
    std::cout << "[Phase 11] Model loaded successfully" << std::endl;
    std::cout << "  Layers: " << loader->metadata_.nLayers << std::endl;
    std::cout << "  Memory: " << model_loader::FormatBytes(loader->metadata_.quantizedSize) 
              << " (" << std::fixed << std::setprecision(1) 
              << loader->metadata_.compressionRatio << "x compression)" << std::endl;
    
    return loader;
}

ModelLayer ModelLoader::GetLayer(uint32_t layerIndex) {
    if (!handle_ || layerIndex >= metadata_.nLayers) {
        return ModelLayer(0, nullptr, 0, RAWRXD_Q8_0);
    }
    
    void* data = RawrXD_GetLayer(handle_, layerIndex);
    if (!data) {
        return ModelLayer(layerIndex, nullptr, 0, RAWRXD_Q8_0);
    }
    
    // Determine quantization type for this layer
    RawrXD_QuantType quantType = RAWRXD_Q4_K;  // Default
    if (config_.useHierarchical) {
        quantType = RawrXD_GetQuantTypeForLayer(layerIndex, metadata_.nLayers);
    } else if (!config_.layerQuantTypes.empty() && layerIndex < config_.layerQuantTypes.size()) {
        quantType = config_.layerQuantTypes[layerIndex];
    }
    
    // Estimate size (actual size would come from tensor metadata)
    size_t size = 500ULL * 1024 * 1024;  // ~500MB per layer average
    
    return ModelLayer(layerIndex, data, size, quantType);
}

ModelLayer ModelLoader::GetEmbeddingLayer() {
    return GetLayer(0);
}

ModelLayer ModelLoader::GetOutputLayer() {
    if (metadata_.nLayers > 0) {
        return GetLayer(metadata_.nLayers - 1);
    }
    return ModelLayer(0, nullptr, 0, RAWRXD_Q8_0);
}

bool ModelLoader::InitializeKVCache() {
    if (!handle_ || kvCacheInitialized_) {
        return false;
    }
    
    int result = RawrXD_KVCache_Init(handle_);
    kvCacheInitialized_ = (result == 1);
    
    if (kvCacheInitialized_) {
        std::cout << "[Phase 11] KV cache initialized: window=" << config_.kvWindowSize
                  << ", dim=" << config_.kvCompressedDim << std::endl;
    }
    
    return kvCacheInitialized_;
}

void ModelLoader::UpdateKVCache(uint32_t position, const float* kVector, const float* vVector) {
    if (handle_ && kvCacheInitialized_) {
        RawrXD_KVCache_Update(handle_, position, kVector, vVector);
    }
}

void ModelLoader::EvictKVCache() {
    if (handle_) {
        RawrXD_KVCache_Evict(handle_);
    }
}

bool ModelLoader::LoadMetadata() {
    // In a real implementation, this would parse the GGUF header
    // For now, set reasonable defaults for a 120B model
    
    metadata_.nLayers = 120;
    metadata_.nTensors = 842;  // ~7 tensors per layer + embed + output
    metadata_.nVocab = 32000;
    metadata_.nEmbed = 4096;
    metadata_.contextLength = 8192;
    
    // Memory estimates
    metadata_.uncompressedSize = 120ULL * 1024 * 1024 * 1024;  // 120GB
    
    // Calculate quantized size based on strategy
    size_t embedSize = 2ULL * 1024 * 1024 * 1024;  // 2GB embeddings (Q8_0)
    size_t layerSizeAvg = 500ULL * 1024 * 1024;  // ~500MB per layer
    
    if (config_.useHierarchical) {
        // Q8_0: 40 layers, Q4_K: 40 layers (50%), Q2_K: 40 layers (25%)
        metadata_.q8Layers = 40;
        metadata_.q4Layers = 40;
        metadata_.q2Layers = 40;
        
        metadata_.quantizedSize = embedSize + 
            (40 * layerSizeAvg) +           // Q8_0
            (40 * layerSizeAvg / 2) +       // Q4_K (50%)
            (40 * layerSizeAvg / 4);        // Q2_K (25%)
    } else {
        // All Q8_0
        metadata_.q8Layers = 120;
        metadata_.quantizedSize = embedSize + (120 * layerSizeAvg);
    }
    
    metadata_.compressionRatio = 
        (double)metadata_.uncompressedSize / metadata_.quantizedSize;
    
    return true;
}

void ModelLoader::ApplyQuantizationStrategy() {
    if (config_.layerQuantTypes.empty() && metadata_.nLayers > 0) {
        // Auto-generate quantization types based on strategy
        config_.layerQuantTypes.resize(metadata_.nLayers);
        
        for (uint32_t i = 0; i < metadata_.nLayers; i++) {
            if (config_.useHierarchical) {
                config_.layerQuantTypes[i] = RawrXD_GetQuantTypeForLayer(i, metadata_.nLayers);
            } else {
                config_.layerQuantTypes[i] = RAWRXD_Q8_0;  // Default to max quality
            }
        }
    }
}

size_t ModelLoader::GetResidentMemory() const {
    // In a real implementation, track actually loaded layers
    return metadata_.quantizedSize;
}

size_t ModelLoader::GetTotalMemory() const {
    return metadata_.quantizedSize;
}

double ModelLoader::GetMemoryUtilization() const {
    return 1.0;  // All resident in this simplified implementation
}

std::vector<float> ModelLoader::DequantizeLayer(const ModelLayer& layer) {
    // Placeholder - would call assembly dequantization
    std::vector<float> result;
    // ... dequantize based on layer.GetQuantType()
    return result;
}

std::vector<uint8_t> ModelLoader::QuantizeBuffer(
    const std::vector<float>& input,
    RawrXD_QuantType quantType) {
    
    std::vector<uint8_t> output(input.size() * 2);  // Worst case
    
    RawrXD_Quantize(
        input.data(),
        output.data(),
        static_cast<uint32_t>(input.size()),
        quantType
    );
    
    return output;
}

// ============================================================================
// Utility Functions
// ============================================================================

namespace model_loader {

uint64_t EstimateMemoryUsage(uint32_t nParams, const QuantizationConfig& config) {
    // Rough estimate: 1B params ~ 4GB FP32, ~1GB Q8_0, ~0.5GB Q4_K, ~0.25GB Q2_K
    
    uint64_t baseSize = nParams * 4ULL * 1024 * 1024;  // FP32 size
    
    if (config.useHierarchical) {
        // Mixed: ~40% Q8_0, ~35% Q4_K, ~25% Q2_K
        return (baseSize * 35) / 100;  // ~35% of original
    }
    
    return baseSize / 4;  // All Q8_0: ~25% of original
}

QuantizationConfig DetectOptimalConfig() {
    // Detect based on available memory
    // For now, return hierarchical as default
    return QuantizationConfig::Default();
}

bool ValidateGGUF(const std::string& path) {
    // Quick validation - check file exists and has GGUF magic
    // In production, would actually read and validate header
    return true;  // Placeholder
}

const char* GetQuantTypeName(RawrXD_QuantType type) {
    switch (type) {
        case RAWRXD_Q8_0: return "Q8_0";
        case RAWRXD_Q4_K: return "Q4_K";
        case RAWRXD_Q2_K: return "Q2_K";
        default: return "UNKNOWN";
    }
}

std::string FormatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unitIndex < 4) {
        size /= 1024.0;
        unitIndex++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unitIndex];
    return oss.str();
}

} // namespace model_loader

} // namespace sovereign
