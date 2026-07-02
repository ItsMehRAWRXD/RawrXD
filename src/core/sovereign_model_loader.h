// ============================================================================
// sovereign_model_loader.h — Phase 11/22 Integration Bridge
// C++ wrapper for RawrXD_120B_Loader.asm assembly module
// ============================================================================

#ifndef SOVEREIGN_MODEL_LOADER_H
#define SOVEREIGN_MODEL_LOADER_H

#include <string>
#include <memory>
#include <vector>
#include <cstdint>
#include <functional>

// Assembly loader C interface
extern "C" {
#include "../build/120b_loader/RawrXD_120B_Loader_C.h"
}

namespace sovereign {

// Forward declarations
class ModelLoader;
using ModelLoaderPtr = std::shared_ptr<ModelLoader>;

// ============================================================================
// Quantization Configuration
// ============================================================================

struct QuantizationConfig {
    // Layer-specific quantization (auto-detected if empty)
    std::vector<RawrXD_QuantType> layerQuantTypes;
    
    // Default strategy
    bool useHierarchical = true;  // Q8_0/Q4_K/Q2_K based on layer position
    bool useCriticalQ8 = true;  // Force Q8_0 for embed/output
    
    // KV cache settings
    uint32_t kvWindowSize = 512;
    uint32_t kvCompressedDim = 64;
    
    static QuantizationConfig Default() {
        return QuantizationConfig{};
    }
    
    static QuantizationConfig MaxQuality() {
        QuantizationConfig cfg;
        cfg.useHierarchical = false;
        // All layers Q8_0
        return cfg;
    }
    
    static QuantizationConfig MaxSpeed() {
        QuantizationConfig cfg;
        cfg.useHierarchical = true;
        cfg.kvCompressedDim = 32;  // More compression
        return cfg;
    }
};

// ============================================================================
// Model Metadata
// ============================================================================

struct ModelMetadata {
    std::string path;
    uint64_t fileSize = 0;
    uint32_t nTensors = 0;
    uint32_t nLayers = 0;
    uint32_t nVocab = 0;
    uint32_t nEmbed = 0;
    uint32_t contextLength = 0;
    
    // Memory estimates
    uint64_t uncompressedSize = 0;
    uint64_t quantizedSize = 0;
    double compressionRatio = 0.0;
    
    // Quantization breakdown
    uint32_t q8Layers = 0;
    uint32_t q4Layers = 0;
    uint32_t q2Layers = 0;
};

// ============================================================================
// Layer Access Interface
// ============================================================================

class ModelLayer {
public:
    ModelLayer(uint32_t index, void* data, size_t size, RawrXD_QuantType quant);
    
    uint32_t GetIndex() const { return index_; }
    void* GetData() { return data_; }
    const void* GetData() const { return data_; }
    size_t GetSize() const { return size_; }
    RawrXD_QuantType GetQuantType() const { return quantType_; }
    
    bool IsQuantized() const { return quantType_ != RAWRXD_Q8_0; }
    bool IsCritical() const { return index_ == 0 || index_ == 119; }
    
private:
    uint32_t index_;
    void* data_;
    size_t size_;
    RawrXD_QuantType quantType_;
};

// ============================================================================
// Model Loader — Main Interface
// ============================================================================

class ModelLoader : public std::enable_shared_from_this<ModelLoader> {
public:
    // Factory methods
    static ModelLoaderPtr LoadFromFile(
        const std::string& path,
        const QuantizationConfig& config = QuantizationConfig::Default()
    );
    
    static ModelLoaderPtr LoadFromFileAsync(
        const std::string& path,
        const QuantizationConfig& config = QuantizationConfig::Default(),
        std::function<void(float)> progressCallback = nullptr
    );
    
    // Destructor
    ~ModelLoader();
    
    // Disable copy, enable move
    ModelLoader(const ModelLoader&) = delete;
    ModelLoader& operator=(const ModelLoader&) = delete;
    ModelLoader(ModelLoader&&) = default;
    ModelLoader& operator=(ModelLoader&&) = default;
    
    // Core API
    ModelLayer GetLayer(uint32_t layerIndex);
    ModelLayer GetEmbeddingLayer();
    ModelLayer GetOutputLayer();
    
    // KV Cache operations
    bool InitializeKVCache();
    void UpdateKVCache(uint32_t position, const float* kVector, const float* vVector);
    void EvictKVCache();
    
    // Metadata
    const ModelMetadata& GetMetadata() const { return metadata_; }
    bool IsLoaded() const { return handle_ != nullptr; }
    
    // Memory management
    size_t GetResidentMemory() const;
    size_t GetTotalMemory() const;
    double GetMemoryUtilization() const;
    
    // Quantization helpers
    static std::vector<float> DequantizeLayer(const ModelLayer& layer);
    static std::vector<uint8_t> QuantizeBuffer(
        const std::vector<float>& input,
        RawrXD_QuantType quantType
    );
    
private:
    ModelLoader() = default;
    explicit ModelLoader(RawrXD_ModelHandle handle);
    
    bool LoadMetadata();
    void ApplyQuantizationStrategy();
    
    RawrXD_ModelHandle handle_ = nullptr;
    ModelMetadata metadata_;
    QuantizationConfig config_;
    bool kvCacheInitialized_ = false;
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace model_loader {
    // Quick size estimation
    uint64_t EstimateMemoryUsage(
        uint32_t nParams,  // in billions
        const QuantizationConfig& config = QuantizationConfig::Default()
    );
    
    // Detect optimal quantization for hardware
    QuantizationConfig DetectOptimalConfig();
    
    // Validate model file
    bool ValidateGGUF(const std::string& path);
    
    // Get layer type name
    const char* GetQuantTypeName(RawrXD_QuantType type);
    
    // Format bytes for display
    std::string FormatBytes(uint64_t bytes);
}

} // namespace sovereign

#endif // SOVEREIGN_MODEL_LOADER_H
