// ============================================================================
// UniversalModelLoader.hpp
// ============================================================================
// Format-agnostic model loader. GGUF is just a serialization format.
// The runtime never branches on format - it produces UniversalTensorDescriptors.
//
// Architecture:
//   GGUF / HF / Safetensors / Raw
//          |
//     FormatReader (pluggable)
//          |
//   UniversalTensorDescriptor[]
//          |
//   KernelRegistry.Resolve()
//          |
//   ResolvedKernelTable
//          |
//   ExecutionGraph
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#pragma once

#include "UniversalTensorDescriptor.hpp"
#include "KernelRegistry.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>

namespace RawrXD {

// ============================================================================
// Model Metadata (architecture-agnostic)
// ============================================================================
struct ModelMetadata {
    std::string architecture;       // "deepseek2", "llama", "qwen3", etc.
    std::string modelName;

    // Dimensions
    uint32_t vocabSize;
    uint32_t hiddenSize;
    uint32_t numLayers;
    uint32_t numHeads;
    uint32_t numKVHeads;
    uint32_t headDim;

    // Legacy aliases for backward compatibility
    uint32_t hiddenDim;        // alias for hiddenSize
    uint32_t contextLength;    // alias for maxContextLen

    // MoE
    bool     isMoE;
    uint32_t numExperts;
    uint32_t numExpertsPerTok;
    uint32_t moeIntermediateSize;

    // Quantization
    QuantType weightQuant;
    QuantType kvQuant;

    // RoPE
    float ropeTheta;
    float ropeScaling;

    // Norm
    float rmsNormEps;

    // Context
    uint32_t maxContextLen;

    ModelMetadata() : vocabSize(0), hiddenSize(0), numLayers(0),
        numHeads(0), numKVHeads(0), headDim(0),
        hiddenDim(0), contextLength(0),
        isMoE(false), numExperts(0), numExpertsPerTok(0), moeIntermediateSize(0),
        weightQuant(QuantType::F32), kvQuant(QuantType::F16),
        ropeTheta(10000.0f), ropeScaling(1.0f), rmsNormEps(1e-6f),
        maxContextLen(4096) {}
};

// ============================================================================
// Tensor Entry (descriptor + raw data reference)
// ============================================================================
struct TensorShape {
    uint32_t dims = 0;
    uint32_t dim[4] = {0, 0, 0, 0};
    uint64_t elements = 0;
};

struct TensorEntry {
    std::string name;
    UniversalTensorDescriptor descriptor;
    TensorShape shape;
    QuantType quantType = QuantType::F32;
    uint64_t fileOffset;     // Offset in source file
    uint64_t byteSize;       // Size in bytes
};

// ============================================================================
// Format Reader Interface (pluggable)
// ============================================================================
class IFormatReader {
public:
    virtual ~IFormatReader() = default;

    // Can this reader handle the given file?
    virtual bool CanRead(const std::string& filePath) = 0;

    // Read metadata
    virtual bool ReadMetadata(const std::string& filePath, ModelMetadata& metadata) = 0;

    // Read tensor catalog (descriptors only, no data loaded)
    virtual bool ReadTensorCatalog(const std::string& filePath,
                                    std::vector<TensorEntry>& tensors) = 0;

    // Load a specific tensor's data (lazy loading)
    virtual bool LoadTensor(const std::string& filePath,
                           const TensorEntry& entry,
                           void* destBuffer) = 0;

    // Get format name
    virtual const char* GetFormatName() const = 0;
};

// ============================================================================
// Universal Model Loader
// ============================================================================
class UniversalModelLoader {
public:
    UniversalModelLoader();
    ~UniversalModelLoader();

    // Register a format reader
    void RegisterFormatReader(std::unique_ptr<IFormatReader> reader);

    // Load model (auto-detects format)
    bool LoadModel(const std::string& filePath);

    // Get metadata
    const ModelMetadata& GetMetadata() const { return metadata_; }

    // Get tensor catalog
    const std::vector<TensorEntry>& GetTensorCatalog() const { return tensors_; }

    // Get resolved kernel table (cached at load time)
    const ResolvedKernelTable& GetKernels() const { return kernels_; }

    // Get tensor by name
    const TensorEntry* FindTensor(const std::string& name) const;

    // Load tensor data into buffer
    bool LoadTensorData(const std::string& tensorName, void* destBuffer);

    // Get loaded format name
    const char* GetFormatName() const { return formatName_.c_str(); }

private:
    std::vector<std::unique_ptr<IFormatReader>> readers_;
    IFormatReader* activeReader_;
    std::string filePath_;
    std::string formatName_;

    ModelMetadata metadata_;
    std::vector<TensorEntry> tensors_;
    ResolvedKernelTable kernels_;

    bool DetectAndLoad();
};

// ============================================================================
// GGUF Format Reader (implementation in .cpp)
// ============================================================================
class GGUFFormatReader : public IFormatReader {
public:
    bool CanRead(const std::string& filePath) override;
    bool ReadMetadata(const std::string& filePath, ModelMetadata& metadata) override;
    bool ReadTensorCatalog(const std::string& filePath,
                            std::vector<TensorEntry>& tensors) override;
    bool LoadTensor(const std::string& filePath,
                    const TensorEntry& entry,
                    void* destBuffer) override;
    const char* GetFormatName() const override { return "GGUF"; }

private:
    // Map GGUF type to QuantType
    static QuantType MapGGUFType(uint32_t ggufType);
};

// ============================================================================
// Safetensors Format Reader (full implementation)
// ============================================================================
class SafetensorsFormatReader : public IFormatReader {
public:
    bool CanRead(const std::string& filePath) override;
    bool ReadMetadata(const std::string& filePath, ModelMetadata& metadata) override;
    bool ReadTensorCatalog(const std::string& filePath,
                            std::vector<TensorEntry>& tensors) override;
    bool LoadTensor(const std::string& filePath,
                    const TensorEntry& entry,
                    void* destBuffer) override;
    const char* GetFormatName() const override;
};

// ============================================================================
// HuggingFace PyTorch Format Reader (full implementation)
// ============================================================================
class HFPyTorchFormatReader : public IFormatReader {
public:
    bool CanRead(const std::string& filePath) override;
    bool ReadMetadata(const std::string& filePath, ModelMetadata& metadata) override;
    bool ReadTensorCatalog(const std::string& filePath,
                            std::vector<TensorEntry>& tensors) override;
    bool LoadTensor(const std::string& filePath,
                    const TensorEntry& entry,
                    void* destBuffer) override;
    const char* GetFormatName() const override;
};

} // namespace RawrXD
