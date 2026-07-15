// RawrXD Sovereign v1.1.0 - Model Compatibility Framework
// GGUFLoader.hpp - GGUF format loader

#pragma once

#include "ModelInterface.hpp"
#include <memory>

namespace RawrXD {
namespace ModelCompatibility {

// Forward declaration for internal GGUF structures
namespace Internal {
    struct GGUFContext;
}

// GGUF-specific load options
struct GGUFLoadOptions {
    // Which layers to load (empty = all)
    std::vector<std::string> layer_whitelist;
    std::vector<std::string> layer_blacklist;
    
    // Tensor options
    bool lazy_load_tensors;      // Load tensors on demand
    bool verify_checksums;         // Verify tensor checksums
    
    // Memory options
    bool use_mmap;               // Use memory mapping
    bool use_mlock;              // Lock memory
    size_t max_tensor_size;      // Skip tensors larger than this
    
    GGUFLoadOptions()
        : lazy_load_tensors(false)
        , verify_checksums(true)
        , use_mmap(true)
        , use_mlock(false)
        , max_tensor_size(0) {}
};

// GGUF loader implementation
class GGUFLoader : public IModelLoader {
public:
    GGUFLoader();
    ~GGUFLoader() override;

    // IModelLoader implementation
    ModelFormat GetFormat() const override { return ModelFormat::GGUF; }
    std::string GetName() const override { return "GGUFLoader"; }
    std::string GetVersion() const override { return "1.0.0"; }
    
    bool CanLoad(const std::string& path) const override;
    bool CanLoadFromMemory() const override { return true; }
    
    std::shared_ptr<IModel> Load(const std::string& path) override;
    std::shared_ptr<IModel> LoadFromMemory(const std::vector<uint8_t>& data) override;
    
    ModelMetadata ExtractMetadata(const std::string& path) override;
    
    bool Validate(const std::string& path, std::string& error) override;

    // GGUF-specific methods
    void SetOptions(const GGUFLoadOptions& options);
    GGUFLoadOptions GetOptions() const;
    
    // Get GGUF-specific info
    std::vector<std::string> GetTensorNames(const std::string& path) const;
    size_t GetTensorCount(const std::string& path) const;
    std::vector<std::string> GetMetadataKeys(const std::string& path) const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// GGUF model implementation
class GGUFModel : public IModel {
public:
    GGUFModel();
    ~GGUFModel() override;

    // IModel implementation
    std::string GetName() const override;
    ModelFormat GetFormat() const override { return ModelFormat::GGUF; }
    ModelMetadata GetMetadata() const override;
    
    bool HasCapability(ModelCapability capability) const override;
    std::vector<ModelCapability> GetCapabilities() const override;
    
    InferenceResult Run(const std::vector<Tensor>& inputs, 
                        const InferenceConfig& config) override;
    
    std::string GenerateText(const std::string& prompt,
                            const InferenceConfig& config) override;
    
    std::vector<float> GetEmbeddings(const std::string& text) override;
    
    bool IsLoaded() const override;
    void Unload() override;
    
    size_t GetMemoryUsage() const override;
    void OptimizeMemory() override;
    
    bool HasTokenizer() const override;
    std::vector<int> Tokenize(const std::string& text) override;
    std::string Detokenize(const std::vector<int>& tokens) override;
    int GetVocabSize() override;

    // GGUF-specific methods
    bool LoadFromFile(const std::string& path, const GGUFLoadOptions& options);
    bool LoadFromMemory(const std::vector<uint8_t>& data, const GGUFLoadOptions& options);
    
    // Tensor access
    std::vector<std::string> GetTensorNames() const;
    std::optional<Tensor> GetTensor(const std::string& name) const;
    bool HasTensor(const std::string& name) const;
    
    // Metadata access
    std::optional<std::string> GetMetadataString(const std::string& key) const;
    std::optional<int64_t> GetMetadataInt(const std::string& key) const;
    std::optional<double> GetMetadataFloat(const std::string& key) const;
    std::optional<bool> GetMetadataBool(const std::string& key) const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// GGUF utilities
namespace GGUFUtils {
    // Check if file is valid GGUF
    bool IsGGUFFile(const std::string& path);
    bool IsGGUFData(const std::vector<uint8_t>& data);
    
    // Get GGUF version
    int GetVersion(const std::string& path);
    
    // Tensor info
    struct TensorInfo {
        std::string name;
        std::vector<size_t> shape;
        std::string type;
        size_t offset;
        size_t size;
    };
    
    std::vector<TensorInfo> GetTensorInfo(const std::string& path);
    
    // Quantization info
    QuantizationType GetQuantizationType(const std::string& tensor_type);
    std::string GetQuantizationName(QuantizationType type);
    size_t GetQuantizationBits(QuantizationType type);
    
    // Architecture detection
    std::string DetectArchitecture(const std::string& path);
    std::string DetectModelType(const std::string& path);
}

} // namespace ModelCompatibility
} // namespace RawrXD
