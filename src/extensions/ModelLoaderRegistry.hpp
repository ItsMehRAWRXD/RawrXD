// RawrXD Model Loader Registry
// Phase X.2: Custom model loader support
// Enables loading models from various formats and sources

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include <optional>

namespace RawrXD {
namespace Extensions {

// Model format
enum class ModelFormat {
    UNKNOWN,
    GGML,           // GGML format (llama.cpp)
    GGUF,           // GGUF format (llama.cpp)
    ONNX,           // ONNX format
    PYTORCH,        // PyTorch format
    TENSORFLOW,     // TensorFlow format
    SAFETENSORS,    // HuggingFace SafeTensors
    CUSTOM          // Custom format
};

// Model metadata
struct ModelMetadata {
    std::string modelId;
    std::string name;
    std::string version;
    std::string author;
    std::string description;
    ModelFormat format;
    std::string formatVersion;
    std::vector<std::string> architectures;
    uint64_t parameterCount;
    uint64_t fileSize;
    std::map<std::string, std::string> hyperparameters;
    std::map<std::string, std::string> tokenizerConfig;
    std::vector<std::string> specialTokens;
    std::chrono::system_clock::time_point createdAt;
    std::string checksum;
    std::string signature;
    bool isQuantized{false};
    std::string quantizationType;
    int quantizationBits{0};
};

// Model loading options
struct ModelLoadOptions {
    bool lazyLoading{false};        // Load weights on demand
    bool mmapEnabled{true};         // Use memory mapping
    int gpuLayers{0};               // Number of layers to offload to GPU
    int contextSize{4096};          // Context window size
    int batchSize{512};             // Batch size for processing
    float ropeFreqBase{10000.0f};   // RoPE frequency base
    float ropeFreqScale{1.0f};      // RoPE frequency scale
    std::map<std::string, std::string> customOptions;
};

// Model loading result
struct ModelLoadResult {
    bool success;
    std::string modelId;
    std::string errorMessage;
    std::chrono::milliseconds loadTime;
    uint64_t memoryUsed;
    ModelMetadata metadata;
    void* modelHandle{nullptr};     // Opaque handle to loaded model
};

// Model loader interface
class IModelLoader {
public:
    virtual ~IModelLoader() = default;
    
    // Loader information
    virtual std::string getName() const = 0;
    virtual std::string getVersion() const = 0;
    virtual std::vector<ModelFormat> getSupportedFormats() const = 0;
    virtual bool canLoad(const std::string& path) const = 0;
    
    // Model inspection
    virtual ModelMetadata inspect(const std::string& path) const = 0;
    virtual bool validate(const std::string& path) const = 0;
    
    // Model loading
    virtual ModelLoadResult load(const std::string& path, const ModelLoadOptions& options) = 0;
    virtual bool unload(const std::string& modelId) = 0;
    
    // Model access
    virtual void* getModel(const std::string& modelId) const = 0;
    virtual bool isLoaded(const std::string& modelId) const = 0;
    
    // Statistics
    virtual uint64_t getMemoryUsage(const std::string& modelId) const = 0;
    virtual std::map<std::string, double> getStatistics(const std::string& modelId) const = 0;
};

// Model loader registry
class ModelLoaderRegistry {
public:
    ModelLoaderRegistry();
    ~ModelLoaderRegistry();
    
    // Initialization
    bool initialize();
    bool shutdown();
    
    // Loader registration
    void registerLoader(std::shared_ptr<IModelLoader> loader);
    void unregisterLoader(const std::string& name);
    std::shared_ptr<IModelLoader> getLoader(const std::string& name) const;
    std::shared_ptr<IModelLoader> findLoaderForPath(const std::string& path) const;
    std::vector<std::string> listLoaders() const;
    std::vector<std::string> listLoadersForFormat(ModelFormat format) const;
    
    // Model loading
    ModelLoadResult loadModel(const std::string& path, const ModelLoadOptions& options = {});
    bool unloadModel(const std::string& modelId);
    bool unloadAllModels();
    
    // Model inspection
    ModelMetadata inspectModel(const std::string& path);
    bool validateModel(const std::string& path);
    ModelFormat detectFormat(const std::string& path) const;
    
    // Model access
    void* getModel(const std::string& modelId) const;
    bool isModelLoaded(const std::string& modelId) const;
    std::vector<std::string> listLoadedModels() const;
    
    // Model metadata
    ModelMetadata getModelMetadata(const std::string& modelId) const;
    bool updateModelMetadata(const std::string& modelId, const ModelMetadata& metadata);
    
    // Format conversion
    bool canConvert(ModelFormat from, ModelFormat to) const;
    bool convertModel(const std::string& inputPath, const std::string& outputPath,
                     ModelFormat targetFormat, const std::map<std::string, std::string>& options = {});
    
    // Quantization
    bool canQuantize(ModelFormat format) const;
    bool quantizeModel(const std::string& inputPath, const std::string& outputPath,
                      const std::string& quantizationType, int bits);
    
    // Model caching
    void enableCaching(bool enabled);
    bool isCachingEnabled() const;
    void setCacheDirectory(const std::string& path);
    void clearCache();
    uint64_t getCacheSize() const;
    
    // Model sources
    void registerSource(const std::string& name, const std::string& basePath);
    void unregisterSource(const std::string& name);
    std::string resolvePath(const std::string& source, const std::string& modelPath) const;
    std::vector<std::string> listSources() const;
    
    // Statistics
    struct LoaderStats {
        uint32_t registeredLoaders;
        uint32_t loadedModels;
        uint64_t totalMemoryUsed;
        uint64_t cacheSize;
        uint32_t successfulLoads;
        uint32_t failedLoads;
    };
    LoaderStats getStats() const;
    
    // Events
    using ModelEventCallback = std::function<void(const std::string& event, const std::string& modelId)>;
    void onModelEvent(ModelEventCallback callback);

private:
    void notifyEvent(const std::string& event, const std::string& modelId);
    std::string generateModelId() const;
    
    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<IModelLoader>> loaders_;
    std::map<std::string, ModelLoadResult> loadedModels_;
    std::map<std::string, std::string> modelSources_;
    std::string cacheDirectory_;
    bool cachingEnabled_{false};
    ModelEventCallback eventCallback_;
    
    uint32_t successfulLoads_{0};
    uint32_t failedLoads_{0};
};

// Built-in GGML/GGUF loader
class GGMLModelLoader : public IModelLoader {
public:
    GGMLModelLoader();
    
    std::string getName() const override { return "GGMLLoader"; }
    std::string getVersion() const override { return "1.0.0"; }
    std::vector<ModelFormat> getSupportedFormats() const override;
    bool canLoad(const std::string& path) const override;
    
    ModelMetadata inspect(const std::string& path) const override;
    bool validate(const std::string& path) const override;
    
    ModelLoadResult load(const std::string& path, const ModelLoadOptions& options) override;
    bool unload(const std::string& modelId) override;
    
    void* getModel(const std::string& modelId) const override;
    bool isLoaded(const std::string& modelId) const override;
    
    uint64_t getMemoryUsage(const std::string& modelId) const override;
    std::map<std::string, double> getStatistics(const std::string& modelId) const override;

private:
    mutable std::mutex mutex_;
    std::map<std::string, void*> models_;
};

// Built-in ONNX loader
class ONNXModelLoader : public IModelLoader {
public:
    ONNXModelLoader();
    
    std::string getName() const override { return "ONNXLoader"; }
    std::string getVersion() const override { return "1.0.0"; }
    std::vector<ModelFormat> getSupportedFormats() const override;
    bool canLoad(const std::string& path) const override;
    
    ModelMetadata inspect(const std::string& path) const override;
    bool validate(const std::string& path) const override;
    
    ModelLoadResult load(const std::string& path, const ModelLoadOptions& options) override;
    bool unload(const std::string& modelId) override;
    
    void* getModel(const std::string& modelId) const override;
    bool isLoaded(const std::string& modelId) const override;
    
    uint64_t getMemoryUsage(const std::string& modelId) const override;
    std::map<std::string, double> getStatistics(const std::string& modelId) const override;

private:
    mutable std::mutex mutex_;
    std::map<std::string, void*> models_;
};

// Model format utilities
class ModelFormatUtils {
public:
    static std::string formatToString(ModelFormat format);
    static ModelFormat stringToFormat(const std::string& str);
    static std::vector<std::string> getFileExtensions(ModelFormat format);
    static ModelFormat detectFromExtension(const std::string& path);
    static bool isValidFormat(const std::string& str);
};

} // namespace Extensions
} // namespace RawrXD
