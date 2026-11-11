// RawrXD Sovereign v1.1.0 - Model Compatibility Framework
// ModelInterface.hpp - Unified model interface

#pragma once

#include "ModelFormat.hpp"
#include <vector>
#include <memory>
#include <string>
#include <map>
#include <optional>

namespace RawrXD {
namespace ModelCompatibility {

// Forward declarations
struct Tensor;
struct ModelMetadata;
struct InferenceConfig;

// Model capabilities
enum class ModelCapability {
    TEXT_GENERATION,
    EMBEDDING,
    CLASSIFICATION,
    TOKEN_CLASSIFICATION,
    QUESTION_ANSWERING,
    SUMMARIZATION,
    TRANSLATION,
    IMAGE_CLASSIFICATION,
    OBJECT_DETECTION,
    MULTIMODAL
};

// Model quantization type
enum class QuantizationType {
    NONE,           // No quantization (FP32)
    FP16,           // Half precision
    INT8,           // 8-bit integer
    INT4,           // 4-bit integer
    Q4_0,           // Q4_0 (llama.cpp)
    Q4_1,           // Q4_1 (llama.cpp)
    Q5_0,           // Q5_0 (llama.cpp)
    Q5_1,           // Q5_1 (llama.cpp)
    Q8_0,           // Q8_0 (llama.cpp)
    GPTQ,           // GPTQ quantization
    AWQ             // AWQ quantization
};

// Model metadata
struct ModelMetadata {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    ModelFormat format;
    QuantizationType quantization;
    
    // Architecture info
    std::string architecture;
    std::string model_type;
    
    // Size info
    size_t parameter_count;
    size_t vocab_size;
    size_t context_length;
    size_t embedding_length;
    size_t head_count;
    size_t layer_count;
    
    // File info
    size_t file_size_bytes;
    std::string file_path;
    std::string checksum_sha256;
    
    // Capabilities
    std::vector<ModelCapability> capabilities;
    
    // Additional metadata
    std::map<std::string, std::string> custom_fields;
    
    ModelMetadata() 
        : format(ModelFormat::UNKNOWN)
        , quantization(QuantizationType::NONE)
        , parameter_count(0)
        , vocab_size(0)
        , context_length(0)
        , embedding_length(0)
        , head_count(0)
        , layer_count(0)
        , file_size_bytes(0) {}
};

// Tensor descriptor
struct TensorDescriptor {
    std::string name;
    std::vector<size_t> shape;
    std::string data_type;  // "float32", "float16", "int32", etc.
    size_t byte_size;
    
    TensorDescriptor() : byte_size(0) {}
};

// Tensor data
struct Tensor {
    TensorDescriptor descriptor;
    std::vector<uint8_t> data;
    
    // Helper methods
    template<typename T>
    std::vector<T> AsVector() const {
        size_t count = data.size() / sizeof(T);
        std::vector<T> result(count);
        std::memcpy(result.data(), data.data(), data.size());
        return result;
    }
    
    template<typename T>
    void FromVector(const std::vector<T>& vec) {
        data.resize(vec.size() * sizeof(T));
        std::memcpy(data.data(), vec.data(), data.size());
    }
};

// Inference configuration
struct InferenceConfig {
    // Generation parameters
    int max_tokens;
    float temperature;
    float top_p;
    int top_k;
    float repetition_penalty;
    
    // Sampling
    bool do_sample;
    int seed;
    
    // Stopping criteria
    std::vector<std::string> stop_sequences;
    
    // Performance
    int batch_size;
    bool use_cache;
    
    // Device
    std::string device;  // "cpu", "cuda", "vulkan"
    int device_id;
    
    InferenceConfig()
        : max_tokens(512)
        , temperature(0.7f)
        , top_p(0.9f)
        , top_k(40)
        , repetition_penalty(1.0f)
        , do_sample(true)
        , seed(-1)
        , batch_size(1)
        , use_cache(true)
        , device("cpu")
        , device_id(0) {}
};

// Inference result
struct InferenceResult {
    std::vector<Tensor> outputs;
    int64_t inference_time_ms;
    int64_t tokens_generated;
    int64_t tokens_per_second;
    bool success;
    std::string error_message;
    
    InferenceResult() 
        : inference_time_ms(0)
        , tokens_generated(0)
        , tokens_per_second(0)
        , success(false) {}
};

// Unified model interface
class IModel {
public:
    virtual ~IModel() = default;
    
    // Model info
    virtual std::string GetName() const = 0;
    virtual ModelFormat GetFormat() const = 0;
    virtual ModelMetadata GetMetadata() const = 0;
    
    // Capabilities
    virtual bool HasCapability(ModelCapability capability) const = 0;
    virtual std::vector<ModelCapability> GetCapabilities() const = 0;
    
    // Inference
    virtual InferenceResult Run(const std::vector<Tensor>& inputs, 
                                 const InferenceConfig& config) = 0;
    
    // Text generation (convenience method)
    virtual std::string GenerateText(const std::string& prompt,
                                      const InferenceConfig& config) = 0;
    
    // Embeddings (convenience method)
    virtual std::vector<float> GetEmbeddings(const std::string& text) = 0;
    
    // State management
    virtual bool IsLoaded() const = 0;
    virtual void Unload() = 0;
    
    // Memory management
    virtual size_t GetMemoryUsage() const = 0;
    virtual void OptimizeMemory() = 0;
    
    // Tokenizer (if built-in)
    virtual bool HasTokenizer() const = 0;
    virtual std::vector<int> Tokenize(const std::string& text) = 0;
    virtual std::string Detokenize(const std::vector<int>& tokens) = 0;
    virtual int GetVocabSize() = 0;
};

// Model loader interface
class IModelLoader {
public:
    virtual ~IModelLoader() = default;
    
    // Loader info
    virtual ModelFormat GetFormat() const = 0;
    virtual std::string GetName() const = 0;
    virtual std::string GetVersion() const = 0;
    
    // Capabilities
    virtual bool CanLoad(const std::string& path) const = 0;
    virtual bool CanLoadFromMemory() const = 0;
    
    // Loading
    virtual std::shared_ptr<IModel> Load(const std::string& path) = 0;
    virtual std::shared_ptr<IModel> LoadFromMemory(const std::vector<uint8_t>& data) = 0;
    
    // Metadata extraction
    virtual ModelMetadata ExtractMetadata(const std::string& path) = 0;
    
    // Validation
    virtual bool Validate(const std::string& path, std::string& error) = 0;
};

// Model factory
class ModelFactory {
public:
    static ModelFactory& GetInstance();
    
    // Register loader
    void RegisterLoader(std::shared_ptr<IModelLoader> loader);
    void UnregisterLoader(ModelFormat format);
    
    // Get loader
    std::shared_ptr<IModelLoader> GetLoader(ModelFormat format);
    std::shared_ptr<IModelLoader> GetLoaderForFile(const std::string& path);
    
    // Get all loaders
    std::vector<std::shared_ptr<IModelLoader>> GetAllLoaders();
    std::vector<std::shared_ptr<IModelLoader>> GetLoadersForFormat(ModelFormat format);
    
    // Create model
    std::shared_ptr<IModel> CreateModel(ModelFormat format);
    
private:
    ModelFactory() = default;
    std::map<ModelFormat, std::shared_ptr<IModelLoader>> loaders_;
};

// Model utilities
namespace ModelUtils {
    // Quantization utilities
    std::string QuantizationToString(QuantizationType quant);
    QuantizationType StringToQuantization(const std::string& str);
    size_t GetQuantizationBits(QuantizationType quant);
    
    // Capability utilities
    std::string CapabilityToString(ModelCapability cap);
    std::vector<std::string> CapabilitiesToStrings(const std::vector<ModelCapability>& caps);
    
    // Tensor utilities
    size_t GetTensorSize(const TensorDescriptor& desc);
    std::string GetDtypeString(const std::string& data_type);
    
    // Memory estimation
    size_t EstimateMemoryUsage(const ModelMetadata& metadata);
    size_t EstimateMemoryUsage(size_t parameter_count, QuantizationType quant);
}

} // namespace ModelCompatibility
} // namespace RawrXD
