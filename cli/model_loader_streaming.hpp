// ============================================================================
// Model Loader Streaming - Header
// ============================================================================
// Zero dependencies GGUF streaming loader
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD {
namespace Streaming {

// Forward declarations
class StreamingModelLoader;
class ModelCache;

// Tensor types
enum class TensorType {
    F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q8_1,
    Q2_K, Q3_K, Q4_K, Q5_K, Q6_K, Q8_K, I8, I16, I32,
    // Q4_K variants
    Q4_K_S, Q4_K_M, Q4_K_L,
    // Blob/medusa types
    BLOB_GENERIC, MEDUSA_TREE, MEDUSA_WEIGHTS,
    UNKNOWN
};

// Tensor descriptor
struct TensorDescriptor {
    std::string name;
    TensorType type;
    std::vector<uint64_t> dimensions;
    uint64_t offset;
    uint64_t size;
    
    uint64_t NumElements() const;
    size_t ElementSize() const;
};

// Model architecture
struct ModelArchitecture {
    std::string architecture = "unknown";
    uint32_t vocab_size = 0;
    uint32_t hidden_size = 0;
    uint32_t num_layers = 0;
    uint32_t num_heads = 0;
    uint32_t num_kv_heads = 0;
    uint32_t intermediate_size = 0;
    uint32_t context_length = 0;
    float rms_norm_eps = 1e-6f;
    float rope_theta = 10000.0f;
    
    bool IsValid() const;
};

// Progress callback
using ProgressCallback = std::function<void(const std::string& stage, float progress, const std::string& details)>;

// Streaming model loader
class StreamingModelLoader {
public:
    StreamingModelLoader();
    ~StreamingModelLoader();
    
    bool Load(const std::string& path, ProgressCallback callback = nullptr);
    void Unload();
    bool IsLoaded() const;
    
    const std::string& GetPath() const;
    uint64_t GetFileSize() const;
    
    ModelArchitecture GetArchitecture() const;
    const TensorDescriptor* GetTensor(const std::string& name) const;
    std::vector<std::string> GetTensorNames() const;
    bool ReadTensorData(const std::string& name, float* output, size_t count) const;
    
    template<typename T>
    bool GetMetadata(const std::string& key, T& value) const;
    
    void PrintInfo() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Model cache
class ModelCache {
public:
    static ModelCache& Instance();
    
    std::shared_ptr<StreamingModelLoader> GetOrLoad(const std::string& path, ProgressCallback callback = nullptr);
    void Clear();
    size_t GetCacheSize() const;
    
private:
    ModelCache() = default;
    ~ModelCache() = default;
    ModelCache(const ModelCache&) = delete;
    ModelCache& operator=(const ModelCache&) = delete;
};

} // namespace Streaming
} // namespace RawrXD

// C API
extern "C" {

typedef void* RawrxdModelHandle;
typedef void (*RawrxdProgressCallback)(const char* stage, float progress, const char* details);

RawrxdModelHandle rawrxd_model_load(const char* path, RawrxdProgressCallback callback);
void rawrxd_model_unload(RawrxdModelHandle handle);
int rawrxd_model_is_loaded(RawrxdModelHandle handle);
void rawrxd_model_get_architecture(RawrxdModelHandle handle, char* arch_out, size_t arch_size,
                                    uint32_t* vocab_size, uint32_t* hidden_size,
                                    uint32_t* num_layers, uint32_t* num_heads);
int rawrxd_model_read_tensor(RawrxdModelHandle handle, const char* tensor_name,
                              float* output, size_t count);

} // extern "C"
