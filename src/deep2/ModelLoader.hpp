// ============================================================================
// ModelLoader.hpp — Model Loading Pipeline
// GGUF → Tensor Map → Model Registry → Inference Session
// ============================================================================

#ifndef MODEL_LOADER_HPP
#define MODEL_LOADER_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace rawr {

// ============================================================================
// Tensor Type (GGML compatible)
// ============================================================================
enum class TensorType : uint32_t {
    F32 = 0,
    F16 = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15
};

// ============================================================================
// Tensor Info
// ============================================================================
struct TensorInfo {
    std::string name;
    TensorType type;
    uint32_t nDims;
    uint64_t shape[4];
    uint64_t offset;
    uint64_t size;
    void* data;  // Loaded data pointer
};

// ============================================================================
// Model Architecture
// ============================================================================
struct ModelArchitecture {
    std::string name;       // "llama", "phi3", "qwen2", etc.
    uint32_t hiddenDim;
    uint32_t numLayers;
    uint32_t numHeads;
    uint32_t numKVHeads;
    uint32_t vocabSize;
    uint32_t headDim;
    uint32_t intermediateDim;
    float normEpsilon;
};

// ============================================================================
// Model Loader Callbacks
// ============================================================================
using LoadProgressCallback = std::function<void(uint32_t current, uint32_t total, const char* tensorName)>;

// ============================================================================
// ModelLoader — Loads GGUF models into tensor registry
// ============================================================================
class ModelLoader {
public:
    static ModelLoader& Get();

    bool Initialize();
    void Shutdown();

    // Load a GGUF model file
    bool Load(const char* path, LoadProgressCallback onProgress = nullptr);
    void Unload();

    // Query
    bool IsLoaded() const { return m_loaded; }
    const ModelArchitecture& GetArchitecture() const { return m_arch; }
    uint32_t GetTensorCount() const { return static_cast<uint32_t>(m_tensors.size()); }

    // Tensor access
    const TensorInfo* GetTensor(const char* name) const;
    const TensorInfo* GetTensorByIndex(uint32_t index) const;
    void* GetTensorData(const char* name) const;

    // Weight access helpers
    const float* GetWeights(const char* layer, const char* type) const;

    // Memory
    uint64_t GetTotalWeightSize() const { return m_totalWeightSize; }
    uint64_t GetLoadedSize() const { return m_loadedSize; }

private:
    ModelLoader() = default;
    ~ModelLoader() = default;
    ModelLoader(const ModelLoader&) = delete;
    ModelLoader& operator=(const ModelLoader&) = delete;

    bool ParseGGUFHeader(const uint8_t* data, uint64_t size);
    bool LoadTensors(const uint8_t* data, uint64_t size, LoadProgressCallback onProgress);

    std::vector<TensorInfo> m_tensors;
    ModelArchitecture m_arch = {};
    bool m_loaded = false;
    uint8_t* m_fileData = nullptr;
    uint64_t m_fileSize = 0;
    uint64_t m_totalWeightSize = 0;
    uint64_t m_loadedSize = 0;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // MODEL_LOADER_HPP
