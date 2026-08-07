// ============================================================================
// ModelRegistry.hpp — Model Registry
// Tracks loaded GGUF files, VRAM usage, backend selection, active sessions
// ============================================================================

#ifndef MODEL_REGISTRY_HPP
#define MODEL_REGISTRY_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace rawr {

// ============================================================================
// Backend Type
// ============================================================================
enum class BackendType : uint8_t {
    CPU = 0,
    Vulkan,
    CUDA,
    HIP,
    Metal
};

// ============================================================================
// Model Info
// ============================================================================
struct ModelInfo {
    std::string path;
    std::string name;
    uint64_t fileSize;
    uint64_t vramUsage;
    uint32_t numLayers;
    uint32_t hiddenDim;
    uint32_t numHeads;
    uint32_t vocabSize;
    BackendType backend;
    bool loaded;
    uint32_t activeSessions;
};

// ============================================================================
// ModelRegistry — Tracks all loaded models
// ============================================================================
class ModelRegistry {
public:
    static ModelRegistry& Get();

    uint32_t RegisterModel(const char* path, const char* name);
    bool UnregisterModel(uint32_t modelId);
    ModelInfo* GetModel(uint32_t modelId);
    ModelInfo* FindModel(const char* name);

    void SetModelLoaded(uint32_t modelId, bool loaded);
    void AddSession(uint32_t modelId);
    void RemoveSession(uint32_t modelId);

    uint32_t GetModelCount() const;
    uint32_t GetLoadedCount() const;
    uint64_t GetTotalVRAMUsage() const;

    std::vector<ModelInfo> ListModels() const;

private:
    ModelRegistry() = default;
    ~ModelRegistry() = default;
    ModelRegistry(const ModelRegistry&) = delete;
    ModelRegistry& operator=(const ModelRegistry&) = delete;

    mutable std::mutex m_mutex;
    std::unordered_map<uint32_t, ModelInfo> m_models;
    uint32_t m_nextId = 1;
};

} // namespace rawr

#endif // MODEL_REGISTRY_HPP
