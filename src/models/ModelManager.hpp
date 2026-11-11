// ============================================================================
// ModelManager.hpp - Model Lifecycle Management
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace IDE {

struct ModelInfo {
    std::string name;
    std::string path;
    std::string architecture;
    size_t parameterCount;
    size_t contextLength;
    std::string quantization;
    bool isLoaded;
    float memoryUsageGB;
    float loadTimeMs;
};

struct ModelConfig {
    std::string modelPath;
    size_t gpuLayers;
    size_t contextSize;
    size_t batchSize;
    int threadCount;
    bool useFlashAttention;
    bool useMemoryMapping;
    float temperature;
    float topP;
    size_t maxTokens;
};

class ModelManager {
public:
    ModelManager();
    ~ModelManager();

    // Discovery
    std::vector<ModelInfo> DiscoverModels(const std::string& searchPath);
    ModelInfo GetModelInfo(const std::string& name);
    
    // Lifecycle
    bool LoadModel(const std::string& name, const ModelConfig& config);
    bool UnloadModel(const std::string& name);
    bool ReloadModel(const std::string& name);
    bool IsLoaded(const std::string& name);
    
    // Selection
    std::string GetActiveModel();
    bool SetActiveModel(const std::string& name);
    
    // Resource management
    size_t GetAvailableMemory();
    bool CanLoadModel(const std::string& name);
    std::vector<std::string> GetLoadedModels();
    
    // Events
    using LoadCallback = std::function<void(const std::string& name, bool success)>;
    void SetLoadCallback(LoadCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
