// ============================================================================
// GGUFModelRegistry.h - Phase 3: Production Model Management
// Central registry for GGUF model artifacts with metadata extraction
// ============================================================================

#ifndef GGUF_MODEL_REGISTRY_H
#define GGUF_MODEL_REGISTRY_H

#include "../GGUFLoader.hpp"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <optional>

namespace Deep2 {
namespace ModelRegistry {

// ============================================================================
// Model Manifest
// Comprehensive metadata for a GGUF model
// ============================================================================
struct ModelManifest {
    // Identity
    std::string modelId;
    std::string name;
    std::string version;
    std::string description;
    
    // Source
    std::string filePath;
    std::string checksum;  // SHA256
    uint64_t fileSizeBytes = 0;
    std::chrono::system_clock::time_point modifiedTime;
    
    // Architecture
    std::string architecture;  // "llama", "mistral", "phi", etc.
    size_t parameterCount = 0;
    size_t hiddenSize = 0;
    size_t numLayers = 0;
    size_t numAttentionHeads = 0;
    size_t numKeyValueHeads = 0;
    size_t contextLength = 0;
    size_t vocabSize = 0;
    
    // Quantization
    std::string quantizationType;  // "Q4_K_M", "Q5_K_M", "Q8_0", etc.
    size_t bitsPerWeight = 0;
    float compressionRatio = 0.0f;
    
    // Capabilities
    std::vector<std::string> capabilities;  // "chat", "instruct", "code", etc.
    std::vector<std::string> languages;
    
    // Requirements
    uint64_t minVRAMBytes = 0;
    uint64_t recommendedVRAMBytes = 0;
    size_t minContextLength = 0;
    
    // Status
    bool isLoaded = false;
    bool isVerified = false;
    std::string loadStatus;
    
    // Metadata
    std::map<std::string, std::string> metadata;
    std::chrono::system_clock::time_point registeredTime;
};

// ============================================================================
// Model State
// ============================================================================
enum class ModelState {
    UNLOADED,      // Not in memory
    LOADING,       // Loading in progress
    LOADED,        // Fully resident
    UNLOADING,     // Unloading in progress
    ERROR          // Load failed
};

// ============================================================================
// Loaded Model Instance
// ============================================================================
struct LoadedModel {
    std::string modelId;
    std::shared_ptr<void> engineHandle;  // Deep2Engine instance
    int primaryDevice = -1;
    int secondaryDevice = -1;
    uint64_t vramUsedBytes = 0;
    ModelState state = ModelState::UNLOADED;
    std::chrono::steady_clock::time_point loadTime;
    std::chrono::steady_clock::time_point lastUsedTime;
    size_t inferenceCount = 0;
    double avgLatencyMs = 0.0;
};

// ============================================================================
// Inference Profile
// Pre-configured execution parameters
// ============================================================================
struct InferenceProfile {
    std::string profileId;
    std::string name;
    std::string description;
    
    // Context
    size_t maxContextLength = 4096;
    size_t maxBatchSize = 1;
    
    // Generation
    float temperature = 0.8f;
    float topP = 0.9f;
    int topK = 40;
    float repetitionPenalty = 1.0f;
    
    // Performance
    bool useFlashAttention = true;
    bool useKVCacheQuantization = false;
    size_t cacheQuantizationBits = 16;
    
    // GPU placement
    std::string executionMode = "hybrid";  // "single", "model_parallel", "hybrid"
    int preferredDevice = -1;  // -1 = auto
    
    // Streaming
    bool streaming = true;
    int streamBufferSize = 4;
};

// ============================================================================
// Model Registry
// Central catalog for all GGUF models
// ============================================================================
class ModelRegistry {
public:
    static ModelRegistry& Instance();
    
    // Initialization
    bool Initialize(const std::string& registryPath = "");
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Discovery
    size_t ScanDirectory(const std::string& directory, bool recursive = true);
    bool RegisterModel(const std::string& filePath);
    bool UnregisterModel(const std::string& modelId);
    
    // Query
    std::vector<ModelManifest> ListModels() const;
    std::vector<ModelManifest> FindModelsByCapability(const std::string& capability) const;
    std::vector<ModelManifest> FindModelsByVRAM(uint64_t maxVRAMBytes) const;
    std::optional<ModelManifest> GetModel(const std::string& modelId) const;
    bool HasModel(const std::string& modelId) const;
    
    // Lifecycle
    bool LoadModel(const std::string& modelId, const InferenceProfile& profile = {});
    bool UnloadModel(const std::string& modelId);
    bool IsModelLoaded(const std::string& modelId) const;
    LoadedModel GetLoadedModel(const std::string& modelId) const;
    std::vector<LoadedModel> GetAllLoadedModels() const;
    
    // Hot swap
    bool HotSwapModel(const std::string& unloadId, const std::string& loadId);
    bool EvictLRUModel();
    
    // Profiles
    void AddProfile(const InferenceProfile& profile);
    void RemoveProfile(const std::string& profileId);
    std::vector<InferenceProfile> ListProfiles() const;
    std::optional<InferenceProfile> GetProfile(const std::string& profileId) const;
    InferenceProfile GetDefaultProfile() const;
    
    // Auto-scheduling
    std::string SelectBestModel(const std::string& taskType, uint64_t availableVRAM) const;
    InferenceProfile SelectBestProfile(const std::string& modelId, 
                                        const std::string& taskType) const;
    
    // Verification
    bool VerifyModel(const std::string& modelId);
    bool ValidateChecksum(const std::string& modelId);
    
    // Persistence
    bool SaveRegistry();
    bool LoadRegistry();
    
    // Events
    using ModelEventCallback = std::function<void(const std::string& modelId)>;
    void SetModelLoadedCallback(ModelEventCallback cb);
    void SetModelUnloadedCallback(ModelEventCallback cb);
    void SetModelRegisteredCallback(ModelEventCallback cb);

private:
    ModelRegistry() = default;
    ~ModelRegistry() = default;
    
    ModelRegistry(const ModelRegistry&) = delete;
    ModelRegistry& operator=(const ModelRegistry&) = delete;
    
    bool initialized_ = false;
    std::string registryPath_;
    
    mutable std::mutex modelsMutex_;
    std::map<std::string, ModelManifest> models_;
    
    mutable std::mutex loadedMutex_;
    std::map<std::string, LoadedModel> loadedModels_;
    
    mutable std::mutex profilesMutex_;
    std::map<std::string, InferenceProfile> profiles_;
    
    ModelEventCallback onModelLoaded_;
    ModelEventCallback onModelUnloaded_;
    ModelEventCallback onModelRegistered_;
    
    // Internal helpers
    ModelManifest ExtractManifest(const std::string& filePath);
    std::string ComputeChecksum(const std::string& filePath);
    bool ParseGGUFMetadata(const std::string& filePath, ModelManifest& manifest);
    uint64_t EstimateVRAM(const ModelManifest& manifest) const;
};

// ============================================================================
// C API
// ============================================================================
extern "C" {

__declspec(dllexport) void* ModelRegistry_Create();
__declspec(dllexport) void ModelRegistry_Destroy(void* registry);
__declspec(dllexport) bool ModelRegistry_Initialize(void* registry, const char* path);
__declspec(dllexport) int ModelRegistry_ScanDirectory(void* registry, const char* directory);
__declspec(dllexport) bool ModelRegistry_LoadModel(void* registry, const char* modelId);
__declspec(dllexport) bool ModelRegistry_UnloadModel(void* registry, const char* modelId);
__declspec(dllexport) int ModelRegistry_GetLoadedModelCount(void* registry);

} // extern "C"

} // namespace ModelRegistry
} // namespace Deep2

#endif // GGUF_MODEL_REGISTRY_H
