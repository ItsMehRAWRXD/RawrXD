// ============================================================================
// DeepSeekMoELoader.hpp - Streaming MoE Loader Header
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <map>

// Include GGUF types from existing loader
#include "GGUFLoader.hpp"
#include "MoEWeightsLoader.hpp"

namespace Deep2 {

// Forward declarations
class MoERouter;
class Deep2Engine;

// ============================================================================
// GGUF Tensor Info (minimal for MoE loading)
// ============================================================================
struct GGUFTensorInfo {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> dimensions;
    uint64_t offset;  // Offset in file
    size_t size;      // Size in bytes
};

// ============================================================================
// MoE Expert Configuration
// ============================================================================
struct ExpertConfig {
    uint32_t numExperts = 0;
    uint32_t activeExperts = 0;
    uint32_t expertDim = 0;
    uint32_t hiddenDim = 0;
    std::string activationType = "silu";
    float routingBias = 0.0f;
};

// ============================================================================
// MoE Architecture Types
// ============================================================================
enum class MoEArchitecture {
    Unknown,
    DeepSeekV2,
    DeepSeekV3,
    Mixtral,
    Qwen3MoE,
    Phi3MoE,
    GenericMoE
};

// ============================================================================
// MoE Model Configuration (used by architecture parsers)
// ============================================================================
struct MoEModelConfig {
    MoEArchitecture architecture = MoEArchitecture::GenericMoE;
    size_t hiddenSize = 0;
    size_t numHiddenLayers = 0;
    size_t numAttentionHeads = 0;
    size_t numKeyValueHeads = 0;
    size_t intermediateSize = 0;
    size_t numExperts = 0;
    size_t numActiveExperts = 0;
    size_t numExpertsPerToken = 0;  // Number of experts selected per token
    size_t expertCapacity = 0;
    size_t moeIntermediateSize = 0;   // MoE-specific intermediate size
    size_t vocabSize = 0;
    size_t maxPositionEmbeddings = 0;
    float routerBias = 0.0f;
    float routerJitter = 0.0f;
    float expertDropout = 0.0f;
    float ropeTheta = 10000.0f;
    std::string ropeScaling;          // e.g., "yarn", "dynamic"
    bool useSharedExpert = false;
    size_t numSharedExperts = 0;
    std::string modelName;
    std::string architectureName;
    
    // Validation
    mutable std::string validationError;
    mutable bool isValidated = false;
    
    bool Validate() const;
    
    // Expert size in bytes (Q4_K_M quantized)
    size_t expertBytesQ4KM = 0;
};

// ============================================================================
// Model Architecture Info
// ============================================================================
struct ModelArchitectureInfo {
    std::string modelType;
    uint32_t vocabSize = 0;
    uint32_t hiddenSize = 0;
    uint32_t numLayers = 0;
    uint32_t numAttentionHeads = 0;
    uint32_t numKeyValueHeads = 0;
    uint32_t intermediateSize = 0;
    float rmsNormEps = 1e-6f;
    float ropeTheta = 10000.0f;
    uint32_t maxPositionEmbeddings = 4096;
    
    // MoE specific
    ExpertConfig moeConfig;
    bool isMoE = false;
};

// ============================================================================
// Loading Progress Callback
// ============================================================================
using LoadProgressCallback = std::function<void(const std::string& stage, float progress)>;

// ============================================================================
// DeepSeek MoE Loader
// ============================================================================
class DeepSeekMoELoader {
public:
    DeepSeekMoELoader();
    ~DeepSeekMoELoader();
    
    // Load model from GGUF file
    bool LoadFromFile(const std::string& filepath, 
                      LoadProgressCallback callback = nullptr);
    
    // Get loaded architecture info
    const ModelArchitectureInfo& GetArchitectureInfo() const { return archInfo_; }
    
    // Get MoE config
    const MoEModelConfig& GetConfig() const { return config_; }
    
    // Stats structure
    struct Stats {
        uint64_t totalLoads = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint64_t evictions = 0;
        uint64_t bytesStreamed = 0;
        double avgLoadTimeMs = 0.0;
    };
    
    // Get stats
    Stats GetStats() const;
    void ResetStats();
    
    // Load expert weights
    const void* LoadExpert(int layer, int expert);
    bool LoadExpertDirect(int layer, int expert, void* buffer, size_t bufferSize);
    
    // Validate against tensors
    bool ValidateAgainstTensors();
    
    // Get tensor info by name
    const GGUFTensorInfo* GetTensorInfo(const std::string& name) const;
    
    // Get all tensor names
    std::vector<std::string> GetTensorNames() const;
    
    // Read tensor data
    bool ReadTensorData(const std::string& name, void* buffer, size_t bufferSize);
    
    // Get MoE router (if loaded)
    std::shared_ptr<MoERouter> GetRouter() const { return router_; }
    
    // Get file size
    size_t GetFileSize() const { return fileSize_; }
    
    // Check if model is loaded
    bool IsLoaded() const { return isLoaded_; }
    
    // Get metadata value
    std::string GetMetadataString(const std::string& key) const;
    int64_t GetMetadataInt(const std::string& key) const;
    double GetMetadataFloat(const std::string& key) const;
    
    // Close and cleanup
    void Close();
    
    // Static helpers
    static bool IsGGUFFile(const std::string& filepath);
    static uint32_t GetGGUFVersion(const std::string& filepath);
    
    // Open file (internal use)
    bool Open(const char* ggufPath, size_t cacheSizeMB = 4096);
    
    // Read data at offset
    bool ReadAt(uint64_t offset, void* buffer, size_t size);
    
    // Load router weights for a layer
    bool LoadRouterWeights(int layer, std::vector<float>& outWeights);
    
    // Load shared expert weights for a layer
    bool LoadSharedExpert(int layer, void* buffer, size_t bufferSize);
    
    // Cache management
    void SetMaxCacheSize(size_t bytes);
    size_t GetCacheSize() const;
    
    // Pin/unpin experts
    void PinExpert(int layer, int expert);
    void UnpinExpert(int layer, int expert);
    
    // Touch cache entry (update access time)
    void TouchCache(int layer, int expert);
    
private:
    bool ParseHeader(LoadProgressCallback callback);
    bool ParseTensors(LoadProgressCallback callback);
    bool ParseMetadata();
    bool LoadArchitectureInfo();
    
    // File I/O helpers
    bool OpenFile(const char* path);
    void CloseFile();
    
    // Internal methods
    size_t DiscoverExpertTensors();
    bool ParseIndex();
    void DetectArchitecture();
    bool ParseArchitectureMetadata();
    bool ParseDeepSeekMetadata();
    bool ParseMixtralMetadata();
    bool ParseQwen3MoEMetadata();
    bool ParseGenericMoEMetadata();
    
    // Template helper for metadata
    template<typename T>
    T GetMetadata(const std::string& key, T defaultValue) const;
    
    // Legacy helpers for compatibility
    void ParseConfigValue(const std::string& key, uint64_t value);
    void ParseConfigValue(const std::string& key, int64_t value);
    void ParseConfigString(const std::string& key, const std::string& value);
    
    // Parse expert tensor name to extract layer and expert index
    static bool ParseExpertName(const std::string& name, int& layer, int& expertIdx);
    
    // Expert tensor tracking (defined before methods that use it)
    struct ExpertTensorInfo {
        int layerIdx = 0;
        std::string name;
        GGMLType type = GGMLType::GGML_TYPE_F32;
        std::vector<uint64_t> dimensions;
        uint64_t fileOffset = 0;
        size_t sizeBytes = 0;
        size_t projSize = 0;
        size_t numExperts = 0;
        enum class Proj { Gate, Up, Down } proj = Proj::Gate;
    };
    
    // Get expert tensor info (inline implementation)
    const ExpertTensorInfo* GetExpertTensor(int layer, int expert) const {
        for (const auto& info : expertTensors_) {
            if (info.layerIdx == layer) {
                return &info;
            }
        }
        return nullptr;
    }
    
    // Internal load method
    const void* LoadExpertInternal(int layer, int expert);
    
    #ifdef _WIN32
    void* fileHandle_ = nullptr;  // HANDLE
    void* fileMapping_ = nullptr;
    #else
    int fileHandle_ = -1;
    #endif
    
    void* mappedBase_ = nullptr;
    size_t fileSize_ = 0;
    uint64_t dataOffset_ = 0;
    size_t maxCacheBytes_ = 0;
    size_t currentCacheBytes_ = 0;
    bool isLoaded_ = false;
    
    uint32_t ggufVersion_ = 3;
    uint64_t tensorCount_ = 0;
    uint64_t metadataCount_ = 0;
    
    std::unordered_map<std::string, GGUFTensorInfo> tensors_;
    std::unordered_map<std::string, std::string> metadataStrings_;
    std::unordered_map<std::string, int64_t> metadataInts_;
    std::unordered_map<std::string, double> metadataFloats_;
    std::unordered_map<std::string, std::string> rawMetadata_;
    
    // Expert tensor tracking (ExpertTensorInfo defined above)
    std::vector<ExpertTensorInfo> expertTensors_;
    std::vector<GGUFTensorInfo> allTensors_;
    std::unordered_map<std::string, size_t> expertTensorMap_;
    
    ModelArchitectureInfo archInfo_;
    MoEModelConfig config_;
    
    // Progress tracking
    struct LoadProgress {
        std::atomic<bool> cancelled{false};
        float percent = 0.0f;
        uint64_t totalTensors = 0;
        uint64_t totalBytes = 0;
        uint64_t loadedBytes = 0;
        uint64_t loadedTensors = 0;
        int currentLayer = 0;
        int currentExpert = 0;
        
        void Reset() {
            cancelled.store(false);
            percent = 0.0f;
        }
    };
    LoadProgress progress_;
    std::shared_ptr<MoERouter> router_;
    
    // Memory mapped file (if available)
    void* mappedFile_ = nullptr;
    size_t mappedSize_ = 0;
    
    // Cache
    struct CacheKey {
        int layer;
        int expert;
        bool operator==(const CacheKey& o) const {
            return layer == o.layer && expert == o.expert;
        }
    };
    struct CacheKeyHash {
        size_t operator()(const CacheKey& k) const noexcept {
            return std::hash<int>()(k.layer) ^ (std::hash<int>()(k.expert) << 16);
        }
    };
    struct CachedExpert {
        void* weights = nullptr;
        size_t size = 0;
        size_t weightBytes = 0;  // Alias for size
        std::chrono::steady_clock::time_point lastAccess;
        bool pinned = false;
        bool isPinned = false;  // Alias for pinned
        uint64_t accessCount = 0;
    };
    std::unordered_map<CacheKey, CachedExpert, CacheKeyHash> cache_;
    mutable std::mutex cacheMutex_;
    
    // Stats (public struct declared above)
    mutable Stats stats_;
    mutable std::mutex statsMutex_;
    
    // Cache management
    void EvictLRU(size_t targetBytes = 0);
};

// ============================================================================
// Streaming Loader for Large Models
// ============================================================================
class StreamingMoELoader {
public:
    StreamingMoELoader();
    ~StreamingMoELoader();
    
    // Initialize streaming load
    bool Initialize(const std::string& filepath);
    
    // Load specific layer on-demand
    bool LoadLayer(uint32_t layerIndex, void* buffer, size_t bufferSize);
    
    // Load specific expert on-demand
    bool LoadExpert(uint32_t expertIndex, void* buffer, size_t bufferSize);
    
    // Prefetch layer/expert (async)
    void PrefetchLayer(uint32_t layerIndex);
    void PrefetchExpert(uint32_t expertIndex);
    
    // Get architecture info
    const ModelArchitectureInfo& GetArchitectureInfo() const;
    
    // Check if layer/expert is cached
    bool IsLayerCached(uint32_t layerIndex) const;
    bool IsExpertCached(uint32_t expertIndex) const;
    
    // Get cache stats
    size_t GetCacheSize() const;
    size_t GetCacheHits() const;
    size_t GetCacheMisses() const;
    
    // Clear cache
    void ClearCache();
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

// ============================================================================
// Test Harness
// ============================================================================
class DeepSeekMoETestHarness {
public:
    DeepSeekMoETestHarness();
    ~DeepSeekMoETestHarness();
    
    struct TestResults {
        bool success = false;
        double loadTimeMs = 0.0;
        double avgExpertLoadMs = 0.0;
        size_t cacheHits = 0;
        size_t cacheMisses = 0;
        size_t peakMemoryMB = 0;
        std::string errorMessage;
    };
    
    TestResults RunQuickTest(const char* ggufPath);
    
    static size_t GetPeakMemoryMB();
    static std::vector<float> GenerateRandomEmbedding(size_t hiddenSize);
};

// ============================================================================
// Utility Functions
// ============================================================================

// Get GGML type name
const char* GGMLTypeName(GGMLType type);

// Calculate tensor size in bytes
size_t CalculateTensorSize(const GGUFTensorInfo& info);

// Validate GGUF file integrity
bool ValidateGGUFFile(const std::string& filepath, std::string* error = nullptr);

// Get recommended buffer size for model
size_t GetRecommendedBufferSize(const ModelArchitectureInfo& info);

} // namespace Deep2
