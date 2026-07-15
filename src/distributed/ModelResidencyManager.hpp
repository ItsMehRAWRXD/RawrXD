// RawrXD Model Residency Manager
// Phase O.3: Track model locations across cluster, avoid redundant reloads
// Manages model placement and migration in distributed environment

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class ClusterManager;
class DistributedScheduler;

// Model residency state
enum class ResidencyState {
    NOT_LOADED,     // Model not present on node
    LOADING,        // Currently loading
    LOADED,         // Fully loaded and ready
    UNLOADING,      // Currently unloading
    MIGRATING,      // Being migrated to another node
    FAILED          // Failed to load
};

// Model format type
enum class ModelFormat {
    GGML,           // GGML format
    GGUF,           // GGUF format
    ONNX,           // ONNX format
    PYTORCH,        // PyTorch format
    SAFETENSORS,    // SafeTensors format
    CUSTOM          // Custom format
};

// Model quantization type
enum class QuantizationType {
    NONE,           // No quantization (FP32)
    FP16,           // Half precision
    Q8_0,           // 8-bit quantization
    Q6_K,           // 6-bit K-quant
    Q5_K_M,         // 5-bit K-quant medium
    Q5_K_S,         // 5-bit K-quant small
    Q4_K_M,         // 4-bit K-quant medium
    Q4_K_S,         // 4-bit K-quant small
    Q4_0,           // 4-bit legacy
    Q3_K_M,         // 3-bit K-quant medium
    Q3_K_S,         // 3-bit K-quant small
    Q2_K            // 2-bit K-quant
};

// Model information
struct ModelInfo {
    std::string modelId;
    std::string modelName;
    std::string version;
    ModelFormat format;
    QuantizationType quantization;
    
    // Size information
    size_t parameterCount;
    size_t fileSize;            // Original file size
    size_t memorySize;          // Size in memory when loaded
    size_t contextSize;         // Context window size
    
    // Capabilities
    bool supportsGPU;
    bool supportsCPU;
    bool supportsStreaming;
    bool supportsBatching;
    uint32_t maxBatchSize;
    
    // Metadata
    std::string architecture;
    std::string vocabularySize;
    std::map<std::string, std::string> metadata;
    
    // Source
    std::string sourceUrl;
    std::string checksum;
    std::chrono::system_clock::time_point lastUpdated;
    
    ModelInfo() : format(ModelFormat::GGUF), quantization(QuantizationType::Q4_K_M),
                  parameterCount(0), fileSize(0), memorySize(0), contextSize(0),
                  supportsGPU(true), supportsCPU(true), supportsStreaming(true),
                  supportsBatching(true), maxBatchSize(1) {}
};

// Model residency on a specific node
struct ModelResidency {
    std::string modelId;
    std::string nodeId;
    ResidencyState state;
    
    // Timing
    std::chrono::steady_clock::time_point loadedAt;
    std::chrono::steady_clock::time_point lastUsedAt;
    std::chrono::steady_clock::time_point lastAccessedAt;
    
    // Usage statistics
    uint64_t requestCount;
    uint64_t tokenCount;
    uint64_t totalInferenceTimeMs;
    
    // Memory tracking
    size_t actualMemoryUsage;
    size_t kvCacheUsage;
    
    // Loading progress (0-100)
    uint8_t loadingProgress;
    
    ModelResidency() : state(ResidencyState::NOT_LOADED), requestCount(0),
                       tokenCount(0), totalInferenceTimeMs(0), actualMemoryUsage(0),
                       kvCacheUsage(0), loadingProgress(0) {}
};

// Node model capacity
struct NodeCapacity {
    std::string nodeId;
    size_t totalVRAM;
    size_t availableVRAM;
    size_t totalRAM;
    size_t availableRAM;
    
    // Model limits
    uint32_t maxConcurrentModels;
    uint32_t currentLoadedModels;
    
    // Performance metrics
    float avgLoadTimeMs;
    float avgInferenceLatencyMs;
};

// Placement strategy
enum class PlacementStrategy {
    MOST_LOADED,        // Place on node with most available resources
    LEAST_LOADED,       // Place on node with least load
    AFFINITY,           // Place near data/request sources
    ROUND_ROBIN,        // Distribute evenly
    HOT_SPARE,          // Keep hot models on multiple nodes
    PREDICTIVE          // Predict and pre-load based on patterns
};

// Residency manager configuration
struct ResidencyConfig {
    PlacementStrategy defaultStrategy = PlacementStrategy::AFFINITY;
    
    // Caching policies
    bool enableLRU = true;
    uint32_t lruMaxAgeMinutes = 60;
    
    // Preloading
    bool enablePredictiveLoading = true;
    uint32_t predictionWindowMinutes = 10;
    
    // Migration
    bool enableAutoMigration = true;
    float migrationThreshold = 0.8f;  // Trigger if node > 80% capacity
    
    // Replication
    uint32_t minReplicas = 1;
    uint32_t maxReplicas = 3;
    bool replicateHotModels = true;
    uint32_t hotModelThreshold = 100;  // Requests per minute
    
    // Cleanup
    bool autoUnloadUnused = true;
    uint32_t unloadAfterIdleMinutes = 30;
    
    // Memory pressure
    float memoryPressureThreshold = 0.9f;
    bool aggressiveCleanupUnderPressure = true;
};

// Model placement decision
struct PlacementDecision {
    std::string modelId;
    std::string targetNodeId;
    bool shouldLoad;
    bool shouldMigrate;
    std::string sourceNodeId;  // For migration
    std::string reason;
    
    // Alternative placements
    std::vector<std::string> alternativeNodes;
    
    // Estimated metrics
    uint32_t estimatedLoadTimeMs;
    size_t estimatedMemoryUsage;
};

// Migration task
struct MigrationTask {
    std::string taskId;
    std::string modelId;
    std::string sourceNodeId;
    std::string targetNodeId;
    
    enum class Status {
        PENDING,
        IN_PROGRESS,
        COPYING,
        VERIFYING,
        COMPLETED,
        FAILED
    } status;
    
    uint8_t progress;
    std::string errorMessage;
    
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point completedAt;
};

// Access pattern for predictive loading
struct AccessPattern {
    std::string modelId;
    std::vector<std::chrono::system_clock::time_point> accessTimes;
    std::map<std::string, uint64_t> accessByHour;  // Hour -> count
    std::map<uint8_t, uint64_t> accessByDayOfWeek; // Day -> count
    float predictedNextAccessMinutes;
    float confidence;
};

// Residency change callback
using ResidencyChangeCallback = std::function<void(const std::string& modelId, 
                                                     const std::string& nodeId,
                                                     ResidencyState oldState,
                                                     ResidencyState newState)>;

// Model Residency Manager class
class ModelResidencyManager {
public:
    ModelResidencyManager(std::shared_ptr<ClusterManager> clusterManager);
    ~ModelResidencyManager();
    
    // Initialization
    bool initialize(const ResidencyConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Model registration
    bool registerModel(const ModelInfo& modelInfo);
    bool unregisterModel(const std::string& modelId);
    bool updateModelInfo(const std::string& modelId, const ModelInfo& info);
    
    // Model catalog
    std::vector<ModelInfo> getRegisteredModels() const;
    ModelInfo getModelInfo(const std::string& modelId) const;
    bool isModelRegistered(const std::string& modelId) const;
    
    // Residency queries
    std::vector<ModelResidency> getResidencies(const std::string& modelId) const;
    std::vector<ModelResidency> getResidenciesOnNode(const std::string& nodeId) const;
    ModelResidency getResidency(const std::string& modelId, const std::string& nodeId) const;
    
    // Placement decisions
    PlacementDecision decidePlacement(const std::string& modelId, 
                                       const std::vector<std::string>& candidateNodes);
    std::vector<std::string> findNodesWithModel(const std::string& modelId) const;
    std::vector<std::string> findNodesWithoutModel(const std::string& modelId) const;
    std::string findBestNodeForModel(const std::string& modelId) const;
    
    // Residency management
    bool requestModelLoad(const std::string& modelId, const std::string& nodeId);
    bool requestModelUnload(const std::string& modelId, const std::string& nodeId);
    bool updateResidencyState(const std::string& modelId, const std::string& nodeId,
                               ResidencyState state);
    bool recordModelAccess(const std::string& modelId, const std::string& nodeId,
                           uint64_t tokens, uint64_t inferenceTimeMs);
    
    // Migration
    std::string startMigration(const std::string& modelId, 
                               const std::string& sourceNodeId,
                               const std::string& targetNodeId);
    bool cancelMigration(const std::string& taskId);
    MigrationTask getMigrationStatus(const std::string& taskId) const;
    std::vector<MigrationTask> getActiveMigrations() const;
    
    // Preloading
    std::vector<std::string> getPreloadRecommendations() const;
    bool preloadModel(const std::string& modelId, const std::string& nodeId);
    
    // Replication
    bool replicateModel(const std::string& modelId, uint32_t targetReplicas);
    bool ensureReplication(const std::string& modelId);
    
    // Cleanup
    std::vector<std::string> getUnloadRecommendations() const;
    bool unloadUnusedModels();
    bool handleMemoryPressure(const std::string& nodeId);
    
    // Statistics
    struct ResidencyStats {
        uint64_t totalModelsRegistered;
        uint64_t totalResidencies;
        uint64_t totalMigrations;
        uint64_t totalPreloads;
        uint64_t totalEvictions;
        
        double avgLoadTimeMs;
        double avgMigrationTimeMs;
        
        std::map<std::string, uint64_t> requestsByModel;
        std::map<std::string, size_t> memoryByModel;
        std::map<std::string, uint32_t> replicasByModel;
    };
    ResidencyStats getStats() const;
    void resetStats();
    
    // Configuration
    ResidencyConfig getConfig() const { return config_; }
    bool updateConfig(const ResidencyConfig& config);
    
    // Callbacks
    void setResidencyChangeCallback(ResidencyChangeCallback callback);
    
    // Capacity planning
    std::vector<std::string> getOverloadedNodes() const;
    std::vector<std::string> getUnderutilizedNodes() const;
    bool canNodeAcceptModel(const std::string& nodeId, const std::string& modelId) const;
    
private:
    // Internal methods
    void residencyLoop();
    void migrationLoop();
    void predictiveLoop();
    
    void updateAccessPattern(const std::string& modelId);
    float calculateAffinityScore(const std::string& modelId, const std::string& nodeId);
    float calculateLoadScore(const std::string& nodeId);
    
    std::string generateTaskId();
    void cleanupCompletedMigrations();
    void notifyResidencyChange(const std::string& modelId, const std::string& nodeId,
                                ResidencyState oldState, ResidencyState newState);
    
    // Threading
    std::atomic<bool> running_;
    std::thread residencyThread_;
    std::thread migrationThread_;
    std::thread predictiveThread_;
    mutable std::mutex modelsMutex_;
    mutable std::mutex residenciesMutex_;
    mutable std::mutex migrationsMutex_;
    
    // State
    std::atomic<bool> initialized_;
    ResidencyConfig config_;
    
    // Data
    std::map<std::string, ModelInfo> registeredModels_;
    std::map<std::string, std::map<std::string, ModelResidency>> residencies_;  // modelId -> nodeId -> residency
    std::map<std::string, MigrationTask> migrations_;
    std::map<std::string, AccessPattern> accessPatterns_;
    
    // Callbacks
    ResidencyChangeCallback residencyCallback_;
    mutable std::mutex callbackMutex_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> totalMigrations{0};
        std::atomic<uint64_t> totalPreloads{0};
        std::atomic<uint64_t> totalEvictions{0};
        std::atomic<double> totalLoadTimeMs{0.0};
        std::atomic<double> totalMigrationTimeMs{0.0};
        std::atomic<uint64_t> loadCount{0};
        std::atomic<uint64_t> migrationCount{0};
    } stats_;
    
    // Dependencies
    std::shared_ptr<ClusterManager> clusterManager_;
    std::shared_ptr<DistributedScheduler> scheduler_;
    
    // Task ID counter
    std::atomic<uint64_t> taskIdCounter_{0};
};

// Hot model tracker for replication decisions
class HotModelTracker {
public:
    HotModelTracker(uint32_t windowSeconds = 300);
    
    void recordAccess(const std::string& modelId);
    uint64_t getAccessCount(const std::string& modelId) const;
    float getAccessRate(const std::string& modelId) const;  // Accesses per minute
    std::vector<std::string> getHotModels(uint32_t threshold) const;
    std::vector<std::pair<std::string, float>> getRankedModels() const;
    
    void clear();
    void cleanupOldEntries();
    
private:
    struct AccessEntry {
        std::chrono::steady_clock::time_point timestamp;
    };
    
    uint32_t windowSeconds_;
    std::map<std::string, std::vector<AccessEntry>> accessLog_;
    mutable std::mutex mutex_;
};

} // namespace Distributed
} // namespace RawrXD
