// RawrXD Distributed Runtime
// Phase O: Complete distributed system integration
// Orchestrates cluster manager, scheduler, model residency, and KV cache

#pragma once

#include <memory>
#include <vector>
#include <map>
#include <string>
#include <functional>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class ClusterManager;
class DistributedScheduler;
class ModelResidencyManager;
class DistributedKVCache;
class DistributedBenchmark;
class WorkStealingScheduler;
class PriorityTaskQueue;
class ModelShardingManager;
class CachePrefetchEngine;

// Distributed runtime configuration
struct DistributedRuntimeConfig {
    // Cluster
    std::string nodeId;
    std::string listenAddress;
    uint32_t listenPort;
    std::vector<std::string> seedNodes;
    
    // Resources
    size_t totalVRAM;
    size_t totalRAM;
    uint32_t cpuCores;
    uint32_t gpuCount;
    uint32_t capabilities;
    
    // Feature toggles
    bool enableWorkStealing = true;
    bool enablePriorityScheduling = true;
    bool enableModelSharding = true;
    bool enablePrefetching = true;
    bool enableBenchmarking = true;
    
    // Performance
    uint32_t workerThreads = 8;
    uint32_t ioThreads = 4;
    uint32_t maxConcurrentRequests = 1000;
};

// Runtime status
struct RuntimeStatus {
    bool isHealthy;
    bool isLeader;
    std::string leaderNodeId;
    
    // Cluster
    uint32_t totalNodes;
    uint32_t healthyNodes;
    uint32_t unhealthyNodes;
    
    // Resources
    size_t totalVRAM;
    size_t availableVRAM;
    size_t totalRAM;
    size_t availableRAM;
    
    // Performance
    double requestsPerSecond;
    double avgLatencyMs;
    double cacheHitRate;
    
    // Queue depths
    uint32_t schedulerQueueDepth;
    uint32_t priorityQueueDepth;
    uint32_t workStealingQueueDepth;
    
    // Models
    uint32_t loadedModels;
    uint32_t shardedModels;
    
    // Errors
    uint32_t failedRequests;
    uint32_t timeoutRequests;
};

// Inference request
struct DistributedInferenceRequest {
    std::string requestId;
    std::string modelId;
    std::string sessionId;
    
    // Input
    std::vector<uint8_t> inputTokens;
    uint32_t maxCompletionTokens;
    float temperature;
    float topP;
    
    // Scheduling
    enum class Priority {
        CRITICAL,
        HIGH,
        NORMAL,
        LOW,
        BACKGROUND
    } priority;
    
    // Constraints
    uint32_t timeoutMs;
    uint32_t maxRetries;
    bool allowSharded;
    bool requireGPU;
    
    // Callbacks
    std::function<void(const std::vector<uint8_t>&)> onToken;
    std::function<void(bool, const std::string&)> onComplete;
};

// Inference response
struct DistributedInferenceResponse {
    std::string requestId;
    bool success;
    std::string errorMessage;
    
    // Output
    std::vector<uint8_t> outputTokens;
    uint32_t tokensGenerated;
    uint32_t tokensPerSecond;
    
    // Timing
    uint32_t queueTimeMs;
    uint32_t executionTimeMs;
    uint32_t totalTimeMs;
    
    // Execution info
    std::string executedOnNode;
    bool usedShardedModel;
    bool wasPrefetched;
};

// Distributed Runtime - Main orchestrator
class DistributedRuntime {
public:
    DistributedRuntime();
    ~DistributedRuntime();
    
    // Lifecycle
    bool initialize(const DistributedRuntimeConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    bool isHealthy() const;
    
    // Configuration
    DistributedRuntimeConfig getConfig() const { return config_; }
    bool updateConfig(const DistributedRuntimeConfig& config);
    
    // Status
    RuntimeStatus getStatus() const;
    std::string getStatusJson() const;
    
    // Inference
    std::string submitInference(const DistributedInferenceRequest& request);
    bool cancelInference(const std::string& requestId);
    DistributedInferenceResponse getInferenceResult(const std::string& requestId);
    
    // Model management
    bool loadModel(const std::string& modelId);
    bool unloadModel(const std::string& modelId);
    bool shardModel(const std::string& modelId);
    bool unshardModel(const std::string& modelId);
    std::vector<std::string> getLoadedModels() const;
    
    // Session management
    std::string createSession(const std::string& modelId);
    bool destroySession(const std::string& sessionId);
    bool extendSession(const std::string& sessionId, uint32_t ttlSeconds);
    
    // Cluster operations
    bool joinCluster(const std::vector<std::string>& seedNodes);
    bool leaveCluster();
    std::vector<std::string> getClusterNodes() const;
    bool isLeader() const;
    
    // Load balancing
    void triggerRebalancing();
    bool migrateModel(const std::string& modelId, const std::string& fromNode, 
                      const std::string& toNode);
    
    // Benchmarking
    std::string startBenchmark(const std::string& benchmarkType);
    bool stopBenchmark(const std::string& benchmarkId);
    std::string getBenchmarkReport(const std::string& benchmarkId);
    
    // Statistics
    struct RuntimeStats {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        uint64_t cancelledRequests;
        
        double avgLatencyMs;
        double p99LatencyMs;
        double throughput;
        
        uint64_t cacheHits;
        uint64_t cacheMisses;
        double cacheHitRate;
        
        uint64_t modelsLoaded;
        uint64_t modelsSharded;
        uint64_t activeSessions;
        
        std::map<std::string, double> latencyByModel;
        std::map<std::string, uint64_t> requestsByModel;
    };
    RuntimeStats getStats() const;
    void resetStats();
    
    // Event callbacks
    using RuntimeEventCallback = std::function<void(const std::string& eventType, 
                                                     const std::map<std::string, std::string>& data)>;
    void setEventCallback(RuntimeEventCallback callback);
    
    // Component access (for advanced usage)
    std::shared_ptr<ClusterManager> getClusterManager() { return clusterManager_; }
    std::shared_ptr<DistributedScheduler> getScheduler() { return scheduler_; }
    std::shared_ptr<ModelResidencyManager> getResidencyManager() { return residencyManager_; }
    std::shared_ptr<DistributedKVCache> getKVCache() { return kvCache_; }
    std::shared_ptr<DistributedBenchmark> getBenchmark() { return benchmark_; }
    
private:
    // Internal methods
    void runtimeLoop();
    void healthCheckLoop();
    void notifyEvent(const std::string& eventType, 
                     const std::map<std::string, std::string>& data);
    
    std::string generateRequestId();
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread runtimeThread_;
    std::thread healthThread_;
    mutable std::mutex mutex_;
    
    // Configuration
    DistributedRuntimeConfig config_;
    
    // Components
    std::shared_ptr<ClusterManager> clusterManager_;
    std::shared_ptr<DistributedScheduler> scheduler_;
    std::shared_ptr<ModelResidencyManager> residencyManager_;
    std::shared_ptr<DistributedKVCache> kvCache_;
    std::shared_ptr<DistributedBenchmark> benchmark_;
    std::shared_ptr<WorkStealingScheduler> workStealingScheduler_;
    std::shared_ptr<PriorityTaskQueue> priorityQueue_;
    std::shared_ptr<ModelShardingManager> shardingManager_;
    std::shared_ptr<CachePrefetchEngine> prefetchEngine_;
    
    // Request tracking
    std::map<std::string, DistributedInferenceRequest> activeRequests_;
    std::map<std::string, DistributedInferenceResponse> completedResponses_;
    
    // Callbacks
    RuntimeEventCallback eventCallback_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> totalRequests{0};
        std::atomic<uint64_t> successfulRequests{0};
        std::atomic<uint64_t> failedRequests{0};
        std::atomic<uint64_t> cancelledRequests{0};
        std::atomic<double> totalLatencyMs{0.0};
        std::atomic<uint64_t> latencyCount{0};
    } stats_;
    
    // Request ID counter
    std::atomic<uint64_t> requestIdCounter_{0};
};

// Distributed runtime factory
class DistributedRuntimeFactory {
public:
    static std::unique_ptr<DistributedRuntime> create(
        const DistributedRuntimeConfig& config);
    
    static DistributedRuntimeConfig createDefaultConfig();
    static DistributedRuntimeConfig createSingleNodeConfig();
    static DistributedRuntimeConfig createClusterConfig(const std::vector<std::string>& seedNodes);
};

// Global runtime instance (optional singleton)
class DistributedRuntimeSingleton {
public:
    static DistributedRuntime& instance();
    static bool initialize(const DistributedRuntimeConfig& config);
    static bool shutdown();
    static bool isInitialized();
    
private:
    static std::unique_ptr<DistributedRuntime> instance_;
    static std::mutex mutex_;
};

} // namespace Distributed
} // namespace RawrXD
