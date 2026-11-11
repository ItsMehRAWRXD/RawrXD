// RawrXD Model Sharding Manager
// Phase O.3: Split large models across multiple nodes for distributed inference
// Enables inference on models larger than single node memory

#pragma once

#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class ClusterManager;
class ModelResidencyManager;

// Shard placement strategy
enum class ShardStrategy {
    LAYER_WISE,         // Each node holds complete layers
    TENSOR_PARALLEL,    // Split tensors across nodes (Megatron-style)
    PIPELINE_PARALLEL,  // Pipeline stages across nodes
    SEQUENCE_PARALLEL,  // Split sequence dimension
    HYBRID              // Combination of above
};

// Shard information
struct ModelShard {
    std::string shardId;
    std::string modelId;
    uint32_t shardIndex;        // Index in sequence
    uint32_t totalShards;       // Total number of shards
    
    // Content
    uint32_t startLayer;        // Start layer index
    uint32_t endLayer;          // End layer index (inclusive)
    std::vector<uint32_t> tensorIndices;  // For tensor parallelism
    
    // Placement
    std::string primaryNodeId;
    std::vector<std::string> replicaNodes;
    
    // Size
    size_t memorySize;
    size_t parameterCount;
    
    // Status
    enum class Status {
        UNLOADED,
        LOADING,
        LOADED,
        ACTIVE,
        FAILED
    } status;
    
    // Timing
    std::chrono::steady_clock::time_point loadedAt;
    std::chrono::steady_clock::time_point lastAccessedAt;
    
    ModelShard() : shardIndex(0), totalShards(0), startLayer(0), endLayer(0),
                   memorySize(0), parameterCount(0), status(Status::UNLOADED) {}
};

// Sharding configuration
struct ShardingConfig {
    ShardStrategy strategy = ShardStrategy::LAYER_WISE;
    
    // Layer-wise sharding
    uint32_t layersPerShard = 4;
    bool shardAttentionSeparately = true;
    
    // Tensor parallelism
    uint32_t tensorParallelDegree = 2;  // Number of nodes for tensor parallelism
    
    // Pipeline parallelism
    uint32_t pipelineStages = 2;
    uint32_t microBatchSize = 1;
    
    // Sequence parallelism
    uint32_t sequenceChunks = 2;
    
    // Hybrid
    std::vector<ShardStrategy> hybridStages;
    
    // Memory constraints
    size_t maxShardSize = 8ULL * 1024 * 1024 * 1024;  // 8GB default
    float memoryOverhead = 0.1f;  // 10% overhead for activations
    
    // Replication
    uint32_t minReplicasPerShard = 1;
    uint32_t maxReplicasPerShard = 2;
};

// Shard placement decision
struct ShardPlacement {
    std::string shardId;
    std::string primaryNodeId;
    std::vector<std::string> replicaNodes;
    bool canPlace;
    std::string reason;
    
    // Estimated metrics
    uint32_t estimatedLoadTimeMs;
    size_t estimatedMemoryUsage;
    float estimatedThroughput;
};

// Distributed inference request
struct ShardedInferenceRequest {
    std::string requestId;
    std::string modelId;
    
    // Input
    std::vector<uint8_t> inputTokens;
    uint32_t sequenceLength;
    uint32_t batchSize;
    
    // Sharding info
    std::vector<std::string> involvedShards;
    std::vector<std::string> involvedNodes;
    
    // Execution plan
    enum class ExecutionMode {
        SEQUENTIAL,     // Pipeline-style
        PARALLEL,       // Tensor-parallel
        HYBRID
    } executionMode;
    
    // Timing
    std::chrono::steady_clock::time_point submittedAt;
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point completedAt;
};

// Shard communication pattern
struct ShardCommunication {
    std::string fromShardId;
    std::string toShardId;
    std::string fromNodeId;
    std::string toNodeId;
    size_t dataSize;
    
    enum class CommType {
        ACTIVATIONS,    // Forward pass activations
        GRADIENTS,      // Backward pass gradients
        WEIGHTS,        // Weight updates
        KV_CACHE        // KV cache exchange
    } type;
};

// Model Sharding Manager class
class ModelShardingManager {
public:
    ModelShardingManager(std::shared_ptr<ClusterManager> clusterManager,
                         std::shared_ptr<ModelResidencyManager> residencyManager);
    ~ModelShardingManager();
    
    // Initialization
    bool initialize(const ShardingConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Model sharding
    bool shardModel(const std::string& modelId, const ShardingConfig& config);
    bool unshardModel(const std::string& modelId);
    bool isModelSharded(const std::string& modelId) const;
    
    // Shard management
    std::vector<ModelShard> getShards(const std::string& modelId) const;
    ModelShard getShard(const std::string& shardId) const;
    std::vector<ModelShard> getShardsOnNode(const std::string& nodeId) const;
    
    // Placement
    ShardPlacement decidePlacement(const ModelShard& shard, 
                                    const std::vector<std::string>& candidateNodes);
    bool placeShard(const std::string& shardId, const std::string& nodeId);
    bool migrateShard(const std::string& shardId, const std::string& fromNodeId,
                      const std::string& toNodeId);
    bool removeShard(const std::string& shardId);
    
    // Replication
    bool replicateShard(const std::string& shardId, uint32_t replicaCount);
    bool ensureShardReplication(const std::string& shardId);
    
    // Inference
    bool canExecuteSharded(const std::string& modelId, uint32_t sequenceLength,
                            uint32_t batchSize) const;
    ShardedInferenceRequest createInferenceRequest(const std::string& modelId,
                                                    const std::vector<uint8_t>& input);
    std::vector<ShardCommunication> getCommunicationPattern(
        const ShardedInferenceRequest& request) const;
    
    // Load balancing
    bool rebalanceShards();
    std::vector<std::string> getOverloadedNodes() const;
    std::vector<std::string> getUnderloadedNodes() const;
    
    // Statistics
    struct ShardingStats {
        uint64_t totalModelsSharded;
        uint64_t totalShards;
        uint64_t activeShards;
        uint64_t failedShards;
        
        uint64_t shardedInferences;
        double avgShardedLatencyMs;
        double avgCommunicationOverheadMs;
        
        size_t totalShardedMemory;
        size_t maxShardSize;
        
        std::map<std::string, uint64_t> inferencesByModel;
        std::map<ShardStrategy, uint64_t> inferencesByStrategy;
    };
    ShardingStats getStats() const;
    void resetStats();
    
    // Configuration
    ShardingConfig getConfig() const { return config_; }
    bool updateConfig(const ShardingConfig& config);
    
private:
    // Internal methods
    void shardingLoop();
    void rebalancingLoop();
    
    std::vector<ModelShard> createLayerWiseShards(const std::string& modelId,
                                                     uint32_t totalLayers);
    std::vector<ModelShard> createTensorParallelShards(const std::string& modelId,
                                                         uint32_t totalLayers);
    std::vector<ModelShard> createPipelineShards(const std::string& modelId,
                                                    uint32_t totalLayers);
    
    std::string generateShardId(const std::string& modelId, uint32_t index);
    void updateShardStats(const std::string& shardId, bool success);
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread shardingThread_;
    std::thread rebalancingThread_;
    mutable std::mutex shardsMutex_;
    
    // State
    ShardingConfig config_;
    std::map<std::string, std::vector<ModelShard>> modelShards_;  // modelId -> shards
    std::map<std::string, ModelShard> shardMap_;  // shardId -> shard
    
    // Dependencies
    std::shared_ptr<ClusterManager> clusterManager_;
    std::shared_ptr<ModelResidencyManager> residencyManager_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> totalModelsSharded{0};
        std::atomic<uint64_t> totalShards{0};
        std::atomic<uint64_t> activeShards{0};
        std::atomic<uint64_t> failedShards{0};
        std::atomic<uint64_t> shardedInferences{0};
        std::atomic<double> totalShardedLatencyMs{0.0};
        std::atomic<double> totalCommunicationOverheadMs{0.0};
    } stats_;
    
    // Shard ID counter
    std::atomic<uint64_t> shardIdCounter_{0};
};

// Pipeline executor for pipeline parallelism
class PipelineExecutor {
public:
    PipelineExecutor(std::shared_ptr<ModelShardingManager> shardingManager);
    
    // Pipeline execution
    bool executePipeline(const ShardedInferenceRequest& request);
    bool executeMicroBatch(const std::vector<ShardedInferenceRequest>& microBatches);
    
    // Pipeline scheduling
    std::vector<std::vector<ShardedInferenceRequest>> createMicroBatches(
        const std::vector<ShardedInferenceRequest>& requests, uint32_t microBatchSize);
    
    // Bubble optimization
    float calculateBubbleOverhead(uint32_t numStages, uint32_t microBatchSize) const;
    uint32_t optimalMicroBatchSize(uint32_t numStages, uint32_t totalBatchSize) const;
    
private:
    std::shared_ptr<ModelShardingManager> shardingManager_;
};

// Tensor parallel executor
class TensorParallelExecutor {
public:
    TensorParallelExecutor(std::shared_ptr<ModelShardingManager> shardingManager);
    
    // All-reduce operations
    bool allReduceActivations(std::vector<std::vector<uint8_t>>& shardActivations);
    bool allGatherGradients(std::vector<std::vector<uint8_t>>& shardGradients);
    
    // Execution
    bool executeTensorParallel(const ShardedInferenceRequest& request);
    
private:
    std::shared_ptr<ModelShardingManager> shardingManager_;
};

} // namespace Distributed
} // namespace RawrXD
