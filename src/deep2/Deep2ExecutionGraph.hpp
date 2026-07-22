// ============================================================================
// Deep2ExecutionGraph.hpp - Compiled Execution Plan
// Eliminates per-op dispatch overhead
// ============================================================================

#pragma once

#include <vector>
#include <memory>
#include <functional>
#include <cstdint>

namespace Deep2 {

// Forward declarations
class DeepSeekMoELoader;
class MoERouter;

// ============================================================================
// Execution Node Types
// ============================================================================
enum class ExecOpType {
    RMSNorm,
    QKV_Proj,
    RoPE,
    Attention,
    MoE_Route,
    Expert_Load,
    Expert_Execute,
    Expert_Combine,
    Residual,
    None
};

// ============================================================================
// Execution Node (compiled, no virtual calls)
// ============================================================================
struct ExecNode {
    ExecOpType type;
    uint32_t layerIdx;
    
    // Function pointer (not std::function - no allocation)
    void (*kernel)(void* ctx, void* input, void* output);
    
    // Context data (pre-allocated)
    void* ctx;
    
    // Input/output buffers (pre-bound)
    void* inputBuffer;
    void* outputBuffer;
    
    // Dependencies (indices into graph.nodes)
    uint32_t deps[4];
    uint8_t numDeps;
    
    // For MoE: which experts
    uint32_t expertIndices[8];
    uint8_t numExperts;
};

// ============================================================================
// Expert Prefetch Request
// ============================================================================
struct PrefetchRequest {
    uint32_t layerIdx;
    uint32_t expertIdx;
    uint32_t priority;  // Higher = load sooner
    bool isPinned;
};

// ============================================================================
// Execution Graph - Pre-compiled, no runtime decisions
// ============================================================================
class Deep2ExecutionGraph {
public:
    Deep2ExecutionGraph();
    ~Deep2ExecutionGraph();
    
    // Build graph for a specific model configuration
    bool Build(const DeepSeekMoELoader& loader, const MoERouter& router);
    
    // Execute entire graph for one token
    // No branching, no allocations, just pointer chasing
    void ExecuteToken(float* hiddenState, uint32_t seqLen);
    
    // Batch execution for higher throughput
    void ExecuteBatch(float* hiddenStates, uint32_t batchSize, uint32_t seqLen);
    
    // Expert prefetching (async)
    void PrefetchExperts(const PrefetchRequest* requests, uint32_t count);
    
    // Get execution stats
    struct Stats {
        uint64_t tokensProcessed;
        uint64_t expertsExecuted;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        double avgTokenLatencyMs;
        double peakThroughputTps;
    };
    Stats GetStats() const;
    void ResetStats();
    
    // Memory management
    size_t GetMemoryUsage() const;
    void CompactMemory();
    
private:
    std::vector<ExecNode> nodes_;
    std::vector<uint32_t> executionOrder_;  // Topologically sorted
    
    // Pre-allocated buffers
    float* activationBuffer_;
    float* expertBuffer_;
    size_t bufferSize_;
    
    // Prefetch thread
    void* prefetchThread_;
    bool prefetchRunning_;
    
    // Stats
    Stats stats_;
    
    // Internal helpers
    void ExecuteNode(const ExecNode& node);
    void* GetBuffer(size_t size);
    void ReleaseBuffer(void* ptr);
};

// ============================================================================
// Expert Residency Manager
// ============================================================================
class ExpertResidencyManager {
public:
    ExpertResidencyManager(DeepSeekMoELoader& loader);
    ~ExpertResidencyManager();
    
    // Initialize with cache size
    bool Initialize(size_t maxCacheBytes);
    
    // Get expert - may trigger load
    const void* GetExpert(uint32_t layer, uint32_t expert);
    
    // Prefetch expert (async)
    void PrefetchExpert(uint32_t layer, uint32_t expert, uint32_t priority);
    
    // Pin expert (don't evict)
    void PinExpert(uint32_t layer, uint32_t expert);
    void UnpinExpert(uint32_t layer, uint32_t expert);
    
    // Eviction policy
    void EvictLRU();
    void EvictByCost();  // Cost model based
    
    // Router lookahead integration
    void OnRouterPrediction(uint32_t layer, const uint32_t* predictedExperts, uint32_t count);
    
    struct ResidencyStats {
        size_t residentExperts;
        size_t pinnedExperts;
        size_t cacheHits;
        size_t cacheMisses;
        size_t prefetchHits;
        size_t bytesUsed;
        size_t bytesTotal;
    };
    ResidencyStats GetStats() const;
    
private:
    DeepSeekMoELoader& loader_;
    
    struct CacheEntry {
        const void* weights;
        size_t weightBytes;
        uint64_t lastAccess;
        uint64_t accessCount;
        bool isPinned;
        bool isPrefetched;
        float costScore;
    };
    
    // Hash map: (layer, expert) -> CacheEntry
    struct Key {
        uint32_t layer;
        uint32_t expert;
        bool operator==(const Key& o) const {
            return layer == o.layer && expert == o.expert;
        }
    };
    struct KeyHash {
        size_t operator()(const Key& k) const {
            return (static_cast<uint64_t>(k.layer) << 32) | k.expert;
        }
    };
    
    std::unordered_map<Key, CacheEntry, KeyHash> cache_;
    mutable std::mutex cacheMutex_;
    
    size_t maxCacheBytes_;
    size_t currentCacheBytes_;
    
    // Prefetch queue
    std::vector<PrefetchRequest> prefetchQueue_;
    std::mutex prefetchMutex_;
    
    // Cost model
    float CalculateCost(const Key& key, const CacheEntry& entry);
};

// ============================================================================
// Token Batch Router
// ============================================================================
class TokenBatchRouter {
public:
    TokenBatchRouter();
    ~TokenBatchRouter();
    
    // Configure batch size
    void SetBatchSize(uint32_t batchSize);
    
    // Add token to batch
    void AddToken(uint32_t tokenId, const float* hiddenState);
    
    // Execute batch when full or flush called
    void Flush();
    
    // Get results
    struct BatchResult {
        uint32_t tokenId;
        float* outputHidden;
        uint32_t selectedExperts[8];
        uint8_t numExperts;
    };
    const std::vector<BatchResult>& GetResults() const;
    
    // Expert bucketing: group tokens by expert
    struct ExpertBucket {
        uint32_t expertIdx;
        std::vector<uint32_t> tokenIndices;
    };
    std::vector<ExpertBucket> BucketByExpert(const std::vector<BatchResult>& results);
    
private:
    uint32_t batchSize_;
    std::vector<uint32_t> tokenIds_;
    std::vector<float*> hiddenStates_;
    std::vector<BatchResult> results_;
    
    void ExecuteBatched();
};

// ============================================================================
// Memory Scheduler
// ============================================================================
class MemoryScheduler {
public:
    MemoryScheduler(ExpertResidencyManager& residency);
    ~MemoryScheduler();
    
    // Predict next required experts based on router output
    void PredictNextExperts(uint32_t currentLayer, const float* routerLogits);
    
    // Schedule loads before compute
    void ScheduleLoads();
    
    // Execute scheduled loads
    void ExecuteLoads();
    
    // Get prediction accuracy
    float GetPredictionAccuracy() const;
    
private:
    ExpertResidencyManager& residency_;
    
    struct Prediction {
        uint32_t layer;
        uint32_t expert;
        float confidence;
        uint64_t predictedAt;
    };
    std::vector<Prediction> predictions_;
    
    uint64_t predictionsCorrect_;
    uint64_t predictionsTotal_;
};

} // namespace Deep2
