// RawrXD Distributed KV Cache
// Phase O.4: Shared KV cache across cluster nodes
// Enables distributed attention computation and memory pooling

#pragma once

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

// KV cache entry state
enum class KVCacheEntryState {
    LOCAL,          // Only on local node
    REPLICATING,    // Being replicated to other nodes
    REPLICATED,     // Available on multiple nodes
    MIGRATING,      // Being moved to another node
    EVICTED,        // Removed from cache
    EXPIRED         // TTL expired
};

// Cache key for KV entries
struct KVCacheKey {
    std::string modelId;
    std::string sessionId;
    uint32_t layerId;
    uint32_t sequencePosition;
    
    bool operator<(const KVCacheKey& other) const {
        if (modelId != other.modelId) return modelId < other.modelId;
        if (sessionId != other.sessionId) return sessionId < other.sessionId;
        if (layerId != other.layerId) return layerId < other.layerId;
        return sequencePosition < other.sequencePosition;
    }
    
    bool operator==(const KVCacheKey& other) const {
        return modelId == other.modelId && 
               sessionId == other.sessionId &&
               layerId == other.layerId &&
               sequencePosition == other.sequencePosition;
    }
};

// KV cache entry metadata
struct KVCacheEntry {
    KVCacheKey key;
    std::string nodeId;         // Primary node
    std::set<std::string> replicaNodes;  // Nodes with replicas
    KVCacheEntryState state;
    
    // Memory info
    size_t keySize;             // Size of K cache
    size_t valueSize;           // Size of V cache
    size_t totalSize;           // Total memory usage
    
    // Timing
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point lastAccessedAt;
    std::chrono::steady_clock::time_point expiresAt;
    
    // Access stats
    uint64_t accessCount;
    uint64_t hitCount;
    uint64_t missCount;
    
    // Consistency
    uint64_t version;           // Version for consistency
    bool isDirty;               // Pending updates
    
    KVCacheEntry() : state(KVCacheEntryState::LOCAL), keySize(0), valueSize(0),
                     totalSize(0), accessCount(0), hitCount(0), missCount(0),
                     version(0), isDirty(false) {}
};

// Cache statistics for a node
struct NodeCacheStats {
    std::string nodeId;
    size_t totalCapacity;
    size_t usedCapacity;
    size_t availableCapacity;
    
    uint64_t entryCount;
    uint64_t hitCount;
    uint64_t missCount;
    double hitRate;
    
    uint64_t evictionCount;
    uint64_t replicationCount;
    uint64_t migrationCount;
    
    double avgAccessLatencyMs;
    double avgReplicationLatencyMs;
};

// Distributed cache configuration
struct DistributedCacheConfig {
    // Capacity
    size_t maxMemoryPerNode;        // Max memory per node
    size_t globalMaxMemory;         // Global memory limit
    
    // TTL settings
    uint32_t defaultTTLSeconds = 3600;      // 1 hour default
    uint32_t maxTTLSeconds = 86400;         // 24 hour max
    bool enableTTL = true;
    
    // Replication
    uint32_t defaultReplicationFactor = 2;
    uint32_t maxReplicationFactor = 3;
    bool enableReplication = true;
    
    // Eviction policy
    enum class EvictionPolicy {
        LRU,        // Least Recently Used
        LFU,        // Least Frequently Used
        FIFO,       // First In First Out
        RANDOM,     // Random eviction
        ADAPTIVE    // Adaptive based on access patterns
    } evictionPolicy = EvictionPolicy::LRU;
    
    float evictionThreshold = 0.9f;     // Start evicting at 90% capacity
    
    // Consistency
    enum class ConsistencyLevel {
        EVENTUAL,   // Eventual consistency
        SESSION,    // Session-level consistency
        STRICT      // Strict consistency (slower)
    } consistencyLevel = ConsistencyLevel::SESSION;
    
    // Prefetching
    bool enablePrefetch = true;
    uint32_t prefetchDistance = 128;   // Tokens ahead to prefetch
    
    // Compression
    bool enableCompression = false;
    float compressionThreshold = 0.8f;  // Compress if ratio > 0.8
};

// Cache operation result
struct CacheResult {
    bool success;
    std::string errorMessage;
    std::string nodeId;         // Node that served the request
    bool isLocal;               // Served from local cache
    bool isReplica;             // Served from replica
    uint64_t latencyUs;         // Microseconds
    size_t bytesTransferred;
};

// Prefetch request
struct PrefetchRequest {
    KVCacheKey startKey;
    uint32_t count;             // Number of entries to prefetch
    std::string targetNodeId;
    uint32_t priority;          // Prefetch priority
};

// Cache invalidation message
struct InvalidationMessage {
    std::vector<KVCacheKey> keys;
    std::string sourceNodeId;
    uint64_t timestamp;
    bool invalidateAll;         // Invalidate all entries for model/session
};

// Cache sync message
struct SyncMessage {
    std::string sourceNodeId;
    std::string targetNodeId;
    std::vector<KVCacheKey> keys;
    uint64_t version;
};

// Distributed KV Cache Manager class
class DistributedKVCache {
public:
    DistributedKVCache(std::shared_ptr<ClusterManager> clusterManager);
    ~DistributedKVCache();
    
    // Initialization
    bool initialize(const DistributedCacheConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Local cache operations
    CacheResult get(const KVCacheKey& key, std::vector<uint8_t>& data);
    CacheResult put(const KVCacheKey& key, const std::vector<uint8_t>& data);
    CacheResult update(const KVCacheKey& key, const std::vector<uint8_t>& data);
    CacheResult remove(const KVCacheKey& key);
    bool contains(const KVCacheKey& key) const;
    
    // Distributed operations
    CacheResult getDistributed(const KVCacheKey& key, std::vector<uint8_t>& data);
    CacheResult putDistributed(const KVCacheKey& key, const std::vector<uint8_t>& data);
    CacheResult replicateEntry(const KVCacheKey& key, const std::string& targetNodeId);
    CacheResult migrateEntry(const KVCacheKey& key, const std::string& targetNodeId);
    
    // Batch operations
    std::vector<CacheResult> getBatch(const std::vector<KVCacheKey>& keys);
    std::vector<CacheResult> putBatch(const std::vector<std::pair<KVCacheKey, std::vector<uint8_t>>>& entries);
    
    // Prefetching
    bool prefetch(const PrefetchRequest& request);
    bool prefetchForSession(const std::string& sessionId, uint32_t upToPosition);
    void cancelPrefetch(const std::string& sessionId);
    
    // Session management
    bool createSession(const std::string& sessionId, const std::string& modelId);
    bool destroySession(const std::string& sessionId);
    bool invalidateSession(const std::string& sessionId);
    std::vector<KVCacheKey> getSessionKeys(const std::string& sessionId) const;
    
    // Model cache management
    bool invalidateModel(const std::string& modelId);
    size_t getModelCacheSize(const std::string& modelId) const;
    
    // Replication
    bool setReplicationFactor(const KVCacheKey& key, uint32_t factor);
    bool replicateToNode(const std::string& nodeId);
    std::vector<std::string> getReplicaNodes(const KVCacheKey& key) const;
    
    // Consistency
    bool syncWithNode(const std::string& nodeId);
    bool invalidateOnNode(const std::string& nodeId, const InvalidationMessage& msg);
    bool handleSyncMessage(const SyncMessage& msg);
    
    // Eviction
    size_t evictExpired();
    size_t evictLRU(size_t targetBytes);
    size_t evictForModel(const std::string& modelId);
    void clear();
    
    // Statistics
    NodeCacheStats getLocalStats() const;
    std::vector<NodeCacheStats> getClusterStats() const;
    NodeCacheStats getNodeStats(const std::string& nodeId) const;
    
    // Global stats
    struct GlobalCacheStats {
        size_t totalCapacity;
        size_t totalUsed;
        size_t totalAvailable;
        uint64_t totalEntries;
        double globalHitRate;
        uint64_t totalReplications;
        uint64_t totalMigrations;
        uint64_t totalEvictions;
    };
    GlobalCacheStats getGlobalStats() const;
    
    // Configuration
    DistributedCacheConfig getConfig() const { return config_; }
    bool updateConfig(const DistributedCacheConfig& config);
    
    // Memory pressure handling
    bool handleMemoryPressure();
    float getMemoryPressure() const;
    bool isUnderPressure() const;
    
    // Entry queries
    std::vector<KVCacheKey> getAllKeys() const;
    std::vector<KVCacheKey> getKeysForModel(const std::string& modelId) const;
    std::vector<KVCacheKey> getKeysForSession(const std::string& sessionId) const;
    KVCacheEntry getEntryInfo(const KVCacheKey& key) const;
    
private:
    // Internal methods
    void cacheLoop();
    void replicationLoop();
    void prefetchLoop();
    
    void evictIfNeeded();
    std::vector<KVCacheKey> selectEvictionCandidates(size_t targetBytes);
    
    bool shouldReplicate(const KVCacheKey& key);
    bool shouldMigrate(const KVCacheKey& key);
    std::string selectReplicationTarget(const KVCacheKey& key);
    
    void updateAccessStats(const KVCacheKey& key);
    void updateHitRate();
    
    std::vector<uint8_t> compressData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decompressData(const std::vector<uint8_t>& data);
    
    // Threading
    std::atomic<bool> running_;
    std::thread cacheThread_;
    std::thread replicationThread_;
    std::thread prefetchThread_;
    mutable std::mutex entriesMutex_;
    mutable std::mutex statsMutex_;
    
    // State
    std::atomic<bool> initialized_;
    DistributedCacheConfig config_;
    std::string localNodeId_;
    
    // Cache storage
    struct CacheData {
        std::vector<uint8_t> keyCache;
        std::vector<uint8_t> valueCache;
        bool isCompressed;
    };
    std::map<KVCacheKey, CacheData> localCache_;
    std::map<KVCacheKey, KVCacheEntry> entryMetadata_;
    
    // Session tracking
    std::map<std::string, std::set<KVCacheKey>> sessionKeys_;
    mutable std::mutex sessionsMutex_;
    
    // Prefetch tracking
    std::set<std::string> activePrefetches_;
    mutable std::mutex prefetchMutex_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> hitCount{0};
        std::atomic<uint64_t> missCount{0};
        std::atomic<uint64_t> evictionCount{0};
        std::atomic<uint64_t> replicationCount{0};
        std::atomic<uint64_t> migrationCount{0};
        std::atomic<uint64_t> bytesTransferred{0};
        std::atomic<double> totalAccessLatencyUs{0.0};
        std::atomic<uint64_t> accessCount{0};
    } stats_;
    
    // Dependencies
    std::shared_ptr<ClusterManager> clusterManager_;
    std::shared_ptr<DistributedScheduler> scheduler_;
};

// Cache coherence protocol
class CacheCoherenceManager {
public:
    CacheCoherenceManager(DistributedKVCache* cache);
    
    // Coherence operations
    bool acquireReadLock(const KVCacheKey& key);
    bool acquireWriteLock(const KVCacheKey& key);
    bool releaseLock(const KVCacheKey& key);
    
    // Invalidation
    bool invalidateEntry(const KVCacheKey& key);
    bool invalidateSession(const std::string& sessionId);
    bool invalidateModel(const std::string& modelId);
    
    // Update propagation
    bool propagateUpdate(const KVCacheKey& key, const std::vector<uint8_t>& data);
    bool syncWithReplicas(const KVCacheKey& key);
    
    // Conflict resolution
    bool resolveConflict(const KVCacheKey& key, uint64_t version1, uint64_t version2);
    
private:
    DistributedKVCache* cache_;
    std::map<KVCacheKey, std::mutex> locks_;
    std::mutex locksMutex_;
};

// Prefetch predictor
class PrefetchPredictor {
public:
    PrefetchPredictor();
    
    // Pattern learning
    void recordAccess(const KVCacheKey& key);
    void recordSequence(const std::vector<KVCacheKey>& sequence);
    
    // Prediction
    std::vector<KVCacheKey> predictNext(const KVCacheKey& current, uint32_t count);
    std::vector<KVCacheKey> predictForSession(const std::string& sessionId, uint32_t count);
    
    // Confidence scoring
    float getPredictionConfidence(const KVCacheKey& from, const KVCacheKey& to);
    
    void clear();
    
private:
    // Markov chain for access patterns
    std::map<KVCacheKey, std::map<KVCacheKey, uint64_t>> transitionCounts_;
    std::map<KVCacheKey, uint64_t> totalTransitions_;
    mutable std::mutex mutex_;
};

} // namespace Distributed
} // namespace RawrXD
