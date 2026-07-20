//=============================================================================
// RawrXD KV Residency Scheduler
// Phase 3B: Intelligent KV Cache Placement and Migration
//
// Transforms the KV cache from passive storage to an actively managed
// residency hierarchy. Makes placement decisions based on:
// - Access frequency (hot/warm/cold classification)
// - Sequence age and position
// - NUMA affinity of compute threads
// - Memory pressure across tiers
//
// This is the "brain" that orchestrates the SovereignMemoryAllocator.
//=============================================================================

#pragma once

#include "SovereignMemoryAllocator.hpp"
#include <cstdint>
#include <atomic>
#include <memory>
#include <queue>
#include <thread>
#include <condition_variable>
#include <functional>
#include <unordered_map>
#include <vector>

namespace RawrXD {
namespace Memory {

//=============================================================================
// Forward Declarations
//=============================================================================
class KVResidencyScheduler;
class ResidencyMigrationTask;

//=============================================================================
// Residency State Enumeration
// Defines where KV data lives in the memory hierarchy
//=============================================================================
enum class ResidencyState : uint8_t {
    HOT_GPU = 0,        // Actively being used by GPU kernels
    ACTIVE_NUMA,        // NUMA-local DRAM, hot for CPU compute
    WARM_NUMA,          // NUMA-local DRAM, recently used
    COLD_DRAM,          // DRAM but not NUMA-local
    COMPRESSED,         // FP8/INT8 compressed in DRAM
    MAPPED_STORAGE,     // Memory-mapped from NVMe
    EVICTED,            // Not resident, must be fetched
    STATE_COUNT
};

const char* ResidencyStateToString(ResidencyState state);

//=============================================================================
// Residency Tier Configuration
// Defines the characteristics of each memory tier
//=============================================================================
struct ResidencyTierConfig {
    ResidencyState state;
    MemoryTier memoryTier;
    uint32_t preferredNumaNode;     // UINT32_MAX = any node
    bool useLargePages;
    bool lockPages;
    uint32_t compressionRatio;      // 1 = uncompressed, 2 = 50%, etc.
    uint64_t accessLatencyNs;       // Expected access latency
    uint64_t bandwidthGBps;         // Expected bandwidth
};

//=============================================================================
// KV Block Metadata
// Tracks residency and access patterns for each KV block
//=============================================================================
struct alignas(64) KVBlockMetadata {
    // Identity
    uint64_t blockId;
    uint64_t sequenceId;
    uint32_t layerId;
    uint32_t headId;
    
    // Residency
    std::atomic<ResidencyState> currentState{ResidencyState::EVICTED};
    std::atomic<ResidencyState> targetState{ResidencyState::EVICTED};
    uint32_t currentNumaNode{UINT32_MAX};
    uint32_t targetNumaNode{UINT32_MAX};
    
    // Access tracking (for hot/cold classification)
    alignas(64) std::atomic<uint64_t> accessCount{0};
    alignas(64) std::atomic<uint64_t> lastAccessTime{0};
    alignas(64) std::atomic<uint64_t> totalAccessTime{0};
    
    // Migration state
    alignas(64) std::atomic<bool> migrationInProgress{false};
    alignas(64) std::atomic<uint64_t> migrationStartTime{0};
    
    // Memory handle (if resident)
    MemoryResidencyHandle memoryHandle;
    void* dataPtr{nullptr};
    size_t dataSize{0};
    
    // Statistics
    uint64_t GetAge(uint64_t currentTime) const {
        return currentTime - lastAccessTime.load(std::memory_order_relaxed);
    }
    
    bool IsResident() const {
        auto state = currentState.load(std::memory_order_acquire);
        return state != ResidencyState::EVICTED && 
               state != ResidencyState::MAPPED_STORAGE;
    }
    
    bool CanMigrate() const {
        return !migrationInProgress.load(std::memory_order_acquire);
    }
};

//=============================================================================
// Access Pattern Tracker
// Per-sequence access pattern analysis for predictive prefetching
//=============================================================================
class AccessPatternTracker {
public:
    struct AccessPattern {
        uint64_t sequenceId;
        std::vector<uint32_t> recentBlockIds;
        std::unordered_map<uint32_t, uint32_t> blockFrequency;
        uint64_t lastAccessTime;
        bool isSequential;
        float predictedNextBlock;
    };
    
    AccessPatternTracker(size_t maxSequences = 1024);
    
    // Record an access
    void RecordAccess(uint64_t sequenceId, uint32_t blockId, uint64_t timestamp);
    
    // Predict next likely blocks
    std::vector<uint32_t> PredictNextBlocks(uint64_t sequenceId, uint32_t numPredictions);
    
    // Get pattern for a sequence
    AccessPattern* GetPattern(uint64_t sequenceId);
    
    // Cleanup old patterns
    void Cleanup(uint64_t currentTime, uint64_t maxAge);
    
private:
    std::unordered_map<uint64_t, AccessPattern> patterns_;
    std::mutex mutex_;
    size_t maxSequences_;
};

//=============================================================================
// Hot/Cold Classifier
// Determines residency state based on access patterns
//=============================================================================
class HotColdClassifier {
public:
    struct ClassificationConfig {
        uint64_t hotThreshold;          // Access count for HOT
        uint64_t warmThreshold;         // Access count for WARM
        uint64_t hotAgeThresholdNs;     // Max age for HOT
        uint64_t warmAgeThresholdNs;    // Max age for WARM
        uint64_t coldAgeThresholdNs;    // Age to trigger compression
    };
    
    HotColdClassifier(const ClassificationConfig& config);
    
    // Classify a block based on its metadata
    ResidencyState Classify(const KVBlockMetadata& metadata, uint64_t currentTime);
    
    // Update thresholds dynamically based on workload
    void AdaptThresholds(const std::vector<KVBlockMetadata*>& blocks);
    
private:
    ClassificationConfig config_;
    std::atomic<uint64_t> globalAccessRate_{0};
};

//=============================================================================
// Async Prefetch Queue
// Lock-free queue for prefetch requests
//=============================================================================
class AsyncPrefetchQueue {
public:
    struct PrefetchRequest {
        uint64_t blockId;
        ResidencyState targetState;
        uint32_t targetNumaNode;
        uint32_t priority;              // Higher = more urgent
        uint64_t requestTime;
    };
    
    AsyncPrefetchQueue(size_t capacity = 1024);
    ~AsyncPrefetchQueue();
    
    // Enqueue a prefetch request
    bool Enqueue(const PrefetchRequest& request);
    
    // Dequeue a request (non-blocking)
    bool Dequeue(PrefetchRequest& request);
    
    // Get queue depth
    size_t GetDepth() const { return size_.load(std::memory_order_relaxed); }
    
    // Clear all requests
    void Clear();
    
private:
    struct alignas(64) Node {
        PrefetchRequest data;
        std::atomic<Node*> next{nullptr};
    };
    
    alignas(64) std::atomic<Node*> head_{nullptr};
    alignas(64) std::atomic<Node*> tail_{nullptr};
    alignas(64) std::atomic<size_t> size_{0};
    
    size_t capacity_;
    std::atomic<bool> shutdown_{false};
};

//=============================================================================
// Residency Migration Engine
// Handles async migration of blocks between tiers
//=============================================================================
class ResidencyMigrationEngine {
public:
    using MigrationCallback = std::function<void(uint64_t blockId, bool success)>;
    
    ResidencyMigrationEngine(SovereignMemoryAllocator* allocator);
    ~ResidencyMigrationEngine();
    
    // Initialize with number of worker threads
    bool Initialize(uint32_t numWorkers = 2);
    void Shutdown();
    
    // Request migration of a block
    bool RequestMigration(uint64_t blockId, 
                          ResidencyState targetState,
                          uint32_t targetNumaNode,
                          MigrationCallback callback = nullptr);
    
    // Get migration statistics
    struct Stats {
        uint64_t migrationsRequested;
        uint64_t migrationsCompleted;
        uint64_t migrationsFailed;
        uint64_t avgMigrationTimeUs;
        uint64_t bytesMigrated;
    };
    Stats GetStats() const;
    
private:
    SovereignMemoryAllocator* allocator_;
    std::vector<std::thread> workers_;
    AsyncPrefetchQueue queue_;
    std::atomic<bool> shutdown_{false};
    
    // Statistics
    alignas(64) std::atomic<uint64_t> migrationsRequested_{0};
    alignas(64) std::atomic<uint64_t> migrationsCompleted_{0};
    alignas(64) std::atomic<uint64_t> migrationsFailed_{0};
    alignas(64) std::atomic<uint64_t> totalMigrationTimeUs_{0};
    alignas(64) std::atomic<uint64_t> bytesMigrated_{0};
    
    void WorkerThread();
    bool ExecuteMigration(uint64_t blockId, ResidencyState targetState, uint32_t targetNumaNode);
};

//=============================================================================
// KV Residency Scheduler
// Main orchestrator for KV cache residency management
//=============================================================================
class KVResidencyScheduler {
public:
    struct Config {
        uint32_t numWorkers = 2;
        uint64_t classificationIntervalMs = 100;
        uint64_t prefetchLookahead = 3;
        bool enableAdaptiveThresholds = true;
        bool enablePredictivePrefetch = true;
        size_t maxTrackedBlocks = 100000;
    };
    
    KVResidencyScheduler(SovereignMemoryAllocator* allocator);
    ~KVResidencyScheduler();
    
    // Initialize
    bool Initialize(const Config& config);
    void Shutdown();
    
    // Register a block for residency management
    bool RegisterBlock(uint64_t blockId, KVBlockMetadata* metadata);
    void UnregisterBlock(uint64_t blockId);
    
    // Record an access (called by attention kernels)
    void RecordAccess(uint64_t blockId, uint64_t sequenceId, uint64_t timestamp);
    
    // Request residency for a block (synchronous)
    bool EnsureResidency(uint64_t blockId, ResidencyState desiredState, uint32_t numaNode);
    
    // Request async prefetch
    bool PrefetchBlock(uint64_t blockId, ResidencyState targetState, uint32_t priority);
    
    // Get current residency state
    ResidencyState GetResidencyState(uint64_t blockId) const;
    
    // Get block metadata
    KVBlockMetadata* GetBlockMetadata(uint64_t blockId);
    
    // Classification and rebalancing
    void RunClassificationPass();
    void RebalanceResidency();
    
    // Telemetry
    struct ResidencyReport {
        uint64_t totalBlocks;
        uint64_t blocksByState[static_cast<size_t>(ResidencyState::STATE_COUNT)];
        uint64_t migrationsInProgress;
        uint64_t prefetchQueueDepth;
        float avgAccessLatency;
        float hitRate;
        std::string tierDistribution;
    };
    ResidencyReport GenerateReport() const;
    std::string GetResidencyDashboard() const;
    
    // Statistics
    uint64_t GetTotalAccesses() const { return totalAccesses_.load(); }
    uint64_t GetResidencyHits() const { return residencyHits_.load(); }
    uint64_t GetResidencyMisses() const { return residencyMisses_.load(); }
    float GetHitRate() const {
        uint64_t total = totalAccesses_.load();
        return total > 0 ? static_cast<float>(residencyHits_.load()) / total : 0.0f;
    }
    
private:
    SovereignMemoryAllocator* allocator_;
    Config config_;
    
    // Block registry
    std::unordered_map<uint64_t, KVBlockMetadata*> blockRegistry_;
    mutable std::shared_mutex registryMutex_;
    
    // Subsystems
    std::unique_ptr<HotColdClassifier> classifier_;
    std::unique_ptr<AccessPatternTracker> patternTracker_;
    std::unique_ptr<ResidencyMigrationEngine> migrationEngine_;
    
    // Background thread for classification
    std::thread classificationThread_;
    std::atomic<bool> shutdown_{false};
    std::condition_variable cv_;
    std::mutex cvMutex_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> totalAccesses_{0};
    alignas(64) std::atomic<uint64_t> residencyHits_{0};
    alignas(64) std::atomic<uint64_t> residencyMisses_{0};
    alignas(64) std::atomic<uint64_t> prefetchRequests_{0};
    alignas(64) std::atomic<uint64_t> prefetchHits_{0};
    
    // Classification pass
    void ClassificationWorker();
    void ClassifyAllBlocks();
    
    // Predictive prefetch
    void IssuePredictivePrefetches(uint64_t sequenceId, uint32_t lastBlockId);
};

//=============================================================================
// Convenience Functions
//=============================================================================
// Get global scheduler instance
KVResidencyScheduler& GetGlobalResidencyScheduler();
bool InitializeGlobalResidencyScheduler(SovereignMemoryAllocator* allocator);
void ShutdownGlobalResidencyScheduler();

} // namespace Memory
} // namespace RawrXD
