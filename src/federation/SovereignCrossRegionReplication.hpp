// Phase D.5 Batch 2/5: Cross-Region Replication
// Geo-Distributed State Synchronization
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignGlobalLoadBalancer.hpp"
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Federation {

// ============================================================================
// Conflict-Free Replicated Data Types (CRDTs)
// ============================================================================

enum class CRDTType {
    G_COUNTER = 0,       // Grow-only counter
    PN_COUNTER = 1,    // Positive-negative counter
    G_SET = 2,         // Grow-only set
    OR_SET = 3,        // Observed-removed set
    LWW_REGISTER = 4,  // Last-write-wins register
    MV_REGISTER = 5,     // Multi-value register
    G_MAP = 6,         // Grow-only map
    OR_MAP = 7         // Observed-removed map
};

struct CRDTState {
    std::string state_id;
    CRDTType type;
    std::string region_id;
    int64_t version = 0;
    std::vector<uint8_t> data;
    std::map<std::string, std::string> vector_clock;
    std::chrono::steady_clock::time_point timestamp;
    
    bool Merge(const CRDTState& other);
    std::string ToJson() const;
    static CRDTState FromJson(const std::string& json);
};

// ============================================================================
// Replication Stream
// ============================================================================

struct ReplicationStream {
    std::string stream_id;
    std::string source_region;
    std::string target_region;
    int64_t sequence_number = 0;
    bool active = false;
    
    struct Stats {
        int64_t events_replicated = 0;
        int64_t bytes_replicated = 0;
        double avg_latency_ms = 0.0;
        int64_t errors = 0;
        std::chrono::steady_clock::time_point last_event;
    };
    Stats stats;
};

// ============================================================================
// Conflict Resolution
// ============================================================================

class ConflictResolver {
public:
    struct Config {
        std::string strategy = "lww";  // lww, vector_clock, crdt
        int64_t max_clock_skew_ms = 60000;
        bool enable_crdt = true;
    };
    
    explicit ConflictResolver(const Config& config);
    
    // Resolve conflicts between local and remote state
    template<typename T>
    T Resolve(const T& local, const T& remote, const std::string& region_id);
    
    // Vector clock operations
    void IncrementClock(const std::string& region_id);
    bool HappenedBefore(const std::map<std::string, std::string>& clock1,
                        const std::map<std::string, std::string>& clock2);
    bool AreConcurrent(const std::map<std::string, std::string>& clock1,
                       const std::map<std::string, std::string>& clock2);
    
    // CRDT operations
    CRDTState MergeCRDT(const CRDTState& local, const CRDTState& remote);
    
private:
    Config config_;
    std::map<std::string, int64_t> vector_clock_;
    mutable std::mutex clock_mutex_;
};

// ============================================================================
// Cross-Region Replication Engine
// ============================================================================

class CrossRegionReplication {
public:
    struct Config {
        int replication_interval_ms = 1000;
        int batch_size = 1000;
        int max_replication_lag_ms = 5000;
        bool compress_streams = true;
        bool encrypt_streams = true;
        std::vector<std::string> replicate_regions;
        std::map<std::string, std::string> region_priorities;
    };
    
    explicit CrossRegionReplication(const Config& config);
    ~CrossRegionReplication();
    
    bool Initialize(const std::string& local_region_id);
    void Shutdown();
    
    // Stream management
    bool CreateStream(const std::string& target_region);
    bool CloseStream(const std::string& stream_id);
    std::vector<ReplicationStream> GetActiveStreams() const;
    
    // Replication operations
    bool ReplicateEvent(const std::string& stream_id, const CRDTState& event);
    bool ReplicateBatch(const std::string& stream_id, 
                        const std::vector<CRDTState>& events);
    
    // State synchronization
    bool SyncRegion(const std::string& region_id);
    bool SyncAllRegions();
    
    // Conflict resolution
    void SetConflictResolver(std::unique_ptr<ConflictResolver> resolver);
    
    // Lag monitoring
    int64_t GetReplicationLag(const std::string& region_id) const;
    std::map<std::string, int64_t> GetAllReplicationLags() const;
    
    // Statistics
    struct Stats {
        int64_t events_replicated = 0;
        int64_t conflicts_detected = 0;
        int64_t conflicts_resolved = 0;
        double avg_replication_latency_ms = 0.0;
        int64_t bytes_transferred = 0;
    };
    Stats GetStats() const;
    
    // Callbacks
    using ReplicationCallback = std::function<void(const ReplicationStream&, const CRDTState&)>;
    void OnReplication(ReplicationCallback cb);
    
private:
    Config config_;
    std::string local_region_id_;
    std::atomic<bool> running_{false};
    
    std::unique_ptr<ConflictResolver> conflict_resolver_;
    
    mutable std::mutex streams_mutex_;
    std::map<std::string, ReplicationStream> streams_;
    
    std::thread replication_thread_;
    ReplicationCallback on_replication_;
    
    std::atomic<int64_t> events_replicated_{0};
    std::atomic<int64_t> conflicts_detected_{0};
    std::atomic<int64_t> conflicts_resolved_{0};
    std::atomic<int64_t> total_latency_us_{0};
    std::atomic<int64_t> bytes_transferred_{0};
    
    void ReplicationLoop();
    bool SendToRegion(const std::string& region_id, const CRDTState& event);
    std::vector<CRDTState> ReceiveFromRegion(const std::string& region_id);
};

// ============================================================================
// Geo-Partitioned State
// ============================================================================

class GeoPartitionedState {
public:
    struct Config {
        std::string partition_strategy = "hash";  // hash, range, geo
        int replication_factor = 3;
        std::vector<std::string> primary_regions;
    };
    
    explicit GeoPartitionedState(const Config& config);
    
    bool Initialize(CrossRegionReplication* replication);
    
    // Data placement
    std::string GetPartitionForKey(const std::string& key);
    std::vector<std::string> GetReplicasForKey(const std::string& key);
    std::string GetPrimaryRegionForKey(const std::string& key);
    
    // Locality hints
    std::string GetOptimalRegionForRead(const std::string& key, 
                                         const std::string& client_region);
    std::string GetOptimalRegionForWrite(const std::string& key,
                                          const std::string& client_region);
    
    // Rebalancing
    bool RebalancePartitions();
    bool MigratePartition(const std::string& partition_id,
                          const std::string& from_region,
                          const std::string& to_region);
    
private:
    Config config_;
    CrossRegionReplication* replication_ = nullptr;
    
    std::map<std::string, std::vector<std::string>> partition_map_;
    mutable std::mutex partition_mutex_;
    
    uint32_t HashKey(const std::string& key);
};

} // namespace Federation
} // namespace Sovereign
