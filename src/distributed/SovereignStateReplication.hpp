// Sovereign Distributed Runtime - Phase D.3 Batch 4/5
// State Replication & Synchronization
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignNodeDiscovery.hpp"
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// Replication Types
// ============================================================================

enum class ConsistencyLevel {
    EVENTUAL = 0,    // Async, may have temporary divergence
    SESSION = 1,     // Consistent within user session
    BOUNDED = 2,     // Bounded staleness (e.g., 100ms)
    STRONG = 3       // Synchronous, all nodes consistent
};

enum class ReplicationStrategy {
    PRIMARY_BACKUP = 0,     // One primary, async backups
    MULTI_MASTER = 1,       // All nodes accept writes
    QUORUM = 2,             // Write to majority
    STATE_MACHINE = 3     // Raft/Paxos log replication
};

struct ReplicatedState {
    std::string state_id;
    std::string state_type;  // "agent", "memory", "config", etc.
    std::string node_id;     // Owner node
    int64_t version = 0;
    std::vector<uint8_t> data;
    std::string checksum;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
    
    std::string ToJson() const;
    static ReplicatedState FromJson(const std::string& json);
};

struct ReplicationEntry {
    int64_t sequence_number = 0;
    std::string operation;   // "CREATE", "UPDATE", "DELETE"
    ReplicatedState state;
    std::vector<std::string> affected_nodes;
    bool committed = false;
    std::chrono::steady_clock::time_point committed_at;
};

// ============================================================================
// State Replication Engine
// ============================================================================

class StateReplicationEngine {
public:
    struct Config {
        ConsistencyLevel consistency = ConsistencyLevel::BOUNDED;
        ReplicationStrategy strategy = ReplicationStrategy::QUORUM;
        int replication_factor = 3;
        int64_t max_staleness_ms = 100;
        int sync_interval_ms = 50;
        int batch_size = 100;
        bool compress_transfers = true;
        int compression_threshold_bytes = 1024;
    };
    
    explicit StateReplicationEngine(const Config& config);
    ~StateReplicationEngine();
    
    // Lifecycle
    bool Initialize(std::shared_ptr<NodeDiscovery> discovery);
    void Shutdown();
    
    // State operations
    bool PublishState(const ReplicatedState& state);
    bool UpdateState(const ReplicatedState& state);
    bool DeleteState(const std::string& state_id);
    
    // Retrieval
    ReplicatedState GetState(const std::string& state_id);
    std::vector<ReplicatedState> GetStatesByType(const std::string& state_type);
    ReplicatedState GetStateFromNode(const std::string& state_id, 
                                      const std::string& node_id);
    
    // Synchronization
    bool SyncState(const std::string& state_id);
    bool SyncAll();
    int64_t GetLatestSequenceNumber() const;
    
    // Conflict resolution
    using ConflictResolver = std::function<ReplicatedState(
        const ReplicatedState& local,
        const ReplicatedState& remote)>;
    void SetConflictResolver(const std::string& state_type, ConflictResolver resolver);
    
    // Callbacks
    using StateChangeCallback = std::function<void(const ReplicatedState&)>;
    void OnStateChange(StateChangeCallback cb);
    
    // Statistics
    struct Stats {
        int64_t states_published = 0;
        int64_t states_replicated = 0;
        int64_t conflicts_detected = 0;
        int64_t conflicts_resolved = 0;
        double avg_replication_latency_ms = 0.0;
        int64_t bytes_transferred = 0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<NodeDiscovery> discovery_;
    std::atomic<bool> running_{false};
    
    mutable std::mutex state_mutex_;
    std::map<std::string, ReplicatedState> local_state_;
    std::map<std::string, std::map<std::string, ReplicatedState>> remote_state_cache_;
    
    mutable std::mutex log_mutex_;
    std::vector<ReplicationEntry> replication_log_;
    int64_t sequence_counter_ = 0;
    
    std::mutex resolver_mutex_;
    std::map<std::string, ConflictResolver> conflict_resolvers_;
    
    StateChangeCallback on_state_change_;
    
    std::thread sync_thread_;
    std::atomic<int64_t> total_replication_latency_us_{0};
    std::atomic<int64_t> replication_count_{0};
    std::atomic<int64_t> bytes_transferred_{0};
    
    // Implementation
    void SyncLoop();
    bool ReplicateToNode(const std::string& node_id, 
                         const ReplicatedState& state);
    bool ApplyRemoteState(const ReplicatedState& state);
    ReplicatedState ResolveConflict(const ReplicatedState& local,
                                    const ReplicatedState& remote);
    std::vector<std::string> SelectReplicationTargets();
    bool IsQuorumAvailable();
    
    // Network
    bool SendState(const std::string& node_id, const ReplicatedState& state);
    ReplicatedState RequestState(const std::string& node_id, 
                                   const std::string& state_id);
};

// ============================================================================
// Memory Synchronization
// ============================================================================

class DistributedMemorySync {
public:
    struct Config {
        int sync_interval_ms = 100;
        int max_synced_memories = 10000;
        bool prioritize_recent = true;
        bool prioritize_frequently_accessed = true;
    };
    
    explicit DistributedMemorySync(const Config& config);
    
    bool Initialize(std::shared_ptr<StateReplicationEngine> replication);
    
    // Memory operations
    bool StoreMemory(const std::string& key, const std::vector<uint8_t>& data);
    std::vector<uint8_t> RetrieveMemory(const std::string& key);
    bool InvalidateMemory(const std::string& key);
    
    // Distributed cache
    bool WarmCache(const std::string& node_id);
    bool EvictFromCache(const std::string& key, const std::string& node_id);
    
    // Statistics
    struct Stats {
        int64_t local_hits = 0;
        int64_t remote_fetches = 0;
        int64_t syncs_completed = 0;
        double cache_hit_ratio = 0.0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<StateReplicationEngine> replication_;
    
    struct MemoryEntry {
        std::vector<uint8_t> data;
        int64_t access_count = 0;
        std::chrono::steady_clock::time_point last_access;
        std::set<std::string> replicated_nodes;
    };
    
    mutable std::mutex memory_mutex_;
    std::map<std::string, MemoryEntry> memory_cache_;
    
    std::atomic<int64_t> local_hits_{0};
    std::atomic<int64_t> remote_fetches_{0};
    std::atomic<int64_t> syncs_completed_{0};
};

} // namespace Distributed
} // namespace Sovereign
