// Sovereign Distributed Runtime - Phase D.3 Batch 3/5
// Distributed Rollback Coordination
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignConsensusEngine.hpp"
#include <vector>
#include <map>
#include <memory>
#include <chrono>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// Rollback Types
// ============================================================================

enum class RollbackScope {
    LOCAL = 0,      // Single node
    PARTITION = 1,  // Affected partition only
    CLUSTER = 2,   // All nodes
    GLOBAL = 3     // Full system halt
};

enum class RollbackState {
    PENDING = 0,
    PREPARING = 1,
    EXECUTING = 2,
    VERIFYING = 3,
    COMPLETED = 4,
    FAILED = 5,
    CANCELLED = 6
};

struct RollbackCheckpoint {
    std::string checkpoint_id;
    std::string node_id;
    int64_t sequence_number = 0;
    std::chrono::steady_clock::time_point timestamp;
    std::string state_hash;  // Cryptographic hash of state
    std::map<std::string, std::string> metadata;
    
    std::string ToJson() const;
};

struct RollbackOperation {
    std::string rollback_id;
    std::string trigger_node;
    RollbackScope scope = RollbackScope::LOCAL;
    RollbackState state = RollbackState::PENDING;
    
    std::string target_checkpoint_id;
    std::vector<std::string> affected_nodes;
    std::map<std::string, RollbackCheckpoint> node_checkpoints;
    
    std::string reason;
    SafetyDecision trigger_decision;
    
    std::chrono::steady_clock::time_point initiated_at;
    std::chrono::steady_clock::time_point completed_at;
    int64_t duration_ms = 0;
    
    std::string ToJson() const;
    static RollbackOperation FromJson(const std::string& json);
};

struct RollbackResult {
    std::string rollback_id;
    bool success = false;
    RollbackState final_state = RollbackState::FAILED;
    std::vector<std::string> successful_nodes;
    std::vector<std::string> failed_nodes;
    std::map<std::string, std::string> node_errors;
    int64_t total_duration_ms = 0;
    
    std::string ToJson() const;
};

// ============================================================================
// Distributed Rollback Coordinator
// ============================================================================

class DistributedRollbackCoordinator {
public:
    struct Config {
        int prepare_timeout_ms = 5000;
        int execute_timeout_ms = 30000;
        int verify_timeout_ms = 10000;
        bool auto_rollback_on_partition = true;
        int max_concurrent_rollbacks = 3;
        bool require_consensus_for_cluster = true;
    };
    
    explicit DistributedRollbackCoordinator(const Config& config);
    ~DistributedRollbackCoordinator();
    
    // Lifecycle
    bool Initialize(std::shared_ptr<NodeDiscovery> discovery,
                    std::shared_ptr<ConsensusEngine> consensus);
    void Shutdown();
    
    // Checkpoint management
    bool CreateCheckpoint(const std::string& node_id, 
                          const RollbackCheckpoint& checkpoint);
    bool DeleteCheckpoint(const std::string& checkpoint_id);
    std::vector<RollbackCheckpoint> GetCheckpoints(const std::string& node_id);
    RollbackCheckpoint GetLatestCheckpoint(const std::string& node_id);
    
    // Rollback operations
    std::string InitiateRollback(const RollbackOperation& operation);
    bool CancelRollback(const std::string& rollback_id);
    RollbackResult GetResult(const std::string& rollback_id, int timeout_ms = 60000);
    
    // Query
    std::vector<RollbackOperation> GetActiveRollbacks() const;
    std::vector<RollbackOperation> GetRollbackHistory(int count = 100) const;
    RollbackOperation GetRollback(const std::string& rollback_id) const;
    
    // Statistics
    struct Stats {
        int total_rollbacks = 0;
        int successful = 0;
        int failed = 0;
        int cancelled = 0;
        double avg_rollback_time_ms = 0.0;
        int checkpoints_created = 0;
        int checkpoints_deleted = 0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<NodeDiscovery> discovery_;
    std::shared_ptr<ConsensusEngine> consensus_;
    std::atomic<bool> running_{false};
    
    mutable std::mutex rollbacks_mutex_;
    std::map<std::string, RollbackOperation> active_rollbacks_;
    std::vector<RollbackOperation> completed_rollbacks_;
    
    mutable std::mutex checkpoints_mutex_;
    std::map<std::string, std::vector<RollbackCheckpoint>> node_checkpoints_;
    
    std::thread coordinator_thread_;
    std::atomic<int64_t> total_rollback_time_ms_{0};
    std::atomic<int> rollback_count_{0};
    std::atomic<int> checkpoints_created_{0};
    std::atomic<int> checkpoints_deleted_{0};
    
    // Implementation
    void CoordinatorLoop();
    bool ExecutePhase(const std::string& rollback_id, RollbackState phase);
    bool PreparePhase(const std::string& rollback_id);
    bool ExecutePhaseImpl(const std::string& rollback_id);
    bool VerifyPhase(const std::string& rollback_id);
    
    bool SendPrepare(const std::string& node_id, const RollbackOperation& op);
    bool SendExecute(const std::string& node_id, const RollbackOperation& op);
    bool SendVerify(const std::string& node_id, const RollbackOperation& op);
    
    void CleanupCompleted();
    bool AcquireConsensus(const RollbackOperation& op);
};

// ============================================================================
// Local Rollback Handler
// ============================================================================

class LocalRollbackHandler {
public:
    using RollbackFunction = std::function<bool(const RollbackCheckpoint&)>;
    
    bool RegisterHandler(const std::string& component, RollbackFunction handler);
    bool UnregisterHandler(const std::string& component);
    
    bool ExecuteLocalRollback(const RollbackCheckpoint& checkpoint);
    
private:
    std::mutex handlers_mutex_;
    std::map<std::string, RollbackFunction> handlers_;
};

} // namespace Distributed
} // namespace Sovereign
