// Phase D.5 Batch 3/5: Global Consensus
// Multi-Region Consensus with Witness Nodes
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignGlobalLoadBalancer.hpp"
#include "SovereignCrossRegionReplication.hpp"
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Sovereign {
namespace Federation {

// ============================================================================
// Witness Node Types
// ============================================================================

enum class WitnessType {
    VOTING = 0,        // Full voting member
    NON_VOTING = 1,    // Observer, no vote
    LIGHT = 2,         // Lightweight witness (only metadata)
    BACKUP = 3         // Backup witness for failover
};

struct WitnessNode {
    std::string witness_id;
    std::string region_id;
    WitnessType type = WitnessType::VOTING;
    std::string endpoint;
    HealthStatus health = HealthStatus::HEALTHY;
    
    // Consensus participation
    int64_t last_vote_timestamp = 0;
    int64_t votes_participated = 0;
    int64_t votes_missed = 0;
    
    // Network metrics
    double avg_latency_ms = 0.0;
    int64_t bytes_stored = 0;
};

// ============================================================================
// Global Proposal
// ============================================================================

struct GlobalProposal {
    std::string proposal_id;
    std::string operation_id;
    std::string proposer_region;
    int proposal_type = 0;  // 0=state_change, 1=config_change, 2=emergency
    std::vector<uint8_t> data;
    std::map<std::string, std::string> affected_regions;
    std::chrono::steady_clock::time_point timestamp;
    int64_t timeout_ms = 10000;
    
    // Quorum requirements
    int required_votes = 0;
    bool require_cross_region = true;
    int min_regions = 2;
};

struct GlobalVote {
    std::string proposal_id;
    std::string voter_region;
    std::string voter_witness;
    bool vote = false;
    std::string rationale;
    std::chrono::steady_clock::time_point timestamp;
    std::string signature;  // Cryptographic signature
};

struct GlobalCommit {
    std::string proposal_id;
    bool committed = false;
    int votes_for = 0;
    int votes_against = 0;
    int regions_participated = 0;
    std::vector<std::string> participating_regions;
    std::chrono::steady_clock::time_point commit_time;
    std::string commit_proof;  // Cryptographic proof
};

// ============================================================================
// Consensus Protocol
// ============================================================================

enum class ConsensusProtocol {
    RAFT = 0,
    PAXOS = 1,
    MULTI_PAXOS = 2,
    FLEXIBLE_PAXOS = 3
};

class GlobalConsensusEngine {
public:
    struct Config {
        ConsensusProtocol protocol = ConsensusProtocol::FLEXIBLE_PAXOS;
        int quorum_ratio = 66;  // Percentage (66% = 2/3)
        int cross_region_ratio = 51;  // Require majority across regions
        int witness_count = 5;
        int proposal_timeout_ms = 10000;
        int leader_lease_ms = 10000;
        bool enable_witnesses = true;
        bool enable_fast_path = true;
    };
    
    explicit GlobalConsensusEngine(const Config& config);
    ~GlobalConsensusEngine();
    
    bool Initialize(const std::string& local_region_id);
    void Shutdown();
    
    // Witness management
    bool RegisterWitness(const WitnessNode& witness);
    bool DeregisterWitness(const std::string& witness_id);
    std::vector<WitnessNode> GetWitnesses() const;
    std::vector<WitnessNode> GetHealthyWitnesses() const;
    
    // Leader election
    bool ElectLeader();
    bool IsLeader() const;
    std::string GetLeader() const;
    void StepDown();
    
    // Consensus operations
    GlobalCommit Propose(const GlobalProposal& proposal);
    GlobalVote Vote(const GlobalProposal& proposal);
    GlobalCommit GetCommit(const std::string& proposal_id) const;
    bool IsCommitted(const std::string& proposal_id) const;
    
    // Quorum calculations
    int GetQuorumSize() const;
    int GetCrossRegionQuorumSize() const;
    bool HasQuorum(const std::vector<GlobalVote>& votes) const;
    bool HasCrossRegionQuorum(const std::vector<GlobalVote>& votes) const;
    
    // Statistics
    struct Stats {
        int64_t proposals_initiated = 0;
        int64_t proposals_committed = 0;
        int64_t proposals_rejected = 0;
        int64_t leader_changes = 0;
        double avg_consensus_time_ms = 0.0;
        int64_t witness_failures = 0;
    };
    Stats GetStats() const;
    
    // Callbacks
    using CommitCallback = std::function<void(const GlobalCommit&)>;
    using LeaderChangeCallback = std::function<void(const std::string&, const std::string&)>;
    void OnCommit(CommitCallback cb);
    void OnLeaderChange(LeaderChangeCallback cb);
    
private:
    Config config_;
    std::string local_region_id_;
    std::string current_leader_;
    std::atomic<bool> running_{false};
    
    mutable std::mutex witnesses_mutex_;
    std::map<std::string, WitnessNode> witnesses_;
    
    mutable std::mutex proposals_mutex_;
    std::map<std::string, GlobalProposal> proposals_;
    std::map<std::string, std::vector<GlobalVote>> proposal_votes_;
    std::map<std::string, GlobalCommit> commits_;
    
    CommitCallback on_commit_;
    LeaderChangeCallback on_leader_change_;
    
    std::atomic<int64_t> proposals_initiated_{0};
    std::atomic<int64_t> proposals_committed_{0};
    std::atomic<int64_t> proposals_rejected_{0};
    std::atomic<int64_t> leader_changes_{0};
    std::atomic<int64_t> total_consensus_time_us_{0};
    std::atomic<int64_t> witness_failures_{0};
    
    // Protocol implementations
    GlobalCommit RunRaft(const GlobalProposal& proposal);
    GlobalCommit RunPaxos(const GlobalProposal& proposal);
    GlobalCommit RunFlexiblePaxos(const GlobalProposal& proposal);
    
    void BroadcastProposal(const GlobalProposal& proposal);
    std::vector<GlobalVote> CollectVotes(const std::string& proposal_id, int timeout_ms);
    void BroadcastCommit(const GlobalCommit& commit);
};

// ============================================================================
// Witness Coordinator
// ============================================================================

class WitnessCoordinator {
public:
    struct Config {
        int heartbeat_interval_ms = 5000;
        int failure_timeout_ms = 15000;
        int min_witnesses = 3;
        bool auto_promote = true;
    };
    
    explicit WitnessCoordinator(const Config& config);
    
    bool Initialize(GlobalConsensusEngine* consensus);
    void Shutdown();
    
    // Witness lifecycle
    bool AddWitness(const std::string& region_id, const std::string& endpoint);
    bool RemoveWitness(const std::string& witness_id);
    bool PromoteWitness(const std::string& witness_id);
    bool DemoteWitness(const std::string& witness_id);
    
    // Health monitoring
    void ReportWitnessHealth(const std::string& witness_id, HealthStatus status);
    std::vector<std::string> GetFailedWitnesses() const;
    
    // Backup witness management
    bool ActivateBackupWitness(const std::string& failed_witness_id);
    bool DeactivateBackupWitness(const std::string& witness_id);
    
private:
    Config config_;
    GlobalConsensusEngine* consensus_ = nullptr;
    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    
    void MonitorLoop();
};

} // namespace Federation
} // namespace Sovereign
