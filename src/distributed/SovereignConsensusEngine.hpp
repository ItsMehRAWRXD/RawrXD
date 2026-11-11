// Sovereign Distributed Runtime - Phase D.3 Batch 2/5
// Consensus Engine for Safety Decisions
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignNodeDiscovery.hpp"
#include <vector>
#include <map>
#include <chrono>
#include <mutex>
#include <condition_variable>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// Consensus Types
// ============================================================================

enum class SafetyDecision {
    ALLOW = 0,
    DENY = 1,
    DEGRADED = 2,    // Allow with restrictions
    ROLLBACK = 3,    // Trigger rollback
    ESCALATE = 4     // Require human review
};

struct SafetyProposal {
    std::string proposal_id;
    std::string operation_id;
    std::string node_id;
    SafetyDecision proposed_action;
    std::string rationale;
    std::map<std::string, double> metrics;
    std::chrono::steady_clock::time_point timestamp;
    int term = 0;
    
    std::string ToJson() const;
    static SafetyProposal FromJson(const std::string& json);
};

struct SafetyVote {
    std::string proposal_id;
    std::string node_id;
    bool approve = false;
    SafetyDecision alternative;
    std::string reason;
    int term = 0;
    
    std::string ToJson() const;
};

struct SafetyCommit {
    std::string proposal_id;
    SafetyDecision final_decision;
    int votes_for = 0;
    int votes_against = 0;
    std::vector<std::string> participating_nodes;
    std::chrono::steady_clock::time_point committed_at;
    
    std::string ToJson() const;
};

// ============================================================================
// Consensus Engine
// ============================================================================

class ConsensusEngine {
public:
    struct Config {
        int consensus_timeout_ms = 5000;
        int vote_retry_count = 3;
        bool require_unanimous_safety = true;  // For ROLLBACK/ESCALATE
        double min_participation_ratio = 0.66; // 2/3 of healthy nodes
        int max_concurrent_proposals = 100;
    };
    
    explicit ConsensusEngine(const Config& config);
    ~ConsensusEngine();
    
    // Lifecycle
    bool Initialize(std::shared_ptr<NodeDiscovery> discovery);
    void Shutdown();
    
    // Proposal lifecycle
    std::string Propose(const SafetyProposal& proposal);
    bool Vote(const std::string& proposal_id, const SafetyVote& vote);
    SafetyCommit GetResult(const std::string& proposal_id, int timeout_ms = 5000);
    
    // Query
    bool IsCommitted(const std::string& proposal_id);
    SafetyDecision GetDecision(const std::string& proposal_id);
    std::vector<SafetyCommit> GetRecentCommits(int count = 100);
    
    // Statistics
    struct Stats {
        int total_proposals = 0;
        int committed = 0;
        int rejected = 0;
        int timeouts = 0;
        double avg_consensus_time_ms = 0.0;
        int current_pending = 0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<NodeDiscovery> discovery_;
    std::atomic<bool> running_{false};
    
    struct PendingProposal {
        SafetyProposal proposal;
        std::map<std::string, SafetyVote> votes;
        std::chrono::steady_clock::time_point deadline;
        std::promise<SafetyCommit> result_promise;
    };
    
    mutable std::mutex proposals_mutex_;
    std::map<std::string, std::unique_ptr<PendingProposal>> pending_;
    std::vector<SafetyCommit> committed_;
    
    std::thread worker_thread_;
    std::atomic<int64_t> total_consensus_time_ms_{0};
    std::atomic<int> consensus_count_{0};
    
    // Implementation
    void WorkerLoop();
    void ProcessProposal(const std::string& proposal_id);
    bool CheckConsensus(const PendingProposal& pending);
    SafetyCommit Finalize(const std::string& proposal_id, 
                          const PendingProposal& pending);
    void BroadcastCommit(const SafetyCommit& commit);
    void CleanupExpired();
    
    // Network
    bool SendVoteRequest(const std::string& node_id, const SafetyProposal& proposal);
    void SendCommitNotification(const std::string& node_id, const SafetyCommit& commit);
};

// ============================================================================
// Distributed Safety Gate
// ============================================================================

class DistributedSafetyGate {
public:
    struct Config {
        bool local_fallback = true;
        int local_timeout_ms = 100;
        int distributed_timeout_ms = 5000;
        bool require_distributed_for_critical = true;
    };
    
    explicit DistributedSafetyGate(const Config& config);
    
    bool Initialize(std::shared_ptr<ConsensusEngine> consensus);
    void Shutdown();
    
    // Safety check with distributed consensus
    SafetyDecision Check(const SafetyProposal& proposal);
    
    // Fast path for non-critical operations
    SafetyDecision CheckLocal(const SafetyProposal& proposal);
    
    // Statistics
    struct Stats {
        int total_checks = 0;
        int local_approvals = 0;
        int distributed_checks = 0;
        int distributed_approvals = 0;
        int rollbacks_triggered = 0;
        double avg_decision_time_ms = 0.0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<ConsensusEngine> consensus_;
    std::atomic<int> total_checks_{0};
    std::atomic<int> local_approvals_{0};
    std::atomic<int> distributed_checks_{0};
    std::atomic<int> distributed_approvals_{0};
    std::atomic<int> rollbacks_{0};
    std::atomic<int64_t> total_decision_time_us_{0};
};

} // namespace Distributed
} // namespace Sovereign
