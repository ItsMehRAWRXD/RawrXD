// Sovereign Distributed Runtime - Phase D.3 Batch 2/5
// Consensus Engine for Safety Decisions
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignNodeDiscovery.hpp"
#include <vector>
#include <map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>
#include <future>
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

enum class SafetyPriority {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3
};

struct SafetyProposal {
    std::string proposal_id;
    std::string operation_id;
    std::string node_id;
    std::string proposer_node;
    SafetyDecision proposed_action;
    SafetyDecision proposed_decision;
    SafetyPriority priority = SafetyPriority::NORMAL;
    std::string rationale;
    std::string context;
    std::map<std::string, double> metrics;
    std::vector<std::string> affected_nodes;
    std::chrono::steady_clock::time_point timestamp;
    int term = 0;
    
    std::string ToJson() const;
    static SafetyProposal FromJson(const std::string& json);
};

struct SafetyVote {
    std::string proposal_id;
    std::string node_id;
    std::string voter_node;
    bool approve = false;
    bool vote = false;
    SafetyDecision alternative;
    std::string reason;
    std::string rationale;
    std::chrono::steady_clock::time_point timestamp;
    int term = 0;
    
    std::string ToJson() const;
};

struct SafetyCommit {
    std::string proposal_id;
    SafetyDecision final_decision;
    int votes_for = 0;
    int votes_against = 0;
    bool committed = false;
    std::vector<std::string> participating_nodes;
    std::chrono::steady_clock::time_point committed_at;
    std::chrono::steady_clock::time_point timestamp;
    std::string rationale;
    int participating_node_count = 0;
    
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
    SafetyCommit Propose(const SafetyProposal& proposal);
    SafetyVote Vote(const SafetyProposal& proposal);
    SafetyCommit GetCommit(const std::string& proposal_id) const;
    
    // Query
    bool IsCommitted(const std::string& proposal_id) const;
    SafetyDecision GetDecision(const std::string& proposal_id);
    std::vector<SafetyCommit> GetRecentCommits(int count = 100);
    
    // Callbacks
    void OnCommit(std::function<void(const SafetyCommit&)> callback);
    
    // Get proposal by ID (for DistributedSafetyGate)
    SafetyProposal GetProposal(const std::string& proposal_id) const;
    
    // Statistics
    struct Stats {
        int total_proposals = 0;
        int committed = 0;
        int rejected = 0;
        int timeouts = 0;
        double avg_consensus_time_ms = 0.0;
        int current_pending = 0;
        int proposals_initiated = 0;
        int commits_reached = 0;
        int commits_failed = 0;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<NodeDiscovery> discovery_;
    std::atomic<bool> running_{false};
    
    mutable std::mutex proposals_mutex_;
    std::map<std::string, SafetyProposal> proposals_;
    mutable std::mutex commits_mutex_;
    std::map<std::string, SafetyCommit> commits_;
    std::atomic<double> avg_consensus_time_ms_{0.0};
    std::function<void(const SafetyCommit&)> on_commit_;
    
    std::thread vote_thread_;
    
    // Vote collection
    mutable std::mutex votes_mutex_;
    std::map<std::string, std::vector<SafetyVote>> pending_votes_;
    std::atomic<int> consensus_count_{0};
    
    // Implementation
    void VoteCollectionLoop();
    void BroadcastProposal(const SafetyProposal& proposal);
    std::vector<SafetyVote> CollectVotes(const std::string& proposal_id, int timeout_ms);
    bool HasRecentCheckpoint() const;
};

// ============================================================================
// Safety Context
// ============================================================================

struct SafetyContext {
    std::string operation_id;
    SafetyPriority priority = SafetyPriority::NORMAL;
    std::string description;
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
        int cache_duration_ms = 5000;
    };
    
    explicit DistributedSafetyGate(const Config& config);
    ~DistributedSafetyGate();
    
    bool Initialize(std::shared_ptr<ConsensusEngine> consensus,
                    std::shared_ptr<NodeDiscovery> discovery);
    void Shutdown();
    
    // Safety check with distributed consensus
    SafetyDecision CheckSafety(const SafetyContext& context);
    
    // Fast path for non-critical operations
    SafetyDecision CheckLocalSafety(const SafetyContext& context);
    
    // Evaluate safety based on context
    SafetyDecision EvaluateSafety(const SafetyContext& context);
    
    // Check if safe to proceed (cached)
    bool IsSafeToProceed(const std::string& operation_id);
    
    // Invalidate cached decision
    void InvalidateCache(const std::string& operation_id);
    
    // Generate unique proposal ID
    static std::string GenerateProposalId();
    
private:
    Config config_;
    std::shared_ptr<ConsensusEngine> consensus_;
    std::shared_ptr<NodeDiscovery> discovery_;
    
    struct CachedDecision {
        SafetyDecision decision;
        std::chrono::steady_clock::time_point timestamp;
        std::string proposal_id;
    };
    
    mutable std::mutex cache_mutex_;
    std::map<std::string, CachedDecision> decision_cache_;
    
    std::function<void(SafetyDecision, const SafetyCommit&)> on_decision_;
    
    void OnConsensusCommit(const SafetyCommit& commit);
};

} // namespace Distributed
} // namespace Sovereign
