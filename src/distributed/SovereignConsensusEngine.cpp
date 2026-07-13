// Sovereign Distributed Runtime - Phase D.3 Batch 2/5
// Consensus Engine Implementation
// Copyright (c) 2026 RawrXD Team

#include "SovereignConsensusEngine.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// SafetyProposal Implementation
// ============================================================================

std::string SafetyProposal::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"proposal_id\":\"" << proposal_id << "\",";
    oss << "\"operation_id\":\"" << operation_id << "\",";
    oss << "\"proposer_node\":\"" << proposer_node << "\",";
    oss << "\"proposed_decision\":" << static_cast<int>(proposed_decision) << ",";
    oss << "\"priority\":" << static_cast<int>(priority) << ",";
    oss << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count() << ",";
    oss << "\"context\":\"" << context << "\",";
    oss << "\"affected_nodes\":[";
    for (size_t i = 0; i < affected_nodes.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << affected_nodes[i] << "\"";
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

SafetyProposal SafetyProposal::FromJson(const std::string& json) {
    SafetyProposal proposal;
    // Simple JSON parsing
    auto extractString = [&](const std::string& key) -> std::string {
        size_t keyPos = json.find("\"" + key + "\":");
        if (keyPos == std::string::npos) return "";
        size_t start = json.find("\"", keyPos + key.length() + 3);
        if (start == std::string::npos) return "";
        size_t end = json.find("\"", start + 1);
        if (end == std::string::npos) return "";
        return json.substr(start + 1, end - start - 1);
    };
    
    auto extractInt = [&](const std::string& key) -> int {
        size_t keyPos = json.find("\"" + key + "\":");
        if (keyPos == std::string::npos) return 0;
        size_t start = keyPos + key.length() + 3;
        size_t end = json.find_first_of(",}", start);
        if (end == std::string::npos) return 0;
        return std::stoi(json.substr(start, end - start));
    };
    
    proposal.proposal_id = extractString("proposal_id");
    proposal.operation_id = extractString("operation_id");
    proposal.proposer_node = extractString("proposer_node");
    proposal.proposed_decision = static_cast<SafetyDecision>(extractInt("proposed_decision"));
    proposal.priority = static_cast<SafetyPriority>(extractInt("priority"));
    proposal.context = extractString("context");
    
    return proposal;
}

// ============================================================================
// SafetyVote Implementation
// ============================================================================

std::string SafetyVote::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"proposal_id\":\"" << proposal_id << "\",";
    oss << "\"voter_node\":\"" << voter_node << "\",";
    oss << "\"vote\":" << (vote ? "true" : "false") << ",";
    oss << "\"rationale\":\"" << rationale << "\",";
    oss << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    oss << "}";
    return oss.str();
}

// ============================================================================
// SafetyCommit Implementation
// ============================================================================

std::string SafetyCommit::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"proposal_id\":\"" << proposal_id << "\",";
    oss << "\"final_decision\":" << static_cast<int>(final_decision) << ",";
    oss << "\"participating_nodes\":" << participating_nodes << ",";
    oss << "\"votes_for\":" << votes_for << ",";
    oss << "\"votes_against\":" << votes_against << ",";
    oss << "\"committed\":" << (committed ? "true" : "false") << ",";
    oss << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    oss << "}";
    return oss.str();
}

// ============================================================================
// ConsensusEngine Implementation
// ============================================================================

ConsensusEngine::ConsensusEngine(const Config& config) : config_(config) {
}

ConsensusEngine::~ConsensusEngine() {
    Shutdown();
}

bool ConsensusEngine::Initialize(std::shared_ptr<NodeDiscovery> discovery) {
    discovery_ = discovery;
    running_ = true;
    
    // Start vote collection thread
    vote_thread_ = std::thread(&ConsensusEngine::VoteCollectionLoop, this);
    
    return true;
}

void ConsensusEngine::Shutdown() {
    running_ = false;
    
    if (vote_thread_.joinable()) {
        vote_thread_.join();
    }
}

SafetyCommit ConsensusEngine::Propose(const SafetyProposal& proposal) {
    SafetyCommit commit;
    commit.proposal_id = proposal.proposal_id;
    commit.final_decision = SafetyDecision::DENY;  // Default to deny
    commit.timestamp = std::chrono::steady_clock::now();
    
    // Check if we have quorum
    auto topology = discovery_->GetTopology();
    if (!topology->HasQuorum()) {
        commit.rationale = "No quorum available";
        return commit;
    }
    
    // Store proposal
    {
        std::lock_guard<std::mutex> lock(proposals_mutex_);
        proposals_[proposal.proposal_id] = proposal;
    }
    
    // Broadcast proposal to all nodes
    BroadcastProposal(proposal);
    
    // Collect votes
    auto votes = CollectVotes(proposal.proposal_id, config_.consensus_timeout_ms);
    
    // Count votes
    int votes_for = 0;
    int votes_against = 0;
    for (const auto& vote : votes) {
        if (vote.vote) {
            votes_for++;
        } else {
            votes_against++;
        }
    }
    
    commit.votes_for = votes_for;
    commit.votes_against = votes_against;
    commit.participating_nodes = votes.size();
    
    // Determine outcome
    int quorum_size = topology->GetQuorumSize();
    bool has_quorum = votes_for >= quorum_size;
    
    if (config_.require_unanimous_safety && 
        (proposal.proposed_decision == SafetyDecision::ROLLBACK ||
         proposal.proposed_decision == SafetyDecision::ESCALATE)) {
        // Require unanimous for critical decisions
        has_quorum = (votes_for == votes.size()) && votes.size() >= quorum_size;
    }
    
    if (has_quorum) {
        commit.final_decision = proposal.proposed_decision;
        commit.committed = true;
        commit.rationale = "Quorum reached";
    } else {
        commit.final_decision = SafetyDecision::DENY;
        commit.committed = false;
        commit.rationale = "Quorum not reached";
    }
    
    // Store commit
    {
        std::lock_guard<std::mutex> lock(commits_mutex_);
        commits_[proposal.proposal_id] = commit;
    }
    
    // Notify callbacks
    if (on_commit_) {
        on_commit_(commit);
    }
    
    return commit;
}

SafetyVote ConsensusEngine::Vote(const SafetyProposal& proposal) {
    SafetyVote vote;
    vote.proposal_id = proposal.proposal_id;
    vote.voter_node = discovery_->GetTopology()->GetHealthyNodes()[0].node_id;
    vote.timestamp = std::chrono::steady_clock::now();
    
    // Simple voting logic - in production, this would evaluate safety metrics
    bool should_approve = true;
    
    // Check if this node is affected
    if (!proposal.affected_nodes.empty()) {
        bool is_affected = false;
        for (const auto& node : proposal.affected_nodes) {
            if (node == vote.voter_node) {
                is_affected = true;
                break;
            }
        }
        
        if (!is_affected) {
            // Not affected, abstain by voting true (neutral)
            should_approve = true;
        }
    }
    
    // Evaluate based on decision type
    switch (proposal.proposed_decision) {
        case SafetyDecision::ALLOW:
            should_approve = true;
            break;
        case SafetyDecision::DENY:
            should_approve = false;
            break;
        case SafetyDecision::DEGRADED:
            should_approve = true;  // Accept degraded mode
            break;
        case SafetyDecision::ROLLBACK:
            // Only approve rollback if we have recent checkpoints
            should_approve = HasRecentCheckpoint();
            break;
        case SafetyDecision::ESCALATE:
            should_approve = true;  // Always allow escalation
            break;
    }
    
    vote.vote = should_approve;
    vote.rationale = should_approve ? "Approved" : "Rejected";
    
    return vote;
}

SafetyCommit ConsensusEngine::GetCommit(const std::string& proposal_id) const {
    std::lock_guard<std::mutex> lock(commits_mutex_);
    auto it = commits_.find(proposal_id);
    if (it != commits_.end()) {
        return it->second;
    }
    return {};
}

bool ConsensusEngine::IsCommitted(const std::string& proposal_id) const {
    std::lock_guard<std::mutex> lock(commits_mutex_);
    auto it = commits_.find(proposal_id);
    if (it != commits_.end()) {
        return it->second.committed;
    }
    return false;
}

void ConsensusEngine::OnCommit(std::function<void(const SafetyCommit&)> callback) {
    on_commit_ = callback;
}

ConsensusEngine::Stats ConsensusEngine::GetStats() const {
    Stats stats;
    
    {
        std::lock_guard<std::mutex> lock(proposals_mutex_);
        stats.proposals_initiated = proposals_.size();
    }
    
    {
        std::lock_guard<std::mutex> lock(commits_mutex_);
        stats.commits_reached = 0;
        stats.commits_failed = 0;
        for (const auto& [id, commit] : commits_) {
            if (commit.committed) {
                stats.commits_reached++;
            } else {
                stats.commits_failed++;
            }
        }
    }
    
    stats.avg_consensus_time_ms = avg_consensus_time_ms_.load();
    
    return stats;
}

void ConsensusEngine::BroadcastProposal(const SafetyProposal& proposal) {
    // Placeholder - in production, send to all nodes via network
    auto nodes = discovery_->GetTopology()->GetHealthyNodes();
    for (const auto& node : nodes) {
        if (node.node_id != proposal.proposer_node) {
            // Send proposal to node
        }
    }
}

std::vector<SafetyVote> ConsensusEngine::CollectVotes(
    const std::string& proposal_id, int timeout_ms) {
    std::vector<SafetyVote> votes;
    
    auto start = std::chrono::steady_clock::now();
    
    while (true) {
        // Check for timeout
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() > timeout_ms) {
            break;
        }
        
        // Collect votes from pending_votes_
        {
            std::lock_guard<std::mutex> lock(votes_mutex_);
            auto it = pending_votes_.find(proposal_id);
            if (it != pending_votes_.end()) {
                votes = it->second;
                
                // Check if we have enough votes
                auto topology = discovery_->GetTopology();
                if (votes.size() >= static_cast<size_t>(topology->GetQuorumSize())) {
                    break;
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Calculate consensus time
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    
    // Update average
    int64_t current_count = consensus_count_.fetch_add(1) + 1;
    double current_avg = avg_consensus_time_ms_.load();
    double new_avg = current_avg + (elapsed_ms - current_avg) / current_count;
    avg_consensus_time_ms_.store(new_avg);
    
    return votes;
}

void ConsensusEngine::VoteCollectionLoop() {
    while (running_) {
        // Process incoming votes
        // In production, this would receive votes from network
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

bool ConsensusEngine::HasRecentCheckpoint() const {
    // Placeholder - check if we have a recent checkpoint
    return true;
}

// ============================================================================
// DistributedSafetyGate Implementation
// ============================================================================

DistributedSafetyGate::DistributedSafetyGate(const Config& config) : config_(config) {
}

DistributedSafetyGate::~DistributedSafetyGate() {
    Shutdown();
}

bool DistributedSafetyGate::Initialize(std::shared_ptr<ConsensusEngine> consensus,
                                       std::shared_ptr<NodeDiscovery> discovery) {
    consensus_ = consensus;
    discovery_ = discovery;
    
    // Register for commit notifications
    consensus_->OnCommit([this](const SafetyCommit& commit) {
        OnConsensusCommit(commit);
    });
    
    return true;
}

void DistributedSafetyGate::Shutdown() {
}

SafetyDecision DistributedSafetyGate::CheckSafety(const SafetyContext& context) {
    // Check if we're in a distributed context
    auto topology = discovery_->GetTopology();
    auto nodes = topology->GetHealthyNodes();
    
    if (nodes.size() <= 1) {
        // Single node - use local safety check
        return CheckLocalSafety(context);
    }
    
    // Multi-node - use consensus
    SafetyProposal proposal;
    proposal.proposal_id = GenerateProposalId();
    proposal.operation_id = context.operation_id;
    proposal.proposer_node = nodes[0].node_id;
    proposal.proposed_decision = EvaluateSafety(context);
    proposal.priority = context.priority;
    proposal.context = context.description;
    
    for (const auto& node : nodes) {
        proposal.affected_nodes.push_back(node.node_id);
    }
    
    auto commit = consensus_->Propose(proposal);
    
    if (commit.committed) {
        return commit.final_decision;
    }
    
    // Consensus failed - fail closed
    return SafetyDecision::DENY;
}

bool DistributedSafetyGate::IsSafeToProceed(const std::string& operation_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    auto it = decision_cache_.find(operation_id);
    if (it != decision_cache_.end()) {
        // Check if decision is still valid
        auto elapsed = std::chrono::steady_clock::now() - it->second.timestamp;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() < 
            config_.cache_duration_ms) {
            return it->second.decision == SafetyDecision::ALLOW ||
                   it->second.decision == SafetyDecision::DEGRADED;
        }
    }
    
    return false;  // No valid cached decision
}

void DistributedSafetyGate::InvalidateCache(const std::string& operation_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    decision_cache_.erase(operation_id);
}

void DistributedSafetyGate::OnConsensusCommit(const SafetyCommit& commit) {
    // Cache the decision
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    CachedDecision cached;
    cached.decision = commit.final_decision;
    cached.timestamp = commit.timestamp;
    cached.proposal_id = commit.proposal_id;
    
    // Extract operation_id from proposal
    SafetyProposal proposal;
    {
        std::lock_guard<std::mutex> plock(proposals_mutex_);
        auto it = proposals_.find(commit.proposal_id);
        if (it != proposals_.end()) {
            proposal = it->second;
        }
    }
    
    if (!proposal.operation_id.empty()) {
        decision_cache_[proposal.operation_id] = cached;
    }
    
    // Notify callbacks
    if (on_decision_) {
        on_decision_(commit.final_decision, commit);
    }
}

SafetyDecision DistributedSafetyGate::CheckLocalSafety(const SafetyContext& context) {
    // Simple local safety check
    if (context.priority == SafetyPriority::CRITICAL) {
        return SafetyDecision::ESCALATE;
    }
    return SafetyDecision::ALLOW;
}

SafetyDecision DistributedSafetyGate::EvaluateSafety(const SafetyContext& context) {
    // Evaluate based on context
    if (context.priority == SafetyPriority::CRITICAL) {
        return SafetyDecision::ESCALATE;
    }
    
    if (context.priority == SafetyPriority::HIGH) {
        return SafetyDecision::ALLOW;
    }
    
    return SafetyDecision::ALLOW;
}

std::string DistributedSafetyGate::GenerateProposalId() {
    static std::atomic<int64_t> counter{0};
    int64_t id = counter.fetch_add(1);
    
    std::ostringstream oss;
    oss << "proposal-" << id << "-" << 
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    return oss.str();
}

} // namespace Distributed
} // namespace Sovereign
