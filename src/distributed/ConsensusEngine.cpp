/**
 * ConsensusEngine.cpp
 *
 * Phase D.3 Batch 3/5: Distributed Consensus & Leadership
 *
 * Raft consensus implementation for distributed state machine replication.
 */

#include "ConsensusEngine.hpp"
#include "../core/Logger.hpp"
#include "../core/ErrorCodes.hpp"
#include <chrono>
#include <random>
#include <fstream>

namespace Distributed {

// ============================================================================
// NodeRole Helpers
// ============================================================================

std::string NodeRoleToString(NodeRole role) {
    switch (role) {
        case NodeRole::FOLLOWER:  return "follower";
        case NodeRole::CANDIDATE: return "candidate";
        case NodeRole::LEADER:    return "leader";
        default: return "unknown";
    }
}

// ============================================================================
// LogEntry Implementation
// ============================================================================

std::string LogEntry::ToJson() const {
    std::string typeStr;
    switch (type) {
        case LogEntryType::COMMAND:       typeStr = "command"; break;
        case LogEntryType::CONFIG_CHANGE: typeStr = "config"; break;
        case LogEntryType::NO_OP:         typeStr = "noop"; break;
    }
    
    std::string json = "{";
    json += "\"index\":" + std::to_string(index) + ",";
    json += "\"term\":" + std::to_string(term) + ",";
    json += "\"type\":\"" + typeStr + "\",";
    json += "\"clientId\":\"" + clientId + "\",";
    json += "\"data\":\"" + std::string(data.begin(), data.end()) + "\"";
    json += "}";
    return json;
}

LogEntry LogEntry::FromJson(const std::string& json) {
    LogEntry entry;
    // Simplified parsing - in production use proper JSON library
    return entry;
}

// ============================================================================
// LogState Implementation
// ============================================================================

std::string LogState::ToJson() const {
    std::string json = "{";
    json += "\"lastIndex\":" + std::to_string(lastIndex) + ",";
    json += "\"lastTerm\":" + std::to_string(lastTerm) + ",";
    json += "\"commitIndex\":" + std::to_string(commitIndex) + ",";
    json += "\"lastApplied\":" + std::to_string(lastApplied);
    json += "}";
    return json;
}

// ============================================================================
// PersistentState Implementation
// ============================================================================

std::string PersistentState::ToJson() const {
    std::string json = "{";
    json += "\"currentTerm\":" + std::to_string(currentTerm) + ",";
    json += "\"votedFor\":\"" + votedFor + "\",";
    json += "\"log\":[";
    for (size_t i = 0; i < log.size(); i++) {
        if (i > 0) json += ",";
        json += log[i].ToJson();
    }
    json += "]}";
    return json;
}

PersistentState PersistentState::FromJson(const std::string& json) {
    PersistentState state;
    // Simplified parsing
    return state;
}

// ============================================================================
// RaftConsensus Implementation
// ============================================================================

RaftConsensus::RaftConsensus(
    std::shared_ptr<CommunicationManager> commManager,
    const RaftConfig& config
) : commManager_(commManager), config_(config) {}

RaftConsensus::~RaftConsensus() {
    Shutdown();
}

bool RaftConsensus::Initialize() {
    running_ = true;
    
    // Load persistent state
    LoadState();
    
    // Initialize timing
    ResetElectionTimer();
    lastHeartbeat_ = GetCurrentTimeMs();
    
    // Start background threads
    electionThread_ = std::thread(&RaftConsensus::ElectionLoop, this);
    heartbeatThread_ = std::thread(&RaftConsensus::HeartbeatLoop, this);
    applyThread_ = std::thread(&RaftConsensus::ApplyLoop, this);
    
    LOG_INFO("Raft consensus initialized, starting as follower");
    return true;
}

void RaftConsensus::Shutdown() {
    running_ = false;
    
    if (electionThread_.joinable()) {
        electionThread_.join();
    }
    if (heartbeatThread_.joinable()) {
        heartbeatThread_.join();
    }
    if (applyThread_.joinable()) {
        applyThread_.join();
    }
    
    // Save state
    SaveState();
}

NodeRole RaftConsensus::GetRole() const {
    return role_.load();
}

bool RaftConsensus::IsLeader() const {
    return role_.load() == NodeRole::LEADER;
}

bool RaftConsensus::IsFollower() const {
    return role_.load() == NodeRole::FOLLOWER;
}

bool RaftConsensus::IsCandidate() const {
    return role_.load() == NodeRole::CANDIDATE;
}

std::string RaftConsensus::GetLeaderId() const {
    return leaderId_;
}

uint64_t RaftConsensus::GetCurrentTerm() const {
    return currentTerm_.load();
}

std::future<bool> RaftConsensus::SubmitCommand(const std::vector<uint8_t>& data) {
    std::promise<bool> promise;
    auto future = promise.get_future();
    
    if (!IsLeader()) {
        promise.set_value(false);
        return future;
    }
    
    // Create log entry
    LogEntry entry;
    entry.term = currentTerm_.load();
    entry.type = LogEntryType::COMMAND;
    entry.data = data;
    
    // Append to log
    uint64_t index = AppendEntry(entry);
    
    // Store promise for later fulfillment
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        PendingCommand pending;
        pending.index = index;
        pending.promise = std::move(promise);
        pendingCommands_[index] = std::move(pending);
    }
    
    // Replicate to followers
    ReplicateLogEntry(index);
    
    return future;
}

std::future<bool> RaftConsensus::SubmitCommand(const std::string& data) {
    return SubmitCommand(std::vector<uint8_t>(data.begin(), data.end()));
}

std::future<bool> RaftConsensus::SubmitCommandJson(const std::string& json) {
    return SubmitCommand(json);
}

bool RaftConsensus::AddNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    if (members_.size() >= config_.maxNodes) {
        return false;
    }
    
    members_.insert(nodeId);
    
    // If leader, initialize replication state for new node
    if (IsLeader()) {
        std::lock_guard<std::mutex> logLock(logMutex_);
        nextIndex_[nodeId] = log_.size() + 1;
        matchIndex_[nodeId] = 0;
    }
    
    return true;
}

bool RaftConsensus::RemoveNode(const std::string& nodeId) {
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    members_.erase(nodeId);
    nextIndex_.erase(nodeId);
    matchIndex_.erase(nodeId);
    
    return true;
}

std::vector<std::string> RaftConsensus::GetClusterMembers() {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return std::vector<std::string>(members_.begin(), members_.end());
}

LogState RaftConsensus::GetLogState() const {
    std::lock_guard<std::mutex> lock(logMutex_);
    
    LogState state;
    state.lastIndex = log_.empty() ? 0 : log_.back().index;
    state.lastTerm = log_.empty() ? 0 : log_.back().term;
    state.commitIndex = commitIndex_.load();
    state.lastApplied = lastApplied_.load();
    
    return state;
}

std::optional<LogEntry> RaftConsensus::GetLogEntry(uint64_t index) {
    std::lock_guard<std::mutex> lock(logMutex_);
    
    if (index == 0 || index > log_.size()) {
        return std::nullopt;
    }
    
    return log_[index - 1];
}

std::vector<LogEntry> RaftConsensus::GetLogEntries(uint64_t start, uint64_t end) {
    std::lock_guard<std::mutex> lock(logMutex_);
    
    std::vector<LogEntry> result;
    for (uint64_t i = start; i <= end && i <= log_.size(); i++) {
        result.push_back(log_[i - 1]);
    }
    
    return result;
}

void RaftConsensus::SetCallbacks(const ConsensusCallbacks& callbacks) {
    callbacks_ = callbacks;
}

bool RaftConsensus::SaveState() {
    std::lock_guard<std::mutex> lock(logMutex_);
    
    PersistentState state;
    state.currentTerm = currentTerm_.load();
    state.votedFor = votedFor_;
    state.log = log_;
    
    std::ofstream file(GetStateFilePath());
    if (!file.is_open()) {
        return false;
    }
    
    file << state.ToJson();
    file.close();
    
    return true;
}

bool RaftConsensus::LoadState() {
    std::ifstream file(GetStateFilePath());
    if (!file.is_open()) {
        return false;
    }
    
    std::string json((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();
    
    PersistentState state = PersistentState::FromJson(json);
    currentTerm_ = state.currentTerm;
    votedFor_ = state.votedFor;
    log_ = state.log;
    
    return true;
}

std::string RaftConsensus::GetStatusJson() const {
    LogState logState = GetLogState();
    
    std::string json = "{";
    json += "\"role\":\"" + NodeRoleToString(role_.load()) + "\",";
    json += "\"term\":" + std::to_string(currentTerm_.load()) + ",";
    json += "\"leader\":\"" + leaderId_ + "\",";
    json += "\"log\":" + logState.ToJson() + ",";
    json += "\"members\":" + std::to_string(members_.size()) + ",";
    json += "\"healthy\":" + std::string(IsHealthy() ? "true" : "false");
    json += "}";
    
    return json;
}

bool RaftConsensus::IsHealthy() const {
    if (IsLeader()) {
        // Leader needs quorum
        size_t active = 1;  // Count self
        {
            std::lock_guard<std::mutex> lock(stateMutex_);
            for (const auto& [nodeId, matchIdx] : matchIndex_) {
                if (matchIdx >= commitIndex_.load()) {
                    active++;
                }
            }
        }
        return active >= GetQuorumSize();
    }
    
    // Follower/candidate just needs recent heartbeat
    return (GetCurrentTimeMs() - lastHeartbeat_) < (config_.maxElectionTimeout * 2);
}

void RaftConsensus::StepDown() {
    if (role_.load() == NodeRole::LEADER) {
        BecomeFollower(currentTerm_.load());
    }
}

void RaftConsensus::ForceElection() {
    StartElection();
}

// ============================================================================
// Background Loops
// ============================================================================

void RaftConsensus::ElectionLoop() {
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        if (!running_) break;
        
        // Check if election timeout elapsed
        uint64_t elapsed = GetCurrentTimeMs() - lastHeartbeat_;
        if (elapsed > electionTimeout_.load()) {
            if (role_.load() != NodeRole::LEADER) {
                StartElection();
            }
        }
    }
}

void RaftConsensus::HeartbeatLoop() {
    while (running_) {
        if (IsLeader()) {
            // Send heartbeats to all followers
            std::lock_guard<std::mutex> lock(stateMutex_);
            
            for (const auto& member : members_) {
                Message msg;
                msg.header.type = MessageType::HEARTBEAT;
                msg.header.destinationNode = member;
                
                // Include log info
                {
                    std::lock_guard<std::mutex> logLock(logMutex_);
                    msg.header.sequence = currentTerm_.load();
                    
                    // Get prev log info
                    uint64_t nextIdx = nextIndex_[member];
                    uint64_t prevIndex = nextIdx - 1;
                    uint64_t prevTerm = 0;
                    
                    if (prevIndex > 0 && prevIndex <= log_.size()) {
                        prevTerm = log_[prevIndex - 1].term;
                    }
                    
                    // TODO: Include entries to replicate
                }
                
                commManager_->SendMessage(member, msg);
            }
            
            lastHeartbeat_ = GetCurrentTimeMs();
        }
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.heartbeatInterval));
    }
}

void RaftConsensus::ApplyLoop() {
    while (running_) {
        ApplyCommittedEntries();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// ============================================================================
// Message Handlers
// ============================================================================

void RaftConsensus::HandleRequestVote(const Message& message) {
    // Parse request
    uint64_t term = message.header.sequence;
    std::string candidateId = message.header.sourceNode;
    
    // If term > currentTerm, become follower
    if (term > currentTerm_.load()) {
        BecomeFollower(term);
    }
    
    // Check if we can vote for this candidate
    bool voteGranted = false;
    if (term == currentTerm_.load() && CanVoteFor(candidateId, term)) {
        // Check if candidate's log is at least as up-to-date
        // TODO: Parse lastLogIndex and lastLogTerm from message
        voteGranted = true;
        votedFor_ = candidateId;
        SaveState();
    }
    
    // Send response
    Message response;
    response.header.type = MessageType::RPC_RESPONSE;
    response.header.destinationNode = candidateId;
    response.header.sequence = term;
    response.payload = voteGranted ? "true" : "false";
    
    commManager_->SendMessage(candidateId, response);
}

void RaftConsensus::HandleRequestVoteResponse(const Message& message) {
    if (role_.load() != NodeRole::CANDIDATE) {
        return;
    }
    
    uint64_t term = message.header.sequence;
    bool granted = (message.payload == "true");
    
    if (term > currentTerm_.load()) {
        BecomeFollower(term);
        return;
    }
    
    if (term == currentTerm_.load() && granted) {
        // Record vote
        static std::set<std::string> votes;
        votes.insert(message.header.sourceNode);
        
        if (HasQuorum(votes)) {
            BecomeLeader();
        }
    }
}

void RaftConsensus::HandleAppendEntries(const Message& message) {
    uint64_t term = message.header.sequence;
    
    // If term > currentTerm, become follower
    if (term > currentTerm_.load()) {
        BecomeFollower(term);
    }
    
    if (term < currentTerm_.load()) {
        // Reject
        return;
    }
    
    // Valid heartbeat/append from leader
    leaderId_ = message.header.sourceNode;
    lastHeartbeat_ = GetCurrentTimeMs();
    ResetElectionTimer();
    
    if (role_.load() != NodeRole::FOLLOWER) {
        BecomeFollower(term);
    }
    
    // TODO: Process log entries
}

void RaftConsensus::HandleAppendEntriesResponse(const Message& message) {
    if (!IsLeader()) {
        return;
    }
    
    // TODO: Update matchIndex and nextIndex
    // TODO: Advance commit index
}

void RaftConsensus::HandleInstallSnapshot(const Message& message) {
    // TODO: Handle snapshot installation
}

// ============================================================================
// Raft Operations
// ============================================================================

void RaftConsensus::StartElection() {
    BecomeCandidate();
    
    // Request votes from all members
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    for (const auto& member : members_) {
        Message msg;
        msg.header.type = MessageType::ELECTION_VOTE_REQUEST;
        msg.header.destinationNode = member;
        msg.header.sequence = currentTerm_.load();
        
        // Include log info
        {
            std::lock_guard<std::mutex> logLock(logMutex_);
            uint64_t lastIdx = log_.empty() ? 0 : log_.back().index;
            uint64_t lastTerm = log_.empty() ? 0 : log_.back().term;
            
            msg.payload = "{\"lastLogIndex\":" + std::to_string(lastIdx) +
                       ",\"lastLogTerm\":" + std::to_string(lastTerm) + "}";
        }
        
        commManager_->SendMessage(member, msg);
    }
}

void RaftConsensus::BecomeFollower(uint64_t term) {
    role_ = NodeRole::FOLLOWER;
    currentTerm_ = term;
    votedFor_.clear();
    SaveState();
    
    ResetElectionTimer();
    
    LOG_INFO("Became follower for term " + std::to_string(term));
}

void RaftConsensus::BecomeCandidate() {
    role_ = NodeRole::CANDIDATE;
    currentTerm_++;
    votedFor_ = "self";  // Vote for self
    SaveState();
    
    ResetElectionTimer();
    
    LOG_INFO("Became candidate for term " + std::to_string(currentTerm_.load()));
}

void RaftConsensus::BecomeLeader() {
    role_ = NodeRole::LEADER;
    leaderId_ = "self";  // TODO: Use actual node ID
    
    // Initialize leader state
    {
        std::lock_guard<std::mutex> lock(logMutex_);
        uint64_t lastIdx = log_.empty() ? 0 : log_.back().index;
        
        for (const auto& member : members_) {
            nextIndex_[member] = lastIdx + 1;
            matchIndex_[member] = 0;
        }
    }
    
    // Send initial heartbeat
    lastHeartbeat_ = GetCurrentTimeMs();
    
    NotifyLeadershipChange(true);
    LOG_INFO("Became leader for term " + std::to_string(currentTerm_.load()));
}

void RaftConsensus::StepDownInternal() {
    if (role_.load() == NodeRole::LEADER) {
        NotifyLeadershipChange(false);
    }
    role_ = NodeRole::FOLLOWER;
}

// ============================================================================
// Log Operations
// ============================================================================

uint64_t RaftConsensus::AppendEntry(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(logMutex_);
    
    LogEntry newEntry = entry;
    newEntry.index = log_.size() + 1;
    
    log_.push_back(newEntry);
    SaveState();
    
    return newEntry.index;
}

bool RaftConsensus::ReplicateLogEntry(uint64_t index) {
    if (!IsLeader()) {
        return false;
    }
    
    // Trigger replication to all followers
    std::lock_guard<std::mutex> lock(stateMutex_);
    
    for (const auto& member : members_) {
        Message msg;
        msg.header.type = MessageType::STATE_DELTA;
        msg.header.destinationNode = member;
        
        // TODO: Include log entry
        
        commManager_->SendMessage(member, msg);
    }
    
    return true;
}

void RaftConsensus::AdvanceCommitIndex() {
    if (!IsLeader()) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(logMutex_);
    
    // Find highest index replicated on majority
    for (uint64_t idx = commitIndex_.load() + 1; idx <= log_.size(); idx++) {
        if (log_[idx - 1].term != currentTerm_.load()) {
            continue;  // Only commit entries from current term
        }
        
        size_t replicated = 1;  // Count self
        for (const auto& [nodeId, matchIdx] : matchIndex_) {
            if (matchIdx >= idx) {
                replicated++;
            }
        }
        
        if (replicated >= GetQuorumSize()) {
            commitIndex_ = idx;
        } else {
            break;
        }
    }
}

void RaftConsensus::ApplyCommittedEntries() {
    while (lastApplied_.load() < commitIndex_.load()) {
        uint64_t idx = lastApplied_.load() + 1;
        
        auto entry = GetLogEntry(idx);
        if (entry) {
            NotifyApply(*entry);
            lastApplied_++;
        } else {
            break;
        }
    }
}

// ============================================================================
// Voting
// ============================================================================

bool RaftConsensus::CanVoteFor(const std::string& candidateId, uint64_t term) {
    if (term < currentTerm_.load()) {
        return false;
    }
    
    if (term > currentTerm_.load()) {
        return true;
    }
    
    // Same term - check if already voted
    return votedFor_.empty() || votedFor_ == candidateId;
}

bool RaftConsensus::IsLogUpToDate(uint64_t lastIndex, uint64_t lastTerm) {
    std::lock_guard<std::mutex> lock(logMutex_);
    
    uint64_t myLastIndex = log_.empty() ? 0 : log_.back().index;
    uint64_t myLastTerm = log_.empty() ? 0 : log_.back().term;
    
    if (lastTerm != myLastTerm) {
        return lastTerm > myLastTerm;
    }
    
    return lastIndex >= myLastIndex;
}

// ============================================================================
// Quorum
// ============================================================================

size_t RaftConsensus::GetQuorumSize() const {
    std::lock_guard<std::mutex> lock(stateMutex_);
    return (members_.size() + 1) / 2 + 1;  // Majority
}

bool RaftConsensus::HasQuorum(const std::set<std::string>& votes) {
    return votes.size() >= GetQuorumSize();
}

// ============================================================================
// Utility
// ============================================================================

uint64_t RaftConsensus::GetRandomElectionTimeout() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(
        config_.minElectionTimeout,
        config_.maxElectionTimeout
    );
    return dist(gen);
}

uint64_t RaftConsensus::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void RaftConsensus::ResetElectionTimer() {
    electionTimeout_ = GetRandomElectionTimeout();
    lastHeartbeat_ = GetCurrentTimeMs();
}

std::string RaftConsensus::GetStateFilePath() const {
    return "raft_state.json";
}

void RaftConsensus::NotifyLeadershipChange(bool isLeader) {
    if (callbacks_.onLeadership) {
        callbacks_.onLeadership(isLeader);
    }
}

void RaftConsensus::NotifyApply(const LogEntry& entry) {
    // Fulfill pending command promise
    {
        std::lock_guard<std::mutex> lock(pendingMutex_);
        auto it = pendingCommands_.find(entry.index);
        if (it != pendingCommands_.end()) {
            it->second.promise.set_value(true);
            pendingCommands_.erase(it);
        }
    }
    
    if (callbacks_.onApply) {
        callbacks_.onApply(entry);
    }
}

// ============================================================================
// LeaderElection Implementation
// ============================================================================

LeaderElection::LeaderElection(RaftConsensus* raft) : raft_(raft) {}

LeaderElection::~LeaderElection() = default;

void LeaderElection::StartElection() {
    electionInProgress_ = true;
    electionTerm_ = raft_->GetCurrentTerm();
    votesGranted_.clear();
    votesRejected_.clear();
}

void LeaderElection::CancelElection() {
    electionInProgress_ = false;
}

void LeaderElection::RecordVote(const std::string& nodeId, bool granted) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (granted) {
        votesGranted_.insert(nodeId);
    } else {
        votesRejected_.insert(nodeId);
    }
}

bool LeaderElection::HasMajority() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: Calculate based on cluster size
    return votesGranted_.size() >= 2;  // Placeholder
}

bool LeaderElection::IsElectionInProgress() const {
    return electionInProgress_.load();
}

uint64_t LeaderElection::GetElectionTerm() const {
    return electionTerm_.load();
}

size_t LeaderElection::GetVoteCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return votesGranted_.size();
}

// ============================================================================
// LogReplicator Implementation
// ============================================================================

LogReplicator::LogReplicator(
    RaftConsensus* raft,
    std::shared_ptr<CommunicationManager> commManager
) : raft_(raft), commManager_(commManager) {}

LogReplicator::~LogReplicator() {
    Shutdown();
}

bool LogReplicator::Initialize() {
    running_ = true;
    return true;
}

void LogReplicator::Shutdown() {
    running_ = false;
}

bool LogReplicator::ReplicateTo(const std::string& peerNodeId, uint64_t index) {
    // TODO: Implement single entry replication
    return true;
}

bool LogReplicator::ReplicateToAll(uint64_t index) {
    // TODO: Implement replication to all peers
    return true;
}

bool LogReplicator::ReplicateBatch(const std::string& peerNodeId, uint64_t startIndex) {
    // TODO: Implement batch replication
    return true;
}

void LogReplicator::HandleAppendSuccess(const std::string& peerNodeId, uint64_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: Update match index
}

void LogReplicator::HandleAppendFailure(const std::string& peerNodeId, uint64_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: Decrement next index and retry
}

uint64_t LogReplicator::GetNextIndex(const std::string& peerNodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: Return next index
    return 0;
}

uint64_t LogReplicator::GetMatchIndex(const std::string& peerNodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: Return match index
    return 0;
}

void LogReplicator::SetNextIndex(const std::string& peerNodeId, uint64_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: Set next index
}

void LogReplicator::SetMatchIndex(const std::string& peerNodeId, uint64_t index) {
    std::lock_guard<std::mutex> lock(mutex_);
    // TODO: Set match index
}

bool LogReplicator::IsCaughtUp(const std::string& peerNodeId) {
    // TODO: Check if peer is caught up
    return false;
}

uint64_t LogReplicator::GetReplicationProgress(const std::string& peerNodeId) {
    // TODO: Calculate progress
    return 0;
}

// ============================================================================
// ConsensusManager Implementation
// ============================================================================

ConsensusManager::ConsensusManager(
    std::shared_ptr<CommunicationManager> commManager,
    const RaftConfig& config
) {
    consensus_ = std::make_unique<RaftConsensus>(commManager, config);
}

ConsensusManager::~ConsensusManager() {
    Shutdown();
}

bool ConsensusManager::Initialize() {
    return consensus_->Initialize();
}

void ConsensusManager::Shutdown() {
    if (consensus_) {
        consensus_->Shutdown();
    }
}

RaftConsensus* ConsensusManager::GetConsensus() {
    return consensus_.get();
}

bool ConsensusManager::IsLeader() const {
    return consensus_->IsLeader();
}

std::future<bool> ConsensusManager::Submit(const std::vector<uint8_t>& data) {
    return consensus_->SubmitCommand(data);
}

std::future<bool> ConsensusManager::Submit(const std::string& data) {
    return consensus_->SubmitCommand(data);
}

bool ConsensusManager::WaitForLeader(uint64_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (!consensus_->GetLeaderId().empty()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return true;
}

bool ConsensusManager::WaitForCommit(uint64_t index, uint64_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (consensus_->GetLogState().commitIndex < index) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();
        
        if (elapsed >= timeoutMs) {
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return true;
}

std::string ConsensusManager::GetStatusJson() const {
    return consensus_->GetStatusJson();
}

} // namespace Distributed
