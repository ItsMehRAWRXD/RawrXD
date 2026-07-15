/**
 * ConsensusEngine.hpp
 *
 * Phase D.3 Batch 3/5: Distributed Consensus & Leadership
 *
 * Raft consensus implementation for distributed state machine replication.
 * Ensures strong consistency for critical operations.
 */

#pragma once

#include "StateSync.hpp"
#include <functional>
#include <queue>

namespace Distributed {

// ============================================================================
// Forward Declarations
// ============================================================================

class RaftConsensus;
class LogReplicator;
class LeaderElection;

// ============================================================================
// Consensus Types
// ============================================================================

enum class NodeRole {
    FOLLOWER,   // Follows leader
    CANDIDATE,  // Running for leader
    LEADER      // Current leader
};

std::string NodeRoleToString(NodeRole role);

enum class LogEntryType {
    COMMAND,        // User command
    CONFIG_CHANGE,  // Cluster membership change
    NO_OP          // No-op (leader establishment)
};

// ============================================================================
// Log Entry
// ============================================================================

/**
 * Single entry in the replicated log.
 */
struct LogEntry {
    uint64_t index;           // Position in log
    uint64_t term;            // Term when entry was created
    LogEntryType type;        // Entry type
    std::vector<uint8_t> data; // Entry data
    std::string clientId;     // Client that submitted (for commands)
    
    std::string ToJson() const;
    static LogEntry FromJson(const std::string& json);
};

// ============================================================================
// Log State
// ============================================================================

/**
 * Current state of the replicated log.
 */
struct LogState {
    uint64_t lastIndex = 0;       // Index of last entry
    uint64_t lastTerm = 0;        // Term of last entry
    uint64_t commitIndex = 0;     // Highest committed entry
    uint64_t lastApplied = 0;     // Highest applied to state machine
    
    std::string ToJson() const;
};

// ============================================================================
// Vote Record
// ============================================================================

/**
 * Records a vote in an election.
 */
struct VoteRecord {
    uint64_t term;            // Term voted in
    std::string votedFor;     // Node voted for
    uint64_t timestamp;       // When vote was cast
    bool granted;             // Whether vote was granted
};

// ============================================================================
// Raft Configuration
// ============================================================================

/**
 * Configuration for Raft consensus.
 */
struct RaftConfig {
    // Timing (in milliseconds)
    uint64_t minElectionTimeout = 150;   // Min election timeout
    uint64_t maxElectionTimeout = 300;   // Max election timeout
    uint64_t heartbeatInterval = 50;     // Leader heartbeat interval
    
    // Performance
    uint64_t maxLogEntriesPerRpc = 100;  // Max entries per AppendEntries
    uint64_t rpcTimeoutMs = 100;           // RPC timeout
    
    // Safety
    bool preVote = true;                  // Enable pre-vote optimization
    bool checkQuorum = true;              // Check quorum for leader
    bool leaderLease = false;             // Enable leader lease
    
    // Snapshotting
    uint64_t snapshotThreshold = 10000;   // Entries before snapshot
    uint64_t snapshotIntervalMs = 60000;  // Snapshot interval
    
    // Membership
    size_t maxNodes = 7;                  // Maximum cluster size
};

// ============================================================================
// Raft State
// ============================================================================

/**
 * Persistent Raft state (must be saved to disk).
 */
struct PersistentState {
    uint64_t currentTerm = 0;           // Latest term seen
    std::string votedFor;               // Candidate voted for in current term
    std::vector<LogEntry> log;          // Replicated log entries
    
    std::string ToJson() const;
    static PersistentState FromJson(const std::string& json);
};

/**
 * Volatile Raft state (rebuilt on restart).
 */
struct VolatileState {
    uint64_t commitIndex = 0;           // Index of highest committed entry
    uint64_t lastApplied = 0;           // Index of highest applied entry
    
    // Leader only
    std::map<std::string, uint64_t> nextIndex;   // Next log index per peer
    std::map<std::string, uint64_t> matchIndex;  // Highest replicated per peer
};

// ============================================================================
// Consensus Callbacks
// ============================================================================

/**
 * Callbacks for consensus events.
 */
struct ConsensusCallbacks {
    using ApplyCallback = std::function<void(const LogEntry&)>;
    using LeadershipCallback = std::function<void(bool isLeader)>;
    using MembershipCallback = std::function<void(const std::vector<std::string>&)>;
    
    ApplyCallback onApply;              // Called when entry applied
    LeadershipCallback onLeadership;    // Called on leadership change
    MembershipCallback onMembership;    // Called on membership change
};

// ============================================================================
// Raft Consensus
// ============================================================================

/**
 * Raft consensus implementation.
 */
class RaftConsensus {
public:
    RaftConsensus(
        std::shared_ptr<CommunicationManager> commManager,
        const RaftConfig& config = RaftConfig{}
    );
    ~RaftConsensus();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // State queries
    NodeRole GetRole() const;
    bool IsLeader() const;
    bool IsFollower() const;
    bool IsCandidate() const;
    std::string GetLeaderId() const;
    uint64_t GetCurrentTerm() const;
    
    // Command submission
    std::future<bool> SubmitCommand(const std::vector<uint8_t>& data);
    std::future<bool> SubmitCommand(const std::string& data);
    std::future<bool> SubmitCommandJson(const std::string& json);
    
    // Configuration changes
    bool AddNode(const std::string& nodeId);
    bool RemoveNode(const std::string& nodeId);
    std::vector<std::string> GetClusterMembers();
    
    // Log queries
    LogState GetLogState() const;
    std::optional<LogEntry> GetLogEntry(uint64_t index);
    std::vector<LogEntry> GetLogEntries(uint64_t start, uint64_t end);
    
    // Callbacks
    void SetCallbacks(const ConsensusCallbacks& callbacks);
    
    // Persistence
    bool SaveState();
    bool LoadState();
    
    // Status
    std::string GetStatusJson() const;
    bool IsHealthy() const;
    
    // Manual operations (for testing/debugging)
    void StepDown();
    void ForceElection();
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    RaftConfig config_;
    ConsensusCallbacks callbacks_;
    
    // State
    std::atomic<NodeRole> role_{NodeRole::FOLLOWER};
    std::atomic<uint64_t> currentTerm_{0};
    std::string votedFor_;
    std::string leaderId_;
    
    // Log
    std::vector<LogEntry> log_;
    std::atomic<uint64_t> commitIndex_{0};
    std::atomic<uint64_t> lastApplied_{0};
    
    // Leader state
    std::map<std::string, uint64_t> nextIndex_;
    std::map<std::string, uint64_t> matchIndex_;
    
    // Timing
    std::atomic<uint64_t> lastHeartbeat_{0};
    std::atomic<uint64_t> electionTimeout_{0};
    
    // Cluster membership
    std::set<std::string> members_;
    
    // Threading
    mutable std::mutex stateMutex_;
    mutable std::mutex logMutex_;
    std::atomic<bool> running_{false};
    
    std::thread electionThread_;
    std::thread heartbeatThread_;
    std::thread applyThread_;
    
    // Pending commands
    struct PendingCommand {
        uint64_t index;
        std::promise<bool> promise;
    };
    std::map<uint64_t, PendingCommand> pendingCommands_;
    std::mutex pendingMutex_;
    
    // Background loops
    void ElectionLoop();
    void HeartbeatLoop();
    void ApplyLoop();
    
    // Message handlers
    void HandleRequestVote(const Message& message);
    void HandleRequestVoteResponse(const Message& message);
    void HandleAppendEntries(const Message& message);
    void HandleAppendEntriesResponse(const Message& message);
    void HandleInstallSnapshot(const Message& message);
    
    // Raft operations
    void StartElection();
    void BecomeFollower(uint64_t term);
    void BecomeCandidate();
    void BecomeLeader();
    void StepDownInternal();
    
    // Log operations
    uint64_t AppendEntry(const LogEntry& entry);
    bool ReplicateLogEntry(uint64_t index);
    void AdvanceCommitIndex();
    void ApplyCommittedEntries();
    
    // Voting
    bool CanVoteFor(const std::string& candidateId, uint64_t term);
    bool IsLogUpToDate(uint64_t lastIndex, uint64_t lastTerm);
    
    // Quorum
    size_t GetQuorumSize() const;
    bool HasQuorum(const std::set<std::string>& votes);
    
    // Persistence
    std::string GetStateFilePath() const;
    
    // Utility
    uint64_t GetRandomElectionTimeout() const;
    uint64_t GetCurrentTimeMs() const;
    void ResetElectionTimer();
    
    // Notify callbacks
    void NotifyLeadershipChange(bool isLeader);
    void NotifyApply(const LogEntry& entry);
};

// ============================================================================
// Leader Election
// ============================================================================

/**
 * Manages leader election process.
 */
class LeaderElection {
public:
    explicit LeaderElection(RaftConsensus* raft);
    ~LeaderElection();
    
    // Start election
    void StartElection();
    void CancelElection();
    
    // Vote handling
    void RecordVote(const std::string& nodeId, bool granted);
    bool HasMajority() const;
    
    // Status
    bool IsElectionInProgress() const;
    uint64_t GetElectionTerm() const;
    size_t GetVoteCount() const;
    
private:
    RaftConsensus* raft_;
    
    std::atomic<bool> electionInProgress_{false};
    std::atomic<uint64_t> electionTerm_{0};
    std::set<std::string> votesGranted_;
    std::set<std::string> votesRejected_;
    
    mutable std::mutex mutex_;
};

// ============================================================================
// Log Replicator
// ============================================================================

/**
 * Replicates log entries to followers.
 */
class LogReplicator {
public:
    LogReplicator(
        RaftConsensus* raft,
        std::shared_ptr<CommunicationManager> commManager
    );
    ~LogReplicator();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Replication
    bool ReplicateTo(const std::string& peerNodeId, uint64_t index);
    bool ReplicateToAll(uint64_t index);
    
    // Batch replication
    bool ReplicateBatch(const std::string& peerNodeId, uint64_t startIndex);
    
    // Handle responses
    void HandleAppendSuccess(const std::string& peerNodeId, uint64_t index);
    void HandleAppendFailure(const std::string& peerNodeId, uint64_t index);
    
    // Progress tracking
    uint64_t GetNextIndex(const std::string& peerNodeId);
    uint64_t GetMatchIndex(const std::string& peerNodeId);
    void SetNextIndex(const std::string& peerNodeId, uint64_t index);
    void SetMatchIndex(const std::string& peerNodeId, uint64_t index);
    
    // Status
    bool IsCaughtUp(const std::string& peerNodeId);
    uint64_t GetReplicationProgress(const std::string& peerNodeId);
    
private:
    RaftConsensus* raft_;
    std::shared_ptr<CommunicationManager> commManager_;
    
    std::atomic<bool> running_{false};
    mutable std::mutex mutex_;
    
    // In-flight tracking
    std::map<std::string, uint64_t> inFlight_;
};

// ============================================================================
// Consensus Manager
// ============================================================================

/**
 * High-level consensus management.
 */
class ConsensusManager {
public:
    ConsensusManager(
        std::shared_ptr<CommunicationManager> commManager,
        const RaftConfig& config = RaftConfig{}
    );
    ~ConsensusManager();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Consensus access
    RaftConsensus* GetConsensus();
    
    // Convenience methods
    bool IsLeader() const;
    std::future<bool> Submit(const std::vector<uint8_t>& data);
    std::future<bool> Submit(const std::string& data);
    
    // Wait for leadership
    bool WaitForLeader(uint64_t timeoutMs);
    bool WaitForCommit(uint64_t index, uint64_t timeoutMs);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    std::unique_ptr<RaftConsensus> consensus_;
};

} // namespace Distributed
