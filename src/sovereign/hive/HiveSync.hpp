// ============================================================================
// HiveSync.hpp - HiveSync RDMA Gossip Protocol
// Distributed state synchronization for the Sovereign cluster
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <atomic>

namespace Sovereign {

// Hive node state
enum class HiveNodeState {
    OFFLINE,
    DISCOVERED,
    SYNCING,
    ACTIVE,
    SUSPECT,
    DEAD
};

// Hive node info
struct HiveNode {
    uint64_t id;
    std::string address;
    uint16_t port;
    HiveNodeState state;
    uint64_t lastSeen;
    uint64_t incarnation;
    std::string version;
    std::vector<std::string> capabilities;
    uint64_t load;
    uint64_t memoryFree;
    uint64_t memoryTotal;
};

// Hive message types
enum class HiveMessageType {
    PING,
    PONG,
    GOSSIP,
    SYNC_REQUEST,
    SYNC_RESPONSE,
    JOIN,
    LEAVE,
    ELECT,
    ELECT_ACK,
    ELECT_DECLINE,
    COORDINATOR_ANNOUNCE,
    STATE_UPDATE,
    STATE_SYNC
};

// Hive message
struct HiveMessage {
    HiveMessageType type;
    uint64_t senderId;
    uint64_t targetId;
    uint64_t timestamp;
    uint64_t sequence;
    std::vector<uint8_t> payload;
};

// Hive configuration
struct HiveConfig {
    uint16_t port = 42069;
    uint32_t gossipIntervalMs = 1000;
    uint32_t syncIntervalMs = 5000;
    uint32_t failureTimeoutMs = 15000;
    uint32_t cleanupIntervalMs = 30000;
    uint32_t maxPeers = 64;
    uint32_t gossipFanout = 3;
    bool enableEncryption = false;
    std::string secretKey;
    std::vector<std::pair<std::string, uint16_t>> seedNodes;
};

// Hive statistics
struct HiveStats {
    uint64_t messagesSent;
    uint64_t messagesReceived;
    uint64_t bytesSent;
    uint64_t bytesReceived;
    uint64_t peersDiscovered;
    uint64_t peersLost;
    uint64_t syncsCompleted;
    uint64_t electionsParticipated;
    uint64_t electionsWon;
    double avgLatencyMs;
    double avgGossipTimeMs;
};

// HiveSync - RDMA gossip protocol
class HiveSync {
public:
    HiveSync();
    ~HiveSync();

    // Initialize
    bool Initialize(const HiveConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Node identity
    void SetNodeId(uint64_t id);
    uint64_t GetNodeId() const { return nodeId_; }
    void SetCapabilities(const std::vector<std::string>& caps);

    // Peer management
    bool AddPeer(const std::string& address, uint16_t port);
    bool RemovePeer(uint64_t nodeId);
    std::vector<HiveNode> GetPeers() const;
    HiveNode GetPeer(uint64_t nodeId) const;
    size_t GetPeerCount() const { return peers_.size(); }

    // Messaging
    bool SendMessage(const HiveMessage& message);
    bool BroadcastMessage(const HiveMessage& message);
    bool GossipMessage(const HiveMessage& message);
    void SetMessageHandler(std::function<void(const HiveMessage&)> handler);

    // State synchronization
    bool RequestSync(uint64_t nodeId);
    bool RespondSync(uint64_t nodeId, const std::vector<uint8_t>& state);
    void SetStateProvider(std::function<std::vector<uint8_t>()> provider);

    // Cluster operations
    bool JoinCluster();
    bool LeaveCluster();
    bool IsCoordinator() const { return isCoordinator_; }
    uint64_t GetCoordinatorId() const { return coordinatorId_; }

    // Failure detection
    bool IsNodeAlive(uint64_t nodeId) const;
    void SuspectNode(uint64_t nodeId);
    void ConfirmNodeDead(uint64_t nodeId);

    // Statistics
    HiveStats GetStats() const;
    void ResetStats();

    // Start/stop
    void Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }

private:
    bool initialized_ = false;
    std::atomic<bool> running_{false};
    uint64_t nodeId_ = 0;
    bool isCoordinator_ = false;
    uint64_t coordinatorId_ = 0;
    HiveConfig config_;
    HiveStats stats_;
    
    std::unordered_map<uint64_t, HiveNode> peers_;
    std::function<void(const HiveMessage&)> messageHandler_;
    std::function<std::vector<uint8_t>()> stateProvider_;
    
    mutable std::mutex mutex_;
    std::thread gossipThread_;
    std::thread syncThread_;
    std::thread cleanupThread_;
    
    // Internal
    void GossipLoop();
    void SyncLoop();
    void CleanupLoop();
    void HandleMessage(const HiveMessage& msg);
    void SendGossipUpdate();
    void PerformElection();
};

// Consensus protocol (Raft-like)
class ConsensusProtocol {
public:
    ConsensusProtocol();
    ~ConsensusProtocol();

    // Initialize
    bool Initialize(uint64_t nodeId, const std::vector<uint64_t>& clusterNodes);
    void Shutdown();

    // Leader election
    bool StartElection();
    bool IsLeader() const { return isLeader_; }
    uint64_t GetLeaderId() const { return leaderId_; }
    uint64_t GetTerm() const { return currentTerm_; }

    // Log replication
    bool AppendEntry(const std::string& command);
    bool CommitEntry(uint64_t index);
    std::string GetCommittedEntry(uint64_t index) const;

    // State machine
    void SetStateMachine(std::function<bool(const std::string&)> apply);
    uint64_t GetCommitIndex() const { return commitIndex_; }
    uint64_t GetLastApplied() const { return lastApplied_; }

    // Cluster membership
    bool AddMember(uint64_t nodeId);
    bool RemoveMember(uint64_t nodeId);
    std::vector<uint64_t> GetMembers() const;

    // Statistics
    struct ConsensusStats {
        uint64_t currentTerm;
        uint64_t electionsStarted;
        uint64_t electionsWon;
        uint64_t entriesAppended;
        uint64_t entriesCommitted;
        uint64_t heartbeatsSent;
        uint64_t heartbeatsReceived;
    };
    ConsensusStats GetStats() const;

private:
    uint64_t nodeId_;
    uint64_t currentTerm_ = 0;
    uint64_t votedFor_ = 0;
    uint64_t leaderId_ = 0;
    uint64_t commitIndex_ = 0;
    uint64_t lastApplied_ = 0;
    bool isLeader_ = false;
    
    std::vector<uint64_t> clusterNodes_;
    std::vector<std::string> log_;
    std::function<bool(const std::string&)> stateMachine_;
    
    mutable std::mutex mutex_;
    std::thread heartbeatThread_;
    
    void HeartbeatLoop();
    void SendHeartbeat();
    void HandleHeartbeat(uint64_t leaderId, uint64_t term);
    void HandleVoteRequest(uint64_t candidateId, uint64_t term);
    void HandleVoteResponse(uint64_t voterId, bool granted);
};

} // namespace Sovereign
