/**
 * NodeCommunication.hpp
 *
 * Phase D.3 Batch 1/5: Distributed Node Discovery & Communication
 *
 * TCP-based inter-node communication for sovereign runtime clusters.
 * Provides reliable message passing, RPC, and event streaming.
 */

#pragma once

#include "NodeDiscovery.hpp"
#include <queue>
#include <condition_variable>
#include <future>

namespace Distributed {

// ============================================================================
// Message Types
// ============================================================================

enum class MessageType : uint8_t {
    // Control
    HEARTBEAT = 1,
    HANDSHAKE = 2,
    DISCONNECT = 3,
    
    // RPC
    RPC_REQUEST = 10,
    RPC_RESPONSE = 11,
    RPC_ERROR = 12,
    
    // Events
    EVENT_SUBSCRIBE = 20,
    EVENT_UNSUBSCRIBE = 21,
    EVENT_PUBLISH = 22,
    
    // State
    STATE_SYNC = 30,
    STATE_DELTA = 31,
    STATE_REQUEST = 32,
    
    // Work
    TASK_ASSIGN = 40,
    TASK_COMPLETE = 41,
    TASK_FAILED = 42,
    TASK_CANCEL = 43,
    
    // Consensus
    CONSENSUS_PROPOSE = 50,
    CONSENSUS_ACCEPT = 51,
    CONSENSUS_REJECT = 52,
    CONSENSUS_COMMIT = 53
};

// ============================================================================
// Message Header
// ============================================================================

struct MessageHeader {
    uint32_t magic;           // 0x52415752 ('RAWR')
    uint8_t version;          // Protocol version
    MessageType type;
    uint32_t payloadLength;
    uint64_t timestamp;
    uint64_t sequenceNumber;
    char senderId[64];
    char targetId[64];        // Empty for broadcast
    
    static constexpr uint32_t MAGIC = 0x52415752;
    static constexpr uint8_t VERSION = 1;
};

// ============================================================================
// Message
// ============================================================================

struct Message {
    MessageHeader header;
    std::vector<uint8_t> payload;
    
    std::vector<uint8_t> Serialize() const;
    static std::optional<Message> Deserialize(const std::vector<uint8_t>& data);
};

// ============================================================================
// RPC Request/Response
// ============================================================================

struct RpcRequest {
    std::string method;
    std::vector<uint8_t> params;
    uint64_t requestId;
    std::chrono::milliseconds timeout;
};

struct RpcResponse {
    uint64_t requestId;
    bool success;
    std::vector<uint8_t> result;
    std::string errorMessage;
};

// ============================================================================
// Connection
// ============================================================================

class NodeConnection {
public:
    NodeConnection();
    ~NodeConnection();
    
    // Lifecycle
    bool Connect(const NodeInfo& node);
    void Disconnect();
    bool IsConnected() const { return connected_.load(); }
    
    // Messaging
    bool SendMessage(const Message& msg);
    bool SendRpcRequest(const RpcRequest& request, RpcResponse& response);
    void SubscribeToEvents(const std::string& eventType);
    void UnsubscribeFromEvents(const std::string& eventType);
    
    // Info
    NodeInfo GetNodeInfo() const { return nodeInfo_; }
    std::string GetNodeId() const { return nodeInfo_.nodeId; }
    
    // Statistics
    struct Stats {
        uint64_t messagesSent = 0;
        uint64_t messagesReceived = 0;
        uint64_t bytesSent = 0;
        uint64_t bytesReceived = 0;
        uint64_t rpcCalls = 0;
        uint64_t rpcFailures = 0;
        double avgLatencyMs = 0.0;
    };
    Stats GetStats() const;
    
private:
    // Socket
    int socket_ = -1;
    std::atomic<bool> connected_{false};
    NodeInfo nodeInfo_;
    
    // Threads
    std::thread receiveThread_;
    std::atomic<bool> running_{false};
    
    // RPC tracking
    std::mutex rpcMutex_;
    std::map<uint64_t, std::promise<RpcResponse>> rpcPromises_;
    uint64_t nextRequestId_ = 1;
    
    // Event subscriptions
    std::mutex eventMutex_;
    std::set<std::string> eventSubscriptions_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    Stats stats_;
    
    // Methods
    void ReceiveLoop();
    bool SendRaw(const void* data, size_t len);
    bool ReceiveRaw(void* buffer, size_t len);
    void ProcessMessage(const Message& msg);
};

// ============================================================================
// Message Bus
// ============================================================================

class MessageBus {
public:
    MessageBus();
    ~MessageBus();
    
    // Lifecycle
    bool Initialize(const DiscoveryConfig& config);
    void Shutdown();
    
    // Connection management
    bool ConnectToNode(const NodeInfo& node);
    void DisconnectFromNode(const std::string& nodeId);
    void DisconnectAll();
    
    // Messaging
    bool SendToNode(const std::string& nodeId, const Message& msg);
    bool Broadcast(const Message& msg);
    bool RpcCall(const std::string& nodeId, const RpcRequest& request, RpcResponse& response);
    
    // Event publishing
    void PublishEvent(const std::string& eventType, const std::vector<uint8_t>& data);
    void SubscribeToEvent(const std::string& eventType, std::function<void(const std::string& nodeId, const std::vector<uint8_t>&)> handler);
    void UnsubscribeFromEvent(const std::string& eventType);
    
    // Queries
    std::vector<std::string> GetConnectedNodes() const;
    bool IsConnectedTo(const std::string& nodeId) const;
    size_t GetConnectionCount() const;
    
    // Statistics
    struct BusStats {
        uint64_t totalMessagesSent = 0;
        uint64_t totalMessagesReceived = 0;
        uint64_t totalBytesSent = 0;
        uint64_t totalBytesReceived = 0;
        uint64_t failedSends = 0;
        uint64_t failedRpcs = 0;
        size_t activeConnections = 0;
    };
    BusStats GetStats() const;
    
private:
    DiscoveryConfig config_;
    std::atomic<bool> running_{false};
    
    // Connections
    mutable std::mutex connectionsMutex_;
    std::map<std::string, std::unique_ptr<NodeConnection>> connections_;
    
    // Event handlers
    mutable std::mutex handlersMutex_;
    std::map<std::string, std::vector<std::function<void(const std::string&, const std::vector<uint8_t>&)>>> eventHandlers_;
    
    // Message queue for async sending
    std::mutex queueMutex_;
    std::condition_variable queueCv_;
    std::queue<std::pair<std::string, Message>> messageQueue_;
    std::thread senderThread_;
    
    // Statistics
    mutable std::mutex statsMutex_;
    BusStats stats_;
    
    // Methods
    void SenderLoop();
    void CleanupConnections();
};

// ============================================================================
// Heartbeat Monitor
// ============================================================================

class HeartbeatMonitor {
public:
    HeartbeatMonitor();
    ~HeartbeatMonitor();
    
    // Lifecycle
    bool Initialize(std::chrono::milliseconds interval, std::chrono::milliseconds timeout);
    void Shutdown();
    
    // Registration
    void RegisterNode(const std::string& nodeId);
    void UnregisterNode(const std::string& nodeId);
    void RecordHeartbeat(const std::string& nodeId);
    
    // Queries
    bool IsNodeAlive(const std::string& nodeId) const;
    std::vector<std::string> GetAliveNodes() const;
    std::vector<std::string> GetFailedNodes() const;
    std::chrono::milliseconds GetLastHeartbeat(const std::string& nodeId) const;
    
    // Callbacks
    void SetNodeFailedCallback(std::function<void(const std::string& nodeId)> callback);
    void SetNodeRecoveredCallback(std::function<void(const std::string& nodeId)> callback);
    
    // Statistics
    struct Stats {
        uint64_t heartbeatsSent = 0;
        uint64_t heartbeatsReceived = 0;
        uint64_t nodeFailures = 0;
        uint64_t nodeRecoveries = 0;
    };
    Stats GetStats() const;
    
private:
    struct NodeHeartbeat {
        std::chrono::steady_clock::time_point lastSeen;
        bool wasAlive;
    };
    
    std::chrono::milliseconds interval_;
    std::chrono::milliseconds timeout_;
    std::atomic<bool> running_{false};
    
    mutable std::mutex nodesMutex_;
    std::map<std::string, NodeHeartbeat> nodes_;
    
    std::function<void(const std::string&)> nodeFailedCallback_;
    std::function<void(const std::string&)> nodeRecoveredCallback_;
    
    std::thread monitorThread_;
    mutable std::mutex statsMutex_;
    Stats stats_;
    
    void MonitorLoop();
};

// ============================================================================
// Communication Manager
// ============================================================================

class CommunicationManager {
public:
    CommunicationManager();
    ~CommunicationManager();
    
    // Lifecycle
    bool Initialize(const DiscoveryConfig& config);
    void Shutdown();
    
    // Discovery integration
    void OnNodeDiscovered(const NodeInfo& node);
    void OnNodeLeft(const std::string& nodeId);
    
    // High-level operations
    bool SendToNode(const std::string& nodeId, const Message& msg);
    bool Broadcast(const Message& msg);
    bool RpcCall(const std::string& nodeId, const std::string& method, 
                 const std::vector<uint8_t>& params, std::vector<uint8_t>& result);
    
    // Event system
    void PublishEvent(const std::string& eventType, const std::vector<uint8_t>& data);
    void Subscribe(const std::string& eventType, std::function<void(const std::string&, const std::vector<uint8_t>&)> handler);
    
    // Status
    bool IsNodeReachable(const std::string& nodeId) const;
    std::vector<std::string> GetReachableNodes() const;
    
    // Statistics
    void PrintStats() const;
    
private:
    DiscoveryConfig config_;
    std::unique_ptr<MessageBus> messageBus_;
    std::unique_ptr<HeartbeatMonitor> heartbeatMonitor_;
};

} // namespace Distributed
