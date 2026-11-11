/**
 * NodeDiscovery.hpp
 *
 * Phase D.3 Batch 1/5: Distributed Node Discovery & Communication
 *
 * UDP multicast-based node discovery for sovereign runtime clusters.
 * Enables automatic node joining, leaving detection, and cluster formation.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <chrono>
#include <mutex>
#include <thread>
#include <atomic>
#include <optional>

// Platform-specific socket includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
#endif

namespace Distributed {

// ============================================================================
// Constants
// ============================================================================

constexpr int DEFAULT_DISCOVERY_PORT = 7946;
constexpr int DEFAULT_COMMUNICATION_PORT = 7947;
constexpr auto DISCOVERY_INTERVAL_MS = std::chrono::milliseconds(1000);
constexpr auto NODE_TIMEOUT_MS = std::chrono::milliseconds(5000);
constexpr const char* MULTICAST_GROUP = "239.192.79.46";  // Sovereign multicast
constexpr int MAX_DISCOVERY_PACKET_SIZE = 1024;

// ============================================================================
// Node Information
// ============================================================================

struct NodeInfo {
    std::string nodeId;
    std::string address;
    int communicationPort;
    std::string region;
    std::string zone;
    uint64_t capacityScore;      // Combined CPU/memory/GPU score
    uint64_t currentLoad;
    std::vector<std::string> capabilities;
    std::chrono::steady_clock::time_point lastSeen;
    std::chrono::steady_clock::time_point joinedAt;
    bool isLeader;
    uint64_t term;               // Raft term
    
    bool IsAlive() const {
        auto now = std::chrono::steady_clock::now();
        return (now - lastSeen) < NODE_TIMEOUT_MS;
    }
    
    double GetUtilization() const {
        if (capacityScore == 0) return 0.0;
        return static_cast<double>(currentLoad) / capacityScore;
    }
    
    std::string ToJson() const;
    static std::optional<NodeInfo> FromJson(const std::string& json);
};

// ============================================================================
// Discovery Events
// ============================================================================

enum class DiscoveryEventType {
    NODE_JOINED,
    NODE_LEFT,
    NODE_UPDATED,
    LEADER_CHANGED,
    CLUSTER_FORMED,
    CLUSTER_PARTITIONED
};

struct DiscoveryEvent {
    DiscoveryEventType type;
    NodeInfo node;
    std::chrono::steady_clock::time_point timestamp;
    std::string reason;
};

using DiscoveryCallback = std::function<void(const DiscoveryEvent&)>;

// ============================================================================
// Discovery Configuration
// ============================================================================

struct DiscoveryConfig {
    std::string nodeId;                      // Unique node identifier
    std::string bindAddress;                 // Local bind address (0.0.0.0 for all)
    int discoveryPort = DEFAULT_DISCOVERY_PORT;
    int communicationPort = DEFAULT_COMMUNICATION_PORT;
    std::string multicastGroup = MULTICAST_GROUP;
    std::string region = "default";
    std::string zone = "default";
    uint64_t capacityScore = 1000;
    std::vector<std::string> capabilities;
    
    // Timing
    std::chrono::milliseconds discoveryInterval = DISCOVERY_INTERVAL_MS;
    std::chrono::milliseconds nodeTimeout = NODE_TIMEOUT_MS;
    
    // Security
    std::string clusterToken;                // Shared secret for cluster auth
    bool enableEncryption = false;
    
    bool Validate() const;
    std::string ToJson() const;
};

// ============================================================================
// Node Registry
// ============================================================================

class NodeRegistry {
public:
    NodeRegistry();
    ~NodeRegistry();
    
    // Registry operations
    void RegisterNode(const NodeInfo& node);
    void UpdateNode(const NodeInfo& node);
    void RemoveNode(const std::string& nodeId);
    
    // Queries
    std::optional<NodeInfo> GetNode(const std::string& nodeId) const;
    std::vector<NodeInfo> GetAllNodes() const;
    std::vector<NodeInfo> GetAliveNodes() const;
    std::vector<NodeInfo> GetNodesByRegion(const std::string& region) const;
    std::vector<NodeInfo> GetNodesByCapability(const std::string& capability) const;
    std::optional<NodeInfo> GetLeader() const;
    
    // Statistics
    size_t GetNodeCount() const;
    size_t GetAliveNodeCount() const;
    bool HasQuorum(size_t totalNodes) const;
    
    // Cleanup
    void RemoveStaleNodes(std::chrono::milliseconds timeout);
    void Clear();
    
private:
    mutable std::mutex mutex_;
    std::map<std::string, NodeInfo> nodes_;
};

// ============================================================================
// Discovery Protocol
// ============================================================================

class DiscoveryProtocol {
public:
    DiscoveryProtocol();
    ~DiscoveryProtocol();
    
    // Lifecycle
    bool Initialize(const DiscoveryConfig& config);
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    // Discovery operations
    bool JoinCluster();
    bool LeaveCluster();
    void AnnouncePresence();
    void RequestNodeList();
    
    // Event handling
    void SetCallback(DiscoveryCallback callback);
    
    // Node info
    NodeInfo GetLocalNode() const { return localNode_; }
    std::string GetNodeId() const { return config_.nodeId; }
    
    // Registry access
    NodeRegistry& GetRegistry() { return registry_; }
    const NodeRegistry& GetRegistry() const { return registry_; }
    
    // Statistics
    struct Stats {
        uint64_t announcementsSent = 0;
        uint64_t announcementsReceived = 0;
        uint64_t nodesDiscovered = 0;
        uint64_t nodesLost = 0;
        uint64_t bytesSent = 0;
        uint64_t bytesReceived = 0;
    };
    Stats GetStats() const;
    void ResetStats();
    
private:
    // Socket management
    bool CreateSocket();
    void CloseSocket();
    bool JoinMulticastGroup();
    bool LeaveMulticastGroup();
    
    // Communication
    void SendAnnouncement();
    void SendDiscoveryRequest();
    void ProcessIncomingPacket(const char* data, size_t len, 
                                const sockaddr_in& fromAddr);
    
    // Threads
    void DiscoveryLoop();
    void ReceiveLoop();
    void CleanupLoop();
    
    // Helpers
    std::string GenerateNodeId() const;
    uint64_t CalculateCapacityScore() const;
    
    DiscoveryConfig config_;
    NodeInfo localNode_;
    NodeRegistry registry_;
    DiscoveryCallback callback_;
    
    // Socket
    int socket_ = -1;
    sockaddr_in multicastAddr_;
    sockaddr_in bindAddr_;
    
    // Threads
    std::thread discoveryThread_;
    std::thread receiveThread_;
    std::thread cleanupThread_;
    std::atomic<bool> running_{false};
    
    // Statistics
    mutable std::mutex statsMutex_;
    Stats stats_;
    
    // Platform
    #ifdef _WIN32
    WSADATA wsaData_;
    bool wsaInitialized_ = false;
    #endif
};

// ============================================================================
// Message Types
// ============================================================================

enum class DiscoveryMessageType : uint8_t {
    ANNOUNCE = 1,      // Node announcing presence
    DISCOVERY = 2,     // Request for node list
    RESPONSE = 3,      // Response with node info
    HEARTBEAT = 4,     // Keepalive
    LEAVE = 5,         // Graceful departure
    ELECTION = 6       // Leader election
};

struct DiscoveryMessage {
    DiscoveryMessageType type;
    std::string senderId;
    NodeInfo nodeInfo;
    std::vector<NodeInfo> knownNodes;  // For RESPONSE
    uint64_t timestamp;
    std::string signature;             // For security
    
    std::vector<uint8_t> Serialize() const;
    static std::optional<DiscoveryMessage> Deserialize(const std::vector<uint8_t>& data);
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string GenerateNodeId();
std::string GetLocalIpAddress();
bool IsValidMulticastAddress(const std::string& addr);

} // namespace Distributed
