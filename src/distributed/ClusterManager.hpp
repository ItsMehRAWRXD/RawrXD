// RawrXD Cluster Manager
// Phase O.1: Distributed Runtime & Scalable Inference
// Manages node discovery, health monitoring, and cluster coordination

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class NodeRegistry;
class HeartbeatService;
class ClusterConfiguration;

// Node capability flags
enum class NodeCapability : uint32_t {
    NONE = 0,
    GPU = 1 << 0,           // Has GPU acceleration
    CPU = 1 << 1,           // CPU inference capable
    QUANTIZED = 1 << 2,     // Supports quantized models
    STREAMING = 1 << 3,     // Supports streaming inference
    EMBEDDINGS = 1 << 4,    // Supports embedding generation
    TRAINING = 1 << 5,      // Supports fine-tuning
    DISTRIBUTED = 1 << 6,    // Participates in distributed execution
    GATEWAY = 1 << 7        // Acts as API gateway
};

inline NodeCapability operator|(NodeCapability a, NodeCapability b) {
    return static_cast<NodeCapability>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b)
    );
}

inline bool hasCapability(NodeCapabilities caps, NodeCapability cap) {
    return (static_cast<uint32_t>(caps) & static_cast<uint32_t>(cap)) != 0;
}

using NodeCapabilities = uint32_t;

// Node information structure
struct NodeInfo {
    std::string nodeId;
    std::string address;
    uint16_t port;
    std::string version;
    NodeCapabilities capabilities;
    
    // Resource information
    struct Resources {
        size_t totalVRAM;      // Total GPU memory in MB
        size_t availableVRAM;  // Available GPU memory in MB
        size_t totalRAM;       // Total system RAM in MB
        size_t availableRAM;   // Available system RAM in MB
        uint32_t cpuCores;     // Number of CPU cores
        uint32_t gpuCount;     // Number of GPUs
        float cpuUtilization;  // Current CPU usage (0-100)
        float gpuUtilization;  // Current GPU usage (0-100)
    } resources;
    
    // Health status
    struct Health {
        bool isHealthy;
        std::string status;    // "healthy", "degraded", "unhealthy"
        uint32_t consecutiveFailures;
        std::chrono::steady_clock::time_point lastHeartbeat;
        uint32_t latencyMs;    // Last measured latency
    } health;
    
    // Timing
    std::chrono::steady_clock::time_point joinedAt;
    std::chrono::steady_clock::time_point lastUpdated;
    
    NodeInfo() : port(0), capabilities(0) {
        health.isHealthy = false;
        health.consecutiveFailures = 0;
        health.latencyMs = 0;
    }
};

// Cluster configuration
struct ClusterConfig {
    std::string clusterId;
    std::string clusterName;
    std::string discoveryMethod;  // "multicast", "consul", "kubernetes", "static"
    
    // Heartbeat settings
    uint32_t heartbeatIntervalMs = 5000;      // 5 seconds
    uint32_t heartbeatTimeoutMs = 15000;      // 15 seconds
    uint32_t maxConsecutiveFailures = 3;
    
    // Failover settings
    bool enableAutoFailover = true;
    uint32_t failoverTimeoutMs = 30000;       // 30 seconds
    
    // Version compatibility
    std::string minCompatibleVersion = "1.0.0";
    bool strictVersionCheck = false;
    
    // Security
    std::string authToken;
    bool enableTLS = false;
    std::string tlsCertPath;
    std::string tlsKeyPath;
};

// Cluster event types
enum class ClusterEventType {
    NODE_JOINED,
    NODE_LEFT,
    NODE_HEALTHY,
    NODE_UNHEALTHY,
    NODE_UPDATED,
    LEADER_ELECTED,
    CLUSTER_PARTITION,
    CLUSTER_MERGED
};

struct ClusterEvent {
    ClusterEventType type;
    std::string nodeId;
    std::chrono::steady_clock::time_point timestamp;
    std::map<std::string, std::string> metadata;
};

// Event callback
using ClusterEventCallback = std::function<void(const ClusterEvent&)>;

// Cluster manager class
class ClusterManager {
public:
    ClusterManager();
    ~ClusterManager();
    
    // Initialization
    bool initialize(const ClusterConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Node management
    bool joinCluster(const std::string& coordinatorAddress = "");
    bool leaveCluster();
    bool isClusterMember() const { return isMember_; }
    
    // Node information
    std::string getLocalNodeId() const { return localNodeId_; }
    NodeInfo getLocalNodeInfo() const;
    std::vector<NodeInfo> getAllNodes() const;
    std::vector<NodeInfo> getHealthyNodes() const;
    std::vector<NodeInfo> getNodesWithCapability(NodeCapability cap) const;
    
    // Node lookup
    NodeInfo getNode(const std::string& nodeId) const;
    bool hasNode(const std::string& nodeId) const;
    std::string getNodeAddress(const std::string& nodeId) const;
    
    // Health monitoring
    bool isNodeHealthy(const std::string& nodeId) const;
    uint32_t getNodeLatency(const std::string& nodeId) const;
    
    // Leader election
    bool isLeader() const { return isLeader_; }
    std::string getLeaderId() const { return leaderId_; }
    
    // Event handling
    void setEventCallback(ClusterEventCallback callback);
    void removeEventCallback();
    
    // Statistics
    struct ClusterStats {
        size_t totalNodes;
        size_t healthyNodes;
        size_t unhealthyNodes;
        size_t gpuNodes;
        size_t cpuNodes;
        uint64_t totalVRAM;
        uint64_t availableVRAM;
        uint64_t totalRAM;
        uint64_t availableRAM;
    };
    ClusterStats getClusterStats() const;
    
    // Configuration
    ClusterConfig getConfig() const { return config_; }
    bool updateConfig(const ClusterConfig& config);
    
private:
    // Internal methods
    void generateNodeId();
    void heartbeatLoop();
    void healthCheckLoop();
    void announceNode();
    void handleNodeJoined(const NodeInfo& node);
    void handleNodeLeft(const std::string& nodeId);
    void handleHeartbeat(const std::string& nodeId);
    void updateNodeHealth(const std::string& nodeId, bool healthy);
    void electLeader();
    void notifyEvent(const ClusterEvent& event);
    
    // Threading
    std::atomic<bool> running_;
    std::thread heartbeatThread_;
    std::thread healthCheckThread_;
    mutable std::mutex nodesMutex_;
    
    // State
    std::atomic<bool> initialized_;
    std::atomic<bool> isMember_;
    std::atomic<bool> isLeader_;
    std::string localNodeId_;
    std::string leaderId_;
    ClusterConfig config_;
    
    // Node registry
    std::map<std::string, NodeInfo> nodes_;
    
    // Event callback
    ClusterEventCallback eventCallback_;
    mutable std::mutex callbackMutex_;
    
    // Services
    std::unique_ptr<NodeRegistry> nodeRegistry_;
    std::unique_ptr<HeartbeatService> heartbeatService_;
    std::unique_ptr<ClusterConfiguration> clusterConfig_;
};

// Node registry interface
class NodeRegistry {
public:
    virtual ~NodeRegistry() = default;
    
    virtual bool registerNode(const NodeInfo& node) = 0;
    virtual bool unregisterNode(const std::string& nodeId) = 0;
    virtual bool updateNode(const NodeInfo& node) = 0;
    
    virtual NodeInfo getNode(const std::string& nodeId) const = 0;
    virtual std::vector<NodeInfo> getAllNodes() const = 0;
    virtual std::vector<NodeInfo> getHealthyNodes() const = 0;
    
    virtual bool hasNode(const std::string& nodeId) const = 0;
    virtual size_t getNodeCount() const = 0;
    virtual size_t getHealthyNodeCount() const = 0;
};

// Heartbeat service interface
class HeartbeatService {
public:
    virtual ~HeartbeatService() = default;
    
    virtual bool start() = 0;
    virtual bool stop() = 0;
    virtual bool isRunning() const = 0;
    
    virtual bool sendHeartbeat(const std::string& nodeId) = 0;
    virtual bool receiveHeartbeat(const std::string& nodeId) = 0;
    
    virtual uint32_t getLastLatency(const std::string& nodeId) const = 0;
    virtual bool isNodeResponsive(const std::string& nodeId) const = 0;
};

// Cluster configuration interface
class ClusterConfiguration {
public:
    virtual ~ClusterConfiguration() = default;
    
    virtual bool load(const std::string& path) = 0;
    virtual bool save(const std::string& path) const = 0;
    
    virtual ClusterConfig getConfig() const = 0;
    virtual bool setConfig(const ClusterConfig& config) = 0;
    
    virtual std::string getClusterId() const = 0;
    virtual std::string getClusterName() const = 0;
};

} // namespace Distributed
} // namespace RawrXD
