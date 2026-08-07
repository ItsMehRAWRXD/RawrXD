#pragma once

#include "ConsistentHash.h"
#include "FabricTransport.h"
#include "FabricOrchestrator.h"
#include <cstdint>
#include <vector>
#include <map>
#include <atomic>
#include <thread>
#include <functional>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Cluster Manager - Multi-Node Orchestration
// 
// Manages a cluster of 4+ nodes with:
// - Automatic node discovery
// - Consistent hashing for tensor placement
// - Automatic rebalancing on join/leave
// - Failure detection and recovery
// ============================================================================

enum class NodeState : uint32_t {
    UNKNOWN = 0,
    JOINING = 1,       // Node is joining cluster
    ACTIVE = 2,        // Node is fully operational
    SUSPECT = 3,       // Node may have failed
    LEAVING = 4,       // Node is gracefully leaving
    FAILED = 5         // Node confirmed failed
};

struct NodeInfo {
    uint32_t nodeId;
    std::string address;
    NodeState state;
    uint64_t lastHeartbeat;
    uint64_t uptimeUs;
    uint32_t loadPercent;
    uint32_t tensorCount;
    uint32_t version;  // For gossip protocol
};

struct ClusterConfig {
    uint32_t localNodeId;
    std::string bindAddress;
    uint16_t bindPort;
    std::vector<std::string> seedNodes;  // Initial cluster nodes
    
    // Timing
    uint32_t heartbeatIntervalMs = 100;
    uint32_t heartbeatTimeoutMs = 500;
    uint32_t suspectTimeoutMs = 2000;
    uint32_t rebalanceIntervalMs = 5000;
    
    // Replication
    int replicationFactor = 2;  // Number of copies per tensor
};

// ============================================================================
// Cluster Manager
// ============================================================================
class ClusterManager {
public:
    ClusterManager();
    ~ClusterManager();
    
    // Lifecycle
    bool Initialize(const ClusterConfig& config, FabricTransport* transport);
    void Shutdown();
    
    // Node Management
    bool JoinCluster(const std::string& seedAddress);
    bool LeaveCluster();
    bool IsInCluster() const;
    
    // Cluster State
    std::vector<NodeInfo> GetActiveNodes() const;
    size_t GetClusterSize() const;
    bool IsNodeActive(uint32_t nodeId) const;
    
    // Tensor Placement
    uint32_t GetPrimaryNode(uint64_t tensorId) const;
    std::vector<uint32_t> GetReplicaNodes(uint64_t tensorId) const;
    bool IsLocalTensor(uint64_t tensorId) const;
    
    // Rebalancing
    bool TriggerRebalance();
    bool IsRebalancing() const;
    double GetRebalanceProgress() const;
    
    // Failure Detection
    void ReportNodeSuspect(uint32_t nodeId);
    void ConfirmNodeFailed(uint32_t nodeId);
    
    // Callbacks
    using NodeJoinedCallback = std::function<void(uint32_t nodeId)>;
    using NodeLeftCallback = std::function<void(uint32_t nodeId)>;
    using RebalanceCallback = std::function<void(double progress)>;
    
    void SetNodeJoinedCallback(NodeJoinedCallback cb);
    void SetNodeLeftCallback(NodeLeftCallback cb);
    void SetRebalanceCallback(RebalanceCallback cb);
    
    // Statistics
    struct Stats {
        uint64_t heartbeatsSent;
        uint64_t heartbeatsReceived;
        uint64_t nodesJoined;
        uint64_t nodesFailed;
        uint64_t rebalanceOperations;
        uint64_t tensorMigrations;
    };
    Stats GetStats() const;
    
private:
    ClusterConfig config_;
    FabricTransport* transport_;
    
    // Node state
    mutable std::shared_mutex nodesMutex_;
    std::map<uint32_t, NodeInfo> nodes_;
    ConsistentHashRing hashRing_;
    
    // Local state
    std::atomic<bool> initialized_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<bool> inCluster_{false};
    std::atomic<bool> rebalancing_{false};
    std::atomic<double> rebalanceProgress_{0.0};
    
    // Worker threads
    std::thread heartbeatThread_;
    std::thread gossipThread_;
    std::thread rebalanceThread_;
    
    // Callbacks
    NodeJoinedCallback nodeJoinedCb_;
    NodeLeftCallback nodeLeftCb_;
    RebalanceCallback rebalanceCb_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> heartbeatsSent_{0};
    alignas(64) std::atomic<uint64_t> heartbeatsReceived_{0};
    alignas(64) std::atomic<uint64_t> nodesJoined_{0};
    alignas(64) std::atomic<uint64_t> nodesFailed_{0};
    alignas(64) std::atomic<uint64_t> rebalanceOps_{0};
    alignas(64) std::atomic<uint64_t> tensorMigrations_{0};
    
    // Thread loops
    void HeartbeatLoop();
    void GossipLoop();
    void RebalanceLoop();
    
    // Message handlers
    void OnHeartbeat(const HeartbeatMessage& msg, uint32_t fromNode);
    void OnNodeJoin(uint32_t nodeId, const std::string& address);
    void OnNodeLeave(uint32_t nodeId);
    
    // Helpers
    void UpdateNodeState(uint32_t nodeId, NodeState state);
    void CheckForFailedNodes();
    void PerformRebalance();
    uint64_t GetTimestampUs() const;
    void BroadcastToCluster(const FabricMessage& msg);
    
    // System metrics helpers
    uint8_t GetSystemLoadPercent();
    uint32_t GetLocalTensorCount();
    std::string GetNodeAddress(uint32_t nodeId);
};

} // namespace Fabric
} // namespace RawrXD
