// Sovereign Distributed Runtime - Phase D.3 Batch 1/5
// Node Discovery & Cluster Formation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// Node Identity & Status
// ============================================================================

enum class NodeRole {
    LEADER = 0,      // Coordinates safety decisions
    FOLLOWER = 1,    // Participates in consensus
    CANDIDATE = 2,   // Leader election in progress
    OBSERVER = 3     // Non-voting, receives updates
};

enum class NodeHealth {
    HEALTHY = 0,
    DEGRADED = 1,
    UNSTABLE = 2,
    OFFLINE = 3
};

struct NodeIdentity {
    std::string node_id;           // UUID
    std::string hostname;
    std::string ip_address;
    int port = 0;
    std::string datacenter;
    std::string rack;
    std::string version;
    std::vector<std::string> capabilities;
    
    std::string ToJson() const;
    static NodeIdentity FromJson(const std::string& json);
};

struct NodeStatus {
    NodeIdentity identity;
    NodeRole role = NodeRole::FOLLOWER;
    NodeHealth health = NodeHealth::HEALTHY;
    
    // Performance metrics
    double cpu_percent = 0.0;
    double memory_gb = 0.0;
    double tps_capacity = 0.0;
    int active_agents = 0;
    
    // Timing
    std::chrono::steady_clock::time_point last_heartbeat;
    int64_t uptime_ms = 0;
    
    // Safety
    bool safety_gates_active = false;
    int rollback_count = 0;
    
    bool IsResponsive() const;
    std::string ToJson() const;
};

// ============================================================================
// Cluster Topology
// ============================================================================

class ClusterTopology {
public:
    // Node management
    bool AddNode(const NodeIdentity& node);
    bool RemoveNode(const std::string& node_id);
    
    // Health queries
    std::vector<NodeIdentity> GetHealthyNodes() const;
    int GetQuorumSize() const;
    bool HasQuorum() const;
    
    // Leader management
    void SetLeader(const std::string& node_id);
    std::string GetLeader() const;
    bool IsLeader(const std::string& node_id) const;
    
    // Health updates
    void UpdateHealth(const std::string& node_id, NodeHealth health);
    NodeHealth GetHealth(const std::string& node_id) const;
    
    // Serialization
    std::string ToJson() const;
    
private:
    mutable std::mutex mutex_;
    std::vector<NodeIdentity> nodes_;
    std::map<std::string, NodeHealth> node_health_;
    std::map<std::string, std::chrono::steady_clock::time_point> last_heartbeat_;
    std::string leader_id_;
    int version_ = 0;
};

// ============================================================================
// Discovery Protocol
// ============================================================================

enum class DiscoveryMethod {
    STATIC_LIST = 0,      // Pre-configured node list
    STATIC = 0,           // Alias for STATIC_LIST
    MULTICAST = 1,        // UDP multicast (LAN)
    CONSUL = 2,           // HashiCorp Consul
    KUBERNETES = 3,       // K8s service discovery
    AWS_CLOUD_MAP = 4,    // AWS Cloud Map
    CUSTOM = 5            // User-provided callback
};

class NodeDiscovery {
public:
    struct Config {
        NodeIdentity self;
        DiscoveryMethod method = DiscoveryMethod::STATIC_LIST;
        std::vector<NodeIdentity> seed_nodes;
        std::vector<NodeIdentity> static_nodes;  // Alias for seed_nodes
        int heartbeat_interval_ms = 1000;
        int heartbeat_timeout_ms = 5000;
        int election_timeout_ms = 10000;
        std::string multicast_address = "239.255.42.99";
        int multicast_port = 42424;
    };
    
    explicit NodeDiscovery(const Config& config);
    ~NodeDiscovery();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Discovery
    bool JoinCluster();
    bool LeaveCluster();
    void UpdateStatus(const NodeStatus& status);
    
    // Topology access
    std::shared_ptr<ClusterTopology> GetTopology() const;
    NodeStatus GetNode(const std::string& node_id) const;
    std::vector<NodeIdentity> GetAllNodes() const;
    std::vector<NodeIdentity> GetNodesInDatacenter(const std::string& datacenter) const;
    std::vector<NodeIdentity> GetNodesInRack(const std::string& rack) const;
    std::string GetLeaderId() const;
    bool IsLeader() const;
    bool ForceElection();
    bool ElectLeader();
    
    // Callbacks
    using TopologyChangeCallback = std::function<void(const ClusterTopology&)>;
    using LeaderChangeCallback = std::function<void(const std::string& old_leader, 
                                                     const std::string& new_leader)>;
    using NodeFailureCallback = std::function<void(const std::string& node_id)>;
    
    void OnTopologyChange(TopologyChangeCallback cb);
    void OnLeaderChange(LeaderChangeCallback cb);
    void OnNodeFailure(NodeFailureCallback cb);
    
    // Manual operations
    bool AddNode(const NodeIdentity& node);
    bool RemoveNode(const std::string& node_id);
    void StepDown();
    void OnLeaderElected(std::function<void()> callback);
    void OnNodeJoined(std::function<void(const NodeIdentity&)> callback);
    void OnNodeLeft(std::function<void(const NodeIdentity&)> callback);
    
private:
    std::function<void()> on_leader_elected_;
    std::function<void(const NodeIdentity&)> on_node_joined_;
    std::function<void(const NodeIdentity&)> on_node_left_;
    Config config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    
    mutable std::mutex topology_mutex_;
    std::shared_ptr<ClusterTopology> topology_;
    NodeStatus self_status_;
    
    std::thread heartbeat_thread_;
    std::thread election_thread_;
    std::thread discovery_thread_;
    
    TopologyChangeCallback on_topology_change_;
    LeaderChangeCallback on_leader_change_;
    NodeFailureCallback on_node_failure_;
    
    // Implementation
    void HeartbeatLoop();
    void ElectionLoop();
    void CheckTimeouts();
    void StartElection();
    void BecomeLeader();
    void BecomeFollower(const std::string& leader_id);
    void MulticastDiscovery();
    void ConsulDiscovery();
    void KubernetesDiscovery();
    std::string GenerateNodeId();
    void SendHeartbeat(const NodeIdentity& node);
    void CheckStaleNodes();
    
    // Network
    bool SendHeartbeat(const std::string& node_id);
    bool RequestVote(const std::string& node_id, int term);
    void BroadcastTopology();
};

// ============================================================================
// Service Registry
// ============================================================================

enum class ServiceStatus {
    HEALTHY = 0,
    DEGRADED = 1,
    UNHEALTHY = 2
};

struct ServiceInfo {
    std::string service_name;
    std::string instance_id;
    std::string node_id;
    std::string endpoint;
    ServiceStatus status = ServiceStatus::HEALTHY;
    std::map<std::string, std::string> metadata;
    int64_t ttl_ms = 30000;
    std::chrono::steady_clock::time_point registered_at;
};

class ServiceRegistry {
public:
    ServiceRegistry() = default;
    explicit ServiceRegistry(std::shared_ptr<NodeDiscovery> discovery);
    
    bool RegisterService(const ServiceInfo& service);
    bool DeregisterService(const std::string& service_name, const std::string& instance_id);
    std::vector<ServiceInfo> DiscoverService(const std::string& service_name) const;
    ServiceInfo GetHealthyInstance(const std::string& service_name) const;
    
    void CleanupExpired();
    
private:
    mutable std::mutex services_mutex_;
    std::map<std::string, std::vector<ServiceInfo>> services_;
    std::shared_ptr<NodeDiscovery> discovery_;
};

} // namespace Distributed
} // namespace Sovereign
