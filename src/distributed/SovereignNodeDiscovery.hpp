// Sovereign Distributed Runtime - Phase D.3 Batch 1/5
// Node Discovery & Cluster Formation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
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

struct ClusterTopology {
    std::string cluster_id;
    std::string leader_id;
    std::map<std::string, NodeStatus> nodes;
    
    int QuorumSize() const { return (nodes.size() / 2) + 1; }
    int HealthyNodes() const;
    std::vector<std::string> GetVotingMembers() const;
    bool HasLeader() const { return !leader_id.empty(); }
    
    std::string ToJson() const;
    static ClusterTopology FromJson(const std::string& json);
};

// ============================================================================
// Discovery Protocol
// ============================================================================

enum class DiscoveryMethod {
    STATIC_LIST = 0,      // Pre-configured node list
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
    ClusterTopology GetTopology() const;
    NodeStatus GetNode(const std::string& node_id) const;
    std::vector<NodeStatus> GetHealthyNodes() const;
    std::string GetLeaderId() const;
    bool IsLeader() const;
    
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
    bool ForceElection();
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    
    mutable std::mutex topology_mutex_;
    ClusterTopology topology_;
    NodeStatus self_status_;
    
    std::thread heartbeat_thread_;
    std::thread election_thread_;
    
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
    
    // Network
    bool SendHeartbeat(const std::string& node_id);
    bool RequestVote(const std::string& node_id, int term);
    void BroadcastTopology();
};

// ============================================================================
// Service Registry
// ============================================================================

class ServiceRegistry {
public:
    struct Service {
        std::string name;
        std::string node_id;
        std::string endpoint;
        std::map<std::string, std::string> metadata;
        int64_t ttl_ms = 30000;
        std::chrono::steady_clock::time_point registered_at;
    };
    
    bool Register(const Service& service);
    bool Deregister(const std::string& service_name, const std::string& node_id);
    std::vector<Service> Discover(const std::string& service_name);
    std::vector<Service> DiscoverHealthy(const std::string& service_name);
    
    void CleanupExpired();
    
private:
    std::mutex mutex_;
    std::map<std::string, std::vector<Service>> services_;
};

} // namespace Distributed
} // namespace Sovereign
