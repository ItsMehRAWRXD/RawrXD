// DistributedScheduler.hpp
// Phase C.2 Batch 5/5 — Distributed Scheduling Coordination

#ifndef DISTRIBUTED_SCHEDULER_HPP
#define DISTRIBUTED_SCHEDULER_HPP

#include <vector>
#include <map>
#include <memory>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <queue>
#include <chrono>
#include <functional>
#include "AdaptiveScheduler.hpp"

namespace Scheduler {

// Forward declarations
class DistributedScheduler;
class NodeRegistry;
class TaskDistributor;
class LoadBalancer;
class ConsensusManager;

// ============================================================================
// Node Types and States
// ============================================================================

enum class NodeType {
    COORDINATOR,
    WORKER,
    HYBRID
};

enum class NodeState {
    INITIALIZING,
    ACTIVE,
    OVERLOADED,
    DEGRADED,
    OFFLINE
};

// ============================================================================
// Node Information
// ============================================================================

struct NodeInfo {
    std::string node_id;
    std::string address;
    uint16_t port;
    NodeType type;
    NodeState state;
    
    // Capabilities
    uint32_t max_workers;
    uint32_t current_workers;
    double cpu_capacity;
    double memory_capacity;
    double network_bandwidth;
    
    // Performance metrics
    double current_load;
    double average_latency;
    double success_rate;
    double throughput;
    
    // Timestamps
    std::chrono::steady_clock::time_point last_heartbeat;
    std::chrono::steady_clock::time_point joined_time;
    
    NodeInfo()
        : port(0)
        , type(NodeType::WORKER)
        , state(NodeState::INITIALIZING)
        , max_workers(0)
        , current_workers(0)
        , cpu_capacity(0.0)
        , memory_capacity(0.0)
        , network_bandwidth(0.0)
        , current_load(0.0)
        , average_latency(0.0)
        , success_rate(0.0)
        , throughput(0.0)
    {}
    
    bool IsHealthy() const;
    bool IsAvailable() const;
    double GetUtilization() const;
    double GetScore() const; // For load balancing
};

// ============================================================================
// Distributed Task
// ============================================================================

struct DistributedTask {
    ScheduledTask base_task;
    
    // Distribution info
    std::string source_node;
    std::string target_node;
    std::vector<std::string> candidate_nodes;
    
    // Execution tracking
    enum class DistributionState {
        PENDING,
        ASSIGNED,
        EXECUTING,
        COMPLETED,
        FAILED,
        MIGRATED
    };
    DistributionState dist_state;
    
    // Migration support
    std::string previous_node;
    uint32_t migration_count;
    std::chrono::steady_clock::time_point migration_time;
    
    // Consensus
    std::vector<std::string> ack_nodes;
    std::vector<std::string> nack_nodes;
    
    DistributedTask() : dist_state(DistributionState::PENDING), migration_count(0) {}
};

// ============================================================================
// Distribution Policy
// ============================================================================

enum class DistributionPolicy {
    ROUND_ROBIN,
    LEAST_LOADED,
    LOCALITY_AWARE,
    CAPACITY_BASED,
    LATENCY_OPTIMIZED,
    COST_OPTIMIZED,
    ADAPTIVE
};

struct DistributionConfig {
    DistributionPolicy policy = DistributionPolicy::ADAPTIVE;
    
    // Load balancing
    double overload_threshold = 0.8;
    double underload_threshold = 0.3;
    uint32_t rebalance_interval_ms = 5000;
    
    // Fault tolerance
    uint32_t replication_factor = 2;
    uint32_t max_retries = 3;
    std::chrono::milliseconds task_timeout{30000};
    std::chrono::milliseconds heartbeat_interval{1000};
    std::chrono::milliseconds heartbeat_timeout{5000};
    
    // Consensus
    bool enable_consensus = true;
    uint32_t consensus_quorum = 2;
    std::chrono::milliseconds consensus_timeout{1000};
    
    // Migration
    bool enable_migration = true;
    uint32_t max_migrations = 3;
    double migration_threshold = 0.9;
    
    // Network
    uint32_t max_concurrent_transfers = 4;
    double network_weight = 0.3;
};

// ============================================================================
// Node Registry
// ============================================================================

class NodeRegistry {
public:
    NodeRegistry(const DistributionConfig& config);
    
    // Node management
    void RegisterNode(const NodeInfo& node);
    void UnregisterNode(const std::string& node_id);
    void UpdateNode(const NodeInfo& node);
    
    // Queries
    NodeInfo GetNode(const std::string& node_id) const;
    std::vector<NodeInfo> GetAllNodes() const;
    std::vector<NodeInfo> GetHealthyNodes() const;
    std::vector<NodeInfo> GetNodesByType(NodeType type) const;
    std::vector<NodeInfo> GetAvailableWorkers() const;
    
    // Load balancing
    NodeInfo SelectLeastLoaded() const;
    NodeInfo SelectByCapacity() const;
    NodeInfo SelectByLatency() const;
    std::vector<NodeInfo> SelectCandidates(uint32_t count) const;
    
    // Health monitoring
    void RecordHeartbeat(const std::string& node_id);
    void UpdateNodeMetrics(const std::string& node_id, 
                          double load, double latency, double throughput);
    std::vector<std::string> GetFailedNodes() const;
    
    // Statistics
    uint32_t GetNodeCount() const;
    uint32_t GetHealthyNodeCount() const;
    double GetClusterLoad() const;
    double GetClusterThroughput() const;
    
private:
    DistributionConfig config_;
    std::map<std::string, NodeInfo> nodes_;
    mutable std::mutex mutex_;
    
    void CleanupFailedNodes();
};

// ============================================================================
// Task Distributor
// ============================================================================

class TaskDistributor {
public:
    TaskDistributor(NodeRegistry* registry, const DistributionConfig& config);
    
    // Distribution
    std::string DistributeTask(const DistributedTask& task);
    std::vector<std::string> DistributeTaskReplicated(const DistributedTask& task, 
                                                       uint32_t replication_factor);
    
    // Policy implementations
    std::string RoundRobin(const DistributedTask& task);
    std::string LeastLoaded(const DistributedTask& task);
    std::string LocalityAware(const DistributedTask& task);
    std::string CapacityBased(const DistributedTask& task);
    std::string LatencyOptimized(const DistributedTask& task);
    std::string CostOptimized(const DistributedTask& task);
    std::string Adaptive(const DistributedTask& task);
    
    // Task migration
    bool ShouldMigrate(const DistributedTask& task) const;
    std::string SelectMigrationTarget(const DistributedTask& task);
    void MigrateTask(DistributedTask& task, const std::string& new_node);
    
    // Batch distribution
    std::map<std::string, std::vector<DistributedTask>> DistributeBatch(
        const std::vector<DistributedTask>& tasks);
    
private:
    NodeRegistry* registry_;
    DistributionConfig config_;
    
    std::atomic<uint64_t> round_robin_counter_{0};
    mutable std::mutex mutex_;
    
    double CalculateNodeScore(const NodeInfo& node, const DistributedTask& task) const;
};

// ============================================================================
// Load Balancer
// ============================================================================

class LoadBalancer {
public:
    LoadBalancer(NodeRegistry* registry, const DistributionConfig& config);
    
    void Start();
    void Stop();
    
    // Rebalancing
    void Rebalance();
    void RebalanceNode(const std::string& node_id);
    
    // Migration decisions
    std::vector<DistributedTask> IdentifyTasksToMigrate(
        const std::string& overloaded_node);
    
    // Statistics
    struct RebalanceStats {
        uint32_t migrations_triggered;
        uint32_t migrations_completed;
        uint32_t migrations_failed;
        double load_variance_before;
        double load_variance_after;
        std::chrono::milliseconds duration;
    };
    
    RebalanceStats GetStats() const;
    
private:
    NodeRegistry* registry_;
    DistributionConfig config_;
    
    std::atomic<bool> running_{false};
    std::thread balancer_thread_;
    
    RebalanceStats stats_;
    mutable std::mutex stats_mutex_;
    
    void BalancerLoop();
    double CalculateLoadVariance() const;
};

// ============================================================================
// Consensus Manager
// ============================================================================

class ConsensusManager {
public:
    ConsensusManager(const DistributionConfig& config);
    
    // Consensus operations
    bool ProposeTask(const DistributedTask& task);
    bool AckTask(const std::string& task_id, const std::string& node_id);
    bool NackTask(const std::string& task_id, const std::string& node_id, 
                  const std::string& reason);
    
    // Check consensus
    bool HasConsensus(const std::string& task_id) const;
    bool IsRejected(const std::string& task_id) const;
    std::vector<std::string> GetConsensusNodes(const std::string& task_id) const;
    
    // Cleanup
    void CleanupCompletedTasks();
    
private:
    DistributionConfig config_;
    
    struct ConsensusState {
        std::vector<std::string> acks;
        std::vector<std::string> nacks;
        std::chrono::steady_clock::time_point proposal_time;
    };
    
    std::map<std::string, ConsensusState> consensus_states_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Fault Tolerance Manager
// ============================================================================

class FaultToleranceManager {
public:
    FaultToleranceManager(NodeRegistry* registry, const DistributionConfig& config);
    
    // Failure detection
    void DetectFailures();
    bool IsNodeFailed(const std::string& node_id) const;
    
    // Recovery
    void HandleNodeFailure(const std::string& node_id);
    void RecoverTask(const DistributedTask& task);
    
    // Task retry
    bool ShouldRetry(const DistributedTask& task) const;
    DistributedTask PrepareRetry(const DistributedTask& task);
    
    // Checkpointing
    void CheckpointTask(const DistributedTask& task);
    DistributedTask RestoreFromCheckpoint(const std::string& task_id);
    
private:
    NodeRegistry* registry_;
    DistributionConfig config_;
    
    std::map<std::string, DistributedTask> checkpoints_;
    mutable std::mutex checkpoint_mutex_;
};

// ============================================================================
// Distributed Scheduler
// ============================================================================

class DistributedScheduler {
public:
    DistributedScheduler(const std::string& node_id,
                        NodeType type,
                        const DistributionConfig& config = DistributionConfig{});
    ~DistributedScheduler();
    
    // Lifecycle
    void Initialize();
    void Start();
    void Stop();
    void Shutdown();
    
    // Node management
    void JoinCluster(const std::string& coordinator_address);
    void LeaveCluster();
    void RegisterWithCoordinator();
    
    // Task submission
    uint64_t SubmitDistributedTask(const ScheduledTask& task);
    void SubmitTaskToNode(const ScheduledTask& task, const std::string& node_id);
    
    // Task execution
    void ExecuteLocalTask(const DistributedTask& task);
    void CompleteDistributedTask(uint64_t task_id, double tps, bool success);
    void FailDistributedTask(uint64_t task_id, const std::string& reason);
    
    // Queries
    DistributedTask GetDistributedTask(uint64_t task_id) const;
    std::vector<DistributedTask> GetLocalTasks() const;
    std::vector<DistributedTask> GetRemoteTasks() const;
    
    // Cluster state
    NodeInfo GetLocalNodeInfo() const;
    std::vector<NodeInfo> GetClusterNodes() const;
    bool IsCoordinator() const;
    std::string GetCoordinatorId() const;
    
    // Statistics
    struct DistributedStats {
        uint64_t tasks_submitted;
        uint64_t tasks_executed_locally;
        uint64_t tasks_executed_remotely;
        uint64_t tasks_migrated;
        uint64_t tasks_failed;
        uint64_t node_failures_detected;
        uint64_t rebalances_triggered;
        double average_task_migration_time_ms;
    };
    
    DistributedStats GetStats() const;
    
    // Configuration
    void SetDistributionPolicy(DistributionPolicy policy);
    DistributionPolicy GetDistributionPolicy() const;
    
private:
    std::string node_id_;
    NodeType type_;
    DistributionConfig config_;
    
    // Components
    std::unique_ptr<NodeRegistry> node_registry_;
    std::unique_ptr<TaskDistributor> task_distributor_;
    std::unique_ptr<LoadBalancer> load_balancer_;
    std::unique_ptr<ConsensusManager> consensus_manager_;
    std::unique_ptr<FaultToleranceManager> ft_manager_;
    std::unique_ptr<AdaptiveScheduler> local_scheduler_;
    
    // Task storage
    std::map<uint64_t, DistributedTask> distributed_tasks_;
    mutable std::mutex tasks_mutex_;
    
    // Statistics
    DistributedStats stats_;
    mutable std::mutex stats_mutex_;
    
    // Running state
    std::atomic<bool> running_{false};
    std::thread heartbeat_thread_;
    std::thread monitor_thread_;
    
    // Private methods
    void HeartbeatLoop();
    void MonitorLoop();
    void ProcessDistributedTask(const DistributedTask& task);
    void HandleTaskCompletion(uint64_t task_id, bool success);
};

// ============================================================================
// Cluster Coordinator
// ============================================================================

class ClusterCoordinator {
public:
    ClusterCoordinator(const std::string& coordinator_id,
                      const DistributionConfig& config);
    
    void Start();
    void Stop();
    
    // Node management
    void RegisterNode(const NodeInfo& node);
    void UnregisterNode(const std::string& node_id);
    void UpdateNodeState(const std::string& node_id, NodeState state);
    
    // Task coordination
    void CoordinateTaskDistribution(const DistributedTask& task);
    void HandleTaskCompletion(const std::string& node_id, uint64_t task_id);
    void HandleTaskFailure(const std::string& node_id, uint64_t task_id, 
                          const std::string& reason);
    
    // Cluster operations
    void TriggerRebalance();
    void HandleNodeFailure(const std::string& node_id);
    void MigrateTasks(const std::string& from_node, const std::string& to_node);
    
    // Statistics
    struct ClusterStats {
        uint32_t active_nodes;
        uint32_t total_nodes;
        uint64_t tasks_in_progress;
        uint64_t tasks_completed;
        double cluster_throughput;
        double cluster_load;
        std::chrono::steady_clock::time_point uptime;
    };
    
    ClusterStats GetClusterStats() const;
    
private:
    std::string coordinator_id_;
    DistributionConfig config_;
    
    std::unique_ptr<NodeRegistry> node_registry_;
    std::unique_ptr<LoadBalancer> load_balancer_;
    
    std::atomic<bool> running_{false};
    std::thread coordinator_thread_;
    
    ClusterStats stats_;
    mutable std::mutex stats_mutex_;
    
    void CoordinatorLoop();
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace DistributedUtils {
    // Network utilities
    std::string GetLocalAddress();
    bool IsReachable(const std::string& address, uint16_t port);
    double MeasureLatency(const std::string& address, uint16_t port);
    
    // Consistent hashing
    std::string ConsistentHash(const std::string& key, 
                               const std::vector<std::string>& nodes);
    
    // Load calculation
    double CalculateLoadScore(const NodeInfo& node);
    double CalculateCapacityScore(const NodeInfo& node);
    
    // Task affinity
    std::string FindAffinityNode(const ScheduledTask& task,
                                  const std::vector<NodeInfo>& nodes);
} // namespace DistributedUtils

} // namespace Scheduler

#endif // DISTRIBUTED_SCHEDULER_HPP
