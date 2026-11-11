// Sovereign Distributed Runtime - Phase D.3 Batch 5/5
// Integration & Testing Framework
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "SovereignNodeDiscovery.hpp"
#include "SovereignConsensusEngine.hpp"
#include "SovereignDistributedRollback.hpp"
#include "SovereignStateReplication.hpp"
#include <memory>
#include <functional>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// Distributed Runtime Configuration
// ============================================================================

struct DistributedRuntimeConfig {
    // Node identity
    NodeIdentity self;
    
    // Discovery
    NodeDiscovery::Config discovery;
    
    // Consensus
    ConsensusEngine::Config consensus;
    
    // Rollback
    DistributedRollbackCoordinator::Config rollback;
    
    // Replication
    StateReplicationEngine::Config replication;
    
    // Safety
    DistributedSafetyGate::Config safety;
    
    // Integration
    bool enable_auto_failover = true;
    bool enable_load_balancing = true;
    int health_check_interval_ms = 5000;
    int metrics_export_interval_ms = 30000;
};

// ============================================================================
// Distributed Runtime (Main Integration)
// ============================================================================

class DistributedRuntime {
public:
    explicit DistributedRuntime(const DistributedRuntimeConfig& config);
    ~DistributedRuntime();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    bool IsLeader() const;
    
    // Cluster operations
    bool JoinCluster(const std::vector<NodeIdentity>& seed_nodes);
    bool LeaveCluster();
    ClusterTopology GetClusterTopology() const;
    
    // Safety operations
    SafetyDecision ProposeSafetyAction(const SafetyProposal& proposal);
    bool IsSafeToProceed(const std::string& operation_id);
    
    // Rollback operations
    std::string InitiateRollback(const RollbackOperation& operation);
    RollbackResult GetRollbackResult(const std::string& rollback_id);
    
    // State operations
    bool PublishState(const ReplicatedState& state);
    ReplicatedState GetState(const std::string& state_id);
    
    // Health & metrics
    struct HealthStatus {
        bool healthy = false;
        NodeHealth node_health = NodeHealth::HEALTHY;
        bool consensus_active = false;
        bool replication_caught_up = false;
        int healthy_nodes = 0;
        int total_nodes = 0;
        std::string leader_id;
        std::vector<std::string> warnings;
    };
    HealthStatus GetHealthStatus() const;
    
    struct Metrics {
        int64_t operations_served = 0;
        int64_t safety_checks = 0;
        int64_t rollbacks_initiated = 0;
        int64_t states_replicated = 0;
        double avg_consensus_time_ms = 0.0;
        double avg_replication_latency_ms = 0.0;
    };
    Metrics GetMetrics() const;
    
    // Callbacks
    using SafetyEventCallback = std::function<void(const SafetyCommit&)>;
    using RollbackEventCallback = std::function<void(const RollbackResult&)>;
    using TopologyChangeCallback = std::function<void(const ClusterTopology&)>;
    
    void OnSafetyEvent(SafetyEventCallback cb);
    void OnRollbackEvent(RollbackEventCallback cb);
    void OnTopologyChange(TopologyChangeCallback cb);
    
    // Testing
    void InjectFault(const std::string& fault_type);
    void ClearFaults();
    
private:
    DistributedRuntimeConfig config_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    
    // Subsystems
    std::unique_ptr<NodeDiscovery> discovery_;
    std::unique_ptr<ConsensusEngine> consensus_;
    std::unique_ptr<DistributedRollbackCoordinator> rollback_;
    std::unique_ptr<StateReplicationEngine> replication_;
    std::unique_ptr<DistributedSafetyGate> safety_gate_;
    
    // Callbacks
    SafetyEventCallback on_safety_event_;
    RollbackEventCallback on_rollback_event_;
    TopologyChangeCallback on_topology_change_;
    
    // Health monitoring
    std::thread health_thread_;
    void HealthLoop();
    
    // Integration helpers
    void SetupEventHandlers();
    void OnConsensusCommit(const SafetyCommit& commit);
    void OnRollbackComplete(const RollbackResult& result);
    void OnClusterTopologyChange(const ClusterTopology& topology);
};

// ============================================================================
// Testing Framework
// ============================================================================

class DistributedTestFramework {
public:
    struct TestScenario {
        std::string name;
        std::string description;
        int node_count = 3;
        std::vector<std::string> fault_injections;
        std::function<bool(DistributedRuntime*)> validation;
        int timeout_ms = 60000;
    };
    
    struct TestResult {
        std::string scenario_name;
        bool passed = false;
        int64_t duration_ms = 0;
        std::string error_message;
        std::map<std::string, std::string> metrics;
    };
    
    // Test scenarios
    static TestScenario LeaderElectionTest();
    static TestScenario ConsensusWithPartitionTest();
    static TestScenario RollbackCoordinationTest();
    static TestScenario StateReplicationTest();
    static TestScenario NetworkPartitionRecoveryTest();
    static TestScenario CascadingFailureTest();
    static TestScenario LoadBalancingTest();
    static TestScenario SafetyGateDistributedTest();
    
    // Execution
    TestResult RunScenario(const TestScenario& scenario);
    std::vector<TestResult> RunAllScenarios();
    
    // Utilities
    static std::vector<std::unique_ptr<DistributedRuntime>> 
        CreateTestCluster(int node_count);
    static void PartitionCluster(std::vector<DistributedRuntime*>& partitioned_nodes);
    static void HealPartition(std::vector<DistributedRuntime*>& partitioned_nodes);
    static void KillNode(DistributedRuntime* node);
    static void ReviveNode(DistributedRuntime* node);
    
private:
    std::vector<TestResult> results_;
};

// ============================================================================
// Benchmark Integration
// ============================================================================

class DistributedBenchmarkAdapter {
public:
    // Run benchmark across cluster
    struct BenchmarkConfig {
        std::string benchmark_name;
        int duration_seconds = 60;
        int concurrent_agents = 100;
        bool enable_fault_injection = false;
        bool measure_consensus_overhead = true;
    };
    
    struct BenchmarkResult {
        std::string benchmark_name;
        int64_t total_operations = 0;
        double throughput_ops_per_sec = 0.0;
        double avg_latency_ms = 0.0;
        double p99_latency_ms = 0.0;
        int consensus_count = 0;
        double avg_consensus_time_ms = 0.0;
        int rollback_count = 0;
        int node_failures = 0;
        bool cluster_stable = false;
    };
    
    BenchmarkResult RunBenchmark(const BenchmarkConfig& config,
                                  std::vector<DistributedRuntime*>& cluster);
    
    // Comparison
    static BenchmarkResult CompareSingleVsDistributed(
        int duration_seconds,
        DistributedRuntime* single_node,
        std::vector<DistributedRuntime*>& cluster);
};

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<DistributedRuntime> CreateDistributedRuntime(
    const DistributedRuntimeConfig& config);

bool ValidateDistributedConfig(const DistributedRuntimeConfig& config);

} // namespace Distributed
} // namespace Sovereign
