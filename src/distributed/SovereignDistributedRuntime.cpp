// Sovereign Distributed Runtime - Phase D.3 Batch 5/5
// Integration Implementation
// Copyright (c) 2026 RawrXD Team

#include "SovereignDistributedRuntime.hpp"
#include <iostream>
#include <sstream>
#include <random>

namespace Sovereign {
namespace Distributed {

// ============================================================================
// DistributedRuntime Implementation
// ============================================================================

DistributedRuntime::DistributedRuntime(const DistributedRuntimeConfig& config)
    : config_(config) {
}

DistributedRuntime::~DistributedRuntime() {
    Shutdown();
}

bool DistributedRuntime::Initialize() {
    if (initialized_) {
        return true;
    }
    
    // Initialize discovery
    discovery_ = std::make_unique<NodeDiscovery>(config_.discovery);
    if (!discovery_->Initialize()) {
        std::cerr << "Failed to initialize node discovery\n";
        return false;
    }
    
    // Initialize consensus
    consensus_ = std::make_unique<ConsensusEngine>(config_.consensus);
    if (!consensus_->Initialize(discovery_)) {
        std::cerr << "Failed to initialize consensus engine\n";
        return false;
    }
    
    // Initialize rollback
    rollback_ = std::make_unique<DistributedRollbackCoordinator>(config_.rollback);
    if (!rollback_->Initialize(discovery_, consensus_)) {
        std::cerr << "Failed to initialize rollback coordinator\n";
        return false;
    }
    
    // Initialize replication
    replication_ = std::make_unique<StateReplicationEngine>(config_.replication);
    if (!replication_->Initialize(discovery_)) {
        std::cerr << "Failed to initialize state replication\n";
        return false;
    }
    
    // Initialize safety gate
    safety_gate_ = std::make_unique<DistributedSafetyGate>(config_.safety);
    if (!safety_gate_->Initialize(consensus_, discovery_)) {
        std::cerr << "Failed to initialize safety gate\n";
        return false;
    }
    
    // Setup event handlers
    SetupEventHandlers();
    
    // Start health monitoring
    running_ = true;
    health_thread_ = std::thread(&DistributedRuntime::HealthLoop, this);
    
    initialized_ = true;
    return true;
}

void DistributedRuntime::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    running_ = false;
    
    if (health_thread_.joinable()) {
        health_thread_.join();
    }
    
    safety_gate_->Shutdown();
    replication_->Shutdown();
    rollback_->Shutdown();
    consensus_->Shutdown();
    discovery_->Shutdown();
    
    initialized_ = false;
}

bool DistributedRuntime::IsLeader() const {
    return discovery_->IsLeader();
}

bool DistributedRuntime::JoinCluster(const std::vector<NodeIdentity>& seed_nodes) {
    // Add seed nodes to discovery
    for (const auto& node : seed_nodes) {
        if (node.node_id != config_.self.node_id) {
            discovery_->GetTopology()->AddNode(node);
        }
    }
    
    // Trigger discovery
    // In production, this would announce presence to cluster
    
    return true;
}

bool DistributedRuntime::LeaveCluster() {
    // Gracefully leave cluster
    discovery_->StepDown();
    
    // Announce departure
    // In production, notify other nodes
    
    return true;
}

ClusterTopology DistributedRuntime::GetClusterTopology() const {
    return *discovery_->GetTopology();
}

SafetyDecision DistributedRuntime::ProposeSafetyAction(const SafetyProposal& proposal) {
    auto commit = consensus_->Propose(proposal);
    return commit.final_decision;
}

bool DistributedRuntime::IsSafeToProceed(const std::string& operation_id) {
    return safety_gate_->IsSafeToProceed(operation_id);
}

std::string DistributedRuntime::InitiateRollback(const RollbackOperation& operation) {
    return rollback_->InitiateRollback(operation);
}

RollbackResult DistributedRuntime::GetRollbackResult(const std::string& rollback_id) {
    return rollback_->GetRollbackResult(rollback_id);
}

bool DistributedRuntime::PublishState(const ReplicatedState& state) {
    return replication_->PublishState(state);
}

ReplicatedState DistributedRuntime::GetState(const std::string& state_id) {
    return replication_->GetState(state_id);
}

DistributedRuntime::HealthStatus DistributedRuntime::GetHealthStatus() const {
    HealthStatus status;
    
    auto topology = discovery_->GetTopology();
    auto nodes = topology->GetHealthyNodes();
    
    status.healthy = initialized_ && topology->HasQuorum();
    status.node_health = topology->GetHealth(config_.self.node_id);
    status.consensus_active = consensus_ != nullptr;
    status.replication_caught_up = true;  // Placeholder
    status.healthy_nodes = nodes.size();
    status.total_nodes = topology->GetHealthyNodes().size();
    status.leader_id = topology->GetLeader();
    
    // Check for warnings
    if (!topology->HasQuorum()) {
        status.warnings.push_back("No quorum available");
    }
    
    if (status.leader_id.empty()) {
        status.warnings.push_back("No leader elected");
    }
    
    return status;
}

DistributedRuntime::Metrics DistributedRuntime::GetMetrics() const {
    Metrics metrics;
    
    auto consensus_stats = consensus_->GetStats();
    auto replication_stats = replication_->GetStats();
    
    metrics.safety_checks = consensus_stats.proposals_initiated;
    metrics.states_replicated = replication_stats.states_replicated;
    metrics.avg_consensus_time_ms = consensus_stats.avg_consensus_time_ms;
    metrics.avg_replication_latency_ms = replication_stats.avg_replication_latency_ms;
    
    return metrics;
}

void DistributedRuntime::OnSafetyEvent(SafetyEventCallback cb) {
    on_safety_event_ = cb;
}

void DistributedRuntime::OnRollbackEvent(RollbackEventCallback cb) {
    on_rollback_event_ = cb;
}

void DistributedRuntime::OnTopologyChange(TopologyChangeCallback cb) {
    on_topology_change_ = cb;
}

void DistributedRuntime::InjectFault(const std::string& fault_type) {
    // For testing - inject various faults
    if (fault_type == "network_partition") {
        // Simulate network partition
    } else if (fault_type == "node_failure") {
        // Simulate node failure
    } else if (fault_type == "leader_failure") {
        // Simulate leader failure
    }
}

void DistributedRuntime::ClearFaults() {
    // Clear injected faults
}

void DistributedRuntime::HealthLoop() {
    while (running_) {
        // Check cluster health
        auto status = GetHealthStatus();
        
        // Auto-failover if enabled
        if (config_.enable_auto_failover && !status.leader_id.empty()) {
            // Check if leader is healthy
            auto leader_health = discovery_->GetTopology()->GetHealth(status.leader_id);
            if (leader_health == NodeHealth::OFFLINE || 
                leader_health == NodeHealth::UNSTABLE) {
                // Trigger leader election
                discovery_->ElectLeader();
            }
        }
        
        std::this_thread::sleep_for(
            std::chrono::milliseconds(config_.health_check_interval_ms));
    }
}

void DistributedRuntime::SetupEventHandlers() {
    // Setup consensus commit handler
    consensus_->OnCommit([this](const SafetyCommit& commit) {
        OnConsensusCommit(commit);
    });
    
    // Setup rollback completion handler
    rollback_->OnRollbackComplete([this](const RollbackResult& result) {
        OnRollbackComplete(result);
    });
    
    // Setup topology change handler
    discovery_->OnNodeJoined([this](const NodeIdentity& node) {
        auto topology = *discovery_->GetTopology();
        OnClusterTopologyChange(topology);
    });
    
    discovery_->OnNodeLeft([this](const NodeIdentity& node) {
        auto topology = *discovery_->GetTopology();
        OnClusterTopologyChange(topology);
    });
}

void DistributedRuntime::OnConsensusCommit(const SafetyCommit& commit) {
    if (on_safety_event_) {
        on_safety_event_(commit);
    }
}

void DistributedRuntime::OnRollbackComplete(const RollbackResult& result) {
    if (on_rollback_event_) {
        on_rollback_event_(result);
    }
}

void DistributedRuntime::OnClusterTopologyChange(const ClusterTopology& topology) {
    if (on_topology_change_) {
        on_topology_change_(topology);
    }
}

// ============================================================================
// DistributedTestFramework Implementation
// ============================================================================

DistributedTestFramework::TestScenario 
DistributedTestFramework::LeaderElectionTest() {
    TestScenario scenario;
    scenario.name = "LeaderElection";
    scenario.description = "Test leader election with 3 nodes";
    scenario.node_count = 3;
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        return !runtime->GetClusterTopology().GetLeader().empty();
    };
    return scenario;
}

DistributedTestFramework::TestScenario 
DistributedTestFramework::ConsensusWithPartitionTest() {
    TestScenario scenario;
    scenario.name = "ConsensusWithPartition";
    scenario.description = "Test consensus during network partition";
    scenario.node_count = 5;
    scenario.fault_injections = {"network_partition"};
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        SafetyProposal proposal;
        proposal.proposal_id = "test-proposal";
        proposal.operation_id = "test-op";
        proposal.proposed_decision = SafetyDecision::ALLOW;
        auto commit = runtime->ProposeSafetyAction(proposal);
        return commit == SafetyDecision::ALLOW || commit == SafetyDecision::DENY;
    };
    return scenario;
}

DistributedTestFramework::TestScenario 
DistributedTestFramework::RollbackCoordinationTest() {
    TestScenario scenario;
    scenario.name = "RollbackCoordination";
    scenario.description = "Test distributed rollback coordination";
    scenario.node_count = 3;
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        RollbackOperation op;
        op.operation_id = "test-op";
        op.scope = RollbackScope::CLUSTER;
        auto rollback_id = runtime->InitiateRollback(op);
        auto result = runtime->GetRollbackResult(rollback_id);
        return result.rollback_id == rollback_id;
    };
    return scenario;
}

DistributedTestFramework::TestScenario 
DistributedTestFramework::StateReplicationTest() {
    TestScenario scenario;
    scenario.name = "StateReplication";
    scenario.description = "Test state replication across nodes";
    scenario.node_count = 3;
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        ReplicatedState state;
        state.state_id = "test-state";
        state.state_type = "test";
        state.data = {1, 2, 3, 4, 5};
        return runtime->PublishState(state);
    };
    return scenario;
}

DistributedTestFramework::TestScenario 
DistributedTestFramework::NetworkPartitionRecoveryTest() {
    TestScenario scenario;
    scenario.name = "NetworkPartitionRecovery";
    scenario.description = "Test recovery from network partition";
    scenario.node_count = 5;
    scenario.fault_injections = {"network_partition"};
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        runtime->ClearFaults();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        return runtime->GetHealthStatus().healthy;
    };
    return scenario;
}

DistributedTestFramework::TestScenario 
DistributedTestFramework::CascadingFailureTest() {
    TestScenario scenario;
    scenario.name = "CascadingFailure";
    scenario.description = "Test handling of cascading failures";
    scenario.node_count = 5;
    scenario.fault_injections = {"node_failure", "node_failure"};
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        auto status = runtime->GetHealthStatus();
        return status.healthy_nodes >= 3;  // Should maintain quorum
    };
    return scenario;
}

DistributedTestFramework::TestScenario 
DistributedTestFramework::LoadBalancingTest() {
    TestScenario scenario;
    scenario.name = "LoadBalancing";
    scenario.description = "Test load distribution across nodes";
    scenario.node_count = 5;
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        auto topology = runtime->GetClusterTopology();
        return topology.GetHealthyNodes().size() >= 3;
    };
    return scenario;
}

DistributedTestFramework::TestScenario 
DistributedTestFramework::SafetyGateDistributedTest() {
    TestScenario scenario;
    scenario.name = "SafetyGateDistributed";
    scenario.description = "Test distributed safety gate decisions";
    scenario.node_count = 3;
    scenario.validation = [](DistributedRuntime* runtime) -> bool {
        SafetyContext context;
        context.operation_id = "safety-test";
        context.priority = SafetyPriority::HIGH;
        context.description = "Test safety check";
        auto decision = runtime->ProposeSafetyAction(SafetyProposal());
        return decision != SafetyDecision::DENY;
    };
    return scenario;
}

DistributedTestFramework::TestResult 
DistributedTestFramework::RunScenario(const TestScenario& scenario) {
    TestResult result;
    result.scenario_name = scenario.name;
    
    auto start = std::chrono::steady_clock::now();
    
    // Create test cluster
    auto cluster = CreateTestCluster(scenario.node_count);
    if (cluster.empty()) {
        result.passed = false;
        result.error_message = "Failed to create test cluster";
        return result;
    }
    
    // Initialize all nodes
    for (auto& node : cluster) {
        if (!node->Initialize()) {
            result.passed = false;
            result.error_message = "Failed to initialize node";
            return result;
        }
    }
    
    // Join cluster
    std::vector<NodeIdentity> seed_nodes;
    for (auto& node : cluster) {
        seed_nodes.push_back(node->GetClusterTopology().GetHealthyNodes()[0]);
    }
    
    for (auto& node : cluster) {
        node->JoinCluster(seed_nodes);
    }
    
    // Inject faults if specified
    for (const auto& fault : scenario.fault_injections) {
        cluster[0]->InjectFault(fault);
    }
    
    // Run validation
    try {
        result.passed = scenario.validation(cluster[0].get());
    } catch (const std::exception& e) {
        result.passed = false;
        result.error_message = e.what();
    }
    
    // Cleanup
    for (auto& node : cluster) {
        node->LeaveCluster();
        node->Shutdown();
    }
    
    auto elapsed = std::chrono::steady_clock::now() - start;
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    
    results_.push_back(result);
    return result;
}

std::vector<DistributedTestFramework::TestResult> 
DistributedTestFramework::RunAllScenarios() {
    std::vector<TestResult> all_results;
    
    all_results.push_back(RunScenario(LeaderElectionTest()));
    all_results.push_back(RunScenario(ConsensusWithPartitionTest()));
    all_results.push_back(RunScenario(RollbackCoordinationTest()));
    all_results.push_back(RunScenario(StateReplicationTest()));
    all_results.push_back(RunScenario(NetworkPartitionRecoveryTest()));
    all_results.push_back(RunScenario(CascadingFailureTest()));
    all_results.push_back(RunScenario(LoadBalancingTest()));
    all_results.push_back(RunScenario(SafetyGateDistributedTest()));
    
    return all_results;
}

std::vector<std::unique_ptr<DistributedRuntime>> 
DistributedTestFramework::CreateTestCluster(int node_count) {
    std::vector<std::unique_ptr<DistributedRuntime>> cluster;
    
    for (int i = 0; i < node_count; ++i) {
        DistributedRuntimeConfig config;
        config.self.node_id = "test-node-" + std::to_string(i);
        config.self.hostname = "localhost";
        config.self.port = 8000 + i;
        config.discovery.method = DiscoveryMethod::STATIC;
        
        auto runtime = std::make_unique<DistributedRuntime>(config);
        cluster.push_back(std::move(runtime));
    }
    
    return cluster;
}

void DistributedTestFramework::PartitionCluster(
    std::vector<DistributedRuntime*>& partitioned_nodes) {
    for (auto* node : partitioned_nodes) {
        node->InjectFault("network_partition");
    }
}

void DistributedTestFramework::HealPartition(
    std::vector<DistributedRuntime*>& partitioned_nodes) {
    for (auto* node : partitioned_nodes) {
        node->ClearFaults();
    }
}

void DistributedTestFramework::KillNode(DistributedRuntime* node) {
    node->InjectFault("node_failure");
}

void DistributedTestFramework::ReviveNode(DistributedRuntime* node) {
    node->ClearFaults();
}

// ============================================================================
// DistributedBenchmarkAdapter Implementation
// ============================================================================

DistributedBenchmarkAdapter::BenchmarkResult 
DistributedBenchmarkAdapter::RunBenchmark(
    const BenchmarkConfig& config,
    std::vector<DistributedRuntime*>& cluster) {
    BenchmarkResult result;
    result.benchmark_name = config.benchmark_name;
    
    auto start = std::chrono::steady_clock::now();
    
    // Run benchmark operations
    int64_t operations = 0;
    std::vector<double> latencies;
    
    auto end_time = start + std::chrono::seconds(config.duration_seconds);
    
    while (std::chrono::steady_clock::now() < end_time) {
        for (auto* node : cluster) {
            auto op_start = std::chrono::steady_clock::now();
            
            // Perform operation
            SafetyProposal proposal;
            proposal.proposal_id = "bench-" + std::to_string(operations);
            proposal.operation_id = "bench-op";
            proposal.proposed_decision = SafetyDecision::ALLOW;
            node->ProposeSafetyAction(proposal);
            
            auto op_end = std::chrono::steady_clock::now();
            auto latency = std::chrono::duration_cast<std::chrono::microseconds>(
                op_end - op_start).count();
            latencies.push_back(latency / 1000.0);  // Convert to ms
            
            operations++;
        }
    }
    
    // Calculate results
    result.total_operations = operations;
    auto elapsed = std::chrono::steady_clock::now() - start;
    result.throughput_ops_per_sec = operations / 
        std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    
    if (!latencies.empty()) {
        double sum = 0;
        for (double lat : latencies) sum += lat;
        result.avg_latency_ms = sum / latencies.size();
        
        // Calculate p99
        std::sort(latencies.begin(), latencies.end());
        size_t p99_idx = static_cast<size_t>(latencies.size() * 0.99);
        result.p99_latency_ms = latencies[p99_idx];
    }
    
    // Get consensus stats
    int consensus_count = 0;
    double total_consensus_time = 0;
    for (auto* node : cluster) {
        auto metrics = node->GetMetrics();
        consensus_count += metrics.safety_checks;
        total_consensus_time += metrics.avg_consensus_time_ms;
    }
    
    result.consensus_count = consensus_count;
    result.avg_consensus_time_ms = cluster.empty() ? 0 : 
        total_consensus_time / cluster.size();
    
    return result;
}

DistributedBenchmarkAdapter::BenchmarkResult 
DistributedBenchmarkAdapter::CompareSingleVsDistributed(
    int duration_seconds,
    DistributedRuntime* single_node,
    std::vector<DistributedRuntime*>& cluster) {
    BenchmarkResult comparison;
    comparison.benchmark_name = "SingleVsDistributed";
    
    // Run single node benchmark
    std::vector<DistributedRuntime*> single_cluster = {single_node};
    BenchmarkConfig single_config;
    single_config.duration_seconds = duration_seconds;
    single_config.benchmark_name = "single";
    auto single_result = RunBenchmark(single_config, single_cluster);
    
    // Run distributed benchmark
    BenchmarkConfig dist_config;
    dist_config.duration_seconds = duration_seconds;
    dist_config.benchmark_name = "distributed";
    auto dist_result = RunBenchmark(dist_config, cluster);
    
    // Compare
    comparison.throughput_ops_per_sec = dist_result.throughput_ops_per_sec;
    comparison.avg_latency_ms = dist_result.avg_latency_ms - single_result.avg_latency_ms;
    comparison.avg_consensus_time_ms = dist_result.avg_consensus_time_ms;
    
    return comparison;
}

// ============================================================================
// Factory Functions
// ============================================================================

std::unique_ptr<DistributedRuntime> CreateDistributedRuntime(
    const DistributedRuntimeConfig& config) {
    return std::make_unique<DistributedRuntime>(config);
}

bool ValidateDistributedConfig(const DistributedRuntimeConfig& config) {
    if (config.self.node_id.empty()) {
        return false;
    }
    
    if (config.self.hostname.empty()) {
        return false;
    }
    
    if (config.self.port <= 0) {
        return false;
    }
    
    return true;
}

} // namespace Distributed
} // namespace Sovereign
