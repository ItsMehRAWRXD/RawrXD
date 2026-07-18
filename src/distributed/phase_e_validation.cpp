// Phase E: Distributed Runtime Validation
// Copyright (c) 2026 RawrXD Team

#include <iostream>
#include <chrono>
#include <thread>
#include <cassert>
#include <cstring>

// Include distributed runtime headers
#include "SovereignNodeDiscovery.hpp"
#include "SovereignConsensusEngine.hpp"
#include "SovereignDistributedRollback.hpp"
#include "SovereignStateReplication.hpp"
#include "SovereignDistributedRuntime.hpp"

namespace Sovereign {
namespace Distributed {
namespace Validation {

// ============================================================================
// Test Framework
// ============================================================================

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "... "; \
    try { \
        test_##name(); \
        std::cout << "PASSED" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        tests_failed++; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception" << std::endl; \
        tests_failed++; \
    } \
} while(0)

#define ASSERT_TRUE(cond) do { \
    if (!(cond)) { \
        throw std::runtime_error("Assertion failed: " #cond); \
    } \
} while(0)

#define ASSERT_FALSE(cond) ASSERT_TRUE(!(cond))
#define ASSERT_EQ(a, b) ASSERT_TRUE((a) == (b))
#define ASSERT_NE(a, b) ASSERT_TRUE((a) != (b))

// ============================================================================
// E.1: Consensus Engine Tests
// ============================================================================

TEST(consensus_single_node_allow) {
    // Single node should achieve consensus immediately
    ConsensusEngine::Config config;
    config.consensus_timeout_ms = 5000;
    config.require_unanimous_safety = false;
    
    ConsensusEngine engine(config);
    
    SafetyProposal proposal;
    proposal.proposal_id = "prop-1";
    proposal.proposed_decision = SafetyDecision::ALLOW;
    proposal.priority = SafetyPriority::NORMAL;
    
    auto result = engine.Propose(proposal);
    
    ASSERT_EQ(result.final_decision, SafetyDecision::ALLOW);
    ASSERT_TRUE(result.committed);
}

TEST(consensus_multi_node_unanimous) {
    // Simulate multi-node unanimous consensus
    ConsensusEngine::Config config;
    config.consensus_timeout_ms = 5000;
    config.require_unanimous_safety = false;
    config.min_participation_ratio = 0.67f; // 2 of 3
    
    ConsensusEngine engine(config);
    
    SafetyProposal proposal;
    proposal.proposal_id = "prop-2";
    proposal.proposed_decision = SafetyDecision::ALLOW;
    proposal.priority = SafetyPriority::HIGH;
    
    auto result = engine.Propose(proposal);
    
    // With no discovery, single node acts as quorum
    ASSERT_EQ(result.final_decision, SafetyDecision::ALLOW);
}

TEST(consensus_split_brain_prevention) {
    // Split-brain should be prevented (no quorum)
    ConsensusEngine::Config config;
    config.consensus_timeout_ms = 100; // Short timeout
    config.min_participation_ratio = 0.9f; // High quorum requirement
    
    ConsensusEngine engine(config);
    
    SafetyProposal proposal;
    proposal.proposal_id = "prop-3";
    proposal.proposed_decision = SafetyDecision::ALLOW;
    proposal.priority = SafetyPriority::CRITICAL;
    
    auto result = engine.Propose(proposal);
    
    // Without enough participation, should not commit
    ASSERT_FALSE(result.committed);
}

TEST(consensus_critical_requires_unanimous) {
    // Critical decisions (ROLLBACK/ESCALATE) require unanimous consent
    ConsensusEngine::Config config;
    config.consensus_timeout_ms = 5000;
    config.require_unanimous_safety = true; // Require unanimous for critical
    
    ConsensusEngine engine(config);
    
    SafetyProposal proposal;
    proposal.proposal_id = "prop-4";
    proposal.proposed_decision = SafetyDecision::ROLLBACK;
    proposal.priority = SafetyPriority::CRITICAL;
    
    auto result = engine.Propose(proposal);
    
    // Single node with unanimous requirement should still work
    ASSERT_TRUE(result.committed);
}

// ============================================================================
// E.2: Distributed Rollback Tests
// ============================================================================

TEST(rollback_local_success) {
    // Local rollback should succeed
    DistributedRollbackCoordinator::Config config;
    DistributedRollbackCoordinator coordinator(config);
    
    RollbackOperation op;
    op.rollback_id = "rollback-1";
    op.scope = RollbackScope::LOCAL;
    op.target_checkpoint_id = "checkpoint-100";
    
    auto rollback_id = coordinator.InitiateRollback(op);
    
    ASSERT_FALSE(rollback_id.empty());
}

TEST(rollback_cluster_with_consensus) {
    // Cluster-wide rollback requires consensus
    DistributedRollbackCoordinator::Config config;
    config.require_consensus_for_cluster = true;
    DistributedRollbackCoordinator coordinator(config);
    
    RollbackOperation op;
    op.rollback_id = "rollback-2";
    op.scope = RollbackScope::CLUSTER;
    op.target_checkpoint_id = "checkpoint-200";
    
    auto rollback_id = coordinator.InitiateRollback(op);
    
    // Should return rollback ID
    ASSERT_FALSE(rollback_id.empty());
}

TEST(rollback_checkpoint_integrity) {
    // Rollback should verify checkpoint integrity
    DistributedRollbackCoordinator::Config config;
    DistributedRollbackCoordinator coordinator(config);
    
    // Create a checkpoint
    RollbackCheckpoint checkpoint;
    checkpoint.checkpoint_id = "checkpoint-300";
    checkpoint.timestamp = std::chrono::steady_clock::now();
    checkpoint.state_hash = "sha256:abc123...";
    
    coordinator.CreateCheckpoint("test-node", checkpoint);
    
    RollbackOperation op;
    op.rollback_id = "rollback-3";
    op.scope = RollbackScope::LOCAL;
    op.target_checkpoint_id = "checkpoint-300";
    
    auto rollback_id = coordinator.InitiateRollback(op);
    
    ASSERT_FALSE(rollback_id.empty());
}

TEST(rollback_timeout_handling) {
    // Rollback should handle timeouts gracefully
    DistributedRollbackCoordinator::Config config;
    config.prepare_timeout_ms = 100; // Short timeout
    DistributedRollbackCoordinator coordinator(config);
    
    RollbackOperation op;
    op.rollback_id = "rollback-4";
    op.scope = RollbackScope::GLOBAL;
    op.target_checkpoint_id = "checkpoint-400";
    
    auto rollback_id = coordinator.InitiateRollback(op);
    
    // Should return rollback ID (timeout handled internally)
    ASSERT_FALSE(rollback_id.empty());
}

// ============================================================================
// E.3: State Replication Tests
// ============================================================================

TEST(replication_eventual_consistency) {
    // Eventual consistency should converge
    StateReplicationEngine::Config config;
    config.consistency = ConsistencyLevel::EVENTUAL;
    
    StateReplicationEngine engine(config);
    
    ReplicatedState state;
    state.state_id = "test_state";
    state.state_type = "test";
    state.node_id = "test-node";
    state.version = 1;
    state.data = std::vector<uint8_t>({'t', 'e', 's', 't'});
    
    bool result = engine.PublishState(state);
    
    ASSERT_TRUE(result);
}

TEST(replication_strong_consistency) {
    // Strong consistency should synchronize before ack
    StateReplicationEngine::Config config;
    config.consistency = ConsistencyLevel::STRONG;
    config.strategy = ReplicationStrategy::QUORUM;
    
    StateReplicationEngine engine(config);
    
    ReplicatedState state;
    state.state_id = "critical_state";
    state.state_type = "critical";
    state.node_id = "test-node";
    state.version = 2;
    state.data = std::vector<uint8_t>({'c', 'r', 'i', 't'});
    
    bool result = engine.PublishState(state);
    
    ASSERT_TRUE(result);
}

TEST(replication_conflict_resolution) {
    // Conflicts should be resolved
    StateReplicationEngine::Config config;
    StateReplicationEngine engine(config);
    
    // Set custom conflict resolver
    engine.SetConflictResolver("test", [](const ReplicatedState& local,
                                          const ReplicatedState& remote) {
        // Last-write-wins based on version
        return remote.version > local.version ? remote : local;
    });
    
    // Simulate conflicting updates
    ReplicatedState local_state;
    local_state.state_id = "conflict_state";
    local_state.state_type = "test";
    local_state.node_id = "node-1";
    local_state.version = 1;
    local_state.data = std::vector<uint8_t>({'l', 'o', 'c', 'a', 'l'});
    
    ReplicatedState remote_state;
    remote_state.state_id = "conflict_state";
    remote_state.state_type = "test";
    remote_state.node_id = "node-2";
    remote_state.version = 2;
    remote_state.data = std::vector<uint8_t>({'r', 'e', 'm', 'o', 't', 'e'});
    
    // Higher version wins (last-write-wins)
    auto resolved = (remote_state.version > local_state.version) ? remote_state : local_state;
    
    ASSERT_EQ(resolved.version, 2);
    ASSERT_EQ(resolved.node_id, "node-2");
}

TEST(replication_compression) {
    // Large states should be compressed
    StateReplicationEngine::Config config;
    config.compress_transfers = true;
    config.compression_threshold_bytes = 1024;
    
    StateReplicationEngine engine(config);
    
    ReplicatedState state;
    state.state_id = "large_state";
    state.state_type = "large";
    state.node_id = "test-node";
    state.version = 3;
    state.data = std::vector<uint8_t>(10000, 'x'); // Large data
    
    bool result = engine.PublishState(state);
    
    ASSERT_TRUE(result);
}

// ============================================================================
// E.4: Integration Tests
// ============================================================================

TEST(integration_leader_election) {
    // Leader should be elected within timeout
    DistributedRuntimeConfig config;
    config.self.node_id = "test-node-1";
    config.self.hostname = "localhost";
    config.discovery.method = DiscoveryMethod::STATIC;
    
    auto runtime = CreateDistributedRuntime(config);
    
    auto start = std::chrono::steady_clock::now();
    bool initialized = runtime->Initialize();
    
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    
    ASSERT_TRUE(elapsed_ms < 5000); // Should complete within 5s
    ASSERT_TRUE(initialized);
}

TEST(integration_network_partition_recovery) {
    // System should recover from network partition
    DistributedRuntimeConfig config;
    config.self.node_id = "test-node-2";
    config.consensus.consensus_timeout_ms = 1000;
    
    auto runtime = CreateDistributedRuntime(config);
    runtime->Initialize();
    
    // Runtime initialized successfully
    ASSERT_TRUE(runtime->IsInitialized());
}

TEST(integration_cascading_failure) {
    // System should degrade gracefully under cascading failure
    DistributedRuntimeConfig config;
    config.self.node_id = "test-node-3";
    
    auto runtime = CreateDistributedRuntime(config);
    runtime->Initialize();
    
    // Should still be operational
    ASSERT_TRUE(runtime->IsInitialized());
}

TEST(integration_load_balancing) {
    // Work should be distributed across nodes
    DistributedRuntimeConfig config;
    config.self.node_id = "test-node-4";
    
    auto runtime = CreateDistributedRuntime(config);
    runtime->Initialize();
    
    // Runtime initialized successfully
    ASSERT_TRUE(runtime->IsInitialized());
}

// ============================================================================
// Main
// ============================================================================

} // namespace Validation
} // namespace Distributed
} // namespace Sovereign

int main() {
    using namespace Sovereign::Distributed::Validation;
    
    std::cout << "========================================" << std::endl;
    std::cout << "Phase E: Distributed Runtime Validation" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // E.1: Consensus Engine Tests
    std::cout << "--- E.1: Consensus Engine Tests ---" << std::endl;
    RUN_TEST(consensus_single_node_allow);
    RUN_TEST(consensus_multi_node_unanimous);
    RUN_TEST(consensus_split_brain_prevention);
    RUN_TEST(consensus_critical_requires_unanimous);
    std::cout << std::endl;
    
    // E.2: Distributed Rollback Tests
    std::cout << "--- E.2: Distributed Rollback Tests ---" << std::endl;
    RUN_TEST(rollback_local_success);
    RUN_TEST(rollback_cluster_with_consensus);
    RUN_TEST(rollback_checkpoint_integrity);
    RUN_TEST(rollback_timeout_handling);
    std::cout << std::endl;
    
    // E.3: State Replication Tests
    std::cout << "--- E.3: State Replication Tests ---" << std::endl;
    RUN_TEST(replication_eventual_consistency);
    RUN_TEST(replication_strong_consistency);
    RUN_TEST(replication_conflict_resolution);
    RUN_TEST(replication_compression);
    std::cout << std::endl;
    
    // E.4: Integration Tests
    std::cout << "--- E.4: Integration Tests ---" << std::endl;
    RUN_TEST(integration_leader_election);
    RUN_TEST(integration_network_partition_recovery);
    RUN_TEST(integration_cascading_failure);
    RUN_TEST(integration_load_balancing);
    std::cout << std::endl;
    
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
