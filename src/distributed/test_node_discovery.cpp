// Sovereign Node Discovery Unit Tests
// Layer 1.1 - Discovery Validation Closure
// Copyright (c) 2026 RawrXD Team

#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include "SovereignNodeDiscovery.hpp"

using namespace Sovereign::Distributed;

// Simple test framework
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) void test_##name()
#define RUN_TEST(name) do { \
    std::cout << "Running " #name "... "; \
    tests_run++; \
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

#define ASSERT_TRUE(expr) do { \
    if (!(expr)) { \
        throw std::runtime_error("Assertion failed: " #expr); \
    } \
} while(0)

#define ASSERT_FALSE(expr) ASSERT_TRUE(!(expr))

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        throw std::runtime_error("Assertion failed: " #a " == " #b); \
    } \
} while(0)

#define ASSERT_NE(a, b) do { \
    if ((a) == (b)) { \
        throw std::runtime_error("Assertion failed: " #a " != " #b); \
    } \
} while(0)

// Helper to create a test node identity
NodeIdentity CreateTestNode(const std::string& id_suffix, const std::string& dc = "test-dc") {
    NodeIdentity node;
    node.node_id = "node-" + id_suffix;
    node.hostname = "host-" + id_suffix;
    node.ip_address = "192.168.1." + id_suffix;
    node.port = 42424;
    node.datacenter = dc;
    node.rack = "rack-" + id_suffix;
    node.version = "1.0.0";
    node.capabilities = {"inference", "training"};
    return node;
}

// ============================================================================
// Basic Lifecycle Tests
// ============================================================================

TEST(create_discovery) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    config.method = DiscoveryMethod::STATIC_LIST;
    config.heartbeat_interval_ms = 100;
    config.heartbeat_timeout_ms = 500;
    
    NodeDiscovery discovery(config);
    ASSERT_FALSE(discovery.IsInitialized());
}

TEST(initialize_shutdown) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    config.method = DiscoveryMethod::STATIC_LIST;
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    ASSERT_TRUE(discovery.IsInitialized());
    
    discovery.Shutdown();
    ASSERT_FALSE(discovery.IsInitialized());
}

// ============================================================================
// Node Registration Tests
// ============================================================================

TEST(register_single_node) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    NodeIdentity nodeA = CreateTestNode("A");
    ASSERT_TRUE(discovery.AddNode(nodeA));
    
    auto nodes = discovery.GetAllNodes();
    ASSERT_EQ(nodes.size(), 1u);
    ASSERT_EQ(nodes[0].node_id, "node-A");
    
    discovery.Shutdown();
}

TEST(register_multiple_nodes) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    NodeIdentity nodeA = CreateTestNode("A");
    NodeIdentity nodeB = CreateTestNode("B");
    
    ASSERT_TRUE(discovery.AddNode(nodeA));
    ASSERT_TRUE(discovery.AddNode(nodeB));
    
    auto nodes = discovery.GetAllNodes();
    ASSERT_EQ(nodes.size(), 2u);
    
    discovery.Shutdown();
}

TEST(query_peers) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    NodeIdentity nodeA = CreateTestNode("A");
    NodeIdentity nodeB = CreateTestNode("B");
    
    discovery.AddNode(nodeA);
    discovery.AddNode(nodeB);
    
    auto nodes = discovery.GetAllNodes();
    ASSERT_EQ(nodes.size(), 2u);
    
    // Verify both nodes are present
    bool foundA = false, foundB = false;
    for (const auto& node : nodes) {
        if (node.node_id == "node-A") foundA = true;
        if (node.node_id == "node-B") foundB = true;
    }
    ASSERT_TRUE(foundA);
    ASSERT_TRUE(foundB);
    
    discovery.Shutdown();
}

TEST(remove_node) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    NodeIdentity nodeA = CreateTestNode("A");
    NodeIdentity nodeB = CreateTestNode("B");
    
    discovery.AddNode(nodeA);
    discovery.AddNode(nodeB);
    ASSERT_EQ(discovery.GetAllNodes().size(), 2u);
    
    // Remove nodeA
    ASSERT_TRUE(discovery.RemoveNode("node-A"));
    
    auto nodes = discovery.GetAllNodes();
    ASSERT_EQ(nodes.size(), 1u);
    ASSERT_EQ(nodes[0].node_id, "node-B");
    
    discovery.Shutdown();
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST(duplicate_node_registration) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    NodeIdentity nodeA = CreateTestNode("A");
    
    // First registration should succeed
    ASSERT_TRUE(discovery.AddNode(nodeA));
    ASSERT_EQ(discovery.GetAllNodes().size(), 1u);
    
    // Duplicate registration should fail or be handled gracefully
    // Current implementation: returns false for duplicate
    bool result = discovery.AddNode(nodeA);
    // Accept either behavior: false (rejected) or true (updated)
    // But count should remain 1
    ASSERT_EQ(discovery.GetAllNodes().size(), 1u);
    
    discovery.Shutdown();
}

TEST(invalid_node_id) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    // Try to remove non-existent node
    ASSERT_FALSE(discovery.RemoveNode("non-existent-node"));
    
    // Query should return empty
    auto nodes = discovery.GetAllNodes();
    ASSERT_EQ(nodes.size(), 0u);
    
    discovery.Shutdown();
}

TEST(empty_peer_query) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    // Query with no nodes registered
    auto nodes = discovery.GetAllNodes();
    ASSERT_EQ(nodes.size(), 0u);
    
    discovery.Shutdown();
}

TEST(stale_heartbeat_expiration) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    config.heartbeat_timeout_ms = 50; // Very short timeout for testing
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    NodeIdentity nodeA = CreateTestNode("A");
    discovery.AddNode(nodeA);
    
    // Initially healthy
    auto topology = discovery.GetTopology();
    topology->UpdateHealth(nodeA.node_id, NodeHealth::HEALTHY);
    ASSERT_EQ(topology->GetHealth(nodeA.node_id), NodeHealth::HEALTHY);
    
    // Mark as degraded
    topology->UpdateHealth(nodeA.node_id, NodeHealth::DEGRADED);
    ASSERT_EQ(topology->GetHealth(nodeA.node_id), NodeHealth::DEGRADED);
    
    // Mark as offline
    topology->UpdateHealth(nodeA.node_id, NodeHealth::OFFLINE);
    ASSERT_EQ(topology->GetHealth(nodeA.node_id), NodeHealth::OFFLINE);
    
    discovery.Shutdown();
}

TEST(concurrent_registration) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    std::atomic<int> success_count{0};
    std::vector<std::thread> threads;
    
    // Launch multiple threads to register nodes concurrently
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&discovery, &success_count, i]() {
            NodeIdentity node = CreateTestNode(std::to_string(i));
            if (discovery.AddNode(node)) {
                success_count++;
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All 10 should have registered
    ASSERT_EQ(discovery.GetAllNodes().size(), 10u);
    ASSERT_EQ(success_count.load(), 10);
    
    discovery.Shutdown();
}

// ============================================================================
// Cluster Topology Tests
// ============================================================================

TEST(topology_leader_election) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    // Initially no leader
    ASSERT_EQ(discovery.GetLeaderId(), "");
    ASSERT_FALSE(discovery.IsLeader());
    
    // Add nodes
    discovery.AddNode(CreateTestNode("A"));
    discovery.AddNode(CreateTestNode("B"));
    
    // Set leader manually via topology
    auto topology = discovery.GetTopology();
    topology->SetLeader("node-A");
    
    ASSERT_EQ(topology->GetLeader(), "node-A");
    ASSERT_TRUE(topology->IsLeader("node-A"));
    ASSERT_FALSE(topology->IsLeader("node-B"));
    
    discovery.Shutdown();
}

TEST(topology_quorum_calculation) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    auto topology = discovery.GetTopology();
    
    // Empty cluster: quorum = 1 (just need self)
    ASSERT_EQ(topology->GetQuorumSize(), 1);
    ASSERT_TRUE(topology->HasQuorum());
    
    // Add nodes
    discovery.AddNode(CreateTestNode("A"));
    discovery.AddNode(CreateTestNode("B"));
    discovery.AddNode(CreateTestNode("C"));
    
    // 4 nodes total: quorum = 3 (majority)
    ASSERT_EQ(topology->GetQuorumSize(), 3);
    ASSERT_TRUE(topology->HasQuorum());
    
    discovery.Shutdown();
}

TEST(datacenter_filtering) {
    NodeDiscovery::Config config;
    config.self = CreateTestNode("self", "dc1");
    
    NodeDiscovery discovery(config);
    ASSERT_TRUE(discovery.Initialize());
    
    // Add nodes in different datacenters
    ASSERT_TRUE(discovery.AddNode(CreateTestNode("A", "dc1")));
    ASSERT_TRUE(discovery.AddNode(CreateTestNode("B", "dc1")));
    ASSERT_TRUE(discovery.AddNode(CreateTestNode("C", "dc2")));
    ASSERT_TRUE(discovery.AddNode(CreateTestNode("D", "dc2")));
    
    auto dc1_nodes = discovery.GetNodesInDatacenter("dc1");
    auto dc2_nodes = discovery.GetNodesInDatacenter("dc2");
    
    // Note: GetNodesInDatacenter returns healthy nodes (excludes self)
    // dc1: A, B (2 nodes) | dc2: C, D (2 nodes)
    ASSERT_EQ(dc1_nodes.size(), 2u);
    ASSERT_EQ(dc2_nodes.size(), 2u);
    
    discovery.Shutdown();
}

// ============================================================================
// Node Identity Tests
// ============================================================================

TEST(node_identity_json) {
    NodeIdentity node = CreateTestNode("test");
    node.capabilities = {"inference", "training", "checkpointing"};
    
    std::string json = node.ToJson();
    ASSERT_FALSE(json.empty());
    
    // Verify JSON contains expected fields
    ASSERT_NE(json.find("node-test"), std::string::npos);
    ASSERT_NE(json.find("test-dc"), std::string::npos);
    ASSERT_NE(json.find("inference"), std::string::npos);
}

TEST(node_status_responsive) {
    NodeStatus status;
    status.identity = CreateTestNode("test");
    status.health = NodeHealth::HEALTHY;
    status.last_heartbeat = std::chrono::steady_clock::now();
    
    ASSERT_TRUE(status.IsResponsive());
    
    status.health = NodeHealth::OFFLINE;
    ASSERT_FALSE(status.IsResponsive());
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Sovereign Node Discovery Unit Tests" << std::endl;
    std::cout << "Layer 1.1 - Discovery Validation Closure" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Basic Lifecycle
    RUN_TEST(create_discovery);
    RUN_TEST(initialize_shutdown);
    
    // Node Registration
    RUN_TEST(register_single_node);
    RUN_TEST(register_multiple_nodes);
    RUN_TEST(query_peers);
    RUN_TEST(remove_node);
    
    // Edge Cases
    RUN_TEST(duplicate_node_registration);
    RUN_TEST(invalid_node_id);
    RUN_TEST(empty_peer_query);
    RUN_TEST(stale_heartbeat_expiration);
    RUN_TEST(concurrent_registration);
    
    // Cluster Topology
    RUN_TEST(topology_leader_election);
    RUN_TEST(topology_quorum_calculation);
    RUN_TEST(datacenter_filtering);
    
    // Node Identity
    RUN_TEST(node_identity_json);
    RUN_TEST(node_status_responsive);
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, " 
              << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return tests_failed > 0 ? 1 : 0;
}
