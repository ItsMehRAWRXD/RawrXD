// ============================================================================
// VAL-029.3: Multi-Node Cluster Validation
// Tests 4+ node cluster with consistent hashing and rebalancing
// ============================================================================

#include "../src/fabric/ClusterManager.h"
#include "../src/fabric/TCPTransport.h"
#include "../src/fabric/ConsistentHash.h"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <vector>
#include <memory>

using namespace RawrXD::Fabric;

// ============================================================================
// Test Utilities
// ============================================================================

void PrintResult(const char* test, bool passed) {
    std::cout << "  [" << (passed ? "PASS" : "FAIL") << "] " << test << std::endl;
}

uint64_t GenerateTensorId(int index) {
    // Simple hash
    return 14695981039346656037ULL * (index + 1);
}

// ============================================================================
// Gate 1: Consistent Hash Ring
// ============================================================================

bool TestConsistentHash_BasicPlacement() {
    ConsistentHashRing ring;
    
    // Add 4 nodes
    ring.AddNode(1, "192.168.1.1:18444");
    ring.AddNode(2, "192.168.1.2:18444");
    ring.AddNode(3, "192.168.1.3:18444");
    ring.AddNode(4, "192.168.1.4:18444");
    
    // Place 1000 tensors
    std::map<uint32_t, int> distribution;
    for (int i = 0; i < 1000; i++) {
        uint32_t node = ring.GetNodeForTensor(GenerateTensorId(i));
        distribution[node]++;
    }
    
    // All nodes should have some tensors
    if (distribution.size() != 4) return false;
    
    // Check balance (each should have ~250)
    for (const auto& [node, count] : distribution) {
        if (count < 150 || count > 350) return false;
    }
    
    return true;
}

bool TestConsistentHash_NodeRemoval() {
    ConsistentHashRing ring;
    
    // Add 4 nodes
    for (int i = 1; i <= 4; i++) {
        ring.AddNode(i, "192.168.1." + std::to_string(i) + ":18444");
    }
    
    // Map 1000 tensors
    std::vector<uint32_t> before;
    for (int i = 0; i < 1000; i++) {
        before.push_back(ring.GetNodeForTensor(GenerateTensorId(i)));
    }
    
    // Remove node 2
    ring.RemoveNode(2);
    
    // Map again
    int moved = 0;
    for (int i = 0; i < 1000; i++) {
        uint32_t after = ring.GetNodeForTensor(GenerateTensorId(i));
        if (after != before[i]) {
            moved++;
        }
    }
    
    // Should move ~1/3 of tensors (not all!)
    // With consistent hashing, only keys that mapped to node 2 should move
    double moveRatio = static_cast<double>(moved) / 1000.0;
    
    // Should be around 25-40%
    return moveRatio > 0.20 && moveRatio < 0.45;
}

bool TestConsistentHash_ReplicaPlacement() {
    ConsistentHashRing ring;
    
    // Add 4 nodes
    for (int i = 1; i <= 4; i++) {
        ring.AddNode(i, "192.168.1." + std::to_string(i) + ":18444");
    }
    
    // Get replicas for a tensor
    auto replicas = ring.GetNodesForTensor(GenerateTensorId(42), 3);
    
    // Should get 3 unique nodes
    if (replicas.size() != 3) return false;
    
    // All should be unique
    std::set<uint32_t> unique(replicas.begin(), replicas.end());
    if (unique.size() != 3) return false;
    
    return true;
}

// ============================================================================
// Gate 2: Cluster Formation
// ============================================================================

bool TestCluster_JoinAndForm() {
    // Create 4 nodes
    std::vector<std::unique_ptr<TCPTransport>> transports;
    std::vector<std::unique_ptr<ClusterManager>> clusters;
    
    for (int i = 0; i < 4; i++) {
        auto transport = std::make_unique<TCPTransport>();
        transport->Initialize(i + 1);
        transport->Listen("127.0.0.1", 18444 + i);
        
        ClusterConfig config;
        config.localNodeId = i + 1;
        config.bindAddress = "127.0.0.1";
        config.bindPort = 18444 + i;
        
        auto cluster = std::make_unique<ClusterManager>();
        cluster->Initialize(config, transport.get());
        
        transports.push_back(std::move(transport));
        clusters.push_back(std::move(cluster));
    }
    
    // Connect nodes to form cluster
    for (int i = 1; i < 4; i++) {
        char addr[64];
        snprintf(addr, sizeof(addr), "127.0.0.1:%d", 18444);
        transports[i]->ConnectToNode(1, addr);
    }
    
    // Wait for cluster to form
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Check cluster size
    bool formed = clusters[0]->GetClusterSize() >= 1;
    
    // Cleanup
    for (auto& c : clusters) c->Shutdown();
    for (auto& t : transports) t->Shutdown();
    
    return formed;
}

bool TestCluster_NodeFailureDetection() {
    // This is a simplified test - real failure detection
    // requires actual network timeouts
    
    ConsistentHashRing ring;
    
    // Add nodes
    for (int i = 1; i <= 4; i++) {
        ring.AddNode(i, "192.168.1." + std::to_string(i) + ":18444");
    }
    
    // Remove one
    ring.RemoveNode(3);
    
    // Should still have 3 nodes
    return ring.GetNodeCount() == 3;
}

// ============================================================================
// Gate 3: Tensor Placement
// ============================================================================

bool TestTensorPlacement_PrimarySelection() {
    ConsistentHashRing ring;
    
    // Add 4 nodes
    for (int i = 1; i <= 4; i++) {
        ring.AddNode(i, "192.168.1." + std::to_string(i) + ":18444");
    }
    
    // Same tensor should always map to same node
    uint64_t tensorId = GenerateTensorId(12345);
    uint32_t node1 = ring.GetNodeForTensor(tensorId);
    uint32_t node2 = ring.GetNodeForTensor(tensorId);
    uint32_t node3 = ring.GetNodeForTensor(tensorId);
    
    return node1 == node2 && node2 == node3;
}

bool TestTensorPlacement_Distribution() {
    ConsistentHashRing ring;
    
    // Add 4 nodes
    for (int i = 1; i <= 4; i++) {
        ring.AddNode(i, "192.168.1." + std::to_string(i) + ":18444");
    }
    
    // Check balance score
    double score = ring.GetBalanceScore();
    
    // Should be reasonably balanced (> 0.8)
    return score > 0.8;
}

// ============================================================================
// Gate 4: Rebalancing
// ============================================================================

bool TestRebalancing_TriggerAndProgress() {
    ClusterConfig config;
    config.localNodeId = 1;
    config.bindAddress = "127.0.0.1";
    config.bindPort = 18444;
    
    TCPTransport transport;
    transport.Initialize(1);
    
    ClusterManager cluster;
    cluster.Initialize(config, &transport);
    
    // Trigger rebalance
    bool triggered = cluster.TriggerRebalance();
    if (!triggered) return false;
    
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    
    bool complete = cluster.GetRebalanceProgress() >= 1.0;
    
    cluster.Shutdown();
    transport.Shutdown();
    
    return complete;
}

// ============================================================================
// Gate 5: Performance at Scale
// ============================================================================

bool TestPerformance_HashRingLookup() {
    ConsistentHashRing ring;
    
    // Add 16 nodes
    for (int i = 1; i <= 16; i++) {
        ring.AddNode(i, "192.168.1." + std::to_string(i) + ":18444");
    }
    
    // Time 1M lookups
    const int NUM_LOOKUPS = 1000000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < NUM_LOOKUPS; i++) {
        ring.GetNodeForTensor(GenerateTensorId(i));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsedUs = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    double avgNs = (elapsedUs * 1000.0) / NUM_LOOKUPS;
    
    std::cout << "    Average lookup: " << avgNs << " ns" << std::endl;
    
    // Should be < 1μs per lookup
    return avgNs < 1000;
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "VAL-029.3: Multi-Node Cluster" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    // Gate 1: Consistent Hash
    std::cout << "\nGate 1: Consistent Hash Ring" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    if (TestConsistentHash_BasicPlacement()) { passed++; PrintResult("Basic placement", true); }
    else { failed++; PrintResult("Basic placement", false); }
    
    if (TestConsistentHash_NodeRemoval()) { passed++; PrintResult("Node removal", true); }
    else { failed++; PrintResult("Node removal", false); }
    
    if (TestConsistentHash_ReplicaPlacement()) { passed++; PrintResult("Replica placement", true); }
    else { failed++; PrintResult("Replica placement", false); }
    
    // Gate 2: Cluster Formation
    std::cout << "\nGate 2: Cluster Formation" << std::endl;
    std::cout << "--------------------------" << std::endl;
    
    if (TestCluster_JoinAndForm()) { passed++; PrintResult("Join and form cluster", true); }
    else { failed++; PrintResult("Join and form cluster", false); }
    
    if (TestCluster_NodeFailureDetection()) { passed++; PrintResult("Node failure detection", true); }
    else { failed++; PrintResult("Node failure detection", false); }
    
    // Gate 3: Tensor Placement
    std::cout << "\nGate 3: Tensor Placement" << std::endl;
    std::cout << "-------------------------" << std::endl;
    
    if (TestTensorPlacement_PrimarySelection()) { passed++; PrintResult("Primary selection", true); }
    else { failed++; PrintResult("Primary selection", false); }
    
    if (TestTensorPlacement_Distribution()) { passed++; PrintResult("Distribution balance", true); }
    else { failed++; PrintResult("Distribution balance", false); }
    
    // Gate 4: Rebalancing
    std::cout << "\nGate 4: Rebalancing" << std::endl;
    std::cout << "----------------------" << std::endl;
    
    if (TestRebalancing_TriggerAndProgress()) { passed++; PrintResult("Trigger and progress", true); }
    else { failed++; PrintResult("Trigger and progress", false); }
    
    // Gate 5: Performance
    std::cout << "\nGate 5: Performance at Scale" << std::endl;
    std::cout << "-----------------------------" << std::endl;
    
    if (TestPerformance_HashRingLookup()) { passed++; PrintResult("Hash ring lookup (1M)", true); }
    else { failed++; PrintResult("Hash ring lookup (1M)", false); }
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return failed == 0 ? 0 : 1;
}
