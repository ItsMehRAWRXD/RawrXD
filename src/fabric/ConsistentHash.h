#pragma once

#include <cstdint>
#include <vector>
#include <map>
#include <mutex>
#include <string>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Consistent Hash Ring for Tensor Placement
// 
// Maps tensor IDs to nodes using a consistent hash ring.
// When nodes join/leave, only 1/N tensors need to move (where N = node count).
// ============================================================================

struct HashRingEntry {
    uint64_t hash;           // Position on the ring (0 to 2^64-1)
    uint32_t nodeId;         // Node at this position
    std::string nodeAddress; // For reconnection
    bool isVirtual;          // Virtual node for better distribution
    
    bool operator<(const HashRingEntry& other) const {
        return hash < other.hash;
    }
};

class ConsistentHashRing {
public:
    ConsistentHashRing();
    ~ConsistentHashRing();
    
    // Configuration
    void SetVirtualNodes(int vnodesPerPhysical);  // Default: 150
    
    // Node Management
    bool AddNode(uint32_t nodeId, const std::string& address);
    bool RemoveNode(uint32_t nodeId);
    bool HasNode(uint32_t nodeId) const;
    size_t GetNodeCount() const;
    
    // Tensor Placement
    uint32_t GetNodeForTensor(uint64_t tensorId) const;
    std::vector<uint32_t> GetNodesForTensor(uint64_t tensorId, int replicaCount) const;
    
    // Rebalancing
    std::vector<std::pair<uint64_t, uint32_t>> GetMigrationPlan(
        uint32_t oldNodeId, 
        uint32_t newNodeId
    ) const;
    
    // Statistics
    double GetBalanceScore() const;  // 1.0 = perfect balance
    void PrintDistribution() const;
    
private:
    mutable std::shared_mutex mutex_;
    std::map<uint64_t, HashRingEntry> ring_;
    std::unordered_map<uint32_t, std::string> nodeAddresses_;
    
    int virtualNodesPerPhysical_;
    
    uint64_t HashNode(uint32_t nodeId, int replica) const;
    uint64_t HashTensor(uint64_t tensorId) const;
    uint64_t JumpConsistentHash(uint64_t key, int numBuckets) const;
};

} // namespace Fabric
} // namespace RawrXD
