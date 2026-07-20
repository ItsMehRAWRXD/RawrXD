#include "ConsistentHash.h"
#include <iostream>
#include <algorithm>
#include <numeric>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// ConsistentHashRing Implementation
// ============================================================================

ConsistentHashRing::ConsistentHashRing()
    : virtualNodesPerPhysical_(150) {
}

ConsistentHashRing::~ConsistentHashRing() = default;

void ConsistentHashRing::SetVirtualNodes(int vnodesPerPhysical) {
    virtualNodesPerPhysical_ = vnodesPerPhysical;
}

bool ConsistentHashRing::AddNode(uint32_t nodeId, const std::string& address) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    if (nodeAddresses_.find(nodeId) != nodeAddresses_.end()) {
        return false;  // Already exists
    }
    
    nodeAddresses_[nodeId] = address;
    
    // Add virtual nodes
    for (int i = 0; i < virtualNodesPerPhysical_; i++) {
        HashRingEntry entry;
        entry.hash = HashNode(nodeId, i);
        entry.nodeId = nodeId;
        entry.nodeAddress = address;
        entry.isVirtual = true;
        
        ring_[entry.hash] = entry;
    }
    
    return true;
}

bool ConsistentHashRing::RemoveNode(uint32_t nodeId) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    
    if (nodeAddresses_.find(nodeId) == nodeAddresses_.end()) {
        return false;  // Doesn't exist
    }
    
    nodeAddresses_.erase(nodeId);
    
    // Remove all virtual nodes for this node
    for (auto it = ring_.begin(); it != ring_.end(); ) {
        if (it->second.nodeId == nodeId) {
            it = ring_.erase(it);
        } else {
            ++it;
        }
    }
    
    return true;
}

bool ConsistentHashRing::HasNode(uint32_t nodeId) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return nodeAddresses_.find(nodeId) != nodeAddresses_.end();
}

size_t ConsistentHashRing::GetNodeCount() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return nodeAddresses_.size();
}

uint32_t ConsistentHashRing::GetNodeForTensor(uint64_t tensorId) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    if (ring_.empty()) {
        return 0;  // No nodes
    }
    
    uint64_t hash = HashTensor(tensorId);
    
    // Find first entry >= hash
    auto it = ring_.lower_bound(hash);
    if (it == ring_.end()) {
        // Wrap around to first node
        it = ring_.begin();
    }
    
    return it->second.nodeId;
}

std::vector<uint32_t> ConsistentHashRing::GetNodesForTensor(
    uint64_t tensorId, 
    int replicaCount
) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::vector<uint32_t> result;
    if (ring_.empty() || replicaCount <= 0) {
        return result;
    }
    
    uint64_t hash = HashTensor(tensorId);
    
    // Find first entry >= hash
    auto it = ring_.lower_bound(hash);
    if (it == ring_.end()) {
        it = ring_.begin();
    }
    
    // Collect unique nodes
    std::set<uint32_t> seen;
    while (result.size() < static_cast<size_t>(replicaCount) && seen.size() < nodeAddresses_.size()) {
        uint32_t nodeId = it->second.nodeId;
        if (seen.insert(nodeId).second) {
            result.push_back(nodeId);
        }
        
        ++it;
        if (it == ring_.end()) {
            it = ring_.begin();
        }
    }
    
    return result;
}

std::vector<std::pair<uint64_t, uint32_t>> ConsistentHashRing::GetMigrationPlan(
    uint32_t oldNodeId,
    uint32_t newNodeId
) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::vector<std::pair<uint64_t, uint32_t>> plan;
    
    // Find all tensors that would map to oldNode but should map to newNode
    // This is a simplified version - in production would iterate actual tensors
    
    return plan;
}

double ConsistentHashRing::GetBalanceScore() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    if (nodeAddresses_.empty()) {
        return 0.0;
    }
    
    // Count virtual nodes per physical node
    std::map<uint32_t, int> nodeCounts;
    for (const auto& [hash, entry] : ring_) {
        nodeCounts[entry.nodeId]++;
    }
    
    if (nodeCounts.size() <= 1) {
        return 1.0;
    }
    
    // Calculate standard deviation
    double mean = static_cast<double>(ring_.size()) / nodeCounts.size();
    double variance = 0.0;
    
    for (const auto& [nodeId, count] : nodeCounts) {
        variance += std::pow(count - mean, 2);
    }
    variance /= nodeCounts.size();
    
    double stddev = std::sqrt(variance);
    double cv = stddev / mean;  // Coefficient of variation
    
    // Score: 1.0 = perfect balance, lower = worse
    return std::max(0.0, 1.0 - cv);
}

void ConsistentHashRing::PrintDistribution() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    std::map<uint32_t, int> nodeCounts;
    for (const auto& [hash, entry] : ring_) {
        nodeCounts[entry.nodeId]++;
    }
    
    std::cout << "Hash Ring Distribution:" << std::endl;
    for (const auto& [nodeId, count] : nodeCounts) {
        double pct = (100.0 * count) / ring_.size();
        std::cout << "  Node " << nodeId << ": " << count 
                  << " vnodes (" << pct << "%)" << std::endl;
    }
    std::cout << "  Balance Score: " << GetBalanceScore() << std::endl;
}

uint64_t ConsistentHashRing::HashNode(uint32_t nodeId, int replica) const {
    // FNV-1a hash of nodeId + replica
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash nodeId
    for (int i = 0; i < 4; i++) {
        hash ^= (nodeId >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    
    // Hash replica
    for (int i = 0; i < 4; i++) {
        hash ^= (replica >> (i * 8)) & 0xFF;
        hash *= 1099511628211ULL;
    }
    
    return hash;
}

uint64_t ConsistentHashRing::HashTensor(uint64_t tensorId) const {
    // Jump consistent hash for better distribution
    return JumpConsistentHash(tensorId, static_cast<int>(ring_.size()));
}

uint64_t ConsistentHashRing::JumpConsistentHash(uint64_t key, int numBuckets) const {
    // "A Fast, Minimal Memory, Consistent Hash Algorithm" (2014)
    int64_t b = -1;
    int64_t j = 0;
    
    while (j < numBuckets) {
        b = j;
        key = key * 2862933555777941757ULL + 1;
        j = static_cast<int64_t>((b + 1) * (static_cast<double>(1LL << 31) / 
                                             static_cast<double>((key >> 33) + 1)));
    }
    
    return static_cast<uint64_t>(b);
}

} // namespace Fabric
} // namespace RawrXD
