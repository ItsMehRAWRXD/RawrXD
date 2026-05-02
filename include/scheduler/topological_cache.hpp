#pragma once
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <memory>
#include <atomic>
#include <shared_mutex>

namespace RawrXD::Scheduler {

// ============================================================================
// INCREMENTAL TOPOLOGICAL CACHE — O(1) cycle check, O(V+E) on mutation only
// ============================================================================

class TopologicalCache {
public:
    struct NodeId {
        uint32_t modelIndex;
        uint32_t nodeId;
        bool operator==(const NodeId& o) const noexcept {
            return modelIndex == o.modelIndex && nodeId == o.nodeId;
        }
    };
    
    struct NodeIdHash {
        size_t operator()(const NodeId& id) const noexcept {
            return (static_cast<uint64_t>(id.modelIndex) << 32) | id.nodeId;
        }
    };

    // ------------------------------------------------------------------------
    // Core API
    // ------------------------------------------------------------------------
    
    // Returns true if adding edge src→dst would create a cycle
    // O(1) amortized — uses cached topological ranks
    bool wouldCreateCycle(const NodeId& src, const NodeId& dst) const;
    
    // Commit an edge after validation. O(1) rank update if no cycle.
    void addEdge(const NodeId& src, const NodeId& dst);
    
    // Remove edge (rare). Invalidates cache — next check rebuilds.
    void removeEdge(const NodeId& src, const NodeId& dst);
    
    // Add isolated node. O(1).
    void addNode(const NodeId& id);
    
    // Remove node + all edges. O(degree).
    void removeNode(const NodeId& id);
    
    // Force full recompute (call after batch mutations).
    void rebuild();
    
    // ------------------------------------------------------------------------
    // Diagnostics
    // ------------------------------------------------------------------------
    size_t nodeCount() const { return m_nodes.size(); }
    size_t edgeCount() const;
    bool isValid() const { return m_valid.load(std::memory_order_acquire); }
    
private:
    struct NodeMeta {
        int64_t topoRank = -1;      // -1 = unassigned
        std::unordered_set<NodeId, NodeIdHash> outgoing;
        std::unordered_set<NodeId, NodeIdHash> incoming;
    };
    
    mutable std::shared_mutex m_mutex;
    std::unordered_map<NodeId, NodeMeta, NodeIdHash> m_nodes;
    std::atomic<bool> m_valid{true};
    std::atomic<uint64_t> m_version{0};
    
    // Incremental rank assignment: dst must have higher rank than src
    // If dst.rank <= src.rank, we need to propagate or detect cycle
    bool validateIncremental(const NodeId& src, const NodeId& dst) const;
    
    // Full Kahn's algorithm rebuild — called only on cache invalidation
    void fullRebuildLocked();
    
    // Propagate rank increases downstream when adding edge to higher-ranked node
    void propagateRank(const NodeId& start, int64_t minRequired);
};

// ============================================================================
// INLINE IMPLEMENTATION
// ============================================================================

inline bool TopologicalCache::wouldCreateCycle(const NodeId& src, const NodeId& dst) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    if (!m_valid.load(std::memory_order_relaxed)) {
        // Cache invalid — pessimistic: run full check under shared lock
        // This path is rare (only after removeEdge/removeNode)
        auto itSrc = m_nodes.find(src);
        auto itDst = m_nodes.find(dst);
        if (itSrc == m_nodes.end() || itDst == m_nodes.end()) return false;
        
        // DFS from dst — can we reach src?
        std::vector<NodeId> stack;
        stack.reserve(64);
        for (const auto& out : itDst->second.outgoing) stack.push_back(out);
        
        std::unordered_set<NodeId, NodeIdHash> visited;
        while (!stack.empty()) {
            NodeId cur = stack.back(); stack.pop_back();
            if (cur == src) return true;
            if (!visited.insert(cur).second) continue;
            
            auto it = m_nodes.find(cur);
            if (it != m_nodes.end()) {
                for (const auto& out : it->second.outgoing) {
                    if (out == src) return true; // Fast path
                    stack.push_back(out);
                }
            }
        }
        return false;
    }
    
    // Fast path: cached ranks
    auto itSrc = m_nodes.find(src);
    auto itDst = m_nodes.find(dst);
    if (itSrc == m_nodes.end() || itDst == m_nodes.end()) return false;
    
    // If dst already has higher rank than src, no cycle possible
    if (itDst->second.topoRank > itSrc->second.topoRank) return false;
    
    // Ranks equal or inverted — need incremental validation
    return !validateIncremental(src, dst);
}

inline bool TopologicalCache::validateIncremental(const NodeId& src, const NodeId& dst) const {
    // BFS from dst. If we can reach src, it's a cycle.
    // This is O(affected subgraph) — much smaller than full DAG in practice
    std::vector<NodeId> queue;
    queue.reserve(64);
    queue.push_back(dst);
    
    std::unordered_set<NodeId, NodeIdHash> visited;
    visited.reserve(64);
    
    for (size_t i = 0; i < queue.size(); ++i) {
        const NodeId& cur = queue[i];
        if (cur == src) return false; // Cycle detected
        
        auto it = m_nodes.find(cur);
        if (it == m_nodes.end()) continue;
        
        for (const auto& out : it->second.outgoing) {
            if (out == src) return false; // Direct cycle
            if (visited.insert(out).second) queue.push_back(out);
        }
    }
    return true; // No cycle
}

inline void TopologicalCache::addEdge(const NodeId& src, const NodeId& dst) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    auto& srcMeta = m_nodes[src]; // Creates if missing
    auto& dstMeta = m_nodes[dst];
    
    srcMeta.outgoing.insert(dst);
    dstMeta.incoming.insert(src);
    
    if (!m_valid.load(std::memory_order_relaxed)) {
        // Cache was invalidated — just add edge, defer rebuild
        return;
    }
    
    // If dst rank > src rank, ordering preserved — no work needed
    if (dstMeta.topoRank > srcMeta.topoRank) return;
    
    // Need to propagate ranks downstream from dst
    lock.unlock();
    propagateRank(dst, srcMeta.topoRank + 1);
}

inline void TopologicalCache::propagateRank(const NodeId& start, int64_t minRequired) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    auto it = m_nodes.find(start);
    if (it == m_nodes.end()) return;
    
    if (it->second.topoRank >= minRequired) return; // Already high enough
    
    // BFS propagation
    std::vector<NodeId> queue;
    queue.push_back(start);
    
    for (size_t i = 0; i < queue.size(); ++i) {
        const NodeId& cur = queue[i];
        auto curIt = m_nodes.find(cur);
        if (curIt == m_nodes.end()) continue;
        
        int64_t required = minRequired + static_cast<int64_t>(i);
        if (curIt->second.topoRank >= required) continue;
        
        curIt->second.topoRank = required;
        
        for (const auto& out : curIt->second.outgoing) {
            auto outIt = m_nodes.find(out);
            if (outIt != m_nodes.end() && outIt->second.topoRank < required + 1) {
                queue.push_back(out);
            }
        }
    }
    
    m_version.fetch_add(1, std::memory_order_relaxed);
}

inline void TopologicalCache::addNode(const NodeId& id) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto& meta = m_nodes[id];
    if (meta.topoRank < 0) {
        meta.topoRank = static_cast<int64_t>(m_nodes.size()); // Append to end
    }
}

inline void TopologicalCache::removeEdge(const NodeId& src, const NodeId& dst) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto itSrc = m_nodes.find(src);
    auto itDst = m_nodes.find(dst);
    if (itSrc != m_nodes.end()) itSrc->second.outgoing.erase(dst);
    if (itDst != m_nodes.end()) itDst->second.incoming.erase(src);
    m_valid.store(false, std::memory_order_release); // Lazy invalidation
}

inline void TopologicalCache::removeNode(const NodeId& id) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    auto it = m_nodes.find(id);
    if (it == m_nodes.end()) return;
    
    // Remove all edges first
    for (const auto& out : it->second.outgoing) {
        auto outIt = m_nodes.find(out);
        if (outIt != m_nodes.end()) outIt->second.incoming.erase(id);
    }
    for (const auto& in : it->second.incoming) {
        auto inIt = m_nodes.find(in);
        if (inIt != m_nodes.end()) inIt->second.outgoing.erase(id);
    }
    
    m_nodes.erase(it);
    m_valid.store(false, std::memory_order_release);
}

inline void TopologicalCache::rebuild() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    fullRebuildLocked();
}

inline void TopologicalCache::fullRebuildLocked() {
    // Kahn's algorithm
    std::unordered_map<NodeId, int64_t, NodeIdHash> inDegree;
    for (const auto& [id, meta] : m_nodes) {
        inDegree[id] = static_cast<int64_t>(meta.incoming.size());
    }
    
    std::vector<NodeId> queue;
    queue.reserve(m_nodes.size());
    for (const auto& [id, deg] : inDegree) {
        if (deg == 0) queue.push_back(id);
    }
    
    int64_t rank = 0;
    size_t processed = 0;
    
    while (!queue.empty()) {
        std::vector<NodeId> nextQueue;
        nextQueue.reserve(queue.size());
        
        for (const auto& id : queue) {
            m_nodes[id].topoRank = rank;
            processed++;
            
            for (const auto& out : m_nodes[id].outgoing) {
                if (--inDegree[out] == 0) {
                    nextQueue.push_back(out);
                }
            }
        }
        
        queue = std::move(nextQueue);
        rank++;
    }
    
    m_valid.store(processed == m_nodes.size(), std::memory_order_release);
    m_version.fetch_add(1, std::memory_order_relaxed);
}

inline size_t TopologicalCache::edgeCount() const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    size_t count = 0;
    for (const auto& [_, meta] : m_nodes) count += meta.outgoing.size();
    return count;
}

} // namespace RawrXD::Scheduler
