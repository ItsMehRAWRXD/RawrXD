#pragma once
#ifndef RAWRXD_EXECUTION_GRAPH_HASH_H
#define RAWRXD_EXECUTION_GRAPH_HASH_H

#include "agentic_task_graph.h"
#include <array>
#include <string>

namespace RawrXD {

// ============================================================================
// DETERMINISTIC GRAPH HASHING
//
// ExecutionNodeHash = f(state, children, collapse_metadata)
// Enables: diffing, caching, replay validation, regression detection
// ============================================================================

using NodeHash = std::array<uint8_t, 32>;
using GraphHash = std::array<uint8_t, 32>;

// ============================================================================
// GraphHasher - Deterministic hash of execution structure
// ============================================================================
class GraphHasher {
public:
    // Hash a single node (deterministic on content)
    static NodeHash hashNode(const AgenticTaskNode& node);
    
    // Hash entire graph (Merkle tree style)
    static GraphHash hashGraph(const AgenticTaskNode& root);
    
    // Hash graph topology only (ignores timestamps, IDs)
    static GraphHash hashTopology(const AgenticTaskNode& root);
    
    // Hash execution outcome (includes results)
    static GraphHash hashOutcome(const AgenticTaskNode& root);
    
    // String representations
    static std::string toHex(const NodeHash& hash);
    static std::string toHex(const GraphHash& hash);
    static NodeHash nodeHashFromHex(const std::string& hex);
    
    // Comparison
    static bool equal(const NodeHash& a, const NodeHash& b);
    static bool equal(const GraphHash& a, const GraphHash& b);
    
    // Diff two graphs
    struct DiffResult {
        std::vector<std::string> addedNodes;
        std::vector<std::string> removedNodes;
        std::vector<std::string> modifiedNodes;
        bool isomorphic = false;
    };
    
    static DiffResult diff(const AgenticTaskNode& a, const AgenticTaskNode& b);

private:
    static void hashNodeRecursive(const AgenticTaskNode& node, 
                                   std::map<std::string, NodeHash>& cache);
    static NodeHash combineHashes(const std::vector<NodeHash>& childHashes,
                                   const std::string& nodeContent);
};

// ============================================================================
// Graph Cache - Reusable subgraph cache
// ============================================================================
class GraphCache {
public:
    static GraphCache& instance();
    
    // Cache a subgraph by its hash
    void cacheSubgraph(const GraphHash& hash, const AgenticTaskNode& root);
    
    // Retrieve cached subgraph
    std::optional<AgenticTaskNode> retrieve(const GraphHash& hash) const;
    
    // Check if subgraph exists in cache
    bool contains(const GraphHash& hash) const;
    
    // Cache statistics
    size_t size() const;
    void clear();
    
    // Prune old entries
    void prune(size_t maxEntries);

private:
    mutable std::mutex m_mutex;
    std::map<GraphHash, AgenticTaskNode, std::less<>> m_cache;
    std::map<GraphHash, std::chrono::steady_clock::time_point> m_accessTimes;
};

// ============================================================================
// Replay Validator - Verify execution matches expected hash
// ============================================================================
class ReplayValidator {
public:
    struct ValidationResult {
        bool matches = false;
        std::string expectedHash;
        std::string actualHash;
        std::vector<std::string> divergences;
    };
    
    // Record expected hash before execution
    void recordExpected(const GraphHash& hash, const std::string& executionId);
    
    // Validate actual execution against expected
    ValidationResult validate(const AgenticTaskNode& actualRoot,
                               const std::string& executionId);
    
    // Check for regression (current vs baseline)
    bool detectRegression(const GraphHash& current, const GraphHash& baseline);

private:
    mutable std::mutex m_mutex;
    std::map<std::string, GraphHash> m_expectedHashes;
    std::map<GraphHash, GraphHash> m_baselines;
};

} // namespace RawrXD

#endif // RAWRXD_EXECUTION_GRAPH_HASH_H
