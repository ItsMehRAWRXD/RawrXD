// ============================================================================
// UniversalGraph.hpp — Universal graph engine
// Everything is a graph transform. Nodes have identity+state+capability.
// Edges are typed relationships. The graph IS the runtime.
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <atomic>
#include <mutex>
#include <functional>

namespace rawrxd::graph {

using NodeId = uint64_t;
using EdgeId = uint64_t;

// ---------------------------------------------------------------------------
// Edge kinds — typed relationships between nodes
// ---------------------------------------------------------------------------
enum class EdgeKind : uint16_t {
    Unknown     = 0,
    DependsOn   = 1,
    Requires    = 2,
    Provides    = 3,
    Contains    = 4,
    Owns        = 5,
    Implements  = 6,
    Specializes = 7,
    Generalizes = 8,
    Generates   = 9,
    Certifies   = 10,
    Invalidates = 11,
    Observes    = 12,
    Executes    = 13,
    Synchronizes= 14,
    Evolves     = 15,
    Transforms  = 16,
    Consumes    = 17,
    Produces    = 18,
    Authorizes  = 19,
};

// ---------------------------------------------------------------------------
// Node — universal graph node
// ---------------------------------------------------------------------------
struct GraphNode {
    NodeId id = 0;
    std::string name;
    std::string type;               // "capability", "resource", "entity", etc.
    std::string state;              // current state descriptor
    std::unordered_map<std::string, std::string> metadata;

    // Evidence + authority attached to this node
    std::string evidenceReceipt;
    std::string authorityVerdict;

    bool operator==(const GraphNode& o) const { return id == o.id; }
};

// ---------------------------------------------------------------------------
// Edge — typed relationship
// ---------------------------------------------------------------------------
struct GraphEdge {
    EdgeId id = 0;
    NodeId source = 0;
    NodeId target = 0;
    EdgeKind kind = EdgeKind::Unknown;
    std::string label;
    std::unordered_map<std::string, std::string> metadata;
};

// ---------------------------------------------------------------------------
// Universal Graph — the single source of truth
// ---------------------------------------------------------------------------
class UniversalGraph {
public:
    UniversalGraph() = default;

    // --- Node operations ---
    NodeId addNode(std::string name, std::string type);
    bool removeNode(NodeId id);
    GraphNode* node(NodeId id);
    const GraphNode* node(NodeId id) const;
    std::vector<GraphNode> allNodes() const;
    size_t nodeCount() const;

    // --- Edge operations ---
    EdgeId addEdge(NodeId src, NodeId dst, EdgeKind kind, std::string label = {});
    bool removeEdge(EdgeId id);
    std::vector<GraphEdge> edgesFrom(NodeId id) const;
    std::vector<GraphEdge> edgesTo(NodeId id) const;
    std::vector<GraphEdge> edgesFrom(NodeId id, EdgeKind kind) const;
    std::vector<GraphEdge> edgesTo(NodeId id, EdgeKind kind) const;
    bool hasEdge(NodeId src, NodeId dst, EdgeKind kind) const;

    // --- Graph algebra ---
    // Topological sort (returns false if cycle detected)
    bool topologicalSort(std::vector<NodeId>& out) const;

    // Find all nodes reachable from a given node
    std::vector<NodeId> reachable(NodeId start) const;

    // Find shortest dependency path between two nodes
    std::vector<NodeId> shortestPath(NodeId from, NodeId to) const;

    // Subgraph rooted at a node (all dependents)
    UniversalGraph subgraph(NodeId root) const;

    // Merge another graph into this one (returns mapping of old→new IDs)
    std::unordered_map<NodeId, NodeId> merge(const UniversalGraph& other);

    // Difference: nodes/edges in this graph but not in other
    struct GraphDiff {
        std::vector<NodeId> addedNodes;
        std::vector<NodeId> removedNodes;
        std::vector<EdgeId> addedEdges;
        std::vector<EdgeId> removedEdges;
    };
    GraphDiff diff(const UniversalGraph& other) const;

    // Canonical form — normalize node ordering for comparison
    std::string canonicalFingerprint() const;

    // Serialize/deserialize
    std::string serialize() const;
    bool deserialize(const std::string& data);

    // Clear
    void clear();

private:
    mutable std::mutex mutex_;
    std::atomic<NodeId> nextNodeId_{1};
    std::atomic<EdgeId> nextEdgeId_{1};
    std::unordered_map<NodeId, GraphNode> nodes_;
    std::unordered_map<EdgeId, GraphEdge> edges_;
    std::unordered_map<NodeId, std::vector<EdgeId>> outEdges_;
    std::unordered_map<NodeId, std::vector<EdgeId>> inEdges_;
};

// ---------------------------------------------------------------------------
// Graph rewrite engine — transforms graphs via rules
// ---------------------------------------------------------------------------
struct RewriteRule {
    std::string name;
    std::function<bool(const UniversalGraph&, NodeId)> matches;  // Does this rule apply?
    std::function<bool(UniversalGraph&, NodeId)> apply;           // Apply the rewrite
    int priority = 0;
};

class GraphRewriteEngine {
public:
    void addRule(RewriteRule rule);

    // Apply all matching rules until fixed point (no more changes)
    // Returns number of rewrites applied
    int rewriteToFixedPoint(UniversalGraph& graph);

    // Apply one pass of all rules
    int rewriteOnce(UniversalGraph& graph);

    // Check if graph is at fixed point (no rules match)
    bool isFixedPoint(const UniversalGraph& graph) const;

    // Metrics
    int totalRewrites() const { return totalRewrites_.load(); }

private:
    std::vector<RewriteRule> rules_;
    std::atomic<int> totalRewrites_{0};
};

} // namespace rawrxd::graph