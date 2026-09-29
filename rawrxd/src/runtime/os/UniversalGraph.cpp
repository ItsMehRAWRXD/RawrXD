// ============================================================================
// UniversalGraph.cpp — Universal graph engine implementation
// ============================================================================
#include "UniversalGraph.hpp"
#include <algorithm>
#include <queue>
#include <set>
#include <sstream>
#include <iomanip>

namespace rawrxd::graph {
UniversalGraph::UniversalGraph(UniversalGraph&& other) noexcept { std::lock_guard<std::mutex> lk(other.mutex_); nextNodeId_.store(other.nextNodeId_.load(std::memory_order_relaxed), std::memory_order_relaxed); nextEdgeId_.store(other.nextEdgeId_.load(std::memory_order_relaxed), std::memory_order_relaxed); nodes_ = std::move(other.nodes_); edges_ = std::move(other.edges_); outEdges_ = std::move(other.outEdges_); inEdges_ = std::move(other.inEdges_); } UniversalGraph& UniversalGraph::operator=(UniversalGraph&& other) noexcept { if (this != &other) { std::lock_guard<std::mutex> lk1(mutex_); std::lock_guard<std::mutex> lk2(other.mutex_); nextNodeId_.store(other.nextNodeId_.load(std::memory_order_relaxed), std::memory_order_relaxed); nextEdgeId_.store(other.nextEdgeId_.load(std::memory_order_relaxed), std::memory_order_relaxed); nodes_ = std::move(other.nodes_); edges_ = std::move(other.edges_); outEdges_ = std::move(other.outEdges_); inEdges_ = std::move(other.inEdges_); } return *this; }


// ---------------------------------------------------------------------------
// Node operations
// ---------------------------------------------------------------------------
NodeId UniversalGraph::addNode(std::string name, std::string type) {
    std::lock_guard<std::mutex> lock(mutex_);
    NodeId id = nextNodeId_.fetch_add(1, std::memory_order_relaxed);
    GraphNode n;
    n.id = id;
    n.name = std::move(name);
    n.type = std::move(type);
    nodes_[id] = std::move(n);
    return id;
}

bool UniversalGraph::removeNode(NodeId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (nodes_.find(id) == nodes_.end()) return false;
    // Remove all edges connected to this node
    std::vector<EdgeId> toRemove;
    for (const auto& eid : outEdges_[id]) toRemove.push_back(eid);
    for (const auto& eid : inEdges_[id]) toRemove.push_back(eid);
    for (EdgeId eid : toRemove) {
        edges_.erase(eid);
    }
    outEdges_.erase(id);
    inEdges_.erase(id);
    nodes_.erase(id);
    return true;
}

GraphNode* UniversalGraph::node(NodeId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? &it->second : nullptr;
}

const GraphNode* UniversalGraph::node(NodeId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(id);
    return (it != nodes_.end()) ? &it->second : nullptr;
}

std::vector<GraphNode> UniversalGraph::allNodes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<GraphNode> result;
    result.reserve(nodes_.size());
    for (const auto& [_, n] : nodes_) result.push_back(n);
    return result;
}

size_t UniversalGraph::nodeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return nodes_.size();
}

// ---------------------------------------------------------------------------
// Edge operations
// ---------------------------------------------------------------------------
EdgeId UniversalGraph::addEdge(NodeId src, NodeId dst, EdgeKind kind, std::string label) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (nodes_.find(src) == nodes_.end() || nodes_.find(dst) == nodes_.end())
        return 0;
    EdgeId id = nextEdgeId_.fetch_add(1, std::memory_order_relaxed);
    GraphEdge e;
    e.id = id;
    e.source = src;
    e.target = dst;
    e.kind = kind;
    e.label = std::move(label);
    edges_[id] = e;
    outEdges_[src].push_back(id);
    inEdges_[dst].push_back(id);
    return id;
}

bool UniversalGraph::removeEdge(EdgeId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = edges_.find(id);
    if (it == edges_.end()) return false;
    auto& outList = outEdges_[it->second.source];
    outList.erase(std::remove(outList.begin(), outList.end(), id), outList.end());
    auto& inList = inEdges_[it->second.target];
    inList.erase(std::remove(inList.begin(), inList.end(), id), inList.end());
    edges_.erase(it);
    return true;
}

std::vector<GraphEdge> UniversalGraph::edgesFrom(NodeId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = outEdges_.find(id);
    if (it == outEdges_.end()) return {};
    std::vector<GraphEdge> result;
    for (EdgeId eid : it->second) {
        auto eit = edges_.find(eid);
        if (eit != edges_.end()) result.push_back(eit->second);
    }
    return result;
}

std::vector<GraphEdge> UniversalGraph::edgesTo(NodeId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = inEdges_.find(id);
    if (it == inEdges_.end()) return {};
    std::vector<GraphEdge> result;
    for (EdgeId eid : it->second) {
        auto eit = edges_.find(eid);
        if (eit != edges_.end()) result.push_back(eit->second);
    }
    return result;
}

std::vector<GraphEdge> UniversalGraph::edgesFrom(NodeId id, EdgeKind kind) const {
    auto all = edgesFrom(id);
    std::vector<GraphEdge> filtered;
    for (const auto& e : all) {
        if (e.kind == kind) filtered.push_back(e);
    }
    return filtered;
}

std::vector<GraphEdge> UniversalGraph::edgesTo(NodeId id, EdgeKind kind) const {
    auto all = edgesTo(id);
    std::vector<GraphEdge> filtered;
    for (const auto& e : all) {
        if (e.kind == kind) filtered.push_back(e);
    }
    return filtered;
}

bool UniversalGraph::hasEdge(NodeId src, NodeId dst, EdgeKind kind) const {
    auto edges = edgesFrom(src, kind);
    for (const auto& e : edges) if (e.target == dst) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Graph algebra
// ---------------------------------------------------------------------------
bool UniversalGraph::topologicalSort(std::vector<NodeId>& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    out.clear();
    // Kahn's algorithm
    std::unordered_map<NodeId, int> inDegree;
    for (const auto& [id, _] : nodes_) inDegree[id] = 0;
    for (const auto& [_, e] : edges_) inDegree[e.target]++;

    std::queue<NodeId> q;
    for (const auto& [id, deg] : inDegree) if (deg == 0) q.push(id);

    while (!q.empty()) {
        NodeId n = q.front(); q.pop();
        out.push_back(n);
        auto it = outEdges_.find(n);
        if (it != outEdges_.end()) {
            for (EdgeId eid : it->second) {
                auto eit = edges_.find(eid);
                if (eit != edges_.end()) {
                    if (--inDegree[eit->second.target] == 0)
                        q.push(eit->second.target);
                }
            }
        }
    }
    return out.size() == nodes_.size();  // false = cycle
}

std::vector<NodeId> UniversalGraph::reachable(NodeId start) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NodeId> result;
    std::set<NodeId> visited;
    std::queue<NodeId> q;
    q.push(start);
    visited.insert(start);
    while (!q.empty()) {
        NodeId n = q.front(); q.pop();
        result.push_back(n);
        auto it = outEdges_.find(n);
        if (it != outEdges_.end()) {
            for (EdgeId eid : it->second) {
                auto eit = edges_.find(eid);
                if (eit != edges_.end() && visited.find(eit->second.target) == visited.end()) {
                    visited.insert(eit->second.target);
                    q.push(eit->second.target);
                }
            }
        }
    }
    return result;
}

std::vector<NodeId> UniversalGraph::shortestPath(NodeId from, NodeId to) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (from == to) return {from};
    std::unordered_map<NodeId, NodeId> parent;
    std::queue<NodeId> q;
    std::set<NodeId> visited;
    q.push(from);
    visited.insert(from);
    bool found = false;
    while (!q.empty() && !found) {
        NodeId n = q.front(); q.pop();
        auto it = outEdges_.find(n);
        if (it != outEdges_.end()) {
            for (EdgeId eid : it->second) {
                auto eit = edges_.find(eid);
                if (eit != edges_.end()) {
                    NodeId tgt = eit->second.target;
                    if (visited.find(tgt) == visited.end()) {
                        visited.insert(tgt);
                        parent[tgt] = n;
                        if (tgt == to) { found = true; break; }
                        q.push(tgt);
                    }
                }
            }
        }
    }
    if (!found) return {};
    // Reconstruct path
    std::vector<NodeId> path;
    NodeId cur = to;
    while (cur != from) {
        path.push_back(cur);
        auto it = parent.find(cur);
        if (it == parent.end()) return {};
        cur = it->second;
    }
    path.push_back(from);
    std::reverse(path.begin(), path.end());
    return path;
}

UniversalGraph UniversalGraph::subgraph(NodeId root) const {
    UniversalGraph sub;
    auto nodes = reachable(root);
    // Build ID mapping
    std::unordered_map<NodeId, NodeId> idMap;
    for (NodeId oldId : nodes) {
        auto it = nodes_.find(oldId);
        if (it != nodes_.end()) {
            NodeId newId = sub.addNode(it->second.name, it->second.type);
            idMap[oldId] = newId;
        }
    }
    // Copy edges within subgraph
    for (NodeId oldId : nodes) {
        auto it = outEdges_.find(oldId);
        if (it != outEdges_.end()) {
            for (EdgeId eid : it->second) {
                auto eit = edges_.find(eid);
                if (eit != edges_.end() && idMap.count(eit->second.target)) {
                    sub.addEdge(idMap[oldId], idMap[eit->second.target],
                               eit->second.kind, eit->second.label);
                }
            }
        }
    }
    return sub;
}

std::unordered_map<NodeId, NodeId> UniversalGraph::merge(const UniversalGraph& other) {
    std::unordered_map<NodeId, NodeId> idMap;
    for (const auto& n : other.allNodes()) {
        NodeId newId = addNode(n.name, n.type);
        idMap[n.id] = newId;
    }
    for (const auto& [_, e] : other.edges_) {
        auto srcIt = idMap.find(e.source);
        auto dstIt = idMap.find(e.target);
        if (srcIt != idMap.end() && dstIt != idMap.end()) {
            addEdge(srcIt->second, dstIt->second, e.kind, e.label);
        }
    }
    return idMap;
}

UniversalGraph::GraphDiff UniversalGraph::diff(const UniversalGraph& other) const {
    GraphDiff d;
    auto myNodes = allNodes();
    auto otherNodes = other.allNodes();
    // Compare by name+type (canonical)
    std::set<std::string> otherKeys;
    for (const auto& n : otherNodes) otherKeys.insert(n.name + ":" + n.type);
    for (const auto& n : myNodes) {
        std::string key = n.name + ":" + n.type;
        if (otherKeys.find(key) == otherKeys.end()) d.addedNodes.push_back(n.id);
    }
    return d;
}

std::string UniversalGraph::canonicalFingerprint() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Sort nodes by name, build deterministic string
    std::vector<std::pair<std::string, NodeId>> sorted;
    for (const auto& [id, n] : nodes_) sorted.emplace_back(n.name, id);
    std::sort(sorted.begin(), sorted.end());
    std::ostringstream oss;
    for (const auto& [name, id] : sorted) {
        oss << "N:" << name << ":" << nodes_.at(id).type << ";";
    }
    // Hash the string (simple FNV-1a)
    std::string s = oss.str();
    uint64_t hash = 14695981039346656037ULL;
    for (char c : s) { hash ^= (uint8_t)c; hash *= 1099511628211ULL; }
    std::ostringstream hex;
    hex << std::hex << hash;
    return hex.str();
}

std::string UniversalGraph::serialize() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream oss;
    oss << "GRAPH " << nodes_.size() << " " << edges_.size() << "\n";
    for (const auto& [id, n] : nodes_) {
        oss << "N " << id << " " << n.name << " " << n.type << "\n";
    }
    for (const auto& [id, e] : edges_) {
        oss << "E " << id << " " << e.source << " " << e.target
            << " " << static_cast<int>(e.kind) << " " << e.label << "\n";
    }
    return oss.str();
}

void UniversalGraph::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    nodes_.clear();
    edges_.clear();
    outEdges_.clear();
    inEdges_.clear();
    nextNodeId_.store(1);
    nextEdgeId_.store(1);
}

// ---------------------------------------------------------------------------
// Graph rewrite engine
// ---------------------------------------------------------------------------
void GraphRewriteEngine::addRule(RewriteRule rule) {
    rules_.push_back(std::move(rule));
    // Sort by priority (highest first)
    std::sort(rules_.begin(), rules_.end(),
              [](const RewriteRule& a, const RewriteRule& b) { return a.priority > b.priority; });
}

int GraphRewriteEngine::rewriteOnce(UniversalGraph& graph) {
    int rewrites = 0;
    auto nodes = graph.allNodes();
    for (const auto& rule : rules_) {
        for (const auto& n : nodes) {
            if (n.id == 0) continue;
            if (rule.matches(graph, n.id)) {
                if (rule.apply(graph, n.id)) {
                    rewrites++;
                    totalRewrites_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
    }
    return rewrites;
}

int GraphRewriteEngine::rewriteToFixedPoint(UniversalGraph& graph) {
    int total = 0;
    for (int iter = 0; iter < 100; ++iter) {  // bounded
        int n = rewriteOnce(graph);
        total += n;
        if (n == 0) break;  // fixed point
    }
    return total;
}

bool GraphRewriteEngine::isFixedPoint(const UniversalGraph& graph) const {
    auto nodes = graph.allNodes();
    for (const auto& rule : rules_) {
        for (const auto& n : nodes) {
            if (n.id != 0 && rule.matches(graph, n.id)) return false;
        }
    }
    return true;
}

} // namespace rawrxd::graph