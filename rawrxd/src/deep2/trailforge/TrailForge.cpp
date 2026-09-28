// ============================================================================
// TrailForge.cpp — Execution-graph kernel implementation
// RAWRXD_TRAILFORGE_001
// ============================================================================
#include "TrailForge.h"
#include <algorithm>
#include <queue>
#include <stack>
#include <sstream>
#include <stdexcept>

namespace Deep2::TrailForge {

// ---------------------------------------------------------------------------
// ExecOp helpers
// ---------------------------------------------------------------------------
const char* execOpName(ExecOp op) {
    switch (op) {
        case ExecOp::None:          return "None";
        case ExecOp::Embed:         return "Embed";
        case ExecOp::ForwardLayer:  return "ForwardLayer";
        case ExecOp::ComputeLogits: return "ComputeLogits";
        case ExecOp::Sample:        return "Sample";
        case ExecOp::AdvanceKV:     return "AdvanceKV";
        case ExecOp::YieldToken:    return "YieldToken";
        case ExecOp::ResetState:    return "ResetState";
        case ExecOp::LoopCondition: return "LoopCondition";
        case ExecOp::PrefillPhase:  return "PrefillPhase";
    }
    return "Unknown";
}

const char* strategyName(ExecutionStrategy s) {
    switch (s) {
        case ExecutionStrategy::Static:        return "Static";
        case ExecutionStrategy::ForwardReady:  return "ForwardReady";
        case ExecutionStrategy::ReverseDemand: return "ReverseDemand";
        case ExecutionStrategy::RandomReady:   return "RandomReady";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// ExecutionRecipe
// ---------------------------------------------------------------------------
size_t ExecutionRecipe::addNode(ExecOp op, size_t layerIdx) {
    ExecutionNode node;
    node.id = nodes.size();
    node.op = op;
    node.layerIndex = layerIdx;
    nodes.push_back(std::move(node));
    return nodes.back().id;
}

void ExecutionRecipe::addDependency(size_t from, size_t to) {
    if (from >= nodes.size() || to >= nodes.size()) {
        // Silently skip; validate() will catch the mismatch
        return;
    }
    nodes[to].deps.push_back(from);
    nodes[from].consumers.push_back(to);
}

bool ExecutionRecipe::validate(std::string* error) const {
    // 1. Node IDs must match their indices
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].id != i) {
            if (error) {
                *error = "Node id " + std::to_string(nodes[i].id) +
                         " != index " + std::to_string(i);
            }
            return false;
        }
    }

    // 2. All dependency references must be in bounds
    for (const auto& node : nodes) {
        for (size_t dep : node.deps) {
            if (dep >= nodes.size()) {
                if (error) {
                    *error = "Node " + std::to_string(node.id) +
                             " has out-of-bounds dependency " + std::to_string(dep);
                }
                return false;
            }
        }
        for (size_t cons : node.consumers) {
            if (cons >= nodes.size()) {
                if (error) {
                    *error = "Node " + std::to_string(node.id) +
                             " has out-of-bounds consumer " + std::to_string(cons);
                }
                return false;
            }
        }
    }

    // 3. No self-loops
    for (const auto& node : nodes) {
        for (size_t dep : node.deps) {
            if (dep == node.id) {
                if (error) {
                    *error = "Node " + std::to_string(node.id) + " depends on itself";
                }
                return false;
            }
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// DependencyGraph
// ---------------------------------------------------------------------------
DependencyGraph::DependencyGraph(const ExecutionRecipe& recipe) {
    build(recipe);
}

bool DependencyGraph::build(const ExecutionRecipe& recipe) {
    nodes_.clear();
    nodes_.reserve(recipe.nodes.size());
    for (size_t i = 0; i < recipe.nodes.size(); ++i) {
        GraphNode gn;
        gn.deps = recipe.nodes[i].deps;
        gn.consumers = recipe.nodes[i].consumers;
        gn.inDegree = static_cast<int>(gn.deps.size());
        nodes_.push_back(std::move(gn));
    }

    // Cycle detection via DFS (3-color)
    std::vector<uint8_t> color(nodes_.size(), 0); // 0=white, 1=gray, 2=black
    for (size_t i = 0; i < nodes_.size(); ++i) {
        if (color[i] == 0) {
            if (detectCycleDFS(i, color)) {
                cycleDetected_ = true;
                return false;
            }
        }
    }
    cycleDetected_ = false;
    return true;
}

bool DependencyGraph::detectCycleDFS(size_t start, std::vector<uint8_t>& color) const {
    color[start] = 1; // gray
    for (size_t cons : nodes_[start].consumers) {
        if (color[cons] == 1) return true; // back edge = cycle
        if (color[cons] == 0) {
            if (detectCycleDFS(cons, color)) return true;
        }
    }
    color[start] = 2; // black
    return false;
}

bool DependencyGraph::hasCycle() const {
    return cycleDetected_;
}

const std::vector<size_t>& DependencyGraph::dependencies(size_t nodeId) const {
    static const std::vector<size_t> empty;
    if (nodeId >= nodes_.size()) return empty;
    return nodes_[nodeId].deps;
}

const std::vector<size_t>& DependencyGraph::consumers(size_t nodeId) const {
    static const std::vector<size_t> empty;
    if (nodeId >= nodes_.size()) return empty;
    return nodes_[nodeId].consumers;
}

int DependencyGraph::inDegree(size_t nodeId) const {
    if (nodeId >= nodes_.size()) return -1;
    return nodes_[nodeId].inDegree;
}

std::vector<size_t> DependencyGraph::entryNodes() const {
    std::vector<size_t> entries;
    for (size_t i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].inDegree == 0) entries.push_back(i);
    }
    return entries;
}

std::vector<size_t> DependencyGraph::terminalNodes() const {
    std::vector<size_t> terminals;
    for (size_t i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].consumers.empty()) terminals.push_back(i);
    }
    return terminals;
}

// ---------------------------------------------------------------------------
// ReadySet
// ---------------------------------------------------------------------------
ReadySet::ReadySet(ExecutionStrategy strategy) : strategy_(strategy) {}

void ReadySet::clear() { data_.clear(); }
bool ReadySet::empty() const { return data_.empty(); }

void ReadySet::insert(size_t nodeId) {
    data_.push_back(nodeId);
}

size_t ReadySet::selectIndex(std::mt19937_64& rng) const {
    switch (strategy_) {
        case ExecutionStrategy::Static:
        case ExecutionStrategy::ForwardReady:
            return 0; // FIFO
        case ExecutionStrategy::ReverseDemand:
            return data_.size() - 1; // LIFO (stack-like)
        case ExecutionStrategy::RandomReady:
            if (data_.size() <= 1) return 0;
            return std::uniform_int_distribution<size_t>(0, data_.size() - 1)(rng);
    }
    return 0;
}

std::optional<size_t> ReadySet::popNext(std::mt19937_64& rng) {
    if (data_.empty()) return std::nullopt;
    size_t idx = selectIndex(rng);
    size_t nodeId = data_[idx];
    data_.erase(data_.begin() + static_cast<std::ptrdiff_t>(idx));
    return nodeId;
}

std::optional<size_t> ReadySet::peekNext(std::mt19937_64& rng) const {
    if (data_.empty()) return std::nullopt;
    size_t idx = selectIndex(rng);
    return data_[idx];
}

// ---------------------------------------------------------------------------
// RecipeScheduler
// ---------------------------------------------------------------------------
std::vector<size_t> RecipeScheduler::schedule(const ExecutionRecipe& recipe,
                                                  ExecutionStrategy strategy,
                                                  std::string* error) {
    if (!recipe.validate(error)) return {};

    DependencyGraph graph(recipe);
    if (graph.hasCycle()) {
        if (error) *error = "Cycle detected in recipe DAG";
        return {};
    }

    std::mt19937_64 rng(42); // deterministic seed for reproducibility

    switch (strategy) {
        case ExecutionStrategy::Static:
            return scheduleStatic(graph);
        case ExecutionStrategy::ForwardReady:
            return scheduleForwardReady(graph);
        case ExecutionStrategy::ReverseDemand:
            return scheduleReverseDemand(graph);
        case ExecutionStrategy::RandomReady:
            return scheduleRandomReady(graph, rng);
    }
    if (error) *error = "Unknown strategy";
    return {};
}

// Topological sort via Kahn's algorithm
std::vector<size_t> RecipeScheduler::scheduleStatic(const DependencyGraph& graph) {
    std::vector<int> inDeg(graph.nodeCount());
    std::vector<std::vector<size_t>> adj(graph.nodeCount());
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        inDeg[i] = graph.inDegree(i);
        adj[i] = graph.consumers(i);
    }

    std::queue<size_t> q;
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        if (inDeg[i] == 0) q.push(i);
    }

    std::vector<size_t> order;
    order.reserve(graph.nodeCount());
    while (!q.empty()) {
        size_t u = q.front(); q.pop();
        order.push_back(u);
        for (size_t v : adj[u]) {
            if (--inDeg[v] == 0) q.push(v);
        }
    }
    return order;
}

std::vector<size_t> RecipeScheduler::scheduleForwardReady(const DependencyGraph& graph) {
    // Same as Static but using ReadySet with FIFO semantics
    std::vector<int> inDeg(graph.nodeCount());
    std::vector<std::vector<size_t>> adj(graph.nodeCount());
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        inDeg[i] = graph.inDegree(i);
        adj[i] = graph.consumers(i);
    }

    ReadySet ready(ExecutionStrategy::ForwardReady);
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        if (inDeg[i] == 0) ready.insert(i);
    }

    std::vector<size_t> order;
    order.reserve(graph.nodeCount());
    std::mt19937_64 rng; // unused for FIFO
    while (!ready.empty()) {
        auto opt = ready.popNext(rng);
        if (!opt) break;
        size_t u = *opt;
        order.push_back(u);
        for (size_t v : adj[u]) {
            if (--inDeg[v] == 0) ready.insert(v);
        }
    }
    return order;
}

std::vector<size_t> RecipeScheduler::scheduleReverseDemand(const DependencyGraph& graph) {
    // Kahn's algorithm with a LIFO ready set (stack semantics).
    // Produces a valid topological sort; order may differ from FIFO
    // when multiple nodes become ready simultaneously.
    std::vector<int> inDeg(graph.nodeCount());
    std::vector<std::vector<size_t>> adj(graph.nodeCount());
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        inDeg[i] = graph.inDegree(i);
        adj[i] = graph.consumers(i);
    }

    ReadySet ready(ExecutionStrategy::ReverseDemand);
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        if (inDeg[i] == 0) ready.insert(i);
    }

    std::vector<size_t> order;
    order.reserve(graph.nodeCount());
    std::mt19937_64 rng; // unused for LIFO
    while (!ready.empty()) {
        auto opt = ready.popNext(rng);
        if (!opt) break;
        size_t u = *opt;
        order.push_back(u);
        for (size_t v : adj[u]) {
            if (--inDeg[v] == 0) ready.insert(v);
        }
    }
    return order;
}

std::vector<size_t> RecipeScheduler::scheduleRandomReady(const DependencyGraph& graph,
                                                               std::mt19937_64& rng) {
    std::vector<int> inDeg(graph.nodeCount());
    std::vector<std::vector<size_t>> adj(graph.nodeCount());
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        inDeg[i] = graph.inDegree(i);
        adj[i] = graph.consumers(i);
    }

    ReadySet ready(ExecutionStrategy::RandomReady);
    for (size_t i = 0; i < graph.nodeCount(); ++i) {
        if (inDeg[i] == 0) ready.insert(i);
    }

    std::vector<size_t> order;
    order.reserve(graph.nodeCount());
    while (!ready.empty()) {
        auto opt = ready.popNext(rng);
        if (!opt) break;
        size_t u = *opt;
        order.push_back(u);
        for (size_t v : adj[u]) {
            if (--inDeg[v] == 0) ready.insert(v);
        }
    }
    return order;
}

bool RecipeScheduler::verifyOrdering(const ExecutionRecipe& recipe,
                                      const std::vector<size_t>& ordering,
                                      std::string* error) {
    if (ordering.size() != recipe.nodes.size()) {
        if (error) *error = "Ordering size mismatch";
        return false;
    }

    // Map nodeId -> position in ordering
    std::vector<size_t> pos(recipe.nodes.size(), static_cast<size_t>(-1));
    for (size_t i = 0; i < ordering.size(); ++i) {
        if (ordering[i] >= recipe.nodes.size()) {
            if (error) *error = "Ordering contains invalid node id";
            return false;
        }
        pos[ordering[i]] = i;
    }

    // Check all dependencies: dep must appear before node
    for (const auto& node : recipe.nodes) {
        for (size_t dep : node.deps) {
            if (pos[dep] == static_cast<size_t>(-1) || pos[dep] > pos[node.id]) {
                if (error) {
                    std::ostringstream oss;
                    oss << "Dependency violated: node " << node.id
                        << " depends on " << dep
                        << " but ordering has " << pos[dep]
                        << " after " << pos[node.id];
                    *error = oss.str();
                }
                return false;
            }
        }
    }
    return true;
}

ExecutionRecipe RecipeScheduler::buildTransformerRecipe(size_t numLayers,
                                                          const std::string& name) {
    ExecutionRecipe recipe;
    recipe.name = name;

    // Phase: prefill (marker)
    size_t prefill = recipe.addNode(ExecOp::PrefillPhase);

    // Embed token
    size_t embed = recipe.addNode(ExecOp::Embed);
    recipe.addDependency(prefill, embed); // prefill happens before embed

    // N transformer layers (each depends on previous)
    size_t prev = embed;
    for (size_t l = 0; l < numLayers; ++l) {
        size_t layer = recipe.addNode(ExecOp::ForwardLayer, l);
        recipe.addDependency(prev, layer);
        prev = layer;
    }

    // Compute logits
    size_t logits = recipe.addNode(ExecOp::ComputeLogits);
    recipe.addDependency(prev, logits);

    // Sample
    size_t sample = recipe.addNode(ExecOp::Sample);
    recipe.addDependency(logits, sample);

    // Advance KV cache
    size_t advance = recipe.addNode(ExecOp::AdvanceKV);
    recipe.addDependency(sample, advance);

    // Yield token
    size_t yield = recipe.addNode(ExecOp::YieldToken);
    recipe.addDependency(advance, yield);

    // Loop condition check (implicit dependency on yield for ordering)
    size_t loop = recipe.addNode(ExecOp::LoopCondition);
    recipe.addDependency(yield, loop);

    return recipe;
}

ExecutionRecipe RecipeScheduler::buildDecodeStepRecipe(size_t numLayers,
                                                        const std::string& name) {
    // Same as transformer recipe for a single decode step
    return buildTransformerRecipe(numLayers, name);
}

} // namespace Deep2::TrailForge
