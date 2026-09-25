#include "SpecialGraph.hpp"

#include <algorithm>
#include <limits>
#include <queue>
#include <utility>

namespace rawrxd::deep2::spec {

namespace {
constexpr std::uint32_t kInvalidNode = std::numeric_limits<std::uint32_t>::max();
}

std::uint32_t SpecialGraph::addNode(GraphOp op, std::string name) {
    const auto id = static_cast<std::uint32_t>(nodes_.size());
    nodes_.push_back(GraphNode{id, op, std::move(name)});
    return id;
}

bool SpecialGraph::addEdge(std::uint32_t from, std::uint32_t to, EdgeCond cond) {
    if (from >= nodes_.size() || to >= nodes_.size()) {
        return false;
    }
    const auto duplicate = std::find_if(edges_.begin(), edges_.end(), [&](const GraphEdge& e) {
        return e.from == from && e.cond == cond;
    });
    if (duplicate != edges_.end()) {
        return false; // deterministic graph: one edge per (node, condition)
    }
    edges_.push_back(GraphEdge{from, to, cond});
    return true;
}

const GraphNode* SpecialGraph::node(std::uint32_t id) const noexcept {
    return id < nodes_.size() ? &nodes_[id] : nullptr;
}

std::uint32_t SpecialGraph::next(std::uint32_t from, EdgeCond cond) const noexcept {
    for (const auto& edge : edges_) {
        if (edge.from == from && edge.cond == cond) {
            return edge.to;
        }
    }
    for (const auto& edge : edges_) {
        if (edge.from == from && edge.cond == EdgeCond::Always) {
            return edge.to;
        }
    }
    return kInvalidNode;
}

bool SpecialGraph::validate(std::string* why) const {
    auto fail = [&](std::string text) {
        if (why) *why = std::move(text);
        return false;
    };

    if (nodes_.empty()) return fail("graph has no nodes");
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].id != i) return fail("node IDs are not dense/stable");
    }
    for (const auto& e : edges_) {
        if (e.from >= nodes_.size() || e.to >= nodes_.size()) {
            return fail("edge references invalid node");
        }
    }

    const auto hasOp = [&](GraphOp op) {
        return std::any_of(nodes_.begin(), nodes_.end(), [&](const GraphNode& n) { return n.op == op; });
    };
    if (!hasOp(GraphOp::Draft) || !hasOp(GraphOp::Verify) ||
        !hasOp(GraphOp::Commit) || !hasOp(GraphOp::Stop)) {
        return fail("speculative graph is missing a required operation");
    }

    // Reachability check. Cycles are intentionally legal because decoding iterates.
    std::vector<bool> seen(nodes_.size(), false);
    std::queue<std::uint32_t> q;
    q.push(0);
    seen[0] = true;
    while (!q.empty()) {
        const auto cur = q.front();
        q.pop();
        for (const auto& e : edges_) {
            if (e.from == cur && !seen[e.to]) {
                seen[e.to] = true;
                q.push(e.to);
            }
        }
    }
    if (std::any_of(seen.begin(), seen.end(), [](bool v) { return !v; })) {
        return fail("graph contains an unreachable node");
    }

    if (why) why->clear();
    return true;
}

SpecialGraph SpecialGraph::makeSpeculativeDecodeGraph() {
    SpecialGraph g;
    const auto draft    = g.addNode(GraphOp::Draft,    "draft");
    const auto verify   = g.addNode(GraphOp::Verify,   "verify");
    const auto accept   = g.addNode(GraphOp::Accept,   "accept");
    const auto rollback = g.addNode(GraphOp::Rollback, "rollback");
    const auto commit   = g.addNode(GraphOp::Commit,   "commit");
    const auto stop     = g.addNode(GraphOp::Stop,     "stop");

    g.addEdge(draft, verify, EdgeCond::DraftProduced);
    g.addEdge(draft, stop, EdgeCond::DraftEmpty);

    g.addEdge(verify, accept, EdgeCond::Always);

    g.addEdge(accept, commit, EdgeCond::AllAccepted);
    g.addEdge(accept, rollback, EdgeCond::Rejected);

    g.addEdge(rollback, commit, EdgeCond::Always);

    g.addEdge(commit, stop, EdgeCond::BudgetExhausted);
    g.addEdge(commit, draft, EdgeCond::BudgetRemaining);

    return g;
}

const char* toString(GraphOp op) noexcept {
    switch (op) {
        case GraphOp::Draft: return "Draft";
        case GraphOp::Verify: return "Verify";
        case GraphOp::Accept: return "Accept";
        case GraphOp::Rollback: return "Rollback";
        case GraphOp::Commit: return "Commit";
        case GraphOp::Stop: return "Stop";
    }
    return "Unknown";
}

const char* toString(EdgeCond cond) noexcept {
    switch (cond) {
        case EdgeCond::Always: return "Always";
        case EdgeCond::DraftProduced: return "DraftProduced";
        case EdgeCond::DraftEmpty: return "DraftEmpty";
        case EdgeCond::AllAccepted: return "AllAccepted";
        case EdgeCond::Rejected: return "Rejected";
        case EdgeCond::BudgetExhausted: return "BudgetExhausted";
        case EdgeCond::BudgetRemaining: return "BudgetRemaining";
    }
    return "Unknown";
}

} // namespace rawrxd::deep2::spec
