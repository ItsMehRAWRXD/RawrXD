#pragma once
#include "seg_node.hpp"
#include <vector>
#include <unordered_map>

namespace seg {

class Graph {
public:
    NodeId AddNode(NodeKind kind, const std::string& name);
    void AddEdge(NodeId from, NodeId to);

    const Node* GetNode(NodeId id) const;
    const std::vector<Node>& Nodes() const { return m_nodes; }
    const std::vector<Edge>& Edges() const { return m_edges; }

    std::vector<NodeId> TopologicalSort() const;

private:
    std::vector<Node> m_nodes;
    std::vector<Edge> m_edges;
    std::unordered_map<uint32_t, size_t> m_index;
};

} // namespace seg
