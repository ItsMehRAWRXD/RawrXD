#include "seg_graph.hpp"
#include <algorithm>

namespace seg {

NodeId Graph::AddNode(NodeKind kind, const std::string& name) {
    NodeId id{ static_cast<uint32_t>(m_nodes.size()) };
    Node n;
    n.id = id;
    n.kind = kind;
    n.name = name;
    m_index[id.value] = m_nodes.size();
    m_nodes.push_back(n);
    return id;
}

void Graph::AddEdge(NodeId from, NodeId to) {
    m_edges.push_back({from, to});
    auto& f = m_nodes[m_index[from.value]];
    auto& t = m_nodes[m_index[to.value]];
    f.outputs.push_back(to);
    t.inputs.push_back(from);
}

const Node* Graph::GetNode(NodeId id) const {
    auto it = m_index.find(id.value);
    if (it == m_index.end()) return nullptr;
    return &m_nodes[it->second];
}

// Simple placeholder topo sort (no cycles handled yet)
std::vector<NodeId> Graph::TopologicalSort() const {
    std::vector<NodeId> order;
    for (const auto& n : m_nodes) {
        order.push_back(n.id);
    }
    return order;
}

} // namespace seg
