// ============================================================================
// W0GraphStore.hpp — canonical node/edge graph (session > project > pack)
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_GRAPH_STORE_HPP
#define RAWRXD_DEEP2W0_W0_GRAPH_STORE_HPP

#include "deep2w0/W0UniversalIR.hpp"

#include <optional>
#include <unordered_map>
#include <vector>

namespace RawrXD {
namespace W0 {

enum class KnowledgeScope : uint8_t { Global = 0, Project = 1, Session = 2 };

class GraphStore {
public:
    uint64_t addNode(KnowledgeNode n, KnowledgeScope scope = KnowledgeScope::Project) {
        if (n.id == 0) n.id = ++m_nextId;
        else if (n.id >= m_nextId) m_nextId = n.id + 1;
        m_nodes[n.id] = std::move(n);
        m_scope[n.id] = scope;
        return m_nodes[n.id].id;
    }

    void addEdge(KnowledgeEdge e) { m_edges.push_back(std::move(e)); }

    const KnowledgeNode* get(uint64_t id) const {
        auto it = m_nodes.find(id);
        return it == m_nodes.end() ? nullptr : &it->second;
    }

    std::vector<uint64_t> findByName(const std::string& name) const {
        std::vector<uint64_t> out;
        for (const auto& kv : m_nodes) {
            if (kv.second.name == name) out.push_back(kv.first);
        }
        return out;
    }

    std::vector<KnowledgeEdge> edgesFrom(uint64_t id) const {
        std::vector<KnowledgeEdge> out;
        for (const auto& e : m_edges) {
            if (e.from == id) out.push_back(e);
        }
        return out;
    }

    const std::unordered_map<uint64_t, KnowledgeNode>& nodes() const { return m_nodes; }
    const std::vector<KnowledgeEdge>& edges() const { return m_edges; }
    size_t nodeCount() const { return m_nodes.size(); }

    void clearSession() {
        std::vector<uint64_t> drop;
        for (const auto& kv : m_scope) {
            if (kv.second == KnowledgeScope::Session) drop.push_back(kv.first);
        }
        for (uint64_t id : drop) {
            m_nodes.erase(id);
            m_scope.erase(id);
        }
    }

private:
    uint64_t m_nextId = 1;
    std::unordered_map<uint64_t, KnowledgeNode> m_nodes;
    std::unordered_map<uint64_t, KnowledgeScope> m_scope;
    std::vector<KnowledgeEdge> m_edges;
};

} // namespace W0
} // namespace RawrXD

#endif
