// ============================================================================
// DependencyGraph.hpp — Dependency Graph
// DAG-based dependency resolution for plugins and services
// ============================================================================

#ifndef DEPENDENCY_GRAPH_HPP
#define DEPENDENCY_GRAPH_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>

namespace rawr {

// ============================================================================
// DependencyGraph — Directed Acyclic Graph
// ============================================================================
class DependencyGraph {
public:
    DependencyGraph() = default;
    ~DependencyGraph() = default;

    void AddNode(const char* name);
    void AddDependency(const char* node, const char* dependsOn);
    void RemoveNode(const char* name);

    // Topological sort
    std::vector<std::string> ResolveOrder() const;
    bool HasCycle() const;

    // Query
    std::vector<std::string> GetDependencies(const char* name) const;
    std::vector<std::string> GetDependents(const char* name) const;
    uint32_t GetNodeCount() const { return static_cast<uint32_t>(m_adjacency.size()); }

    void Clear();

private:
    bool Visit(const std::string& node,
               std::unordered_set<std::string>& visited,
               std::unordered_set<std::string>& stack,
               std::vector<std::string>& order) const;

    std::unordered_map<std::string, std::unordered_set<std::string>> m_adjacency;
    mutable std::mutex m_mutex;
};

} // namespace rawr

#endif // DEPENDENCY_GRAPH_HPP
