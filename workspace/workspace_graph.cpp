// workspace_graph.cpp — Workspace Dependency Graph
#include "workspace_manager.hpp"
#include <queue>
#include <set>

namespace RawrXD {
namespace Workspace {

// ============================================================================
// Workspace Dependency Graph
// ============================================================================
class WorkspaceGraphBuilder {
public:
    static WorkspaceGraphBuilder& Get();

    // Build dependency graph from projects
    WorkspaceManager::WorkspaceGraph Build(const std::vector<ProjectInfo>& projects);

    // Topological sort
    std::vector<std::filesystem::path> TopologicalSort(const WorkspaceManager::WorkspaceGraph& graph);

    // Find circular dependencies
    std::vector<std::vector<std::filesystem::path>> FindCycles(const WorkspaceManager::WorkspaceGraph& graph);

    // Find affected projects (reverse dependency graph)
    std::vector<std::filesystem::path> FindAffected(const WorkspaceManager::WorkspaceGraph& graph, const std::filesystem::path& changedProject);

    // Get dependency depth
    int GetDepth(const WorkspaceManager::WorkspaceGraph& graph, const std::filesystem::path& project);

    // Visualize graph as DOT
    std::string ToDot(const WorkspaceManager::WorkspaceGraph& graph) const;

private:
    WorkspaceGraphBuilder() = default;
    void DFS(const std::filesystem::path& node,
             const std::map<std::filesystem::path, std::vector<std::filesystem::path>>& edges,
             std::set<std::filesystem::path>& visited,
             std::set<std::filesystem::path>& inStack,
             std::vector<std::filesystem::path>& stack,
             std::vector<std::vector<std::filesystem::path>>& cycles);
};

WorkspaceGraphBuilder& WorkspaceGraphBuilder::Get() {
    static WorkspaceGraphBuilder instance;
    return instance;
}

WorkspaceManager::WorkspaceGraph WorkspaceGraphBuilder::Build(const std::vector<ProjectInfo>& projects) {
    WorkspaceManager::WorkspaceGraph graph;

    for (const auto& project : projects) {
        graph.nodes.push_back(project.rootPath);
        for (const auto& dep : project.dependencies) {
            // Find matching project
            for (const auto& p : projects) {
                if (p.name == dep || p.rootPath.string().find(dep) != std::string::npos) {
                    graph.edges[project.rootPath].push_back(p.rootPath);
                    break;
                }
            }
        }
    }

    return graph;
}

std::vector<std::filesystem::path> WorkspaceGraphBuilder::TopologicalSort(const WorkspaceManager::WorkspaceGraph& graph) {
    std::map<std::filesystem::path, int> inDegree;
    for (const auto& node : graph.nodes) {
        inDegree[node] = 0;
    }
    for (const auto& [node, deps] : graph.edges) {
        for (const auto& dep : deps) {
            inDegree[dep]++;
        }
    }

    std::queue<std::filesystem::path> q;
    for (const auto& [node, degree] : inDegree) {
        if (degree == 0) q.push(node);
    }

    std::vector<std::filesystem::path> result;
    while (!q.empty()) {
        auto node = q.front();
        q.pop();
        result.push_back(node);

        auto it = graph.edges.find(node);
        if (it != graph.edges.end()) {
            for (const auto& dep : it->second) {
                if (--inDegree[dep] == 0) {
                    q.push(dep);
                }
            }
        }
    }

    return result;
}

std::vector<std::vector<std::filesystem::path>> WorkspaceGraphBuilder::FindCycles(const WorkspaceManager::WorkspaceGraph& graph) {
    std::vector<std::vector<std::filesystem::path>> cycles;
    std::set<std::filesystem::path> visited;
    std::set<std::filesystem::path> inStack;
    std::vector<std::filesystem::path> stack;

    for (const auto& node : graph.nodes) {
        if (!visited.count(node)) {
            DFS(node, graph.edges, visited, inStack, stack, cycles);
        }
    }

    return cycles;
}

void WorkspaceGraphBuilder::DFS(const std::filesystem::path& node,
                                const std::map<std::filesystem::path, std::vector<std::filesystem::path>>& edges,
                                std::set<std::filesystem::path>& visited,
                                std::set<std::filesystem::path>& inStack,
                                std::vector<std::filesystem::path>& stack,
                                std::vector<std::vector<std::filesystem::path>>& cycles) {
    visited.insert(node);
    inStack.insert(node);
    stack.push_back(node);

    auto it = edges.find(node);
    if (it != edges.end()) {
        for (const auto& neighbor : it->second) {
            if (!visited.count(neighbor)) {
                DFS(neighbor, edges, visited, inStack, stack, cycles);
            } else if (inStack.count(neighbor)) {
                // Found a cycle
                std::vector<std::filesystem::path> cycle;
                auto start = std::find(stack.begin(), stack.end(), neighbor);
                for (auto it2 = start; it2 != stack.end(); ++it2) {
                    cycle.push_back(*it2);
                }
                cycle.push_back(neighbor);
                cycles.push_back(cycle);
            }
        }
    }

    stack.pop_back();
    inStack.erase(node);
}

std::vector<std::filesystem::path> WorkspaceGraphBuilder::FindAffected(const WorkspaceManager::WorkspaceGraph& graph, const std::filesystem::path& changedProject) {
    // Build reverse graph
    std::map<std::filesystem::path, std::vector<std::filesystem::path>> reverseEdges;
    for (const auto& [node, deps] : graph.edges) {
        for (const auto& dep : deps) {
            reverseEdges[dep].push_back(node);
        }
    }

    // BFS from changed project
    std::vector<std::filesystem::path> affected;
    std::queue<std::filesystem::path> q;
    std::set<std::filesystem::path> visited;

    q.push(changedProject);
    visited.insert(changedProject);

    while (!q.empty()) {
        auto node = q.front();
        q.pop();
        affected.push_back(node);

        auto it = reverseEdges.find(node);
        if (it != reverseEdges.end()) {
            for (const auto& dependent : it->second) {
                if (!visited.count(dependent)) {
                    visited.insert(dependent);
                    q.push(dependent);
                }
            }
        }
    }

    return affected;
}

int WorkspaceGraphBuilder::GetDepth(const WorkspaceManager::WorkspaceGraph& graph, const std::filesystem::path& project) {
    // BFS to find max depth
    std::queue<std::pair<std::filesystem::path, int>> q;
    std::set<std::filesystem::path> visited;

    q.push({project, 0});
    visited.insert(project);

    int maxDepth = 0;
    while (!q.empty()) {
        auto [node, depth] = q.front();
        q.pop();
        maxDepth = std::max(maxDepth, depth);

        auto it = graph.edges.find(node);
        if (it != graph.edges.end()) {
            for (const auto& dep : it->second) {
                if (!visited.count(dep)) {
                    visited.insert(dep);
                    q.push({dep, depth + 1});
                }
            }
        }
    }

    return maxDepth;
}

std::string WorkspaceGraphBuilder::ToDot(const WorkspaceManager::WorkspaceGraph& graph) const {
    std::string dot = "digraph Workspace {\n";
    dot += "  rankdir=LR;\n";
    dot += "  node [shape=box, style=rounded];\n\n";

    for (const auto& node : graph.nodes) {
        std::string name = node.filename().string();
        dot += "  \"" + name + "\";\n";
    }

    dot += "\n";
    for (const auto& [node, deps] : graph.edges) {
        std::string fromName = node.filename().string();
        for (const auto& dep : deps) {
            std::string toName = dep.filename().string();
            dot += "  \"" + fromName + "\" -> \"" + toName + "\";\n";
        }
    }

    dot += "}\n";
    return dot;
}

} // namespace Workspace
} // namespace RawrXD
