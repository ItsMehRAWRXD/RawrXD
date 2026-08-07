// ============================================================================
// DependencyGraph.cpp — Dependency Graph Implementation
// ============================================================================

#include "DependencyGraph.hpp"
#include <algorithm>
#include <stdexcept>

namespace rawr {

void DependencyGraph::AddNode(const char* name) {
    if (!name) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_adjacency.find(name) == m_adjacency.end()) {
        m_adjacency[name] = {};
    }
}

void DependencyGraph::AddDependency(const char* node, const char* dependsOn) {
    if (!node || !dependsOn) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_adjacency[node].insert(dependsOn);
    // Ensure dependency node exists
    if (m_adjacency.find(dependsOn) == m_adjacency.end()) {
        m_adjacency[dependsOn] = {};
    }
}

void DependencyGraph::RemoveNode(const char* name) {
    if (!name) return;
    std::lock_guard<std::mutex> lock(m_mutex);
    m_adjacency.erase(name);
    for (auto& [node, deps] : m_adjacency) {
        deps.erase(name);
    }
}

std::vector<std::string> DependencyGraph::ResolveOrder() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> stack;
    std::vector<std::string> order;

    for (const auto& [node, deps] : m_adjacency) {
        if (visited.find(node) == visited.end()) {
            if (!Visit(node, visited, stack, order)) {
                throw std::runtime_error("Circular dependency detected");
            }
        }
    }

    return order;
}

bool DependencyGraph::HasCycle() const {
    try {
        ResolveOrder();
        return false;
    } catch (...) {
        return true;
    }
}

std::vector<std::string> DependencyGraph::GetDependencies(const char* name) const {
    if (!name) return {};
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_adjacency.find(name);
    if (it != m_adjacency.end()) {
        return { it->second.begin(), it->second.end() };
    }
    return {};
}

std::vector<std::string> DependencyGraph::GetDependents(const char* name) const {
    if (!name) return {};
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> dependents;
    for (const auto& [node, deps] : m_adjacency) {
        if (deps.find(name) != deps.end()) {
            dependents.push_back(node);
        }
    }
    return dependents;
}

void DependencyGraph::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_adjacency.clear();
}

bool DependencyGraph::Visit(const std::string& node,
                             std::unordered_set<std::string>& visited,
                             std::unordered_set<std::string>& stack,
                             std::vector<std::string>& order) const {
    if (stack.find(node) != stack.end()) return false;  // Cycle
    if (visited.find(node) != visited.end()) return true;

    stack.insert(node);

    auto it = m_adjacency.find(node);
    if (it != m_adjacency.end()) {
        for (const auto& dep : it->second) {
            if (!Visit(dep, visited, stack, order)) return false;
        }
    }

    stack.erase(node);
    visited.insert(node);
    order.push_back(node);
    return true;
}

} // namespace rawr
