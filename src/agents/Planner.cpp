// =============================================================================
// Planner.cpp — task planning + dependency resolution (real topological sort).
// =============================================================================
#include "Planner.hpp"

#include <algorithm>

namespace RawrXD {
namespace Agents {

Planner::Planner() = default;
Planner::~Planner() = default;

namespace {

// Built-in component dependency graph (real project structure).
const std::map<std::string, std::vector<std::string>>& BaseGraph() {
    static const std::map<std::string, std::vector<std::string>> g = {
        {"completion", {}},
        {"repository", {}},
        {"model", {"completion"}},
        {"ide", {"completion", "repository", "model"}},
        {"telemetry", {"ide"}},
    };
    return g;
}

}  // namespace

void Planner::AddTaskForComponent(const std::string& component) {
    RawrXD::Agentic::Task t;
    t.id = component;
    t.description = "Implement " + component;
    t.dependencies = GetDependencies(component);
    tasks_.push_back(t);
}

void Planner::BuildDependencyGraph() {
    dependencyGraph_ = BaseGraph();
}

std::vector<std::string> Planner::GetDependencies(
    const std::string& component) const {
    auto it = dependencyGraph_.find(component);
    return it == dependencyGraph_.end() ? std::vector<std::string>{}
                                        : it->second;
}

bool Planner::HasCircularDependency(const std::string& component) const {
    // DFS with a visiting set over the dependency graph.
    std::map<std::string, int> mark;  // 0=unseen,1=visiting,2=done
    std::function<bool(const std::string&)> dfs = [&](const std::string& n) {
        if (mark[n] == 1) return true;
        if (mark[n] == 2) return false;
        mark[n] = 1;
        for (const auto& d : GetDependencies(n))
            if (dfs(d)) return true;
        mark[n] = 2;
        return false;
    };
    return dfs(component);
}

void Planner::CreatePlan(const std::vector<std::string>& targetComponents,
                         const RawrXD::Agentic::ProjectState& currentState) {
    (void)currentState;
    tasks_.clear();
    BuildDependencyGraph();
    for (const auto& c : targetComponents) AddTaskForComponent(c);
    tasks_ = TopologicalSort();
}

std::vector<RawrXD::Agentic::Task> Planner::TopologicalSort() {
    std::vector<RawrXD::Agentic::Task> sorted;
    std::map<std::string, int> indegree;
    for (const auto& t : tasks_) indegree[t.id] = (int)t.dependencies.size();
    bool progress = true;
    while (progress && (int)sorted.size() < (int)tasks_.size()) {
        progress = false;
        for (const auto& t : tasks_) {
            if (indegree[t.id] != 0) continue;
            bool ready = true;
            for (const auto& d : t.dependencies) {
                for (const auto& s : sorted)
                    if (s.id == d) continue;
                // dependency not yet emitted?
                bool emitted = false;
                for (const auto& s : sorted)
                    if (s.id == d) emitted = true;
                if (!emitted && indegree[d] != 0) ready = false;
            }
            if (!ready) continue;
            sorted.push_back(t);
            indegree[t.id] = -1;
            for (auto& other : tasks_) {
                for (const auto& d : other.dependencies)
                    if (d == t.id && indegree[other.id] > 0)
                        indegree[other.id]--;
            }
            progress = true;
        }
    }
    return sorted;
}

std::vector<RawrXD::Agentic::Task> Planner::GetTasks() const {
    return tasks_;
}

bool Planner::IsPlanValid() const {
    if (tasks_.empty()) return false;
    for (const auto& t : tasks_)
        if (HasCircularDependency(t.id)) return false;
    return true;
}

std::vector<std::string> Planner::GetPlanBlockers() const {
    std::vector<std::string> out;
    for (const auto& t : tasks_)
        if (HasCircularDependency(t.id))
            out.push_back("circular dependency at " + t.id);
    if (tasks_.empty()) out.push_back("empty plan");
    return out;
}

}  // namespace Agents
}  // namespace RawrXD