// ============================================================================
// Planner.cpp - Task Planning Implementation
// ============================================================================

#include "Planner.hpp"
#include <algorithm>
#include <queue>
#include <unordered_set>

namespace RawrXD {
namespace Agents {

Planner::Planner() = default;
Planner::~Planner() = default;

void Planner::CreatePlan(const std::vector<std::string>& targetComponents, 
                         const ProjectState& currentState) {
    tasks_.clear();
    
    // Define component dependencies
    dependencyGraph_ = {
        {"Repository Intelligence", {}},
        {"Model Manager", {"Repository Intelligence"}},
        {"Completion Engine", {"Model Manager", "Repository Intelligence"}},
        {"IDE Shell", {"Completion Engine", "Model Manager"}}
    };
    
    // Add tasks for missing components
    for (const auto& component : targetComponents) {
        if (!IsComponentBuilt(component, currentState)) {
            AddTaskForComponent(component);
        }
    }
    
    // Sort by dependencies
    tasks_ = TopologicalSort();
}

std::vector<Task> Planner::GetTasks() const {
    return tasks_;
}

std::vector<std::string> Planner::GetDependencies(const std::string& component) const {
    auto it = dependencyGraph_.find(component);
    if (it != dependencyGraph_.end()) {
        return it->second;
    }
    return {};
}

bool Planner::HasCircularDependency(const std::string& component) const {
    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> recursionStack;
    
    std::function<bool(const std::string&)> dfs = [&](const std::string& node) -> bool {
        visited.insert(node);
        recursionStack.insert(node);
        
        auto deps = GetDependencies(node);
        for (const auto& dep : deps) {
            if (recursionStack.find(dep) != recursionStack.end()) {
                return true; // Cycle detected
            }
            if (visited.find(dep) == visited.end()) {
                if (dfs(dep)) return true;
            }
        }
        
        recursionStack.erase(node);
        return false;
    };
    
    return dfs(component);
}

bool Planner::IsPlanValid() const {
    for (const auto& task : tasks_) {
        if (HasCircularDependency(task.description)) {
            return false;
        }
    }
    return true;
}

std::vector<std::string> Planner::GetPlanBlockers() const {
    std::vector<std::string> blockers;
    
    for (const auto& task : tasks_) {
        if (HasCircularDependency(task.description)) {
            blockers.push_back("Circular dependency in: " + task.description);
        }
    }
    
    return blockers;
}

void Planner::AddTaskForComponent(const std::string& component) {
    Task task;
    task.id = component;
    task.description = component;
    task.dependencies = GetDependencies(component);
    
    // Set up executor based on component type
    if (component == "Repository Intelligence") {
        task.executor = []() { return true; }; // Placeholder
    } else if (component == "Model Manager") {
        task.executor = []() { return true; };
    } else if (component == "Completion Engine") {
        task.executor = []() { return true; };
    } else if (component == "IDE Shell") {
        task.executor = []() { return true; };
    }
    
    tasks_.push_back(task);
}

std::vector<Task> Planner::TopologicalSort() {
    std::map<std::string, int> inDegree;
    std::map<std::string, Task> taskMap;
    
    // Initialize
    for (const auto& task : tasks_) {
        inDegree[task.id] = 0;
        taskMap[task.id] = task;
    }
    
    // Calculate in-degrees
    for (const auto& task : tasks_) {
        for (const auto& dep : task.dependencies) {
            if (taskMap.find(dep) != taskMap.end()) {
                inDegree[task.id]++;
            }
        }
    }
    
    // Queue for nodes with no dependencies
    std::queue<std::string> q;
    for (const auto& [id, degree] : inDegree) {
        if (degree == 0) {
            q.push(id);
        }
    }
    
    // Process
    std::vector<Task> sorted;
    while (!q.empty()) {
        std::string current = q.front();
        q.pop();
        
        if (taskMap.find(current) != taskMap.end()) {
            sorted.push_back(taskMap[current]);
        }
        
        // Reduce in-degree for dependents
        for (const auto& task : tasks_) {
            if (std::find(task.dependencies.begin(), task.dependencies.end(), current) 
                != task.dependencies.end()) {
                inDegree[task.id]--;
                if (inDegree[task.id] == 0) {
                    q.push(task.id);
                }
            }
        }
    }
    
    return sorted;
}

bool Planner::IsComponentBuilt(const std::string& component, const ProjectState& state) {
    if (component == "Repository Intelligence") return state.hasRepositoryIntelligence;
    if (component == "Model Manager") return state.hasModelManager;
    if (component == "Completion Engine") return state.hasCompletionEngine;
    if (component == "IDE Shell") return state.hasIDEShell;
    return false;
}

} // namespace Agents
} // namespace RawrXD
