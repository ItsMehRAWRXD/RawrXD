// ============================================================================
// Planner.hpp - Task Planning and Dependency Resolution
// ============================================================================

#pragma once

#include "CEOAgent.hpp"
#include <vector>
#include <map>
#include <queue>

namespace RawrXD {
namespace Agents {

// ============================================================================
// Task Planner
// ============================================================================
class Planner {
public:
    Planner();
    ~Planner();
    
    // Create execution plan from component list
    void CreatePlan(const std::vector<std::string>& targetComponents, 
                    const ProjectState& currentState);
    
    // Get ordered tasks
    std::vector<Task> GetTasks() const;
    
    // Dependency resolution
    std::vector<std::string> GetDependencies(const std::string& component) const;
    bool HasCircularDependency(const std::string& component) const;
    
    // Plan validation
    bool IsPlanValid() const;
    std::vector<std::string> GetPlanBlockers() const;

private:
    std::vector<Task> tasks_;
    std::map<std::string, std::vector<std::string>> dependencyGraph_;
    
    void BuildDependencyGraph();
    std::vector<Task> TopologicalSort();
    void AddTaskForComponent(const std::string& component);
};

} // namespace Agents
} // namespace RawrXD
