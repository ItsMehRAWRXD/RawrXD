// ============================================================================
// ProjectState.hpp — Persistent Project State Management
// Tracks goals, tasks, and progress across sessions
// ============================================================================
#pragma once

#include "CEOAgentTypes.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <mutex>

namespace RawrXD {
namespace CEO {

using json = nlohmann::json;

// ============================================================================
// Project State
// ============================================================================
class ProjectState {
public:
    ProjectState();
    ~ProjectState();
    ProjectState(const ProjectState&) = delete;
    ProjectState& operator=(const ProjectState&) = delete;
    ProjectState(ProjectState&&) = default;
    ProjectState& operator=(ProjectState&&) = default;
    
    // Initialization
    bool Initialize(const std::string& storagePath);
    void Shutdown();
    
    // Goal Management
    void SetCurrentGoal(const Goal& goal);
    Goal GetCurrentGoal() const;
    void AddGoal(const Goal& goal);
    void UpdateGoal(const Goal& goal);
    std::vector<Goal> GetAllGoals() const;
    std::vector<Goal> GetCompletedGoals() const;
    std::vector<Goal> GetPendingGoals() const;
    
    // Task Tracking
    void AddTask(const Task& task);
    void UpdateTask(const Task& task);
    Task GetTask(const std::string& taskId) const;
    std::vector<Task> GetAllTasks() const;
    std::vector<Task> GetCompletedTasks() const;
    std::vector<Task> GetFailedTasks() const;
    std::vector<Task> GetPendingTasks() const;
    
    // Statistics
    int GetCompletedTaskCount() const;
    int GetFailedTaskCount() const;
    int GetTotalTaskCount() const;
    
    // Memory
    void AddMemory(const std::string& key, const json& value);
    json GetMemory(const std::string& key) const;
    void ClearMemory();
    
    // Persistence
    bool SaveToFile(const std::string& path);
    bool LoadFromFile(const std::string& path);
    bool AutoSave();
    
    // Export
    json ToJSON() const;
    bool FromJSON(const json& data);
    
private:
    std::string m_storagePath;
    mutable std::mutex m_mutex;
    
    Goal m_currentGoal;
    std::vector<Goal> m_goals;
    std::vector<Task> m_tasks;
    std::map<std::string, json> m_memory;
    
    bool m_initialized = false;
};

} // namespace CEO
} // namespace RawrXD
