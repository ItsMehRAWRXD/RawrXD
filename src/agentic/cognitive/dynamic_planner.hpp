/**
 * @file dynamic_planner.hpp
 * @brief Priority-based task scheduler with capability matching
 * @description The Dynamic Planner maintains a priority queue of tasks, matches
 *              them to agents based on capabilities, and handles replanning
 *              when tasks fail or new information arrives.
 * @version 1.0.0
 * @date 2026-07-22
 */

#pragma once

#include "cognitive_types.hpp"
#include "enhanced_blackboard.hpp"
#include <queue>
#include <condition_variable>
#include <memory>
#include <shared_mutex>
#include <optional>
#include <string>

namespace rawrxd::cognitive {

// ============================================================================
// Capability Registry
// ============================================================================

class CapabilityRegistry {
public:
    void RegisterCapability(const Capability& cap);
    void UnregisterCapability(const std::string& name);
    std::optional<Capability> GetCapability(const std::string& name) const;
    std::vector<Capability> GetAllCapabilities() const;
    std::vector<std::string> FindAgentsForCapability(const std::string& capability_name) const;
    void RegisterAgentCapability(const std::string& agent_name, const std::string& capability_name);
    void UnregisterAgent(const std::string& agent_name);
    
private:
    std::unordered_map<std::string, Capability> m_capabilities;
    std::unordered_map<std::string, std::vector<std::string>> m_agent_capabilities; // agent -> capabilities
    std::unordered_map<std::string, std::vector<std::string>> m_capability_agents; // capability -> agents
    mutable std::shared_mutex m_mutex;
};

// ============================================================================
// Execution Result
// ============================================================================

struct ExecutionResult {
    bool success{false};
    std::string task_id;
    std::string agent_name;
    std::unordered_map<std::string, float> outputs;
    std::string error_message;
    std::chrono::milliseconds execution_time{0};
    std::vector<std::string> evidence_produced;
};

// ============================================================================
// Task Executor Interface
// ============================================================================

class ITaskExecutor {
public:
    virtual ~ITaskExecutor() = default;
    virtual bool CanExecute(const Task& task) const = 0;
    virtual ExecutionResult Execute(const Task& task) = 0;
    virtual std::vector<std::string> GetCapabilities() const = 0;
};

// ============================================================================
// Dynamic Planner
// ============================================================================

class DynamicPlanner {
public:
    explicit DynamicPlanner(EnhancedBlackboard* blackboard);
    ~DynamicPlanner();
    
    // Prevent copy/move
    DynamicPlanner(const DynamicPlanner&) = delete;
    DynamicPlanner& operator=(const DynamicPlanner&) = delete;
    DynamicPlanner(DynamicPlanner&&) = delete;
    DynamicPlanner& operator=(DynamicPlanner&&) = delete;
    
    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    void Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }
    
    // ------------------------------------------------------------------------
    // Mission Scheduling
    // ------------------------------------------------------------------------
    void ScheduleMission(const std::vector<SubGoal>& subgoals);
    void ScheduleTask(Task&& task);
    void ScheduleTasks(const std::vector<Task>& tasks);
    
    // ------------------------------------------------------------------------
    // Task Execution
    // ------------------------------------------------------------------------
    std::optional<Task> GetNextRunnableTask();
    void SubmitResult(const ExecutionResult& result);
    void CancelTask(const std::string& task_id);
    void CancelAllTasks();
    
    // ------------------------------------------------------------------------
    // Replanning
    // ------------------------------------------------------------------------
    void Replan(const std::vector<SubGoal>& updated_subgoals);
    void InjectTasks(const std::vector<Task>& new_tasks, const std::string& after_task_id);
    void BoostPriority(const std::string& task_id, int boost);
    void PenalizePriority(const std::string& task_id, int penalty);
    
    // ------------------------------------------------------------------------
    // Agent Management
    // ------------------------------------------------------------------------
    void RegisterExecutor(const std::string& name, std::shared_ptr<ITaskExecutor> executor);
    void UnregisterExecutor(const std::string& name);
    std::vector<std::string> FindCapableExecutors(const Task& task) const;
    std::optional<std::string> SelectBestExecutor(const Task& task) const;
    
    // ------------------------------------------------------------------------
    // Status
    // ------------------------------------------------------------------------
    bool HasPendingTasks() const;
    bool HasRunnableTasks();
    size_t PendingTaskCount() const;
    size_t ActiveTaskCount() const;
    size_t CompletedTaskCount() const;
    size_t FailedTaskCount() const;
    float MissionProgress() const;
    
    // ------------------------------------------------------------------------
    // Utility
    // ------------------------------------------------------------------------
    std::vector<Task> GetTaskQueueSnapshot() const;
    std::string GenerateScheduleReport() const;
    void WaitForCompletion(); // Blocks until all tasks complete
    
private:
    EnhancedBlackboard* m_blackboard;
    std::unique_ptr<CapabilityRegistry> m_capability_registry;
    
    // Task storage
    std::priority_queue<Task> m_task_queue;
    std::unordered_map<std::string, Task> m_active_tasks;
    std::unordered_map<std::string, Task> m_completed_tasks;
    std::unordered_map<std::string, Task> m_failed_tasks;
    std::unordered_set<std::string> m_cancelled_tasks;
    
    // Executors
    std::unordered_map<std::string, std::shared_ptr<ITaskExecutor>> m_executors;
    
    // Synchronization
    mutable std::shared_mutex m_mutex;
    std::condition_variable_any m_task_available;
    std::atomic<bool> m_running{false};
    std::thread m_scheduler_thread;
    
    // Configuration
    size_t m_max_concurrent_tasks{4};
    std::chrono::seconds m_task_timeout{300};
    
    // Scheduler loop
    void SchedulerLoop();
    
    // Helper methods
    bool AreDependenciesMet(const Task& task) const;
    bool IsTaskExpired(const Task& task) const;
    void PruneExpiredTasks();
    void RecalculateAllPriorities();
    int ComputeTaskPriority(const Task& task) const;
    void RebuildQueue();
    std::vector<Task> DrainQueue();
};

} // namespace rawrxd::cognitive
