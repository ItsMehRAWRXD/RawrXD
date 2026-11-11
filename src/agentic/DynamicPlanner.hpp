// ============================================================================
// DynamicPlanner.hpp - Priority-based scheduling with replanning
// Part of RawrXD Cognitive Foundation (Phase 1)
// ============================================================================
#pragma once
#include "CognitiveBlackboard.hpp"
#include "SubGoal.hpp"
#include <queue>
#include <functional>
#include <unordered_set>
#include <future>

namespace rawrxd::agentic {

// Forward declarations
class ToolRegistry;
class AgentPool;

// Task execution result
struct TaskResult {
    std::string task_id;
    bool success{false};
    float confidence{0.0f};
    std::string summary;
    std::vector<std::string> produced_evidence;
    std::chrono::milliseconds execution_time{0};
    std::string error_message;
};

// Task execution callback
typedef std::function<void(const TaskResult&)> TaskCompletionCallback;

// Scheduled task with execution context
struct ScheduledTask {
    SubGoal subgoal;
    std::vector<std::string> dependencies;
    int priority{50};                    // Higher = more urgent
    std::chrono::system_clock::time_point scheduled_time;
    std::chrono::system_clock::time_point deadline;
    TaskCompletionCallback on_complete;
    int retry_count{0};
    int max_retries{3};
    
    // For priority queue (higher priority first)
    bool operator<(const ScheduledTask& other) const {
        return priority < other.priority;
    }
};

// Execution statistics
struct ExecutionStats {
    int total_tasks{0};
    int completed_tasks{0};
    int failed_tasks{0};
    int retried_tasks{0};
    int cancelled_tasks{0};
    std::chrono::milliseconds total_execution_time{0};
    std::chrono::milliseconds average_task_time{0};
    float success_rate{0.0f};
    int current_parallel_tasks{0};
    int max_parallel_tasks{4};
};

// Planner configuration
struct PlannerConfig {
    int max_parallel_tasks{4};
    bool enable_priority_boost{true};
    bool enable_deadline_checking{true};
    std::chrono::seconds default_timeout{std::chrono::seconds(300)};
    float priority_boost_factor{1.5f};  // Multiply priority for critical path
    int priority_decay_interval{60};     // Decay priority every N seconds
    bool enable_speculative_execution{false}; // Execute likely paths early
};

// Dynamic Planner - Priority-based scheduling with replanning
class DynamicPlanner {
public:
    DynamicPlanner(CognitiveBlackboard* bb, 
                  ToolRegistry* registry = nullptr,
                  AgentPool* agent_pool = nullptr);
    ~DynamicPlanner();
    
    // Delete copy/move
    DynamicPlanner(const DynamicPlanner&) = delete;
    DynamicPlanner& operator=(const DynamicPlanner&) = delete;
    
    // ==================== Mission Scheduling ====================
    
    // Schedule a complete mission
    void ScheduleMission(const std::vector<SubGoal>& subgoals);
    
    // Schedule individual task
    void ScheduleTask(const SubGoal& subgoal, 
                     TaskCompletionCallback callback = nullptr);
    
    // Schedule multiple tasks
    void ScheduleTasks(const std::vector<SubGoal>& subgoals,
                      TaskCompletionCallback callback = nullptr);
    
    // ==================== Execution Control ====================
    
    // Start execution
    void Start();
    void Stop();
    void Pause();
    void Resume();
    bool IsRunning() const { return m_running.load(); }
    bool IsPaused() const { return m_paused.load(); }
    
    // Get next runnable task (non-blocking)
    std::optional<ScheduledTask> GetNextTask();
    
    // Wait for next task (blocking)
    std::optional<ScheduledTask> WaitForNextTask(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));
    
    // ==================== Task Completion ====================
    
    // Notify planner of task completion
    void OnTaskComplete(const std::string& task_id,
                       bool success,
                       float confidence,
                       const std::string& summary);
    
    // Notify planner of task failure
    void OnTaskFailure(const std::string& task_id, 
                      const std::string& reason,
                      bool retryable = true);
    
    // ==================== Replanning ====================
    
    // Replace current plan with new plan
    void Replan(const std::vector<SubGoal>& updated_plan);
    
    // Cancel specific task
    void CancelTask(const std::string& task_id);
    
    // Cancel all tasks
    void CancelAllTasks();
    
    // Cancel tasks dependent on failed task
    void CancelDependentTasks(const std::string& failed_task_id);
    
    // ==================== Priority Management ====================
    
    // Boost priority of critical path tasks
    void BoostCriticalPath(const std::vector<std::string>& critical_task_ids);
    
    // Increase priority of specific task
    void IncreasePriority(const std::string& task_id, int boost);
    
    // Decrease priority of specific task
    void DecreasePriority(const std::string& task_id, int penalty);
    
    // Apply priority decay over time
    void ApplyPriorityDecay();
    
    // ==================== Status Queries ====================
    
    bool HasPendingTasks() const;
    bool HasRunnableTasks() const;
    size_t PendingTaskCount() const;
    size_t RunnableTaskCount() const;
    size_t ActiveTaskCount() const;
    size_t CompletedTaskCount() const;
    size_t FailedTaskCount() const;
    
    // Mission progress
    float MissionProgress() const;
    std::vector<std::string> GetCompletedTaskIds() const;
    std::vector<std::string> GetFailedTaskIds() const;
    std::vector<std::string> GetPendingTaskIds() const;
    
    // ==================== Configuration ====================
    
    void SetConfig(const PlannerConfig& config);
    PlannerConfig GetConfig() const;
    
    // ==================== Statistics ====================
    
    ExecutionStats GetStats() const;
    void ResetStats();
    
    // Get execution timeline
    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> 
        GetExecutionTimeline() const;
    
private:
    CognitiveBlackboard* m_blackboard;
    ToolRegistry* m_tool_registry;
    AgentPool* m_agent_pool;
    
    // Task storage
    std::priority_queue<ScheduledTask> m_task_queue;
    std::unordered_map<std::string, ScheduledTask> m_active_tasks;
    std::unordered_set<std::string> m_completed_tasks;
    std::unordered_set<std::string> m_failed_tasks;
    std::unordered_set<std::string> m_cancelled_tasks;
    
    // Synchronization
    mutable std::mutex m_queue_mutex;
    mutable std::mutex m_state_mutex;
    std::condition_variable m_task_available;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_paused{false};
    
    // Configuration
    PlannerConfig m_config;
    
    // Statistics
    ExecutionStats m_stats;
    std::chrono::steady_clock::time_point m_start_time;
    std::vector<std::pair<std::string, std::chrono::system_clock::time_point>> m_timeline;
    
    // Helper methods
    bool AreDependenciesMet(const ScheduledTask& task);
    bool IsTaskRunnable(const ScheduledTask& task);
    bool HasCapability(const std::string& capability);
    void PruneStaleTasks();
    void RecalculatePriorities();
    void UpdateStats(const TaskResult& result);
    void CleanupCompletedTasks();
    std::vector<std::string> GetDependentTasks(const std::string& task_id);
};

} // namespace rawrxd::agentic
