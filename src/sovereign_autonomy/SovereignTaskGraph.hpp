/**
 * @file SovereignTaskGraph.hpp
 * @brief DAG-based task scheduler for sovereign agent missions
 *
 * Supports dependency chains, parallel execution, priority scheduling,
 * retry with backoff, and checkpoint/restore.
 */

#pragma once

#include <string>
#include <map>
#include <vector>
#include <set>
#include <mutex>
#include <chrono>
#include <functional>
#include <optional>
#include <any>

namespace RawrXD::Autonomy {

enum class TaskState {
    Pending,      // Waiting for dependencies
    Ready,        // Dependencies satisfied, ready to execute
    Running,      // Currently executing
    Completed,    // Success
    Failed,       // Permanent failure
    Cancelled,    // Aborted by user/system
    Retrying      // Backoff retry in progress
};

struct TaskNode {
    std::string id;
    std::string description;
    std::string agent_id;       // Assigned agent (empty = unassigned)
    std::string tool_name;      // Tool to invoke
    std::map<std::string, std::any> parameters;

    TaskState state = TaskState::Pending;
    int priority = 0;           // Higher = sooner
    int retry_count = 0;
    int max_retries = 3;
    std::chrono::milliseconds retry_delay{1000};

    std::vector<std::string> dependencies;   // Task IDs that must complete first
    std::vector<std::string> dependents;     // Tasks that depend on this one

    std::any result;
    std::string error_message;

    std::chrono::steady_clock::time_point created_at;
    std::optional<std::chrono::steady_clock::time_point> started_at;
    std::optional<std::chrono::steady_clock::time_point> completed_at;
    std::optional<std::chrono::milliseconds> duration_ms;
};

class SovereignTaskGraph {
public:
    using TaskCallback = std::function<void(const TaskNode& task)>;
    using ExecuteCallback = std::function<bool(const TaskNode& task, std::any& out_result)>;

    SovereignTaskGraph() = default;
    ~SovereignTaskGraph() = default;

    // Task lifecycle
    std::string AddTask(const std::string& description,
                        const std::string& tool_name,
                        const std::map<std::string, std::any>& params,
                        int priority = 0,
                        const std::vector<std::string>& deps = {});

    bool RemoveTask(const std::string& task_id);
    bool SetTaskAgent(const std::string& task_id, const std::string& agent_id);

    // Dependency management
    bool AddDependency(const std::string& task_id, const std::string& dep_id);
    bool RemoveDependency(const std::string& task_id, const std::string& dep_id);
    bool HasCircularDependency(const std::string& task_id) const;

    // Execution
    std::vector<std::string> GetReadyTasks() const;
    std::vector<std::string> GetRunningTasks() const;
    std::vector<std::string> GetPendingTasks() const;
    std::vector<std::string> GetFailedTasks() const;

    bool MarkRunning(const std::string& task_id);
    bool MarkCompleted(const std::string& task_id, const std::any& result);
    bool MarkFailed(const std::string& task_id, const std::string& error);
    bool MarkCancelled(const std::string& task_id);
    bool MarkRetrying(const std::string& task_id);

    // Bulk execution
    bool ExecuteReadyTasks(ExecuteCallback executor, TaskCallback on_complete, TaskCallback on_fail);
    bool ExecuteAll(ExecuteCallback executor, TaskCallback on_complete, TaskCallback on_fail);

    // State queries
    TaskState GetTaskState(const std::string& task_id) const;
    std::optional<TaskNode> GetTask(const std::string& task_id) const;
    std::vector<TaskNode> GetAllTasks() const;   // All tasks for reflection/audit
    bool IsComplete() const;           // All tasks done (success or fail)
    bool IsSuccessful() const;         // All tasks completed successfully
    float ProgressPercent() const;
    size_t TaskCount() const;
    size_t CompletedCount() const;
    size_t FailedCount() const;

    // Critical path
    std::vector<std::string> GetCriticalPath() const;
    std::chrono::milliseconds EstimatedRemainingTime() const;

    // Checkpoint / restore
    std::string Serialize() const;
    bool Deserialize(const std::string& data);
    void Clear();

    // Event subscriptions
    void OnTaskStateChange(TaskCallback cb) { on_state_change_ = std::move(cb); }

private:
    mutable std::mutex mutex_;
    std::map<std::string, TaskNode> tasks_;
    TaskCallback on_state_change_;

    void UpdateReadyState();
    bool WouldCreateCycle(const std::string& from, const std::string& to,
                          std::set<std::string>& visited) const;
    void NotifyDependents(const std::string& task_id);
};

} // namespace RawrXD::Autonomy
