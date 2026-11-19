#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <chrono>

namespace RawrXD {

// TaskOrchestrator — coordinates autonomous task execution
// Native implementation (no Qt dependencies)
class TaskOrchestrator {
public:
    using TaskCallback = std::function<void()>;
    using TaskResult = std::string;

    explicit TaskOrchestrator() = default;
    ~TaskOrchestrator() = default;

    // Register a task for execution
    void registerTask(const std::string& name, TaskCallback callback);

    // Execute all registered tasks
    bool executeAll();

    // Execute a specific task by name
    bool executeTask(const std::string& name);

    // Get task status
    const std::string& getTaskStatus(const std::string& name) const;

    // Get all task names
    std::vector<std::string> getTaskNames() const;

    // Clear all tasks
    void clearTasks();

private:
    struct TaskEntry {
        std::string name;
        TaskCallback callback;
        std::string status;  // "pending", "completed", "failed"
        std::string result;
        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point endTime;
    };

    std::vector<TaskEntry> m_tasks;
    mutable std::mutex m_mutex;
};

} // namespace RawrXD