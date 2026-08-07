// task_runner.hpp — Task Automation Core
// VS Code tasks.json equivalent — build, test, benchmark, deploy pipelines
// Pure C++20 / Win32 — Zero Qt Dependencies
#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <atomic>
#include <filesystem>
#include <optional>
#include <chrono>

namespace RawrXD {
namespace Tasks {

// ============================================================================
// Task Types
// ============================================================================
enum class TaskType {
    Shell,
    Process,
    Build,
    Test,
    Benchmark,
    Deploy,
    Custom
};

// ============================================================================
// Task Run Options
// ============================================================================
struct TaskOptions {
    std::string cwd;
    std::map<std::string, std::string> env;
    int timeoutMs = 0;        // 0 = no timeout
    bool shell = true;        // Run via shell
    bool background = false;  // Run in background
    std::string group;        // "build", "test", "none"
    bool isDefault = false;   // Default build/test task
    std::vector<std::string> dependsOn;  // Task dependencies
};

// ============================================================================
// Problem Matcher
// ============================================================================
struct ProblemMatcher {
    std::string name;
    std::string filePattern;     // Regex for file path
    std::string linePattern;     // Regex for line number
    std::string columnPattern;   // Regex for column number
    std::string severityPattern; // Regex for severity (error/warning)
    std::string messagePattern;  // Regex for error message
    bool applyToAll = false;     // Apply to all output lines
    std::string owner;           // "cpp", "typescript", etc.
};

// ============================================================================
// Task Definition
// ============================================================================
struct TaskDefinition {
    std::string label;
    TaskType type = TaskType::Shell;
    std::string command;
    std::vector<std::string> args;
    TaskOptions options;
    std::vector<ProblemMatcher> problemMatchers;
    std::string detail;
    std::string presentation;  // "reveal", "echo", "focus", "panel"
};

// ============================================================================
// Task State
// ============================================================================
enum class TaskState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Skipped
};

// ============================================================================
// Task Result
// ============================================================================
struct TaskResult {
    std::string taskId;
    TaskState state = TaskState::Pending;
    int exitCode = -1;
    std::string output;
    std::string errorOutput;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    std::vector<std::string> matchedProblems;
    std::vector<std::string> warnings;
};

// ============================================================================
// Task Instance
// ============================================================================
class TaskInstance {
public:
    TaskInstance(const TaskDefinition& def, const std::string& id);
    ~TaskInstance();

    const std::string& GetId() const { return m_id; }
    const TaskDefinition& GetDefinition() const { return m_definition; }
    TaskState GetState() const { return m_state; }
    const TaskResult& GetResult() const { return m_result; }

    bool Run();
    void Cancel();
    bool IsRunning() const { return m_state == TaskState::Running; }

    // Output callbacks
    using OutputCallback = std::function<void(const std::string& line)>;
    void SetOutputCallback(OutputCallback callback) { m_outputCallback = callback; }
    void SetErrorCallback(OutputCallback callback) { m_errorCallback = callback; }

private:
    void ExecuteShell();
    void ExecuteProcess();
    void ApplyProblemMatchers(const std::string& output);

    std::string m_id;
    TaskDefinition m_definition;
    TaskState m_state = TaskState::Pending;
    TaskResult m_result;
    std::atomic<bool> m_cancelled{false};
    void* m_processHandle = nullptr;
    OutputCallback m_outputCallback;
    OutputCallback m_errorCallback;
    std::mutex m_mutex;
};

// ============================================================================
// Task Runner
// ============================================================================
class TaskRunner {
public:
    TaskRunner();
    ~TaskRunner();

    // Initialize
    bool Initialize();

    // Shutdown
    void Shutdown();

    // Register a task definition
    void RegisterTask(const TaskDefinition& task);

    // Register multiple tasks from a JSON file
    bool LoadTasksFile(const std::filesystem::path& path);

    // Save tasks to JSON file
    bool SaveTasksFile(const std::filesystem::path& path) const;

    // Run a task by label
    TaskResult* RunTask(const std::string& label);

    // Run a task with dependencies
    TaskResult* RunTaskWithDeps(const std::string& label);

    // Run the default build task
    TaskResult* RunDefaultBuildTask();

    // Run the default test task
    TaskResult* RunDefaultTestTask();

    // Cancel a running task
    bool CancelTask(const std::string& taskId);

    // Cancel all running tasks
    void CancelAll();

    // Get task result
    TaskResult* GetResult(const std::string& taskId);

    // Get all task results
    std::vector<TaskResult*> GetAllResults() const;

    // Get registered tasks
    std::vector<TaskDefinition> GetRegisteredTasks() const;

    // Get task by label
    TaskDefinition* GetTask(const std::string& label);

    // Check if any task is running
    bool IsAnyRunning() const;

    // Get running task count
    size_t GetRunningCount() const { return m_runningCount.load(); }

    // Events
    using TaskEventCallback = std::function<void(const std::string& taskId, TaskState state)>;
    void OnTaskStarted(TaskEventCallback callback) { m_onStarted = callback; }
    void OnTaskCompleted(TaskEventCallback callback) { m_onCompleted = callback; }
    void OnTaskFailed(TaskEventCallback callback) { m_onFailed = callback; }

private:
    std::string GenerateTaskId();
    void ExecuteTaskDependencies(const std::string& label);

    std::map<std::string, TaskDefinition> m_tasks;
    std::map<std::string, std::unique_ptr<TaskInstance>> m_runningTasks;
    std::map<std::string, TaskResult> m_results;
    std::atomic<size_t> m_runningCount{0};
    std::atomic<uint64_t> m_taskCounter{0};

    TaskEventCallback m_onStarted;
    TaskEventCallback m_onCompleted;
    TaskEventCallback m_onFailed;

    mutable std::mutex m_mutex;
    bool m_initialized = false;
};

} // namespace Tasks
} // namespace RawrXD
