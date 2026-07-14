#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>
#include <thread>
#include <process.h>

namespace RawrXD {
namespace Tasks {

// Task execution status
enum class TaskStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled
};

// Problem matcher for parsing build output
struct ProblemMatcher {
    std::string name;
    std::string regexp;
    int fileGroup = 1;
    int lineGroup = 2;
    int columnGroup = 3;
    int severityGroup = 4;
    int codeGroup = 5;
    int messageGroup = 6;
    std::string pattern;
};

// Task definition
struct TaskDefinition {
    std::string label;
    std::string type;           // "shell" or "process"
    std::string command;
    std::vector<std::string> args;
    std::vector<std::string> dependsOn;
    std::map<std::string, std::string> env;
    std::string cwd;
    bool isBackground = false;
    std::vector<ProblemMatcher> problemMatchers;
    std::string group;          // "build", "test", "none"
    std::string presentationOptions;
};

// Task execution result
struct TaskResult {
    int exitCode = 0;
    std::string stdout;
    std::string stderr;
    std::vector<std::string> problems;
    TaskStatus status = TaskStatus::Pending;
};

// Running task instance
struct RunningTask {
    std::string id;
    TaskDefinition definition;
    TaskResult result;
    HANDLE processHandle = nullptr;
    HANDLE threadHandle = nullptr;
    std::thread outputReader;
    bool cancelled = false;
    std::chrono::steady_clock::time_point startTime;
};

// Task runner - executes tasks.json tasks
class TaskRunner {
public:
    static TaskRunner& Instance();
    
    // Lifecycle
    bool Initialize();
    bool Shutdown();
    
    // Task configuration
    bool LoadTasksConfiguration(const std::string& path);
    bool SaveTasksConfiguration(const std::string& path);
    
    // Task management
    std::vector<TaskDefinition> GetAvailableTasks() const;
    TaskDefinition* GetTask(const std::string& label);
    bool AddTask(const TaskDefinition& task);
    bool RemoveTask(const std::string& label);
    
    // Task execution
    std::string RunTask(const std::string& label);
    std::string RunTask(const TaskDefinition& task);
    bool CancelTask(const std::string& taskId);
    
    // Task queries
    std::vector<RunningTask> GetRunningTasks() const;
    RunningTask* GetRunningTask(const std::string& taskId);
    TaskResult GetTaskResult(const std::string& taskId);
    
    // Build tasks
    std::string RunBuildTask();
    std::string RunTestTask();
    
    // Problem matchers
    void RegisterProblemMatcher(const ProblemMatcher& matcher);
    std::vector<ProblemMatcher> GetProblemMatchers() const;
    
    // Events
    using TaskEventCallback = std::function<void(const std::string& taskId, TaskStatus status)>;
    void SetTaskEventCallback(TaskEventCallback callback) { taskEventCallback_ = callback; }
    
    using OutputCallback = std::function<void(const std::string& taskId, const std::string& output)>;
    void SetOutputCallback(OutputCallback callback) { outputCallback_ = callback; }
    
private:
    TaskRunner() = default;
    ~TaskRunner() = default;
    
    std::vector<TaskDefinition> tasks_;
    std::map<std::string, std::unique_ptr<RunningTask>> runningTasks_;
    std::vector<ProblemMatcher> problemMatchers_;
    
    mutable std::mutex mutex_;
    TaskEventCallback taskEventCallback_;
    OutputCallback outputCallback_;
    
    void ExecuteTask(RunningTask* task);
    void ReadOutput(RunningTask* task, HANDLE hRead);
    void ParseProblems(RunningTask* task);
    std::string GenerateTaskId();
    void CleanupTask(const std::string& taskId);
};

} // namespace Tasks
} // namespace RawrXD