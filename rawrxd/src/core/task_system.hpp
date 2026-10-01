// task_system.hpp - Task Runner and Build System
// Author: RAW RXD IDE Team
// License: MIT

#ifndef TASK_SYSTEM_HPP
#define TASK_SYSTEM_HPP

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <memory>
#include <queue>
#include <chrono>
#include <optional>

// RAWRXD_TASK_CONFIG_001: loadConfig/saveConfig are real JSON now, so the header
// needs a JSON parser and file streams. nlohmann::json is already vendored in
// 3rdparty and already used across the tree (core/settings_persistence.cpp,
// core/workspace_model.cpp).
#include <fstream>
#include <cstdio>
#include <nlohmann/json.hpp>
#include <variant>
#include <regex>

namespace rawrxd {

// ═══════════════════════════════════════════════════════════════════════
// TASK TYPES
// ═══════════════════════════════════════════════════════════════════════

enum class TaskType {
    Shell,
    Process,
    Build,
    Test,
    Run,
    Custom
};

enum class TaskStatus {
    Pending,
    Running,
    Success,
    Failed,
    Cancelled,
    Skipped
};

enum class TaskGroupKind {
    Build,
    Test,
    Run,
    Clean,
    Default
};

struct TaskDependency {
    std::string task_id;
    bool required = true;
};

struct TaskProblem {
    std::string file;
    int line;
    int column;
    std::string message;
    std::string severity;  // error, warning, info
    std::string code;
    std::string source;
};

struct TaskOutput {
    std::string text;
    std::string stream;  // stdout, stderr
    bool is_error = false;
    std::chrono::steady_clock::time_point timestamp;
};

struct TaskResult {
    std::string task_id;
    TaskStatus status;
    int exit_code;
    std::string output;
    std::vector<TaskProblem> problems;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::chrono::milliseconds duration;
};

struct TaskDefinition {
    std::string label;
    std::string task_id;
    TaskType type = TaskType::Shell;
    std::string command;
    std::vector<std::string> args;
    std::map<std::string, std::string> env;
    std::string cwd;
    std::string shell;
    std::vector<TaskDependency> depends_on;
    std::vector<std::string> problem_matcher;
    std::string group;
    std::string presentation;
    std::string detail;
    bool is_background = false;
    bool show_output = true;
    bool close_on_exit = true;
    bool prompt_on_close = false;
    int timeout_ms = 0;  // 0 = no timeout
    std::map<std::string, std::string> options;
};

struct TaskConfig {
    std::string version = "2.0.0";
    std::vector<TaskDefinition> tasks;
    std::map<std::string, std::string> variables;
    std::map<std::string, std::string> inputs;
    std::map<std::string, std::string> outputs;
};

struct ProblemMatcher {
    std::string name;
    std::string owner;
    std::string file_location;
    std::vector<std::string> patterns;
    std::regex pattern_regex;
    bool apply_to_all = false;
};

struct TaskGroup {
    std::string id;
    std::string label;
    TaskGroupKind kind;
    std::vector<std::string> task_ids;
    bool is_default = false;
    bool runs_in_parallel = false;
};

// ═══════════════════════════════════════════════════════════════════════
// RAWRXD_TASK_CONFIG_001
//
// The measured outcome of loading a task configuration. Declared before
// TaskRunner because loadConfigWithResult() returns it.
//
// A bare bool or void cannot distinguish "loaded zero tasks because the file was
// absent" from "loaded zero tasks because the file was malformed", and those
// demand opposite responses from a caller.
// ═══════════════════════════════════════════════════════════════════════

struct TaskConfigLoadResult {
    bool        loadCalled = false;
    bool        fileExisted = false;
    bool        parsed = false;
    bool        refused = false;          // present but not adopted
    std::size_t tasksParsed = 0;
    std::size_t tasksAdopted = 0;
    std::size_t tasksSkipped = 0;
    std::size_t entriesRejected = 0;     // malformed entries, counted not silent
    std::string version;
    std::string lastError;
};

// ═══════════════════════════════════════════════════════════════════════
// RAWRXD_TASK_CONFIG_001 -- free functions for the product path
//
// Declared here rather than in task_config_bridge.cpp so main_win32.cpp needs one
// include instead of two. They exist so a caller can operate on a TaskRunner it
// already owns. They deliberately do not own a runner: handing the IDE a second,
// private TaskRunner would create a second task registry, which is the same class
// of mistake already made and undone once in the git-safety integration.
//
// Forward declared because the definitions follow the class below.
// ═══════════════════════════════════════════════════════════════════════

class TaskRunner;

TaskConfigLoadResult LoadTaskConfigFor(TaskRunner& runner, const std::string& path);
void                    SaveTaskConfigFor(TaskRunner& runner, const std::string& path);
std::size_t             TaskConfigTaskCount(const TaskRunner& runner);
std::vector<std::string> TaskConfigTaskLabels(const TaskRunner& runner);

// ═══════════════════════════════════════════════════════════════════════
// TASK RUNNER
// ═══════════════════════════════════════════════════════════════════════

class TaskRunner {
public:
    TaskRunner();
    ~TaskRunner();

    // Task Management
    std::string addTask(const TaskDefinition& task);
    bool removeTask(const std::string& task_id);
    bool hasTask(const std::string& task_id) const;
    TaskDefinition getTask(const std::string& task_id) const;
    std::vector<TaskDefinition> getAllTasks() const;
    
    // Task Execution
    TaskResult runTask(const std::string& task_id);
    TaskResult runTask(const TaskDefinition& task);
    void runTaskAsync(const std::string& task_id,
                     std::function<void(const TaskResult&)> callback = nullptr);
    void runTaskAsync(const TaskDefinition& task,
                     std::function<void(const TaskResult&)> callback = nullptr);
    
    // Task Groups
    void runGroup(const std::string& group_id,
                 std::function<void(const std::vector<TaskResult>&)> callback = nullptr);
    
    // Build Operations
    TaskResult build();
    TaskResult rebuild();
    TaskResult clean();
    TaskResult test();
    
    // Control
    void cancel(const std::string& task_id);
    void cancelAll();
    bool isRunning(const std::string& task_id) const;
    bool isAnyRunning() const;
    
    // Configuration
    // RAWRXD_TASK_CONFIG_001: config load/save. loadConfig keeps its original
    // void signature; loadConfigWithResult returns the measured outcome so an
    // absent file and a malformed one cannot look alike to a caller.
    void loadConfig(const std::string& config_path);
    void saveConfig(const std::string& config_path);
    TaskConfigLoadResult loadConfigWithResult(const std::string& config_path);
    void setConfig(const TaskConfig& config) { config_ = config; }
    TaskConfig getConfig() const { return config_; }
    
    // Problem Matchers
    void addProblemMatcher(const ProblemMatcher& matcher);
    void removeProblemMatcher(const std::string& name);
    ProblemMatcher getProblemMatcher(const std::string& name) const;
    
    // Events
    void onTaskStart(std::function<void(const std::string&)> callback);
    void onTaskOutput(std::function<void(const std::string&, const TaskOutput&)> callback);
    void onTaskEnd(std::function<void(const std::string&, const TaskResult&)> callback);
    void onProblem(std::function<void(const TaskProblem&)> callback);

private:
    TaskConfig config_;
    std::map<std::string, TaskDefinition> tasks_;
    std::map<std::string, ProblemMatcher> problem_matchers_;
    std::map<std::string, TaskGroup> groups_;
    
    std::map<std::string, TaskStatus> task_status_;
    std::map<std::string, HANDLE> task_handles_;
    std::map<std::string, std::thread> task_threads_;
    
    std::atomic<bool> running_{false};
    std::mutex tasks_mutex_;
    std::mutex callbacks_mutex_;
    
    std::vector<std::function<void(const std::string&)>> start_callbacks_;
    std::vector<std::function<void(const std::string&, const TaskOutput&)>> output_callbacks_;
    std::vector<std::function<void(const std::string&, const TaskResult&)>> end_callbacks_;
    std::vector<std::function<void(const TaskProblem&)>> problem_callbacks_;
    
    // Internal helpers
    TaskResult executeTask(const TaskDefinition& task);
    std::vector<TaskProblem> parseOutput(const std::string& output,
                                         const std::vector<std::string>& matchers);
    std::vector<TaskProblem> matchProblems(const std::string& output,
                                           const ProblemMatcher& matcher);
    bool resolveDependencies(const std::string& task_id,
                            std::set<std::string>& visited,
                            std::vector<std::string>& order);
    std::string expandVariables(const std::string& input);
    std::string generateTaskId();
    
    // Process management
    HANDLE createProcess(const TaskDefinition& task,
                        HANDLE* out_read, HANDLE* err_read, HANDLE* in_write);
    bool readProcessOutput(HANDLE hProcess, HANDLE out_read, HANDLE err_read,
                          std::string& output, std::string& error);
    void terminateProcess(HANDLE hProcess);
};

// ═══════════════════════════════════════════════════════════════════════
// BUILD SYSTEM
// ═══════════════════════════════════════════════════════════════════════

class BuildSystem {
public:
    BuildSystem();
    ~BuildSystem();
    
    // Build Configuration
    bool loadBuildFile(const std::string& path);
    bool detectBuildSystem(const std::string& workspace_root);
    
    // Build Operations
    TaskResult configure();
    TaskResult build(const std::string& target = "");
    TaskResult rebuild(const std::string& target = "");
    TaskResult clean();
    TaskResult install();
    
    // CMake Support
    TaskResult cmakeConfigure(const std::string& build_type = "Release",
                              const std::string& generator = "");
    TaskResult cmakeBuild(const std::string& target = "");
    TaskResult cmakeClean();
    TaskResult cmakeInstall();
    
    // Make Support
    TaskResult makeBuild(const std::string& target = "");
    TaskResult makeClean();
    
    // MSBuild Support
    TaskResult msbuildBuild(const std::string& project = "",
                           const std::string& config = "Release");
    TaskResult msbuildClean(const std::string& project = "",
                           const std::string& config = "Release");
    
    // Ninja Support
    TaskResult ninjaBuild(const std::string& target = "");
    TaskResult ninjaClean();
    
    // Build Info
    std::vector<std::string> getTargets();
    std::string getBuildType() const { return build_type_; }
    void setBuildType(const std::string& type) { build_type_ = type; }
    
    // Task Runner
    TaskRunner& getTaskRunner() { return task_runner_; }

private:
    TaskRunner task_runner_;
    std::string build_system_;
    std::string build_type_ = "Release";
    std::string build_dir_ = "build";
    std::string workspace_root_;
    
    // Build file detection
    bool detectCMake(const std::string& root);
    bool detectMake(const std::string& root);
    bool detectMSBuild(const std::string& root);
    bool detectNinja(const std::string& root);
    
    // Build file parsing
    bool parseCMakeLists(const std::string& path);
    bool parseMakefile(const std::string& path);
    bool parseVcxproj(const std::string& path);
};

// ═══════════════════════════════════════════════════════════════════════
// INLINE IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════

inline TaskRunner::TaskRunner() {
    // Add default problem matchers
    ProblemMatcher gcc_matcher;
    gcc_matcher.name = "gcc";
    gcc_matcher.owner = "cpp";
    gcc_matcher.patterns = {
        R"(([^:]+):(\d+):(\d+):\s+(error|warning):\s+(.+))"
    };
    gcc_matcher.pattern_regex = std::regex(gcc_matcher.patterns[0]);
    addProblemMatcher(gcc_matcher);
    
    ProblemMatcher msvc_matcher;
    msvc_matcher.name = "msvc";
    msvc_matcher.owner = "cpp";
    msvc_matcher.patterns = {
        R"(([^:]+)\((\d+),(\d+)\):\s+(error|warning)\s+([A-Z]+\d+):\s+(.+))"
    };
    msvc_matcher.pattern_regex = std::regex(msvc_matcher.patterns[0]);
    addProblemMatcher(msvc_matcher);
    
    ProblemMatcher cmake_matcher;
    cmake_matcher.name = "cmake";
    cmake_matcher.owner = "cmake";
    cmake_matcher.patterns = {
        R"(CMake (Error|Warning) at ([^:]+):(\d+).*?:\s+(.+))"
    };
    cmake_matcher.pattern_regex = std::regex(cmake_matcher.patterns[0]);
    addProblemMatcher(cmake_matcher);
}

inline TaskRunner::~TaskRunner() {
    cancelAll();
}

inline std::string TaskRunner::generateTaskId() {
    static std::atomic<int> counter{0};
    return "task_" + std::to_string(++counter);
}

inline std::string TaskRunner::addTask(const TaskDefinition& task) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    
    std::string id = task.task_id.empty() ? generateTaskId() : task.task_id;
    TaskDefinition t = task;
    t.task_id = id;
    
    tasks_[id] = t;
    task_status_[id] = TaskStatus::Pending;
    
    return id;
}

inline bool TaskRunner::removeTask(const std::string& task_id) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    
    if (task_status_[task_id] == TaskStatus::Running) {
        return false;  // Can't remove running task
    }
    
    tasks_.erase(task_id);
    task_status_.erase(task_id);
    return true;
}

inline bool TaskRunner::hasTask(const std::string& task_id) const {
    return tasks_.count(task_id) > 0;
}

inline TaskDefinition TaskRunner::getTask(const std::string& task_id) const {
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) {
        return TaskDefinition{};
    }
    return it->second;
}

inline std::vector<TaskDefinition> TaskRunner::getAllTasks() const {
    std::vector<TaskDefinition> result;
    for (const auto& [id, task] : tasks_) {
        result.push_back(task);
    }
    return result;
}

inline TaskResult TaskRunner::runTask(const std::string& task_id) {
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) {
        TaskResult result;
        result.task_id = task_id;
        result.status = TaskStatus::Failed;
        result.exit_code = -1;
        result.output = "Task not found: " + task_id;
        return result;
    }
    
    return runTask(it->second);
}

inline TaskResult TaskRunner::runTask(const TaskDefinition& task) {
    // Resolve dependencies
    std::set<std::string> visited;
    std::vector<std::string> order;
    
    if (!resolveDependencies(task.task_id, visited, order)) {
        TaskResult result;
        result.task_id = task.task_id;
        result.status = TaskStatus::Failed;
        result.exit_code = -1;
        result.output = "Circular dependency detected";
        return result;
    }
    
    // Run dependencies first
    for (const auto& dep_id : order) {
        if (dep_id == task.task_id) continue;
        
        auto dep_result = runTask(dep_id);
        if (dep_result.status != TaskStatus::Success) {
            TaskResult result;
            result.task_id = task.task_id;
            result.status = TaskStatus::Skipped;
            result.exit_code = -1;
            result.output = "Dependency failed: " + dep_id;
            return result;
        }
    }
    
    // Execute task
    return executeTask(task);
}

inline void TaskRunner::runTaskAsync(const std::string& task_id,
                                     std::function<void(const TaskResult&)> callback) {
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) return;
    
    runTaskAsync(it->second, callback);
}

inline void TaskRunner::runTaskAsync(const TaskDefinition& task,
                                    std::function<void(const TaskResult&)> callback) {
    task_threads_[task.task_id] = std::thread([this, task, callback] {
        auto result = runTask(task);
        if (callback) {
            callback(result);
        }
    });
}

inline TaskResult TaskRunner::executeTask(const TaskDefinition& task) {
    TaskResult result;
    result.task_id = task.task_id;
    result.start_time = std::chrono::steady_clock::now();
    
    // Update status
    task_status_[task.task_id] = TaskStatus::Running;
    
    // Notify start
    for (const auto& callback : start_callbacks_) {
        callback(task.task_id);
    }
    
    // Expand variables
    std::string command = expandVariables(task.command);
    std::string cwd = expandVariables(task.cwd);
    
    // Create process
    HANDLE out_read = nullptr, err_read = nullptr, in_write = nullptr;
    HANDLE hProcess = createProcess(task, &out_read, &err_read, &in_write);
    
    if (!hProcess) {
        result.status = TaskStatus::Failed;
        result.exit_code = -1;
        result.output = "Failed to create process";
        result.end_time = std::chrono::steady_clock::now();
        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            result.end_time - result.start_time);
        
        task_status_[task.task_id] = TaskStatus::Failed;
        
        for (const auto& callback : end_callbacks_) {
            callback(task.task_id, result);
        }
        
        return result;
    }
    
    task_handles_[task.task_id] = hProcess;
    
    // Read output
    std::string output, error;
    readProcessOutput(hProcess, out_read, err_read, output, error);
    
    // Wait for process
    DWORD exit_code = 0;
    WaitForSingleObject(hProcess, task.timeout_ms > 0 ? task.timeout_ms : INFINITE);
    GetExitCodeProcess(hProcess, &exit_code);
    
    // Close handles
    CloseHandle(out_read);
    CloseHandle(err_read);
    CloseHandle(in_write);
    CloseHandle(hProcess);
    
    task_handles_.erase(task.task_id);
    
    // Parse problems
    result.output = output + error;
    result.problems = parseOutput(result.output, task.problem_matcher);
    
    // Notify problems
    for (const auto& problem : result.problems) {
        for (const auto& callback : problem_callbacks_) {
            callback(problem);
        }
    }
    
    // Set result
    result.exit_code = exit_code;
    result.status = (exit_code == 0) ? TaskStatus::Success : TaskStatus::Failed;
    result.end_time = std::chrono::steady_clock::now();
    result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.end_time - result.start_time);
    
    task_status_[task.task_id] = result.status;
    
    // Notify end
    for (const auto& callback : end_callbacks_) {
        callback(task.task_id, result);
    }
    
    return result;
}

inline HANDLE TaskRunner::createProcess(const TaskDefinition& task,
                                        HANDLE* out_read, HANDLE* err_read, HANDLE* in_write) {
    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    
    HANDLE out_write, err_write, in_read;
    
    // Create pipes
    if (!CreatePipe(out_read, &out_write, &sa, 0)) return nullptr;
    if (!CreatePipe(err_read, &err_write, &sa, 0)) return nullptr;
    if (!CreatePipe(&in_read, in_write, &sa, 0)) return nullptr;
    
    SetHandleInformation(*out_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(*err_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(*in_write, HANDLE_FLAG_INHERIT, 0);
    
    // Create process
    STARTUPINFOA si = {};
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_write;
    si.hStdError = err_write;
    si.hStdInput = in_read;
    
    PROCESS_INFORMATION pi = {};
    
    // Build command line
    std::string cmd = task.command;
    for (const auto& arg : task.args) {
        cmd += " " + arg;
    }
    
    // Set environment
    std::string env_block;
    for (const auto& [key, value] : task.env) {
        env_block += key + "=" + value + "\0";
    }
    env_block += "\0";
    
    // Create process
    BOOL success = CreateProcessA(
        nullptr,
        const_cast<LPSTR>(cmd.c_str()),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        env_block.empty() ? nullptr : (LPVOID)env_block.c_str(),
        task.cwd.empty() ? nullptr : task.cwd.c_str(),
        &si,
        &pi
    );
    
    // Close write ends
    CloseHandle(out_write);
    CloseHandle(err_write);
    CloseHandle(in_read);
    
    if (!success) {
        CloseHandle(*out_read);
        CloseHandle(*err_read);
        CloseHandle(*in_write);
        return nullptr;
    }
    
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

inline bool TaskRunner::readProcessOutput(HANDLE hProcess, HANDLE out_read, HANDLE err_read,
                                          std::string& output, std::string& error) {
    char buffer[4096];
    DWORD read;
    
    // Read stdout
    while (true) {
        DWORD available = 0;
        if (!PeekNamedPipe(out_read, nullptr, 0, nullptr, &available, nullptr)) break;
        if (available == 0) break;
        
        if (!ReadFile(out_read, buffer, sizeof(buffer) - 1, &read, nullptr)) break;
        buffer[read] = '\0';
        output += buffer;
        
        // Notify output
        TaskOutput out;
        out.text = buffer;
        out.stream = "stdout";
        out.timestamp = std::chrono::steady_clock::now();
        
        for (const auto& callback : output_callbacks_) {
            callback("", out);
        }
    }
    
    // Read stderr
    while (true) {
        DWORD available = 0;
        if (!PeekNamedPipe(err_read, nullptr, 0, nullptr, &available, nullptr)) break;
        if (available == 0) break;
        
        if (!ReadFile(err_read, buffer, sizeof(buffer) - 1, &read, nullptr)) break;
        buffer[read] = '\0';
        error += buffer;
        
        // Notify output
        TaskOutput out;
        out.text = buffer;
        out.stream = "stderr";
        out.is_error = true;
        out.timestamp = std::chrono::steady_clock::now();
        
        for (const auto& callback : output_callbacks_) {
            callback("", out);
        }
    }
    
    return true;
}

inline void TaskRunner::terminateProcess(HANDLE hProcess) {
    if (hProcess) {
        TerminateProcess(hProcess, 1);
    }
}

inline std::vector<TaskProblem> TaskRunner::parseOutput(const std::string& output,
                                                        const std::vector<std::string>& matchers) {
    std::vector<TaskProblem> problems;
    
    for (const auto& matcher_name : matchers) {
        auto it = problem_matchers_.find(matcher_name);
        if (it != problem_matchers_.end()) {
            auto matched = matchProblems(output, it->second);
            problems.insert(problems.end(), matched.begin(), matched.end());
        }
    }
    
    return problems;
}

inline std::vector<TaskProblem> TaskRunner::matchProblems(const std::string& output,
                                                          const ProblemMatcher& matcher) {
    std::vector<TaskProblem> problems;
    
    std::smatch match;
    std::string::const_iterator search_start = output.cbegin();
    
    while (std::regex_search(search_start, output.cend(), match, matcher.pattern_regex)) {
        TaskProblem problem;
        
        if (matcher.name == "gcc") {
            problem.file = match[1].str();
            problem.line = std::stoi(match[2].str());
            problem.column = std::stoi(match[3].str());
            problem.severity = match[4].str();
            problem.message = match[5].str();
            problem.source = "gcc";
        } else if (matcher.name == "msvc") {
            problem.file = match[1].str();
            problem.line = std::stoi(match[2].str());
            problem.column = std::stoi(match[3].str());
            problem.severity = match[4].str();
            problem.code = match[5].str();
            problem.message = match[6].str();
            problem.source = "msvc";
        } else if (matcher.name == "cmake") {
            problem.severity = match[1].str();
            problem.file = match[2].str();
            problem.line = std::stoi(match[3].str());
            problem.message = match[4].str();
            problem.source = "cmake";
        }
        
        problems.push_back(problem);
        search_start = match.suffix().first;
    }
    
    return problems;
}

inline bool TaskRunner::resolveDependencies(const std::string& task_id,
                                           std::set<std::string>& visited,
                                           std::vector<std::string>& order) {
    if (visited.count(task_id)) {
        return false;  // Circular dependency
    }
    
    visited.insert(task_id);
    
    auto it = tasks_.find(task_id);
    if (it == tasks_.end()) {
        return true;
    }
    
    for (const auto& dep : it->second.depends_on) {
        if (!resolveDependencies(dep.task_id, visited, order)) {
            return false;
        }
    }
    
    order.push_back(task_id);
    return true;
}

inline std::string TaskRunner::expandVariables(const std::string& input) {
    std::string result = input;
    
    // Expand config variables
    for (const auto& [key, value] : config_.variables) {
        std::string placeholder = "${" + key + "}";
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.length(), value);
            pos += value.length();
        }
    }
    
    // Expand environment variables
    for (const auto& [key, value] : config_.variables) {
        std::string placeholder = "$" + key;
        size_t pos = 0;
        while ((pos = result.find(placeholder, pos)) != std::string::npos) {
            result.replace(pos, placeholder.length(), value);
            pos += value.length();
        }
    }
    
    return result;
}

inline void TaskRunner::cancel(const std::string& task_id) {
    auto it = task_handles_.find(task_id);
    if (it != task_handles_.end()) {
        terminateProcess(it->second);
        task_status_[task_id] = TaskStatus::Cancelled;
    }
}

inline void TaskRunner::cancelAll() {
    for (auto& [id, handle] : task_handles_) {
        terminateProcess(handle);
        task_status_[id] = TaskStatus::Cancelled;
    }
    
    for (auto& [id, thread] : task_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    
    task_threads_.clear();
}

inline bool TaskRunner::isRunning(const std::string& task_id) const {
    auto it = task_status_.find(task_id);
    return it != task_status_.end() && it->second == TaskStatus::Running;
}

inline bool TaskRunner::isAnyRunning() const {
    for (const auto& [id, status] : task_status_) {
        if (status == TaskStatus::Running) {
            return true;
        }
    }
    return false;
}

// ═══════════════════════════════════════════════════════════════════════
// RAWRXD_TASK_CONFIG_001
//
// loadConfig/saveConfig were `// TODO: Parse JSON/YAML config file` and// `// TODO: Write JSON/YAML config file`. That is why this runner could not load
// a tasks.json even though everything else about it -- process execution, output
// capture, problem matching, dependency resolution, variable expansion, and
// CMake/Make/MSBuild/Ninja detection -- is implemented. The external contract was
// two empty functions.
//
// Implemented against the VS Code tasks.json shape, because that is what the
// product is asked to read (application.cpp used to call
// LoadTasksConfiguration("<workspace>/.vscode/tasks.json)"). Accepted forms:
//
//   { "version": "2.0.0", "tasks": [ { "label": ..., "type": ...,
//     "command": ..., "args": [...], "options": { "cwd": ..., "env": {...} },
//     "group": ..., "dependsOn": [...], "isBackground": ...,
//     "problemMatcher": [...], "detail": ..., "presentation": ... } ] }
//
// plus the older flat form with "taskName"/"identifier" instead of "label".
//
// Returns a measured outcome rather than void, because "loaded zero tasks
// because the file was absent" and "loaded zero tasks because the file was
// malformed" must not look alike. See TaskConfigLoadResult.
// ═══════════════════════════════════════════════════════════════════════


inline TaskConfigLoadResult TaskRunner::loadConfigWithResult(const std::string& config_path) {
    TaskConfigLoadResult result;
    result.loadCalled = true;

    std::ifstream file(config_path);
    if (!file.is_open()) {
        result.lastError = "tasks config absent";
        return result;
    }
    result.fileExisted = true;

    nlohmann::json j;
    try {
        file >> j;
        result.parsed = true;
    } catch (const std::exception& ex) {
        result.lastError = std::string("tasks config unparsable: ") + ex.what();
        return result;
    }

    try {
        TaskConfig cfg;
        if (j.contains("version") && j["version"].is_string()) {
            cfg.version = j["version"].get<std::string>();
        }
        result.version = cfg.version;

        if (j.contains("variables") && j["variables"].is_object()) {
            for (auto it = j["variables"].begin(); it != j["variables"].end(); ++it) {
                if (it.value().is_string()) cfg.variables[it.key()] = it.value().get<std::string>();
            }
        }

        if (!j.contains("tasks") || !j["tasks"].is_array()) {
            result.lastError = "tasks config has no 'tasks' array";
            return result;
        }

        for (const auto& t : j["tasks"]) {
            if (!t.is_object()) { ++result.entriesRejected; continue; }

            TaskDefinition def;

            // label, with the older flat aliases accepted.
            if (t.contains("label") && t["label"].is_string()) {
                def.label = t["label"].get<std::string>();
            } else if (t.contains("taskName") && t["taskName"].is_string()) {
                def.label = t["taskName"].get<std::string>();
            }
            if (def.label.empty()) { ++result.entriesRejected; continue; }
            def.task_id = def.label;

            // type
            if (t.contains("type") && t["type"].is_string()) {
                const std::string ty = t["type"].get<std::string>();
                if      (ty == "shell")    def.type = TaskType::Shell;
                else if (ty == "process")  def.type = TaskType::Process;
                else if (ty == "build")    def.type = TaskType::Build;
                else if (ty == "test")     def.type = TaskType::Test;
                else if (ty == "run")      def.type = TaskType::Run;
                else if (ty == "custom")   def.type = TaskType::Custom;
            }

            if (t.contains("command")) {
                if (t["command"].is_string()) def.command = t["command"].get<std::string>();
                else if (t["command"].is_array() && t["command"].size() >= 1 &&
                         t["command"][0].is_string()) {
                    // ["cmd", "arg", ...] form: command is element 0.
                    def.command = t["command"][0].get<std::string>();
                    for (std::size_t i = 1; i < t["command"].size(); ++i) {
                        if (t["command"][i].is_string())
                            def.args.push_back(t["command"][i].get<std::string>());
                    }
                }
            }

            if (t.contains("args") && t["args"].is_array()) {
                for (const auto& a : t["args"]) {
                    if (a.is_string()) def.args.push_back(a.get<std::string>());
                }
            }

            if (t.contains("cwd") && t["cwd"].is_string()) def.cwd = t["cwd"].get<std::string>();
            if (t.contains("detail") && t["detail"].is_string()) def.detail = t["detail"].get<std::string>();
            if (t.contains("presentation") && t["presentation"].is_string())
                def.presentation = t["presentation"].get<std::string>();
            if (t.contains("isBackground") && t["isBackground"].is_boolean())
                def.is_background = t["isBackground"].get<bool>();
            if (t.contains("group")) {
                if (t["group"].is_string()) def.group = t["group"].get<std::string>();
                else if (t["group"].is_object() && t["group"].contains("kind"))
                    def.group = t["group"]["kind"].is_string()
                                  ? t["group"]["kind"].get<std::string>() : std::string();
            }
            if (t.contains("dependsOn")) {
                if (t["dependsOn"].is_array()) {
                    for (const auto& d : t["dependsOn"]) {
                        if (d.is_string()) def.depends_on.push_back({d.get<std::string>(), true});
                    }
                } else if (t["dependsOn"].is_string()) {
                    def.depends_on.push_back({t["dependsOn"].get<std::string>(), true});
                }
            }
            if (t.contains("problemMatcher") && t["problemMatcher"].is_array()) {
                for (const auto& p : t["problemMatcher"]) {
                    if (p.is_string()) def.problem_matcher.push_back(p.get<std::string>());
                }
            }

            // options: cwd, env, shell. Note options.env values may be non-string
            // in practice, so numbers and booleans are coerced rather than dropped.
            if (t.contains("options") && t["options"].is_object()) {
                const auto& o = t["options"];
                if (o.contains("cwd") && o["cwd"].is_string()) def.cwd = o["cwd"].get<std::string>();
                if (o.contains("shell") && o["shell"].is_string()) def.shell = o["shell"].get<std::string>();
                if (o.contains("env") && o["env"].is_object()) {
                    for (auto it = o["env"].begin(); it != o["env"].end(); ++it) {
                        const auto& v = it.value();
                        if      (v.is_string())  def.env[it.key()] = v.get<std::string>();
                        else if (v.is_boolean()) def.env[it.key()] = v.get<bool>() ? "1" : "0";
                        else if (v.is_number())  def.env[it.key()] = v.dump();
                    }
                }
            }

            cfg.tasks.push_back(def);
            ++result.tasksParsed;
        }

        // Adopt only after the whole document parsed, so a malformed entry cannot
        // leave a half-populated registry. addTask returns the assigned task id,
        // or an empty string when it refused the definition.
        for (const auto& def : cfg.tasks) {
            if (!addTask(def).empty()) ++result.tasksAdopted; else ++result.tasksSkipped;
        }
        if (result.tasksAdopted == 0 && result.tasksParsed == 0) {
            result.refused = true;
            result.lastError = "no usable task definitions";
        }
        return result;

    } catch (const std::exception& ex) {
        result.refused = true;
        result.lastError = std::string("tasks config schema error: ") + ex.what();
        return result;
    }
}

inline void TaskRunner::loadConfig(const std::string& config_path) {
    (void)loadConfigWithResult(config_path);
}

inline void TaskRunner::saveConfig(const std::string& config_path) {
    nlohmann::json j;
    j["version"] = "2.0.0";
    j["tasks"] = nlohmann::json::array();

    // TaskType -> the string tasks.json uses. Written out rather than relying on
    // an enum-to-string helper, because that helper does not exist and inventing
    // one for a single call site is worse than the six cases.
    auto typeName = [](TaskType t) -> const char* {
        switch (t) {
            case TaskType::Shell:   return "shell";
            case TaskType::Process: return "process";
            case TaskType::Build:   return "build";
            case TaskType::Test:    return "test";
            case TaskType::Run:     return "run";
            case TaskType::Custom:  return "custom";
        }
        return "shell";
    };

    for (const TaskDefinition& def : getAllTasks()) {
        nlohmann::json t;
        t["label"]   = def.label;
        t["type"]    = typeName(def.type);
        t["command"] = def.command;
        if (!def.args.empty())          t["args"]    = def.args;
        if (!def.cwd.empty())           t["cwd"]     = def.cwd;
        if (!def.detail.empty())        t["detail"]  = def.detail;
        if (!def.group.empty())         t["group"]   = def.group;
        if (!def.presentation.empty())  t["presentation"] = def.presentation;
        if (def.is_background)          t["isBackground"] = true;
        if (!def.problem_matcher.empty()) t["problemMatcher"] = def.problem_matcher;
        if (!def.depends_on.empty()) {
            t["dependsOn"] = nlohmann::json::array();
            for (const auto& d : def.depends_on) t["dependsOn"].push_back(d.task_id);
        }
        if (!def.shell.empty() || !def.env.empty()) {
            nlohmann::json o;
            if (!def.shell.empty()) o["shell"] = def.shell;
            if (!def.env.empty()) {
                o["env"] = nlohmann::json::object();
                for (const auto& e : def.env) o["env"][e.first] = e.second;
            }
            t["options"] = o;
        }
        j["tasks"].push_back(t);
    }

    // Atomic: a crash mid-write must not leave a truncated tasks.json.
    const std::string tmp = config_path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return;
        out << j.dump(2);
        out.flush();
        if (!out.good()) { out.close(); std::remove(tmp.c_str()); return; }
    }
#if defined(_WIN32)
    if (!ReplaceFileA(config_path.c_str(), tmp.c_str(), nullptr, 0, nullptr, nullptr)) {
        MoveFileExA(tmp.c_str(), config_path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
#else
    std::rename(tmp.c_str(), config_path.c_str());
#endif
}

inline void TaskRunner::addProblemMatcher(const ProblemMatcher& matcher) {
    problem_matchers_[matcher.name] = matcher;
}

inline void TaskRunner::removeProblemMatcher(const std::string& name) {
    problem_matchers_.erase(name);
}

inline ProblemMatcher TaskRunner::getProblemMatcher(const std::string& name) const {
    auto it = problem_matchers_.find(name);
    if (it == problem_matchers_.end()) {
        return ProblemMatcher{};
    }
    return it->second;
}

inline void TaskRunner::onTaskStart(std::function<void(const std::string&)> callback) {
    start_callbacks_.push_back(callback);
}

inline void TaskRunner::onTaskOutput(std::function<void(const std::string&, const TaskOutput&)> callback) {
    output_callbacks_.push_back(callback);
}

inline void TaskRunner::onTaskEnd(std::function<void(const std::string&, const TaskResult&)> callback) {
    end_callbacks_.push_back(callback);
}

inline void TaskRunner::onProblem(std::function<void(const TaskProblem&)> callback) {
    problem_callbacks_.push_back(callback);
}

inline TaskResult TaskRunner::build() {
    // Find build task
    for (const auto& [id, task] : tasks_) {
        if (task.group == "build") {
            return runTask(id);
        }
    }
    
    TaskResult result;
    result.status = TaskStatus::Failed;
    result.output = "No build task found";
    return result;
}

inline TaskResult TaskRunner::test() {
    // Find test task
    for (const auto& [id, task] : tasks_) {
        if (task.group == "test") {
            return runTask(id);
        }
    }
    
    TaskResult result;
    result.status = TaskStatus::Failed;
    result.output = "No test task found";
    return result;
}

inline TaskResult TaskRunner::clean() {
    // Find clean task
    for (const auto& [id, task] : tasks_) {
        if (task.group == "clean") {
            return runTask(id);
        }
    }
    
    TaskResult result;
    result.status = TaskStatus::Failed;
    result.output = "No clean task found";
    return result;
}

inline TaskResult TaskRunner::rebuild() {
    auto clean_result = clean();
    if (clean_result.status != TaskStatus::Success) {
        return clean_result;
    }
    
    return build();
}

// ═══════════════════════════════════════════════════════════════════════
// BUILD SYSTEM IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════

inline BuildSystem::BuildSystem() {
}

inline BuildSystem::~BuildSystem() {
}

inline bool BuildSystem::detectBuildSystem(const std::string& workspace_root) {
    workspace_root_ = workspace_root;
    
    if (detectCMake(workspace_root)) {
        build_system_ = "cmake";
        return true;
    }
    
    if (detectMake(workspace_root)) {
        build_system_ = "make";
        return true;
    }
    
    if (detectMSBuild(workspace_root)) {
        build_system_ = "msbuild";
        return true;
    }
    
    if (detectNinja(workspace_root)) {
        build_system_ = "ninja";
        return true;
    }
    
    return false;
}

inline bool BuildSystem::detectCMake(const std::string& root) {
    std::string cmake_lists = root + "/CMakeLists.txt";
    DWORD attr = GetFileAttributesA(cmake_lists.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

inline bool BuildSystem::detectMake(const std::string& root) {
    std::string makefile = root + "/Makefile";
    DWORD attr = GetFileAttributesA(makefile.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

inline bool BuildSystem::detectMSBuild(const std::string& root) {
    WIN32_FIND_DATAA find_data;
    HANDLE find = FindFirstFileA((root + "/*.vcxproj").c_str(), &find_data);
    
    if (find == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    FindClose(find);
    return true;
}

inline bool BuildSystem::detectNinja(const std::string& root) {
    std::string ninja_file = root + "/build.ninja";
    DWORD attr = GetFileAttributesA(ninja_file.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

inline TaskResult BuildSystem::cmakeConfigure(const std::string& build_type,
                                               const std::string& generator) {
    TaskDefinition task;
    task.label = "CMake Configure";
    task.command = "cmake";
    task.args = {
        "-S", workspace_root_,
        "-B", build_dir_,
        "-DCMAKE_BUILD_TYPE=" + build_type
    };
    
    if (!generator.empty()) {
        task.args.push_back("-G");
        task.args.push_back(generator);
    }
    
    task.problem_matcher = {"cmake"};
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::cmakeBuild(const std::string& target) {
    TaskDefinition task;
    task.label = "CMake Build";
    task.command = "cmake";
    task.args = {
        "--build", build_dir_,
        "--config", build_type_
    };
    
    if (!target.empty()) {
        task.args.push_back("--target");
        task.args.push_back(target);
    }
    
    task.problem_matcher = {"gcc", "msvc"};
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::cmakeClean() {
    TaskDefinition task;
    task.label = "CMake Clean";
    task.command = "cmake";
    task.args = {
        "--build", build_dir_,
        "--target", "clean"
    };
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::cmakeInstall() {
    TaskDefinition task;
    task.label = "CMake Install";
    task.command = "cmake";
    task.args = {
        "--install", build_dir_
    };
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::makeBuild(const std::string& target) {
    TaskDefinition task;
    task.label = "Make Build";
    task.command = "make";
    
    if (!target.empty()) {
        task.args.push_back(target);
    }
    
    task.problem_matcher = {"gcc"};
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::makeClean() {
    TaskDefinition task;
    task.label = "Make Clean";
    task.command = "make";
    task.args = {"clean"};
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::msbuildBuild(const std::string& project,
                                           const std::string& config) {
    TaskDefinition task;
    task.label = "MSBuild Build";
    task.command = "msbuild";
    
    if (!project.empty()) {
        task.args.push_back(project);
    }
    
    task.args.push_back("/p:Configuration=" + config);
    task.problem_matcher = {"msvc"};
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::msbuildClean(const std::string& project,
                                           const std::string& config) {
    TaskDefinition task;
    task.label = "MSBuild Clean";
    task.command = "msbuild";
    
    if (!project.empty()) {
        task.args.push_back(project);
    }
    
    task.args.push_back("/t:Clean");
    task.args.push_back("/p:Configuration=" + config);
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::ninjaBuild(const std::string& target) {
    TaskDefinition task;
    task.label = "Ninja Build";
    task.command = "ninja";
    
    if (!target.empty()) {
        task.args.push_back(target);
    }
    
    task.problem_matcher = {"gcc", "msvc"};
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::ninjaClean() {
    TaskDefinition task;
    task.label = "Ninja Clean";
    task.command = "ninja";
    task.args = {"-t", "clean"};
    task.cwd = workspace_root_;
    
    return task_runner_.runTask(task);
}

inline TaskResult BuildSystem::configure() {
    if (build_system_ == "cmake") {
        return cmakeConfigure(build_type_);
    }
    
    TaskResult result;
    result.status = TaskStatus::Failed;
    result.output = "No build system detected";
    return result;
}

inline TaskResult BuildSystem::build(const std::string& target) {
    if (build_system_ == "cmake") {
        return cmakeBuild(target);
    } else if (build_system_ == "make") {
        return makeBuild(target);
    } else if (build_system_ == "msbuild") {
        return msbuildBuild(target, build_type_);
    } else if (build_system_ == "ninja") {
        return ninjaBuild(target);
    }
    
    TaskResult result;
    result.status = TaskStatus::Failed;
    result.output = "No build system detected";
    return result;
}

inline TaskResult BuildSystem::rebuild(const std::string& target) {
    auto clean_result = clean();
    if (clean_result.status != TaskStatus::Success) {
        return clean_result;
    }
    
    return build(target);
}

inline TaskResult BuildSystem::clean() {
    if (build_system_ == "cmake") {
        return cmakeClean();
    } else if (build_system_ == "make") {
        return makeClean();
    } else if (build_system_ == "msbuild") {
        return msbuildClean("", build_type_);
    } else if (build_system_ == "ninja") {
        return ninjaClean();
    }
    
    TaskResult result;
    result.status = TaskStatus::Failed;
    result.output = "No build system detected";
    return result;
}

inline TaskResult BuildSystem::install() {
    if (build_system_ == "cmake") {
        return cmakeInstall();
    }
    
    TaskResult result;
    result.status = TaskStatus::Failed;
    result.output = "Install not supported for this build system";
    return result;
}

inline std::vector<std::string> BuildSystem::getTargets() {
    // TODO: Parse build files to get targets
    return {};
}

} // namespace rawrxd

#endif // TASK_SYSTEM_HPP
