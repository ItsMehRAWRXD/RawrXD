#include "task_runner.h"
#include <windows.h>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <regex>

namespace RawrXD {
namespace Tasks {

TaskRunner& TaskRunner::Instance() {
    static TaskRunner instance;
    return instance;
}

bool TaskRunner::Initialize() {
    // Register default problem matchers
    ProblemMatcher gccMatcher;
    gccMatcher.name = "gcc";
    gccMatcher.regexp = "^(.*):(\\d+):(\\d+):\\s*(error|warning|note):\\s*(.*)$";
    gccMatcher.fileGroup = 1;
    gccMatcher.lineGroup = 2;
    gccMatcher.severityGroup = 4;
    gccMatcher.messageGroup = 5;
    RegisterProblemMatcher(gccMatcher);
    
    ProblemMatcher msvcMatcher;
    msvcMatcher.name = "msvc";
    msvcMatcher.regexp = "^(.*)\\((\\d+),(\\d+)\\):\\s*(error|warning)\\s*(\\w+)?\\s*:\\s*(.*)$";
    msvcMatcher.fileGroup = 1;
    msvcMatcher.lineGroup = 2;
    msvcMatcher.columnGroup = 3;
    msvcMatcher.severityGroup = 4;
    msvcMatcher.codeGroup = 5;
    msvcMatcher.messageGroup = 6;
    RegisterProblemMatcher(msvcMatcher);
    
    return true;
}

bool TaskRunner::Shutdown() {
    // Cancel all running tasks
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, task] : runningTasks_) {
        CancelTask(id);
    }
    runningTasks_.clear();
    return true;
}

bool TaskRunner::LoadTasksConfiguration(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(file, root)) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.clear();
    
    const Json::Value& tasks = root["tasks"];
    for (const auto& task : tasks) {
        TaskDefinition def;
        def.label = task["label"].asString();
        def.type = task.get("type", "shell").asString();
        def.command = task["command"].asString();
        def.group = task.get("group", "none").asString();
        def.cwd = task.get("options", Json::Value()).get("cwd", "").asString();
        
        const Json::Value& args = task["args"];
        for (const auto& arg : args) {
            def.args.push_back(arg.asString());
        }
        
        const Json::Value& depends = task["dependsOn"];
        for (const auto& dep : depends) {
            def.dependsOn.push_back(dep.asString());
        }
        
        const Json::Value& env = task.get("options", Json::Value()).get("env", Json::Value());
        for (const auto& member : env.getMemberNames()) {
            def.env[member] = env[member].asString();
        }
        
        tasks_.push_back(def);
    }
    
    return true;
}

bool TaskRunner::SaveTasksConfiguration(const std::string& path) {
    Json::Value root;
    Json::Value tasks(Json::arrayValue);
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& task : tasks_) {
        Json::Value t;
        t["label"] = task.label;
        t["type"] = task.type;
        t["command"] = task.command;
        t["group"] = task.group;
        
        Json::Value args(Json::arrayValue);
        for (const auto& arg : task.args) {
            args.append(arg);
        }
        t["args"] = args;
        
        if (!task.cwd.empty()) {
            t["options"]["cwd"] = task.cwd;
        }
        
        tasks.append(t);
    }
    
    root["version"] = "2.0.0";
    root["tasks"] = tasks;
    
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    Json::StreamWriterBuilder builder;
    file << Json::writeString(builder, root);
    return true;
}

std::vector<TaskDefinition> TaskRunner::GetAvailableTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tasks_;
}

TaskDefinition* TaskRunner::GetTask(const std::string& label) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& task : tasks_) {
        if (task.label == label) return &task;
    }
    return nullptr;
}

bool TaskRunner::AddTask(const TaskDefinition& task) {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.push_back(task);
    return true;
}

bool TaskRunner::RemoveTask(const std::string& label) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::remove_if(tasks_.begin(), tasks_.end(),
        [&label](const TaskDefinition& t) { return t.label == label; });
    if (it == tasks_.end()) return false;
    tasks_.erase(it, tasks_.end());
    return true;
}

std::string TaskRunner::RunTask(const std::string& label) {
    TaskDefinition* def = GetTask(label);
    if (!def) return "";
    return RunTask(*def);
}

std::string TaskRunner::RunTask(const TaskDefinition& task) {
    std::string taskId = GenerateTaskId();
    
    auto runningTask = std::make_unique<RunningTask>();
    runningTask->id = taskId;
    runningTask->definition = task;
    runningTask->result.status = TaskStatus::Running;
    runningTask->startTime = std::chrono::steady_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(mutex_);
        runningTasks_[taskId] = std::move(runningTask);
    }
    
    // Execute in separate thread
    std::thread execThread([this, taskId]() {
        RunningTask* task = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = runningTasks_.find(taskId);
            if (it != runningTasks_.end()) {
                task = it->second.get();
            }
        }
        if (task) {
            ExecuteTask(task);
        }
    });
    execThread.detach();
    
    if (taskEventCallback_) {
        taskEventCallback_(taskId, TaskStatus::Running);
    }
    
    return taskId;
}

bool TaskRunner::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = runningTasks_.find(taskId);
    if (it == runningTasks_.end()) return false;
    
    it->second->cancelled = true;
    if (it->second->processHandle) {
        TerminateProcess(it->second->processHandle, 1);
    }
    it->second->result.status = TaskStatus::Cancelled;
    
    return true;
}

std::vector<RunningTask> TaskRunner::GetRunningTasks() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<RunningTask> result;
    for (const auto& [id, task] : runningTasks_) {
        if (task->result.status == TaskStatus::Running) {
            result.push_back(*task);
        }
    }
    return result;
}

RunningTask* TaskRunner::GetRunningTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = runningTasks_.find(taskId);
    if (it != runningTasks_.end()) return it->second.get();
    return nullptr;
}

TaskResult TaskRunner::GetTaskResult(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = runningTasks_.find(taskId);
    if (it != runningTasks_.end()) return it->second->result;
    return TaskResult{};
}

std::string TaskRunner::RunBuildTask() {
    // Find default build task
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& task : tasks_) {
        if (task.group == "build") {
            return RunTask(task.label);
        }
    }
    return "";
}

std::string TaskRunner::RunTestTask() {
    // Find default test task
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& task : tasks_) {
        if (task.group == "test") {
            return RunTask(task.label);
        }
    }
    return "";
}

void TaskRunner::RegisterProblemMatcher(const ProblemMatcher& matcher) {
    std::lock_guard<std::mutex> lock(mutex_);
    problemMatchers_.push_back(matcher);
}

std::vector<ProblemMatcher> TaskRunner::GetProblemMatchers() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return problemMatchers_;
}

void TaskRunner::ExecuteTask(RunningTask* task) {
    // Build command line
    std::string cmdLine = task->definition.command;
    for (const auto& arg : task->definition.args) {
        cmdLine += " " + arg;
    }
    
    // Setup pipes for output capture
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = nullptr;
    
    HANDLE hReadOut, hWriteOut;
    HANDLE hReadErr, hWriteErr;
    
    CreatePipe(&hReadOut, &hWriteOut, &sa, 0);
    CreatePipe(&hReadErr, &hWriteErr, &sa, 0);
    
    SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hReadErr, HANDLE_FLAG_INHERIT, 0);
    
    // Setup process
    STARTUPINFOA si = {};
    si.cb = sizeof(STARTUPINFOA);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWriteOut;
    si.hStdError = hWriteErr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    
    PROCESS_INFORMATION pi = {};
    
    // Create process
    BOOL success = CreateProcessA(
        nullptr,
        const_cast<char*>(cmdLine.c_str()),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        task->definition.cwd.empty() ? nullptr : task->definition.cwd.c_str(),
        &si,
        &pi
    );
    
    CloseHandle(hWriteOut);
    CloseHandle(hWriteErr);
    
    if (!success) {
        task->result.status = TaskStatus::Failed;
        task->result.exitCode = -1;
        if (taskEventCallback_) {
            taskEventCallback_(task->id, TaskStatus::Failed);
        }
        return;
    }
    
    task->processHandle = pi.hProcess;
    task->threadHandle = pi.hThread;
    
    // Read output
    std::thread outThread([this, task, hReadOut]() {
        ReadOutput(task, hReadOut);
    });
    
    std::thread errThread([this, task, hReadErr]() {
        ReadOutput(task, hReadErr);
    });
    
    // Wait for completion
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    outThread.join();
    errThread.join();
    
    CloseHandle(hReadOut);
    CloseHandle(hReadErr);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    task->result.exitCode = static_cast<int>(exitCode);
    task->result.status = (exitCode == 0) ? TaskStatus::Succeeded : TaskStatus::Failed;
    
    // Parse problems
    ParseProblems(task);
    
    if (taskEventCallback_) {
        taskEventCallback_(task->id, task->result.status);
    }
}

void TaskRunner::ReadOutput(RunningTask* task, HANDLE hRead) {
    char buffer[4096];
    DWORD bytesRead;
    
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        task->result.stdout += buffer;
        
        if (outputCallback_) {
            outputCallback_(task->id, buffer);
        }
    }
}

void TaskRunner::ParseProblems(RunningTask* task) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& matcher : problemMatchers_) {
        try {
            std::regex re(matcher.regexp);
            std::sregex_iterator iter(task->result.stdout.begin(), 
                                      task->result.stdout.end(), re);
            std::sregex_iterator end;
            
            for (; iter != end; ++iter) {
                std::smatch match = *iter;
                std::string problem = match.str(matcher.fileGroup) + ":" +
                                     match.str(matcher.lineGroup) + ": " +
                                     match.str(matcher.messageGroup);
                task->result.problems.push_back(problem);
            }
        } catch (...) {
            // Regex error, skip this matcher
        }
    }
}

std::string TaskRunner::GenerateTaskId() {
    static int counter = 0;
    return "task_" + std::to_string(++counter) + "_" + 
           std::to_string(GetTickCount());
}

void TaskRunner::CleanupTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(mutex_);
    runningTasks_.erase(taskId);
}

} // namespace Tasks
} // namespace RawrXD
