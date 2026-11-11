// task_runner.cpp — Task Automation Implementation
#include "task_runner.hpp"
#include <fstream>
#include <sstream>
#include <thread>
#include <algorithm>
#include <regex>
#include <shellapi.h>

namespace RawrXD {
namespace Tasks {

// ============================================================================
// TaskInstance Implementation
// ============================================================================
TaskInstance::TaskInstance(const TaskDefinition& def, const std::string& id)
    : m_definition(def), m_id(id)
{
    m_result.taskId = id;
}

TaskInstance::~TaskInstance() {
    if (m_state == TaskState::Running) {
        Cancel();
    }
}

bool TaskInstance::Run() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state == TaskState::Running) return false;

    m_state = TaskState::Running;
    m_result.startTime = std::chrono::steady_clock::now();

    if (m_definition.type == TaskType::Shell) {
        ExecuteShell();
    } else {
        ExecuteProcess();
    }

    return true;
}

void TaskInstance::Cancel() {
    m_cancelled = true;
    if (m_processHandle) {
        TerminateProcess(m_processHandle, 1);
        CloseHandle(m_processHandle);
        m_processHandle = nullptr;
    }
    m_state = TaskState::Cancelled;
    m_result.endTime = std::chrono::steady_clock::now();
}

void TaskInstance::ExecuteShell() {
    // Build command string
    std::string cmd = m_definition.command;
    for (const auto& arg : m_definition.args) {
        cmd += " " + arg;
    }

    // Set up process
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hStdoutRead, hStdoutWrite;
    HANDLE hStderrRead, hStderrWrite;

    CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0);
    CreatePipe(&hStderrRead, &hStderrWrite, &sa, 0);
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hStderrRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStderrWrite;

    PROCESS_INFORMATION pi;
    std::string cmdLine = "cmd.exe /c " + cmd;

    // Set working directory
    std::string cwd = m_definition.options.cwd;
    if (cwd.empty()) cwd = std::filesystem::current_path().string();

    if (CreateProcessA(nullptr, cmdLine.data(), nullptr, nullptr, TRUE,
                       CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi)) {
        m_processHandle = pi.hProcess;
        CloseHandle(pi.hThread);
        CloseHandle(hStdoutWrite);
        CloseHandle(hStderrWrite);

        // Read output
        char buffer[4096];
        DWORD bytesRead;
        std::string output;
        std::string errorOutput;

        while (WaitForSingleObject(pi.hProcess, 100) == WAIT_TIMEOUT) {
            if (m_cancelled) {
                TerminateProcess(pi.hProcess, 1);
                break;
            }
            // Read stdout
            while (PeekNamedPipe(hStdoutRead, nullptr, 0, nullptr, &bytesRead, nullptr) && bytesRead > 0) {
                if (ReadFile(hStdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
                    buffer[bytesRead] = '\0';
                    output += buffer;
                    if (m_outputCallback) m_outputCallback(buffer);
                }
            }
            // Read stderr
            while (PeekNamedPipe(hStderrRead, nullptr, 0, nullptr, &bytesRead, nullptr) && bytesRead > 0) {
                if (ReadFile(hStderrRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
                    buffer[bytesRead] = '\0';
                    errorOutput += buffer;
                    if (m_errorCallback) m_errorCallback(buffer);
                }
            }
        }

        // Final read
        while (ReadFile(hStdoutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
            if (m_outputCallback) m_outputCallback(buffer);
        }
        while (ReadFile(hStderrRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            errorOutput += buffer;
            if (m_errorCallback) m_errorCallback(buffer);
        }

        GetExitCodeProcess(pi.hProcess, reinterpret_cast<DWORD*>(&m_result.exitCode));
        CloseHandle(pi.hProcess);
        CloseHandle(hStdoutRead);
        CloseHandle(hStderrRead);

        m_result.output = output;
        m_result.errorOutput = errorOutput;
        m_state = (m_result.exitCode == 0) ? TaskState::Succeeded : TaskState::Failed;

        // Apply problem matchers
        ApplyProblemMatchers(output + errorOutput);
    } else {
        m_result.exitCode = GetLastError();
        m_result.errorOutput = "Failed to create process";
        m_state = TaskState::Failed;
    }

    m_result.endTime = std::chrono::steady_clock::now();
}

void TaskInstance::ExecuteProcess() {
    // Direct process execution (no shell)
    ExecuteShell(); // Fallback to shell for now
}

void TaskInstance::ApplyProblemMatchers(const std::string& output) {
    for (const auto& matcher : m_definition.problemMatchers) {
        std::regex pattern(matcher.messagePattern);
        std::smatch match;
        std::string::const_iterator searchStart(output.cbegin());
        while (std::regex_search(searchStart, output.cend(), match, pattern)) {
            m_result.matchedProblems.push_back(match.str());
            searchStart = match.suffix().first;
        }
    }
}

// ============================================================================
// TaskRunner Implementation
// ============================================================================
TaskRunner::TaskRunner() = default;
TaskRunner::~TaskRunner() { Shutdown(); }

bool TaskRunner::Initialize() {
    m_initialized = true;
    return true;
}

void TaskRunner::Shutdown() {
    CancelAll();
    m_tasks.clear();
    m_results.clear();
    m_initialized = false;
}

void TaskRunner::RegisterTask(const TaskDefinition& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_tasks[task.label] = task;
}

bool TaskRunner::LoadTasksFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) return false;

    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    TaskDefinition currentTask;
    bool inTask = false;

    while (std::getline(file, line)) {
        auto parseStr = [](const std::string& l, const std::string& key) -> std::string {
            auto pos = l.find("\"" + key + "\"");
            if (pos == std::string::npos) return {};
            auto colon = l.find(':', pos);
            if (colon == std::string::npos) return {};
            auto start = l.find('"', colon + 1);
            if (start == std::string::npos) return {};
            auto end = l.find('"', start + 1);
            if (end == std::string::npos) return {};
            return l.substr(start + 1, end - start - 1);
        };

        if (line.find("\"label\"") != std::string::npos) {
            if (inTask) {
                RegisterTask(currentTask);
                currentTask = TaskDefinition();
            }
            currentTask.label = parseStr(line, "label");
            inTask = true;
        }
        if (line.find("\"command\"") != std::string::npos) currentTask.command = parseStr(line, "command");
        if (line.find("\"detail\"") != std::string::npos) currentTask.detail = parseStr(line, "detail");
        if (line.find("\"group\"") != std::string::npos) currentTask.options.group = parseStr(line, "group");
        if (line.find("\"isDefault\"") != std::string::npos) currentTask.options.isDefault = true;
        if (line.find("\"background\"") != std::string::npos) currentTask.options.background = true;
    }

    if (inTask) {
        RegisterTask(currentTask);
    }

    return true;
}

bool TaskRunner::SaveTasksFile(const std::filesystem::path& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << "{\n";
    file << "  \"version\": \"2.0.0\",\n";
    file << "  \"tasks\": [\n";

    bool first = true;
    for (const auto& [label, task] : m_tasks) {
        if (!first) file << ",\n";
        first = false;
        file << "    {\n";
        file << "      \"label\": \"" << task.label << "\",\n";
        file << "      \"command\": \"" << task.command << "\",\n";
        file << "      \"detail\": \"" << task.detail << "\",\n";
        file << "      \"group\": \"" << task.options.group << "\"\n";
        file << "    }";
    }

    file << "\n  ]\n";
    file << "}\n";
    return true;
}

TaskResult* TaskRunner::RunTask(const std::string& label) {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_tasks.find(label);
    if (it == m_tasks.end()) return nullptr;

    auto taskId = GenerateTaskId();
    auto instance = std::make_unique<TaskInstance>(it->second, taskId);

    // Set up callbacks
    instance->SetOutputCallback([this, taskId](const std::string& line) {
        // Forward output
    });

    m_runningTasks[taskId] = std::move(instance);
    m_runningCount++;

    if (m_onStarted) m_onStarted(taskId, TaskState::Running);

    // Run in background thread
    std::thread([this, taskId]() {
        auto it = m_runningTasks.find(taskId);
        if (it == m_runningTasks.end()) return;

        it->second->Run();
        auto result = it->second->GetResult();

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_results[taskId] = result;
        }

        m_runningCount--;

        if (result.state == TaskState::Succeeded) {
            if (m_onCompleted) m_onCompleted(taskId, TaskState::Succeeded);
        } else if (result.state == TaskState::Failed) {
            if (m_onFailed) m_onFailed(taskId, TaskState::Failed);
        }

        // Clean up running task reference
        std::lock_guard<std::mutex> lock(m_mutex);
        m_runningTasks.erase(taskId);
    }).detach();

    return &m_results[taskId];
}

TaskResult* TaskRunner::RunTaskWithDeps(const std::string& label) {
    // Execute dependencies first
    auto it = m_tasks.find(label);
    if (it == m_tasks.end()) return nullptr;

    for (const auto& dep : it->second.options.dependsOn) {
        auto depResult = RunTask(dep);
        if (depResult && depResult->state != TaskState::Succeeded) {
            // Dependency failed, skip this task
            TaskResult skipped;
            skipped.taskId = GenerateTaskId();
            skipped.state = TaskState::Skipped;
            m_results[skipped.taskId] = skipped;
            return &m_results[skipped.taskId];
        }
    }

    return RunTask(label);
}

TaskResult* TaskRunner::RunDefaultBuildTask() {
    for (const auto& [label, task] : m_tasks) {
        if (task.options.group == "build" && task.options.isDefault) {
            return RunTaskWithDeps(label);
        }
    }
    // Fallback: find any build task
    for (const auto& [label, task] : m_tasks) {
        if (task.options.group == "build") {
            return RunTaskWithDeps(label);
        }
    }
    return nullptr;
}

TaskResult* TaskRunner::RunDefaultTestTask() {
    for (const auto& [label, task] : m_tasks) {
        if (task.options.group == "test" && task.options.isDefault) {
            return RunTaskWithDeps(label);
        }
    }
    for (const auto& [label, task] : m_tasks) {
        if (task.options.group == "test") {
            return RunTaskWithDeps(label);
        }
    }
    return nullptr;
}

bool TaskRunner::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_runningTasks.find(taskId);
    if (it == m_runningTasks.end()) return false;
    it->second->Cancel();
    return true;
}

void TaskRunner::CancelAll() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& [id, instance] : m_runningTasks) {
        instance->Cancel();
    }
    m_runningTasks.clear();
    m_runningCount = 0;
}

TaskResult* TaskRunner::GetResult(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_results.find(taskId);
    return it != m_results.end() ? &it->second : nullptr;
}

std::vector<TaskResult*> TaskRunner::GetAllResults() const {
    std::vector<TaskResult*> results;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, result] : m_results) {
        results.push_back(const_cast<TaskResult*>(&result));
    }
    return results;
}

std::vector<TaskDefinition> TaskRunner::GetRegisteredTasks() const {
    std::vector<TaskDefinition> tasks;
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [label, task] : m_tasks) {
        tasks.push_back(task);
    }
    return tasks;
}

TaskDefinition* TaskRunner::GetTask(const std::string& label) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto it = m_tasks.find(label);
    return it != m_tasks.end() ? &it->second : nullptr;
}

bool TaskRunner::IsAnyRunning() const {
    return m_runningCount.load() > 0;
}

std::string TaskRunner::GenerateTaskId() {
    return "task-" + std::to_string(++m_taskCounter);
}

} // namespace Tasks
} // namespace RawrXD
