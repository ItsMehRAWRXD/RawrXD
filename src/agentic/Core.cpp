/**
 * @file Core.cpp
 * @brief Unified Agentic Core Implementation
 * 
 * Consolidates all AgenticEngine implementations into a single,
 * coherent implementation following the 5-layer architecture.
 * 
 * @copyright RawrXD 2026
 */

#include "Core.h"
#include "../inference/InferenceEngine.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <thread>
#include <unordered_map>

// Platform-specific includes
#ifdef _WIN32
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace RawrXD {
namespace Agentic {

// Forward declarations for subsystems
class TaskSchedulerImpl;
class ToolRegistryImpl;
class HistoryRecorderImpl;
class PolicyEngineImpl;
class SubAgentManagerImpl;

// ============================================================================
// Subsystem Stub Implementations
// ============================================================================

class TaskSchedulerImpl : public TaskScheduler {
public:
    bool Initialize() override { return true; }
    void Shutdown() override {}
    std::string ScheduleTask(const Task& task) override { 
        return "task-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()); 
    }
    bool CancelTask(const std::string& taskId) override { return true; }
    TaskStatus GetTaskStatus(const std::string& taskId) override { return TaskStatus::Pending; }
    std::vector<std::string> GetActiveTasks() override { return {}; }
    void SetMaxConcurrent(size_t max) override {}
    size_t GetMaxConcurrent() const override { return 4; }
};

class ToolRegistryImpl : public ToolRegistry {
public:
    bool Initialize() override { return true; }
    void Shutdown() override {}
    bool RegisterTool(const Tool& tool) override { return true; }
    bool UnregisterTool(const std::string& toolId) override { return true; }
    std::optional<Tool> GetTool(const std::string& toolId) override { return std::nullopt; }
    std::vector<Tool> GetAllTools() override { return {}; }
    std::vector<Tool> GetToolsByCategory(ToolCategory category) override { return {}; }
    bool ExecuteTool(const std::string& toolId, const std::string& params, std::string& output) override { 
        return false; 
    }
};

class HistoryRecorderImpl : public HistoryRecorder {
public:
    bool Initialize() override { return true; }
    void Shutdown() override {}
    void RecordTask(const Task& task, const TaskResult& result) override {}
    std::vector<TaskHistoryEntry> GetHistory(size_t limit) override { return {}; }
    std::vector<TaskHistoryEntry> GetHistoryByType(TaskType type, size_t limit) override { return {}; }
    void ClearHistory() override {}
    void SetMaxHistorySize(size_t max) override {}
};

class PolicyEngineImpl : public PolicyEngine {
public:
    bool Initialize() override { return true; }
    void Shutdown() override {}
    bool ValidateTask(const Task& task, std::string& reason) override { return true; }
    bool CheckPermission(const std::string& action, const std::string& resource) override { return true; }
    void SetPolicy(PolicyType type, bool enabled) override {}
    bool GetPolicy(PolicyType type) const override { return true; }
};

class SubAgentManagerImpl : public SubAgentManager {
public:
    bool Initialize() override { return true; }
    void Shutdown() override {}
    std::string CreateSubAgent(const SubAgentConfig& config) override { return "subagent-0"; }
    bool DestroySubAgent(const std::string& agentId) override { return true; }
    std::optional<SubAgentInfo> GetSubAgentInfo(const std::string& agentId) override { return std::nullopt; }
    std::vector<SubAgentInfo> GetAllSubAgents() override { return {}; }
    bool SendMessageToSubAgent(const std::string& agentId, const std::string& message) override { return false; }
};

// ============================================================================
// Internal Implementation
// ============================================================================

class CoreImpl : public Core {
public:
    explicit CoreImpl(const CoreConfig& config);
    ~CoreImpl() override;

    // Lifecycle
    bool Initialize() override;
    bool Shutdown(std::chrono::milliseconds timeout) override;
    bool IsInitialized() const override;

    // Task Execution - Async
    std::future<TaskResult> SubmitTask(const Task& task) override;
    std::future<TaskResult> SubmitTask(const Task& task,
                                           TaskProgressCallback onProgress,
                                           TaskOutputCallback onOutput) override;
    std::vector<std::future<TaskResult>> SubmitBatch(
        const std::vector<Task>& tasks) override;

    // Task Execution - Sync
    TaskResult ExecuteSync(const Task& task) override;
    TaskResult ExecuteSync(const Task& task, std::chrono::milliseconds timeout) override;

    // Task Management
    bool CancelTask(const std::string& taskId) override;
    TaskStatus GetTaskStatus(const std::string& taskId) override;
    std::optional<TaskResult> GetTaskResult(const std::string& taskId) override;
    bool WaitForTask(const std::string& taskId, std::chrono::milliseconds timeout) override;

    // Task Queries
    size_t GetPendingCount() const override;
    size_t GetRunningCount() const override;
    size_t GetTotalTaskCount() const override;
    std::vector<std::string> GetActiveTaskIds() const override;
    std::optional<Task> GetTaskInfo(const std::string& taskId) override;

    // Event Registration
    int OnTaskStart(TaskStartCallback callback) override;
    int OnTaskComplete(TaskCompleteCallback callback) override;
    void UnregisterCallback(int callbackId) override;

    // Subsystem Access
    TaskScheduler& GetScheduler() override;
    ToolRegistry& GetToolRegistry() override;
    HistoryRecorder& GetHistory() override;
    PolicyEngine& GetPolicies() override;
    SubAgentManager& GetSubAgentManager() override;
    void SetInferenceEngine(std::shared_ptr<Inference::InferenceEngine> engine) override;
    std::shared_ptr<Inference::InferenceEngine> GetInferenceEngine() override;

    // Convenience Methods
    std::string ReadFile(const std::string& path) override;
    bool WriteFile(const std::string& path, const std::string& content) override;
    std::string ExecuteCommand(const std::string& command) override;
    std::string SearchCodebase(const std::string& query) override;
    std::string Generate(const std::string& prompt) override;

    // Diagnostics
    CoreStats GetStats() const override;
    void ResetStats() override;
    std::string GetLastError() const override;
    bool ValidateConfig() const override;

private:
    // Configuration
    CoreConfig m_config;
    
    // State
    mutable std::mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shuttingDown{false};
    std::string m_lastError;
    
    // Subsystems
    std::unique_ptr<TaskSchedulerImpl> m_scheduler;
    std::unique_ptr<ToolRegistryImpl> m_toolRegistry;
    std::unique_ptr<HistoryRecorderImpl> m_history;
    std::unique_ptr<PolicyEngineImpl> m_policies;
    std::unique_ptr<SubAgentManagerImpl> m_subAgentManager;
    std::shared_ptr<Inference::InferenceEngine> m_inferenceEngine;
    
    // Task tracking
    struct TaskEntry {
        Task task;
        TaskStatus status = TaskStatus::Pending;
        std::promise<TaskResult> promise;
        std::shared_future<TaskResult> future;
        std::chrono::steady_clock::time_point submitTime;
        std::chrono::steady_clock::time_point startTime;
        std::thread worker;
        TaskProgressCallback onProgress;
        TaskOutputCallback onOutput;
    };
    
    std::unordered_map<std::string, std::shared_ptr<TaskEntry>> m_tasks;
    std::queue<std::shared_ptr<TaskEntry>> m_pendingQueue;
    std::condition_variable m_taskAvailable;
    
    // Callbacks
    std::atomic<int> m_nextCallbackId{1};
    std::unordered_map<int, TaskStartCallback> m_startCallbacks;
    std::unordered_map<int, TaskCompleteCallback> m_completeCallbacks;
    
    // Statistics
    mutable std::atomic<int64_t> m_tasksSubmitted{0};
    mutable std::atomic<int64_t> m_tasksCompleted{0};
    mutable std::atomic<int64_t> m_tasksFailed{0};
    mutable std::atomic<int64_t> m_tasksCancelled{0};
    
    // Worker threads
    std::vector<std::thread> m_workers;
    
    // Internal Methods
    void WorkerLoop();
    TaskResult ExecuteTaskInternal(std::shared_ptr<TaskEntry> entry);
    TaskResult ExecuteFileTask(const Task& task);
    TaskResult ExecuteTerminalTask(const Task& task);
    TaskResult ExecuteSearchTask(const Task& task);
    TaskResult ExecuteInferenceTask(const Task& task);
    TaskResult ExecuteToolTask(const Task& task);
    void NotifyTaskStart(const Task& task);
    void NotifyTaskComplete(const Task& task, const TaskResult& result);
    std::string GenerateTaskId();
};

// ============================================================================
// Factory Implementation
// ============================================================================

std::unique_ptr<Core> Core::Create(const CoreConfig& config) {
    return std::make_unique<CoreImpl>(config);
}

std::unique_ptr<Core> Core::Create() {
    return Create(CoreConfig{});
}

std::unique_ptr<Core> Core::CreateLegacyAdapter(
    void* legacyEngine,
    const CoreConfig& config) {
    // Forward declaration - implementation is in LegacyCoreAdapter.cpp
    // This avoids circular dependency
    extern std::unique_ptr<Core> CreateLegacyCoreAdapter(void* engine, const CoreConfig& cfg);
    return CreateLegacyCoreAdapter(legacyEngine, config);
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

CoreImpl::CoreImpl(const CoreConfig& config)
    : m_config(config)
    , m_scheduler(std::make_unique<TaskSchedulerImpl>())
    , m_toolRegistry(std::make_unique<ToolRegistryImpl>())
    , m_history(std::make_unique<HistoryRecorderImpl>())
    , m_policies(std::make_unique<PolicyEngineImpl>())
    , m_subAgentManager(std::make_unique<SubAgentManagerImpl>()) {
}

CoreImpl::~CoreImpl() {
    if (m_initialized) {
        Shutdown(std::chrono::milliseconds{5000});
    }
}

// ============================================================================
// Lifecycle
// ============================================================================

bool CoreImpl::Initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_initialized) {
        return true;
    }
    
    // Initialize subsystems
    // TODO: Initialize actual subsystem implementations
    
    // Start worker threads
    size_t numWorkers = m_config.maxConcurrentTasks;
    if (numWorkers == 0) {
        numWorkers = std::thread::hardware_concurrency();
    }
    
    for (size_t i = 0; i < numWorkers; ++i) {
        m_workers.emplace_back(&CoreImpl::WorkerLoop, this);
    }
    
    m_initialized = true;
    return true;
}

bool CoreImpl::Shutdown(std::chrono::milliseconds timeout) {
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_shuttingDown = true;
    }
    
    m_taskAvailable.notify_all();
    
    // Wait for workers to finish
    auto deadline = std::chrono::steady_clock::now() + timeout;
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            auto remaining = deadline - std::chrono::steady_clock::now();
            if (remaining.count() > 0) {
                // Note: Can't actually timeout join in standard C++
                // This is simplified
                worker.join();
            }
        }
    }
    
    m_initialized = false;
    return true;
}

bool CoreImpl::IsInitialized() const {
    return m_initialized;
}

// ============================================================================
// Task Execution - Async
// ============================================================================

std::future<TaskResult> CoreImpl::SubmitTask(const Task& task) {
    return SubmitTask(task, nullptr, nullptr);
}

std::future<TaskResult> CoreImpl::SubmitTask(const Task& task,
                                               TaskProgressCallback onProgress,
                                               TaskOutputCallback onOutput) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) {
        std::promise<TaskResult> promise;
        TaskResult result;
        result.success = false;
        result.errorMessage = "Core not initialized";
        promise.set_value(result);
        return promise.get_future();
    }
    
    auto entry = std::make_shared<TaskEntry>();
    entry->task = task;
    entry->task.id = task.id.empty() ? GenerateTaskId() : task.id;
    entry->task.submitTime = std::chrono::steady_clock::now();
    entry->status = TaskStatus::Pending;
    entry->submitTime = entry->task.submitTime;
    entry->onProgress = onProgress;
    entry->onOutput = onOutput;
    
    // Create future before moving promise
    std::future<TaskResult> future = entry->promise.get_future();
    entry->future = future.share();
    
    m_tasks[entry->task.id] = entry;
    m_pendingQueue.push(entry);
    m_tasksSubmitted++;
    
    m_taskAvailable.notify_one();
    
    // Return future (promise is stored in entry)
    // Need to return the future from the promise
    return std::move(future);
}

std::vector<std::future<TaskResult>> CoreImpl::SubmitBatch(
    const std::vector<Task>& tasks) {
    std::vector<std::future<TaskResult>> futures;
    futures.reserve(tasks.size());
    
    for (const auto& task : tasks) {
        futures.push_back(SubmitTask(task));
    }
    
    return futures;
}

// ============================================================================
// Task Execution - Sync
// ============================================================================

TaskResult CoreImpl::ExecuteSync(const Task& task) {
    return ExecuteSync(task, m_config.defaultTaskTimeout);
}

TaskResult CoreImpl::ExecuteSync(const Task& task, std::chrono::milliseconds timeout) {
    auto future = SubmitTask(task);
    
    if (future.wait_for(timeout) == std::future_status::timeout) {
        CancelTask(task.id);
        TaskResult result;
        result.success = false;
        result.errorMessage = "Task timed out";
        result.status = TaskStatus::Timeout;
        return result;
    }
    
    return future.get();
}

// ============================================================================
// Task Management
// ============================================================================

bool CoreImpl::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return false;
    }
    
    auto& entry = it->second;
    if (entry->status == TaskStatus::Pending) {
        entry->status = TaskStatus::Cancelled;
        TaskResult result;
        result.success = false;
        result.errorMessage = "Task cancelled";
        result.status = TaskStatus::Cancelled;
        result.taskId = taskId;
        entry->promise.set_value(result);
        m_tasksCancelled++;
        return true;
    }
    
    // Can't cancel running tasks easily without more infrastructure
    return false;
}

TaskStatus CoreImpl::GetTaskStatus(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return TaskStatus::Failed;
    }
    
    return it->second->status;
}

std::optional<TaskResult> CoreImpl::GetTaskResult(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return std::nullopt;
    }
    
    auto& entry = it->second;
    if (entry->status != TaskStatus::Completed && 
        entry->status != TaskStatus::Failed &&
        entry->status != TaskStatus::Cancelled &&
        entry->status != TaskStatus::Timeout) {
        return std::nullopt;
    }
    
    // Get result from future
    if (entry->future.valid()) {
        try {
            return entry->future.get();
        } catch (...) {
            return std::nullopt;
        }
    }
    
    return std::nullopt;
}

bool CoreImpl::WaitForTask(const std::string& taskId, std::chrono::milliseconds timeout) {
    auto future = GetTaskResult(taskId);
    if (future.has_value()) {
        return true;
    }
    
    // Poll until timeout
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - start < timeout) {
        future = GetTaskResult(taskId);
        if (future.has_value()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    return false;
}

// ============================================================================
// Task Queries
// ============================================================================

size_t CoreImpl::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pendingQueue.size();
}

size_t CoreImpl::GetRunningCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count = 0;
    for (const auto& [id, entry] : m_tasks) {
        if (entry->status == TaskStatus::Running) {
            count++;
        }
    }
    return count;
}

size_t CoreImpl::GetTotalTaskCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_tasks.size();
}

std::vector<std::string> CoreImpl::GetActiveTaskIds() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::vector<std::string> ids;
    for (const auto& [id, entry] : m_tasks) {
        if (entry->status == TaskStatus::Pending || entry->status == TaskStatus::Running) {
            ids.push_back(id);
        }
    }
    return ids;
}

std::optional<Task> CoreImpl::GetTaskInfo(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_tasks.find(taskId);
    if (it == m_tasks.end()) {
        return std::nullopt;
    }
    
    return it->second->task;
}

// ============================================================================
// Event Registration
// ============================================================================

int CoreImpl::OnTaskStart(TaskStartCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    int id = m_nextCallbackId++;
    m_startCallbacks[id] = callback;
    return id;
}

int CoreImpl::OnTaskComplete(TaskCompleteCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    int id = m_nextCallbackId++;
    m_completeCallbacks[id] = callback;
    return id;
}

void CoreImpl::UnregisterCallback(int callbackId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_startCallbacks.erase(callbackId);
    m_completeCallbacks.erase(callbackId);
}

// ============================================================================
// Subsystem Access
// ============================================================================

TaskScheduler& CoreImpl::GetScheduler() {
    return *m_scheduler;
}

ToolRegistry& CoreImpl::GetToolRegistry() {
    return *m_toolRegistry;
}

HistoryRecorder& CoreImpl::GetHistory() {
    return *m_history;
}

PolicyEngine& CoreImpl::GetPolicies() {
    return *m_policies;
}

SubAgentManager& CoreImpl::GetSubAgentManager() {
    return *m_subAgentManager;
}

void CoreImpl::SetInferenceEngine(std::shared_ptr<Inference::InferenceEngine> engine) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_inferenceEngine = engine;
}

std::shared_ptr<Inference::InferenceEngine> CoreImpl::GetInferenceEngine() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_inferenceEngine;
}

// ============================================================================
// Convenience Methods
// ============================================================================

std::string CoreImpl::ReadFile(const std::string& path) {
    Task task;
    task.type = TaskType::File;
    task.instruction = "read " + path;
    task.fileParams.operation = "read";
    task.fileParams.path = path;
    
    auto result = ExecuteSync(task);
    if (result.success) {
        return result.output;
    }
    return "";
}

bool CoreImpl::WriteFile(const std::string& path, const std::string& content) {
    Task task;
    task.type = TaskType::File;
    task.instruction = "write " + path;
    task.fileParams.operation = "write";
    task.fileParams.path = path;
    task.fileParams.content = content;
    
    auto result = ExecuteSync(task);
    return result.success;
}

std::string CoreImpl::ExecuteCommand(const std::string& command) {
    Task task;
    task.type = TaskType::Terminal;
    task.instruction = command;
    task.terminalParams.command = command;
    
    auto result = ExecuteSync(task);
    if (result.success) {
        return result.output;
    }
    return result.errorMessage;
}

std::string CoreImpl::SearchCodebase(const std::string& query) {
    Task task;
    task.type = TaskType::Search;
    task.instruction = query;
    task.searchParams.query = query;
    
    auto result = ExecuteSync(task);
    if (result.success) {
        return result.output;
    }
    return "";
}

std::string CoreImpl::Generate(const std::string& prompt) {
    if (!m_inferenceEngine) {
        return "Error: No inference engine set";
    }
    
    Inference::GenerationParams params;
    auto result = m_inferenceEngine->Generate(prompt, params);
    if (result.success) {
        return result.text;
    }
    return "Error: " + result.errorMessage;
}

// ============================================================================
// Diagnostics
// ============================================================================

CoreStats CoreImpl::GetStats() const {
    CoreStats stats{};
    stats.tasksSubmitted = m_tasksSubmitted.load();
    stats.tasksCompleted = m_tasksCompleted.load();
    stats.tasksFailed = m_tasksFailed.load();
    stats.tasksCancelled = m_tasksCancelled.load();
    return stats;
}

void CoreImpl::ResetStats() {
    m_tasksSubmitted = 0;
    m_tasksCompleted = 0;
    m_tasksFailed = 0;
    m_tasksCancelled = 0;
}

std::string CoreImpl::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastError;
}

bool CoreImpl::ValidateConfig() const {
    // Check workspace root exists
    if (!m_config.workspaceRoot.empty()) {
        if (!std::filesystem::exists(m_config.workspaceRoot)) {
            return false;
        }
    }
    
    // Check reasonable thread count
    if (m_config.maxConcurrentTasks > 256) {
        return false;
    }
    
    return true;
}

// ============================================================================
// Internal Methods
// ============================================================================

void CoreImpl::WorkerLoop() {
    while (!m_shuttingDown) {
        std::shared_ptr<TaskEntry> entry;
        
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_taskAvailable.wait(lock, [this] {
                return !m_pendingQueue.empty() || m_shuttingDown;
            });
            
            if (m_shuttingDown) {
                return;
            }
            
            if (!m_pendingQueue.empty()) {
                entry = m_pendingQueue.front();
                m_pendingQueue.pop();
                entry->status = TaskStatus::Running;
                entry->startTime = std::chrono::steady_clock::now();
            }
        }
        
        if (entry) {
            NotifyTaskStart(entry->task);
            auto result = ExecuteTaskInternal(entry);
            entry->promise.set_value(result);
            NotifyTaskComplete(entry->task, result);
        }
    }
}

TaskResult CoreImpl::ExecuteTaskInternal(std::shared_ptr<TaskEntry> entry) {
    TaskResult result;
    result.taskId = entry->task.id;
    result.startTime = std::chrono::steady_clock::now();
    
    try {
        switch (entry->task.type) {
            case TaskType::File:
                result = ExecuteFileTask(entry->task);
                break;
            case TaskType::Terminal:
                result = ExecuteTerminalTask(entry->task);
                break;
            case TaskType::Search:
                result = ExecuteSearchTask(entry->task);
                break;
            case TaskType::Inference:
                result = ExecuteInferenceTask(entry->task);
                break;
            case TaskType::Tool:
                result = ExecuteToolTask(entry->task);
                break;
            default:
                result.success = false;
                result.errorMessage = "Unknown task type";
                break;
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = e.what();
    }
    
    result.endTime = std::chrono::steady_clock::now();
    result.durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        result.endTime - result.startTime).count();
    
    if (result.success) {
        m_tasksCompleted++;
    } else {
        m_tasksFailed++;
    }
    
    return result;
}

TaskResult CoreImpl::ExecuteFileTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    const auto& params = task.fileParams;
    std::filesystem::path resolvedPath = params.path;
    
    // Resolve relative paths
    if (resolvedPath.is_relative() && !m_config.workspaceRoot.empty()) {
        resolvedPath = std::filesystem::path(m_config.workspaceRoot) / resolvedPath;
    }
    
    // Security check
    if (m_config.sandboxFileOps) {
        auto canonical = std::filesystem::weakly_canonical(resolvedPath);
        auto workspace = std::filesystem::weakly_canonical(m_config.workspaceRoot);
        if (canonical.string().find(workspace.string()) != 0) {
            result.success = false;
            result.errorMessage = "Path outside workspace: " + params.path;
            return result;
        }
    }
    
    try {
        if (params.operation == "read") {
            std::ifstream file(resolvedPath, std::ios::binary);
            if (!file) {
                result.success = false;
                result.errorMessage = "Cannot open file: " + params.path;
                return result;
            }
            std::ostringstream content;
            content << file.rdbuf();
            result.output = content.str();
            result.success = true;
            result.bytesProcessed = result.output.size();
        }
        else if (params.operation == "write") {
            if (params.createDirs) {
                std::filesystem::create_directories(resolvedPath.parent_path());
            }
            std::ofstream file(resolvedPath, std::ios::binary);
            if (!file) {
                result.success = false;
                result.errorMessage = "Cannot write file: " + params.path;
                return result;
            }
            file << params.content;
            result.output = "Written " + std::to_string(params.content.size()) + " bytes";
            result.success = true;
            result.bytesProcessed = params.content.size();
        }
        else if (params.operation == "list") {
            std::ostringstream listing;
            for (const auto& entry : std::filesystem::directory_iterator(resolvedPath)) {
                listing << (entry.is_directory() ? "[DIR]  " : "[FILE] ")
                      << entry.path().filename().string() << "\n";
            }
            result.output = listing.str();
            result.success = true;
        }
        else if (params.operation == "delete") {
            std::filesystem::remove(resolvedPath);
            result.output = "Deleted: " + params.path;
            result.success = true;
        }
        else {
            result.success = false;
            result.errorMessage = "Unknown file operation: " + params.operation;
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = e.what();
    }
    
    return result;
}

TaskResult CoreImpl::ExecuteTerminalTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    const auto& params = task.terminalParams;
    
    // Security check
    for (const auto& blocked : m_config.blockedCommands) {
        if (params.command.find(blocked) != std::string::npos) {
            result.success = false;
            result.errorMessage = "Command blocked: " + blocked;
            return result;
        }
    }
    
#ifdef _WIN32
    // Windows implementation
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    
    HANDLE hStdOutRead, hStdOutWrite;
    CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0);
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;
    si.dwFlags = STARTF_USESTDHANDLES;
    
    std::string cmdLine = "cmd.exe /C " + params.command;
    
    BOOL success = CreateProcessA(
        nullptr,
        const_cast<LPSTR>(cmdLine.c_str()),
        nullptr,
        nullptr,
        TRUE,
        CREATE_NO_WINDOW,
        nullptr,
        params.workingDir.empty() ? nullptr : params.workingDir.c_str(),
        &si,
        &pi
    );
    
    if (!success) {
        result.success = false;
        result.errorMessage = "Failed to create process";
        return result;
    }
    
    // Read output
    CloseHandle(hStdOutWrite);
    
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    while (::ReadFile(hStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdOutRead);
    
    result.output = output;
    result.success = (exitCode == 0);
    if (!result.success) {
        result.errorMessage = "Process exited with code " + std::to_string(exitCode);
    }
#else
    // Linux implementation
    FILE* pipe = popen(params.command.c_str(), "r");
    if (!pipe) {
        result.success = false;
        result.errorMessage = "Failed to execute command";
        return result;
    }
    
    std::string output;
    char buffer[4096];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    
    int exitCode = pclose(pipe);
    result.output = output;
    result.success = (exitCode == 0);
    if (!result.success) {
        result.errorMessage = "Process exited with code " + std::to_string(exitCode);
    }
#endif
    
    return result;
}

TaskResult CoreImpl::ExecuteSearchTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    // TODO: Implement actual codebase search
    // For now, return a placeholder
    result.output = "Search not fully implemented. Query: " + task.searchParams.query;
    result.success = true;
    
    return result;
}

TaskResult CoreImpl::ExecuteInferenceTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    if (!m_inferenceEngine) {
        result.success = false;
        result.errorMessage = "No inference engine configured";
        return result;
    }
    
    Inference::GenerationParams params;
    params.temperature = task.inferenceParams.temperature;
    params.maxTokens = task.inferenceParams.maxTokens;
    params.streamOutput = task.inferenceParams.stream;
    
    auto genResult = m_inferenceEngine->Generate(task.inferenceParams.prompt, params);
    
    result.success = genResult.success;
    result.output = genResult.text;
    result.tokensGenerated = genResult.tokensGenerated;
    result.errorMessage = genResult.errorMessage;
    
    return result;
}

TaskResult CoreImpl::ExecuteToolTask(const Task& task) {
    TaskResult result;
    result.taskId = task.id;
    
    // TODO: Implement tool execution via ToolRegistry
    result.success = false;
    result.errorMessage = "Tool execution not yet implemented";
    
    return result;
}

void CoreImpl::NotifyTaskStart(const Task& task) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, callback] : m_startCallbacks) {
        if (callback) {
            try {
                callback(task);
            } catch (...) {
                // Ignore callback errors
            }
        }
    }
}

void CoreImpl::NotifyTaskComplete(const Task& task, const TaskResult& result) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [id, callback] : m_completeCallbacks) {
        if (callback) {
            try {
                callback(task, result);
            } catch (...) {
                // Ignore callback errors
            }
        }
    }
}

std::string CoreImpl::GenerateTaskId() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return "task_" + std::to_string(now) + "_" + std::to_string(counter++);
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string GenerateTaskId() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return "task_" + std::to_string(now) + "_" + std::to_string(counter++);
}

const char* GetAgenticVersion() {
    return "RawrXD Agentic Core v15.0.0";
}

const char* TaskTypeToString(TaskType type) {
    switch (type) {
        case TaskType::File: return "file";
        case TaskType::Terminal: return "terminal";
        case TaskType::Search: return "search";
        case TaskType::Inference: return "inference";
        case TaskType::Tool: return "tool";
        case TaskType::SubAgent: return "subagent";
        case TaskType::Composite: return "composite";
        case TaskType::Custom: return "custom";
        default: return "unknown";
    }
}

TaskType StringToTaskType(const std::string& str) {
    if (str == "file") return TaskType::File;
    if (str == "terminal") return TaskType::Terminal;
    if (str == "search") return TaskType::Search;
    if (str == "inference") return TaskType::Inference;
    if (str == "tool") return TaskType::Tool;
    if (str == "subagent") return TaskType::SubAgent;
    if (str == "composite") return TaskType::Composite;
    return TaskType::Custom;
}

const char* TaskStatusToString(TaskStatus status) {
    switch (status) {
        case TaskStatus::Pending: return "pending";
        case TaskStatus::Running: return "running";
        case TaskStatus::Completed: return "completed";
        case TaskStatus::Failed: return "failed";
        case TaskStatus::Cancelled: return "cancelled";
        case TaskStatus::Timeout: return "timeout";
        default: return "unknown";
    }
}

} // namespace Agentic
} // namespace RawrXD
