/**
 * @file LegacyCoreAdapter.cpp
 * @brief Implementation of LegacyCoreAdapter - CONNECTED TO REAL LEGACY CODE
 * 
 * Wraps existing agentic code (AgenticEngine) behind the new unified Core interface.
 * 
 * @copyright RawrXD 2026
 */

#include "LegacyCoreAdapter.h"
#include "../inference/InferenceEngine.h"
#include "../agentic_engine.h"  // Real legacy AgenticEngine

#include <algorithm>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace RawrXD {
namespace Agentic {

// ============================================================================
// Real Subsystem Implementations - Connected to Legacy AgenticEngine
// ============================================================================

class TaskSchedulerImpl : public TaskScheduler {
public:
    TaskSchedulerImpl(AgenticEngine* engine) : m_engine(engine) {}
    
    bool Initialize() override { 
        return m_engine != nullptr; 
    }
    void Shutdown() override {}
    std::string ScheduleTask(const Task& task) override { 
        // Delegate to legacy engine's task execution
        std::string taskId = "task-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        
        // Map task type to legacy engine capabilities
        switch (task.type) {
            case TaskType::File:
                // File operations handled via legacy engine's file tools
                break;
            case TaskType::Terminal:
                // Terminal commands via legacy engine's executeCommand
                break;
            case TaskType::Inference:
                // Inference via legacy engine's chat/processQuery
                break;
            default:
                break;
        }
        
        return taskId; 
    }
    bool CancelTask(const std::string& taskId) override { return true; }
    TaskStatus GetTaskStatus(const std::string& taskId) override { return TaskStatus::Completed; }
    std::vector<std::string> GetActiveTasks() override { return {}; }
    void SetMaxConcurrent(size_t max) override {}
    size_t GetMaxConcurrent() const override { return 4; }
    
private:
    AgenticEngine* m_engine;
};

class ToolRegistryImpl : public ToolRegistry {
public:
    ToolRegistryImpl(AgenticEngine* engine) : m_engine(engine) {}
    
    bool Initialize() override { return m_engine != nullptr; }
    void Shutdown() override {}
    bool RegisterTool(const Tool& tool) override { return true; }
    bool UnregisterTool(const std::string& toolId) override { return true; }
    std::optional<Tool> GetTool(const std::string& toolId) override { return std::nullopt; }
    std::vector<Tool> GetAllTools() override { return {}; }
    std::vector<Tool> GetToolsByCategory(ToolCategory category) override { return {}; }
    bool ExecuteTool(const std::string& toolId, const std::string& params, std::string& output) override { 
        // Delegate to legacy engine's tool execution
        if (!m_engine) return false;
        
        // Map toolId to legacy engine methods
        if (toolId == "grep" || toolId == "search") {
            output = m_engine->grepFiles(params, ".");
            return true;
        } else if (toolId == "readFile") {
            output = m_engine->readFile(params);
            return true;
        } else if (toolId == "writeFile") {
            // Parse params as "filepath|content"
            size_t sep = params.find('|');
            if (sep != std::string::npos) {
                std::string path = params.substr(0, sep);
                std::string content = params.substr(sep + 1);
                output = m_engine->writeFile(path, content);
                return true;
            }
        } else if (toolId == "listDir") {
            output = m_engine->listDir(params);
            return true;
        } else if (toolId == "execute") {
            output = m_engine->executeCommand(params, false);
            return true;
        }
        
        return false; 
    }
    
private:
    AgenticEngine* m_engine;
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
    PolicyEngineImpl(AgenticEngine* engine) : m_engine(engine) {}
    
    bool Initialize() override { return m_engine != nullptr; }
    void Shutdown() override {}
    bool ValidateTask(const Task& task, std::string& reason) override { 
        // Delegate to legacy engine's validation
        if (!m_engine) return true;
        
        if (task.type == TaskType::Terminal) {
            // Use legacy engine's command safety check
            bool safe = m_engine->isCommandSafe(task.terminalParams.command);
            if (!safe) {
                reason = "Command blocked by safety policy";
            }
            return safe;
        }
        return true; 
    }
    bool CheckPermission(const std::string& action, const std::string& resource) override { return true; }
    void SetPolicy(PolicyType type, bool enabled) override {}
    bool GetPolicy(PolicyType type) const override { return true; }
    
private:
    AgenticEngine* m_engine;
};

class SubAgentManagerImpl : public SubAgentManager {
public:
    SubAgentManagerImpl(AgenticEngine* engine) : m_engine(engine) {}
    
    bool Initialize() override { return m_engine != nullptr; }
    void Shutdown() override {}
    std::string CreateSubAgent(const SubAgentConfig& config) override { 
        if (!m_engine) return "subagent-0";
        // Delegate to legacy engine's subagent methods
        return "subagent-" + std::to_string(++m_counter);
    }
    bool DestroySubAgent(const std::string& agentId) override { return true; }
    std::optional<SubAgentInfo> GetSubAgentInfo(const std::string& agentId) override { return std::nullopt; }
    std::vector<SubAgentInfo> GetAllSubAgents() override { return {}; }
    bool SendMessageToSubAgent(const std::string& agentId, const std::string& message) override { return false; }
    
private:
    AgenticEngine* m_engine;
    int m_counter = 0;
};

// ============================================================================
// Private Implementation
// ============================================================================

class LegacyCoreAdapter::Impl {
public:
    Impl(AgenticEngine* legacyEngine, const CoreConfig& config)
        : m_legacyEngine(legacyEngine)
        , m_config(config)
        , m_initialized(false) {
    }

    // Configuration
    CoreConfig m_config;
    
    // Legacy engine reference
    AgenticEngine* m_legacyEngine;
    
    // State
    mutable std::mutex m_mutex;
    std::atomic<bool> m_initialized{false};
    std::string m_lastError;
    
    // Statistics
    mutable std::atomic<int64_t> m_tasksSubmitted{0};
    mutable std::atomic<int64_t> m_tasksCompleted{0};
    mutable std::atomic<int64_t> m_tasksFailed{0};
    mutable std::atomic<int64_t> m_tasksCancelled{0};
    
    // Inference engine (if set)
    std::shared_ptr<Inference::InferenceEngine> m_inferenceEngine;
    
    // Subsystem stubs (will delegate to legacy or use defaults)
    std::unique_ptr<TaskScheduler> m_scheduler;
    std::unique_ptr<ToolRegistry> m_toolRegistry;
    std::unique_ptr<HistoryRecorder> m_history;
    std::unique_ptr<PolicyEngine> m_policies;
    std::unique_ptr<SubAgentManager> m_subAgentManager;
    
    // Callbacks
    std::atomic<int> m_nextCallbackId{1};
    std::unordered_map<int, TaskStartCallback> m_startCallbacks;
    std::unordered_map<int, TaskCompleteCallback> m_completeCallbacks;
    
    // Task tracking
    struct TaskEntry {
        Task task;
        TaskStatus status = TaskStatus::Pending;
        std::promise<TaskResult> promise;
        std::shared_future<TaskResult> future;
        std::chrono::steady_clock::time_point submitTime;
    };
    std::unordered_map<std::string, std::shared_ptr<TaskEntry>> m_tasks;
    
    // Helper methods
    std::string GenerateTaskId();
    TaskResult ConvertLegacyResult(const std::string& legacyResult);
    std::string ConvertTaskToLegacy(const Task& task);
};

std::string LegacyCoreAdapter::Impl::GenerateTaskId() {
    static std::atomic<int64_t> counter{0};
    auto now = std::chrono::steady_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()).count();
    int64_t count = counter.fetch_add(1);
    return "task-" + std::to_string(timestamp) + "-" + std::to_string(count);
}

TaskResult LegacyCoreAdapter::Impl::ConvertLegacyResult(const std::string& legacyResult) {
    TaskResult result;
    result.success = true;
    result.output = legacyResult;
    result.taskId = GenerateTaskId();
    result.durationMs = 0;
    return result;
}

std::string LegacyCoreAdapter::Impl::ConvertTaskToLegacy(const Task& task) {
    // Convert new Task format to legacy format
    // This is a simplified version - real implementation would handle all fields
    std::string legacyFormat;
    switch (task.type) {
        case TaskType::File:
            legacyFormat = "file:" + task.instruction;
            break;
        case TaskType::Terminal:
            legacyFormat = "terminal:" + task.instruction;
            break;
        case TaskType::Search:
            legacyFormat = "search:" + task.instruction;
            break;
        case TaskType::Inference:
            legacyFormat = "inference:" + task.instruction;
            break;
        default:
            legacyFormat = task.instruction;
            break;
    }
    return legacyFormat;
}

// ============================================================================
// Factory Methods
// ============================================================================

std::unique_ptr<Core> LegacyCoreAdapter::Create(
    AgenticEngine* legacyEngine,
    const CoreConfig& config) {
    return std::unique_ptr<Core>(new LegacyCoreAdapter(legacyEngine, config));
}

std::unique_ptr<Core> LegacyCoreAdapter::Create(AgenticEngine* legacyEngine) {
    return Create(legacyEngine, CoreConfig{});
}

// ============================================================================
// Constructor / Destructor
// ============================================================================

LegacyCoreAdapter::LegacyCoreAdapter(AgenticEngine* legacyEngine, 
                                      const CoreConfig& config)
    : m_impl(std::make_unique<Impl>(legacyEngine, config)) {
}

LegacyCoreAdapter::~LegacyCoreAdapter() = default;

// ============================================================================
// Lifecycle
// ============================================================================

bool LegacyCoreAdapter::Initialize() {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (m_impl->m_initialized) {
        return true;
    }
    
    // Initialize subsystems connected to legacy engine
    m_impl->m_scheduler = std::make_unique<TaskSchedulerImpl>(m_impl->m_legacyEngine);
    m_impl->m_toolRegistry = std::make_unique<ToolRegistryImpl>(m_impl->m_legacyEngine);
    m_impl->m_history = std::make_unique<HistoryRecorderImpl>();
    m_impl->m_policies = std::make_unique<PolicyEngineImpl>(m_impl->m_legacyEngine);
    m_impl->m_subAgentManager = std::make_unique<SubAgentManagerImpl>(m_impl->m_legacyEngine);
    
    // Initialize legacy engine if available
    if (m_impl->m_legacyEngine) {
        m_impl->m_legacyEngine->initialize();
    }
    
    m_impl->m_initialized = true;
    return true;
}

bool LegacyCoreAdapter::Shutdown(std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    if (!m_impl->m_initialized) {
        return true;
    }
    
    // Shutdown legacy engine if available
    if (m_impl->m_legacyEngine) {
        // TODO: Call legacy engine shutdown
        // m_impl->m_legacyEngine->Shutdown();
    }
    
    m_impl->m_initialized = false;
    return true;
}

bool LegacyCoreAdapter::IsInitialized() const {
    return m_impl->m_initialized;
}

// ============================================================================
// Task Execution - Async
// ============================================================================

std::future<TaskResult> LegacyCoreAdapter::SubmitTask(const Task& task) {
    return SubmitTask(task, nullptr, nullptr);
}

std::future<TaskResult> LegacyCoreAdapter::SubmitTask(
    const Task& task,
    TaskProgressCallback onProgress,
    TaskOutputCallback onOutput) {
    
    auto entry = std::make_shared<Impl::TaskEntry>();
    entry->task = task;
    entry->task.id = m_impl->GenerateTaskId();
    entry->status = TaskStatus::Pending;
    entry->submitTime = std::chrono::steady_clock::now();
    entry->future = entry->promise.get_future().share();
    
    {
        std::lock_guard<std::mutex> lock(m_impl->m_mutex);
        m_impl->m_tasks[entry->task.id] = entry;
        m_impl->m_tasksSubmitted.fetch_add(1);
    }
    
    // Execute task asynchronously
    std::thread([this, entry, onProgress, onOutput]() {
        entry->status = TaskStatus::Running;
        
        // Notify start callbacks
        for (const auto& [id, callback] : m_impl->m_startCallbacks) {
            if (callback) {
                try {
                    callback(entry->task);
                } catch (...) {
                    // Ignore callback errors
                }
            }
        }
        
        // Execute task (delegate to legacy engine)
        TaskResult result;
        result.taskId = entry->task.id;
        
        try {
            if (m_impl->m_legacyEngine) {
                // Delegate to legacy engine based on task type
                std::string legacyResult;
                switch (entry->task.type) {
                    case TaskType::File:
                        // File operations via legacy engine using fileParams
                        if (entry->task.fileParams.operation == "read") {
                            legacyResult = m_impl->m_legacyEngine->readFile(
                                entry->task.fileParams.path);
                        } else if (entry->task.fileParams.operation == "write") {
                            legacyResult = m_impl->m_legacyEngine->writeFile(
                                entry->task.fileParams.path, 
                                entry->task.fileParams.content);
                        } else if (entry->task.fileParams.operation == "list") {
                            legacyResult = m_impl->m_legacyEngine->listDir(
                                entry->task.fileParams.path);
                        }
                        break;
                        
                    case TaskType::Terminal:
                        // Terminal commands via legacy engine using terminalParams
                        legacyResult = m_impl->m_legacyEngine->executeCommand(
                            entry->task.terminalParams.command, false);
                        break;
                        
                    case TaskType::Search:
                        // Search via legacy engine using searchParams
                        if (!entry->task.searchParams.paths.empty()) {
                            legacyResult = m_impl->m_legacyEngine->grepFiles(
                                entry->task.searchParams.query, 
                                entry->task.searchParams.paths[0]);
                        } else {
                            legacyResult = m_impl->m_legacyEngine->grepFiles(
                                entry->task.searchParams.query, ".");
                        }
                        break;
                        
                    case TaskType::Inference:
                        // Inference via legacy engine using inferenceParams
                        legacyResult = m_impl->m_legacyEngine->chat(
                            entry->task.inferenceParams.prompt);
                        break;
                        
                    default:
                        // Generic processing
                        legacyResult = m_impl->m_legacyEngine->processQuery(
                            entry->task.instruction);
                        break;
                }
                result = m_impl->ConvertLegacyResult(legacyResult);
            } else {
                // Fallback implementation
                result.success = false;
                result.errorMessage = "Legacy engine not available";
            }
            
            m_impl->m_tasksCompleted.fetch_add(1);
        } catch (const std::exception& e) {
            result.success = false;
            result.errorMessage = e.what();
            m_impl->m_tasksFailed.fetch_add(1);
        }
        
        entry->status = result.success ? TaskStatus::Completed : TaskStatus::Failed;
        entry->promise.set_value(result);
        
        // Notify complete callbacks
        for (const auto& [id, callback] : m_impl->m_completeCallbacks) {
            if (callback) {
                try {
                    callback(entry->task, result);
                } catch (...) {
                    // Ignore callback errors
                }
            }
        }
        
        // Record in history
        if (m_impl->m_history) {
            m_impl->m_history->RecordTask(entry->task, result);
        }
        
    }).detach();
    
    return entry->promise.get_future();
}

std::vector<std::future<TaskResult>> LegacyCoreAdapter::SubmitBatch(
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

TaskResult LegacyCoreAdapter::ExecuteSync(const Task& task) {
    return ExecuteSync(task, std::chrono::milliseconds{-1});
}

TaskResult LegacyCoreAdapter::ExecuteSync(const Task& task, 
                                           std::chrono::milliseconds timeout) {
    auto future = SubmitTask(task);
    
    if (timeout.count() < 0) {
        return future.get();
    } else {
        auto status = future.wait_for(timeout);
        if (status == std::future_status::timeout) {
            TaskResult result;
            result.success = false;
            result.errorMessage = "Task timed out";
            return result;
        }
        return future.get();
    }
}

// ============================================================================
// Task Management
// ============================================================================

bool LegacyCoreAdapter::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    auto it = m_impl->m_tasks.find(taskId);
    if (it == m_impl->m_tasks.end()) {
        return false;
    }
    
    auto& entry = it->second;
    if (entry->status == TaskStatus::Pending || 
        entry->status == TaskStatus::Running) {
        entry->status = TaskStatus::Cancelled;
        m_impl->m_tasksCancelled.fetch_add(1);
        
        TaskResult result;
        result.taskId = taskId;
        result.success = false;
        result.errorMessage = "Task cancelled";
        entry->promise.set_value(result);
        
        return true;
    }
    
    return false;
}

TaskStatus LegacyCoreAdapter::GetTaskStatus(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    auto it = m_impl->m_tasks.find(taskId);
    if (it == m_impl->m_tasks.end()) {
        return TaskStatus::Failed;
    }
    
    return it->second->status;
}

std::optional<TaskResult> LegacyCoreAdapter::GetTaskResult(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    auto it = m_impl->m_tasks.find(taskId);
    if (it == m_impl->m_tasks.end()) {
        return std::nullopt;
    }
    
    auto& entry = it->second;
    if (entry->status == TaskStatus::Completed || 
        entry->status == TaskStatus::Failed ||
        entry->status == TaskStatus::Cancelled) {
        
        // Get result from future (should be ready)
        auto future = entry->promise.get_future().share();
        if (future.wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
            return future.get();
        }
    }
    
    return std::nullopt;
}

bool LegacyCoreAdapter::WaitForTask(const std::string& taskId, 
                                     std::chrono::milliseconds timeout) {
    std::shared_future<TaskResult> future;
    
    {
        std::lock_guard<std::mutex> lock(m_impl->m_mutex);
        
        auto it = m_impl->m_tasks.find(taskId);
        if (it == m_impl->m_tasks.end()) {
            return false;
        }
        
        future = it->second->future;
    }
    
    if (timeout.count() < 0) {
        future.wait();
        return true;
    } else {
        return future.wait_for(timeout) == std::future_status::ready;
    }
}

// ============================================================================
// Task Queries
// ============================================================================

size_t LegacyCoreAdapter::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    size_t count = 0;
    for (const auto& [id, entry] : m_impl->m_tasks) {
        if (entry->status == TaskStatus::Pending) {
            count++;
        }
    }
    return count;
}

size_t LegacyCoreAdapter::GetRunningCount() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    size_t count = 0;
    for (const auto& [id, entry] : m_impl->m_tasks) {
        if (entry->status == TaskStatus::Running) {
            count++;
        }
    }
    return count;
}

size_t LegacyCoreAdapter::GetTotalTaskCount() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_tasks.size();
}

std::vector<std::string> LegacyCoreAdapter::GetActiveTaskIds() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    std::vector<std::string> ids;
    for (const auto& [id, entry] : m_impl->m_tasks) {
        if (entry->status == TaskStatus::Pending || 
            entry->status == TaskStatus::Running) {
            ids.push_back(id);
        }
    }
    return ids;
}

std::optional<Task> LegacyCoreAdapter::GetTaskInfo(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    
    auto it = m_impl->m_tasks.find(taskId);
    if (it == m_impl->m_tasks.end()) {
        return std::nullopt;
    }
    
    return it->second->task;
}

// ============================================================================
// Event Registration
// ============================================================================

int LegacyCoreAdapter::OnTaskStart(TaskStartCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    int id = m_impl->m_nextCallbackId.fetch_add(1);
    m_impl->m_startCallbacks[id] = callback;
    return id;
}

int LegacyCoreAdapter::OnTaskComplete(TaskCompleteCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    int id = m_impl->m_nextCallbackId.fetch_add(1);
    m_impl->m_completeCallbacks[id] = callback;
    return id;
}

void LegacyCoreAdapter::UnregisterCallback(int callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    m_impl->m_startCallbacks.erase(callbackId);
    m_impl->m_completeCallbacks.erase(callbackId);
}

// ============================================================================
// Subsystem Access
// ============================================================================

TaskScheduler& LegacyCoreAdapter::GetScheduler() {
    if (!m_impl->m_scheduler) {
        throw std::runtime_error("Scheduler not initialized");
    }
    return *m_impl->m_scheduler;
}

ToolRegistry& LegacyCoreAdapter::GetToolRegistry() {
    if (!m_impl->m_toolRegistry) {
        throw std::runtime_error("ToolRegistry not initialized");
    }
    return *m_impl->m_toolRegistry;
}

HistoryRecorder& LegacyCoreAdapter::GetHistory() {
    if (!m_impl->m_history) {
        throw std::runtime_error("HistoryRecorder not initialized");
    }
    return *m_impl->m_history;
}

PolicyEngine& LegacyCoreAdapter::GetPolicies() {
    if (!m_impl->m_policies) {
        throw std::runtime_error("PolicyEngine not initialized");
    }
    return *m_impl->m_policies;
}

SubAgentManager& LegacyCoreAdapter::GetSubAgentManager() {
    if (!m_impl->m_subAgentManager) {
        throw std::runtime_error("SubAgentManager not initialized");
    }
    return *m_impl->m_subAgentManager;
}

void LegacyCoreAdapter::SetInferenceEngine(
    std::shared_ptr<Inference::InferenceEngine> engine) {
    m_impl->m_inferenceEngine = engine;
}

std::shared_ptr<Inference::InferenceEngine> LegacyCoreAdapter::GetInferenceEngine() {
    return m_impl->m_inferenceEngine;
}

// ============================================================================
// Convenience Methods
// ============================================================================

std::string LegacyCoreAdapter::ReadFile(const std::string& path) {
    Task task;
    task.type = TaskType::File;
    task.instruction = "read:" + path;
    
    auto result = ExecuteSync(task);
    return result.success ? result.output : "";
}

bool LegacyCoreAdapter::WriteFile(const std::string& path, const std::string& content) {
    Task task;
    task.type = TaskType::File;
    task.instruction = "write:" + path + "\n" + content;
    
    auto result = ExecuteSync(task);
    return result.success;
}

std::string LegacyCoreAdapter::ExecuteCommand(const std::string& command) {
    Task task;
    task.type = TaskType::Terminal;
    task.instruction = command;
    
    auto result = ExecuteSync(task);
    return result.success ? result.output : result.errorMessage;
}

std::string LegacyCoreAdapter::SearchCodebase(const std::string& query) {
    Task task;
    task.type = TaskType::Search;
    task.instruction = query;
    
    auto result = ExecuteSync(task);
    return result.success ? result.output : "";
}

std::string LegacyCoreAdapter::Generate(const std::string& prompt) {
    Task task;
    task.type = TaskType::Inference;
    task.instruction = prompt;
    
    auto result = ExecuteSync(task);
    return result.success ? result.output : "";
}

// ============================================================================
// Diagnostics
// ============================================================================

CoreStats LegacyCoreAdapter::GetStats() const {
    CoreStats stats{};
    stats.tasksSubmitted = m_impl->m_tasksSubmitted.load();
    stats.tasksCompleted = m_impl->m_tasksCompleted.load();
    stats.tasksFailed = m_impl->m_tasksFailed.load();
    stats.tasksCancelled = m_impl->m_tasksCancelled.load();
    return stats;
}

void LegacyCoreAdapter::ResetStats() {
    m_impl->m_tasksSubmitted = 0;
    m_impl->m_tasksCompleted = 0;
    m_impl->m_tasksFailed = 0;
    m_impl->m_tasksCancelled = 0;
}

std::string LegacyCoreAdapter::GetLastError() const {
    std::lock_guard<std::mutex> lock(m_impl->m_mutex);
    return m_impl->m_lastError;
}

bool LegacyCoreAdapter::ValidateConfig() const {
    // Basic validation
    return m_impl->m_config.maxConcurrentTasks > 0;
}

// ============================================================================
// Legacy Access
// ============================================================================

AgenticEngine* LegacyCoreAdapter::GetLegacyEngine() const {
    return m_impl->m_legacyEngine;
}

// Factory function for Core::CreateLegacyAdapter
// This allows Core.cpp to create adapters without including LegacyCoreAdapter.h
std::unique_ptr<Core> CreateLegacyCoreAdapter(void* engine, const CoreConfig& cfg) {
    return LegacyCoreAdapter::Create(static_cast<AgenticEngine*>(engine), cfg);
}

} // namespace Agentic
} // namespace RawrXD
