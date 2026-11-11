//=============================================================================
// AgenticSupervisor.hpp - Autonomous Agent Orchestration Layer
// Closes the loop between instrumentation and action
//=============================================================================

#pragma once

#include <memory>
#include <functional>
#include <queue>
#include <mutex>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <chrono>
#include <vector>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <future>
#include <numeric>
#include <string>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <random>

// Sovereign Lifecycle Integration
#include "../sovereign/IDE_Lifecycle_Hook.hpp"

namespace RawrXD {
namespace Agentic {

//=============================================================================
// Task Priority & Status
//=============================================================================
enum class TaskPriority {
    CRITICAL = 0,
    HIGH = 1,
    NORMAL = 2,
    BACKGROUND = 3
};

enum class TaskStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    RETRYING,
    CANCELLED
};

//=============================================================================
// Agent Identity Layer (1. Agent Identity)
//=============================================================================
enum class AgentRole {
    PLANNER,
    CODER,
    REVIEWER,
    DEBUGGER,
    SECURITY,
    OPTIMIZER,
    BUILD,
    TEST
};

std::string AgentRoleToString(AgentRole role);

struct AgentIdentity {
    uint64_t id;
    AgentRole role;
    std::vector<std::string> capabilities;
    int trustLevel;
    
    AgentIdentity() : id(0), role(AgentRole::PLANNER), trustLevel(5) {}
    
    static AgentIdentity Create(AgentRole role, int trustLevel = 5);
};

//=============================================================================
// Tool Invocation Layer (2. Tool Invocation)
//=============================================================================
struct ToolCall {
    std::string tool;
    std::string arguments;
    bool requiresApproval;
    
    ToolCall() : requiresApproval(false) {}
    ToolCall(const std::string& t, const std::string& args, bool approval = false)
        : tool(t), arguments(args), requiresApproval(approval) {}
};

using ToolHandler = std::function<bool(const std::string& arguments)>;

class AgentToolRuntime {
public:
    bool Execute(const ToolCall& call);
    void RegisterTool(const std::string& name, ToolHandler handler);
    
private:
    std::unordered_map<std::string, ToolHandler> toolHandlers_;
};

//=============================================================================
// Anti-Hallucination Validation (3. Reality Validator)
//=============================================================================
class RealityValidator {
public:
    bool Validate(const ToolCall& call);
    
private:
    bool FileExists(const std::string& path);
    bool VerifyBinarySignature(const std::string& path);
};

//=============================================================================
// Performance Metrics
//=============================================================================
struct PerformanceMetrics {
    double tasksPerSecond = 0.0;
    double averageLatencyMs = 0.0;
    double successRate = 1.0;
    size_t activeTasks = 0;
    size_t queuedTasks = 0;
    size_t completedTasks = 0;
    size_t failedTasks = 0;
    double cpuUtilization = 0.0;
    double memoryUtilization = 0.0;
    size_t pageFaults = 0;
    int checkpointsCreated = 0;
    int sessionBranches = 0;
    double lastBurnInLatency = 0.0;
};

//=============================================================================
// Autonomous Context Injection (4. Context Injection)
//=============================================================================
struct AgentContext {
    std::string workspace;
    std::vector<std::string> openFiles;
    std::vector<std::string> recentErrors;
    PerformanceMetrics metrics;
    std::vector<std::string> availableTools;
    
    static AgentContext Gather();
    static std::string BuildPrompt(const AgentContext& ctx);
};

//=============================================================================
// Agent Graph Execution (5. Agent Graph)
//=============================================================================
struct AgentNode {
    uint64_t id;
    std::string name;
    std::vector<uint64_t> dependencies;
    AgentIdentity owner;
    std::vector<ToolCall> plan;
    std::function<bool()> action;
};

struct AgentGraph {
    std::vector<AgentNode> nodes;
    std::string goal;
};

class AgentGraphRuntime {
public:
    bool ExecuteGraph(const AgentGraph& graph);
};

//=============================================================================
// IDE Event Hooks (7. IDE Integration)
//=============================================================================
enum class IDEEvent {
    FILE_CHANGED,
    BUILD_FAILED,
    TEST_FAILED,
    CRASH_DETECTED,
    MODEL_LOADED,
    WORKSPACE_OPENED
};

//=============================================================================
// Autonomous Permission Levels (8. Permission Levels)
//=============================================================================
enum class AutonomyLevel {
    OBSERVE,        // Read-only monitoring
    SUGGEST,        // Can suggest but not execute
    PATCH,          // Can modify code with approval
    EXECUTE,        // Can execute tools
    FULL_AUTONOMOUS // Complete autonomy
};

//=============================================================================
// Agentic Task Definition (Enhanced with Agent Identity & Tool Plan)
//=============================================================================
class AgenticTask {
public:
    std::string id;
    std::string name;
    std::string description;
    TaskPriority priority;
    TaskStatus status;
    
    // Agent Identity (1. Agent Identity)
    AgentIdentity owner;
    
    // Tool Plan (2. Tool Invocation)
    std::vector<ToolCall> plan;
    
    // Direct execution (fallback)
    std::function<bool()> execute;
    std::function<void()> onSuccess;
    std::function<void(const std::string&)> onFailure;
    
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point completed;
    int retryCount;
    int maxRetries;
    
    size_t estimatedMemoryMB;
    int estimatedTimeSeconds;
    bool requiresCheckpoint;
    AutonomyLevel autonomyLevel;
    
    AgenticTask()
        : priority(TaskPriority::NORMAL)
        , status(TaskStatus::PENDING)
        , created(std::chrono::steady_clock::now())
        , retryCount(0)
        , maxRetries(3)
        , estimatedMemoryMB(0)
        , estimatedTimeSeconds(0)
        , requiresCheckpoint(true)
        , autonomyLevel(AutonomyLevel::SUGGEST)
    {}
};

//=============================================================================
// Agentic Supervisor - The "Brain" of the System
//=============================================================================
class AgenticSupervisor {
public:
    struct Config {
        int maxConcurrentTasks = 4;
        int maxQueueDepth = 100;
        bool enableSelfHealing = true;
        bool enablePerformanceMonitoring = true;
        std::chrono::milliseconds taskTimeout{30000};
        std::chrono::milliseconds metricsInterval{1000};
        double targetSuccessRate = 0.95;
        double maxLatencyMs = 100.0;
    };
    
    static AgenticSupervisor& Instance();
    
    bool Initialize(const Config& config = Config());
    void Shutdown();
    bool IsRunning() const { return running_.load(); }
    
    std::string SubmitTask(AgenticTask task);
    bool CancelTask(const std::string& taskId);
    AgenticTask GetTaskStatus(const std::string& taskId) const;
    
    bool ExecuteWithCheckpoint(const std::string& name, 
                               std::function<bool()> operation);
    bool ExecuteWithRetry(const std::string& name,
                          std::function<bool()> operation,
                          int maxRetries = 3);
    
    PerformanceMetrics GetMetrics() const;
    bool IsHealthy() const;
    std::string GetHealthReport() const;
    
    void TriggerSelfHealing(const std::string& reason);
    bool OptimizePerformance();
    
    void OnTaskStart(const std::string& taskId);
    void OnTaskComplete(const std::string& taskId, bool success);
    void OnTaskFailure(const std::string& taskId, const std::string& error);
    
private:
    AgenticSupervisor() = default;
    ~AgenticSupervisor() = default;
    
    AgenticSupervisor(const AgenticSupervisor&) = delete;
    AgenticSupervisor& operator=(const AgenticSupervisor&) = delete;
    
    void WorkerLoop(int workerId);
    void MetricsLoop();
    void HealingLoop();
    
    void ExecuteTask(AgenticTask& task);
    void ExecuteTaskById(const std::string& taskId);
    void CompleteTask(const std::string& taskId);
    void FailTask(const std::string& taskId, const std::string& error);
    void RetryTask(const std::string& taskId);
    
public:
    uint64_t GenerateTaskId();
    
    // IDE Event Hooks
    void InitializeIDEHooks();
    void OnIDEEvent(IDEEvent event, const std::string& data);
    void SubmitDebugTask(const std::string& errorInfo);
    void SubmitRepairTask(const std::string& testInfo);
    
    struct TaskComparator {
        bool operator()(const std::string& a, const std::string& b) const;
    };
    
    Config config_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};
    std::atomic<uint64_t> nextTaskId_{1};
    
    mutable std::mutex tasksMutex_;
    std::map<std::string, AgenticTask> tasks_;
    std::priority_queue<std::string, std::vector<std::string>, TaskComparator> taskQueue_;
    std::unordered_set<std::string> activeTasks_;
    
    std::vector<std::thread> workers_;
    std::thread metricsThread_;
    std::thread healingThread_;
    std::condition_variable taskCv_;
    
    PerformanceMetrics metrics_;
    std::vector<double> latencyHistory_;
    mutable std::mutex latencyMutex_;
    
    std::atomic<bool> healingInProgress_{false};
    std::queue<std::string> healingQueue_;
    mutable std::mutex healingMutex_;
};

//=============================================================================
// Scoped Agentic Task - RAII wrapper
//=============================================================================
class ScopedAgenticTask {
public:
    ScopedAgenticTask(const std::string& name, 
                      std::function<bool()> operation,
                      bool requireCheckpoint = true);
    ~ScopedAgenticTask();
    
    bool Execute();
    bool WasSuccessful() const { return success_; }
    
private:
    std::string taskId_;
    std::function<bool()> operation_;
    bool requireCheckpoint_;
    bool success_;
    bool executed_;
};

//=============================================================================
// Convenience Macros
//=============================================================================
#define AGENTIC_TASK(name, code) \
    do { \
        auto _task_result = RawrXD::Agentic::AgenticSupervisor::Instance().ExecuteWithCheckpoint( \
            name, [&]() -> bool { code; return true; }); \
        if (!_task_result) { \
            printf("[AGENTIC] Task '%s' failed\n", name); \
        } \
    } while(0)

#define AGENTIC_TASK_RETRY(name, retries, code) \
    do { \
        auto _task_result = RawrXD::Agentic::AgenticSupervisor::Instance().ExecuteWithRetry( \
            name, [&]() -> bool { code; return true; }, retries); \
        if (!_task_result) { \
            printf("[AGENTIC] Task '%s' failed after %d retries\n", name, retries); \
        } \
    } while(0)

} // namespace Agentic
} // namespace RawrXD
