//=============================================================================
// AgenticSupervisor.hpp - Autonomous Agent Orchestration Layer
// RawrXD Sovereign Substrate - Level 4: Self-Observing, Self-Correcting
// Zero-dependency, x64-optimized, lock-free telemetry hot path
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <queue>
#include <map>
#include <unordered_set>
#include <vector>
#include <string>
#include <functional>
#include <chrono>
#include <future>

namespace RawrXD {
namespace Agentic {

//=============================================================================
// Task Priority & Status Enums
//=============================================================================
enum class TaskPriority : uint8_t {
    CRITICAL   = 0,  // System integrity tasks
    HIGH       = 1,  // User-facing operations
    NORMAL     = 2,  // Background inference
    BACKGROUND = 3   // Telemetry, compaction
};

enum class TaskStatus : uint8_t {
    PENDING    = 0,
    RUNNING    = 1,
    COMPLETED  = 2,
    FAILED     = 3,
    RETRYING   = 4,
    CANCELLED  = 5
};

//=============================================================================
// AgenticTask - The Unit of Work
//=============================================================================
struct AgenticTask {
    std::string id;                           // Unique task identifier
    std::string name;                         // Human-readable name
    std::string description;                  // Detailed description
    TaskPriority priority = TaskPriority::NORMAL;
    TaskStatus status = TaskStatus::PENDING;
    
    std::function<bool()> execute;            // The work
    std::function<void()> onSuccess;          // Completion callback
    std::function<void(const std::string&)> onFailure; // Error callback
    
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point started;
    std::chrono::steady_clock::time_point completed;
    
    int retryCount = 0;
    int maxRetries = 3;
    
    size_t estimatedMemoryMB = 0;             // For scheduling
    int estimatedTimeSeconds = 0;             // For timeout
    bool requiresCheckpoint = true;           // Auto-checkpoint before execution
};

//=============================================================================
// PerformanceMetrics - Telemetry Snapshot
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
// Interrupt & Generation Flags (Global, Lock-Free)
//=============================================================================
// These are checked at token boundaries in the Deep2 inference loop
alignas(64) extern std::atomic<bool> g_interrupt_flag;
alignas(64) extern std::atomic<bool> g_is_generating;

//=============================================================================
// AgenticSupervisor - The Orchestration Engine
//=============================================================================
class AgenticSupervisor {
public:
    struct Config {
        int maxConcurrentTasks;
        int maxQueueDepth;
        bool enableSelfHealing;
        bool enablePerformanceMonitoring;
        std::chrono::milliseconds taskTimeout;
        std::chrono::milliseconds metricsInterval;
        double targetSuccessRate;
        double maxLatencyMs;
        
        Config()
            : maxConcurrentTasks(4)
            , maxQueueDepth(100)
            , enableSelfHealing(true)
            , enablePerformanceMonitoring(true)
            , taskTimeout(30000)
            , metricsInterval(1000)
            , targetSuccessRate(0.95)
            , maxLatencyMs(100.0)
        {}
    };
    
    // Singleton access
    static AgenticSupervisor& Instance();
    
    // Lifecycle
    bool Initialize(const Config& config = Config());
    void Shutdown();
    bool IsRunning() const { return running_.load(std::memory_order_acquire); }
    
    // Task Management
    std::string SubmitTask(AgenticTask task);
    bool CancelTask(const std::string& taskId);
    AgenticTask GetTaskStatus(const std::string& taskId) const;
    
    // Convenience Wrappers
    bool ExecuteWithCheckpoint(const std::string& name,
                               std::function<bool()> operation);
    bool ExecuteWithRetry(const std::string& name,
                          std::function<bool()> operation,
                          int maxRetries = 3);
    
    // Health & Telemetry
    PerformanceMetrics GetMetrics() const;
    bool IsHealthy() const;
    std::string GetHealthReport() const;
    
    // Self-Healing Interface
    void TriggerSelfHealing(const std::string& reason);
    bool OptimizePerformance();
    
    // Event Hooks (called by Deep2Engine / PatchRegistry)
    void OnTaskStart(const std::string& taskId);
    void OnTaskComplete(const std::string& taskId, bool success);
    void OnTaskFailure(const std::string& taskId, const std::string& error);
    
private:
    AgenticSupervisor() = default;
    ~AgenticSupervisor() = default;
    AgenticSupervisor(const AgenticSupervisor&) = delete;
    AgenticSupervisor& operator=(const AgenticSupervisor&) = delete;
    
    // Worker threads
    void WorkerLoop();
    void ExecuteTaskById(const std::string& taskId);
    void CompleteTask(const std::string& taskId);
    void FailTask(const std::string& taskId, const std::string& error);
    
    // Background threads
    void MetricsLoop();
    void HealingLoop();
    
    // Priority queue comparator
    struct TaskComparator {
        bool operator()(const std::string& a, const std::string& b) const;
    };
    
    Config config_;
    std::atomic<bool> running_{false};
    
    // Task state (locked)
    mutable std::mutex tasksMutex_;
    std::map<std::string, AgenticTask> tasks_;
    std::priority_queue<std::string, std::vector<std::string>, TaskComparator> taskQueue_;
    std::unordered_set<std::string> activeTasks_;
    
    // Thread pool
    std::vector<std::thread> workers_;
    std::thread metricsThread_;
    std::thread healingThread_;
    std::condition_variable taskCv_;
    
    // Metrics (locked)
    mutable std::mutex metricsMutex_;
    PerformanceMetrics metrics_;
    std::vector<double> latencyHistory_;
    
    // Healing state
    std::atomic<bool> healingInProgress_{false};
    std::queue<std::string> healingQueue_;
    mutable std::mutex healingMutex_;
};

//=============================================================================
// ScopedAgenticTask - RAII Wrapper
//=============================================================================
class ScopedAgenticTask {
public:
    ScopedAgenticTask(const std::string& name,
                      std::function<bool()> operation,
                      bool requireCheckpoint = true);
    ~ScopedAgenticTask();
    
    bool Execute();           // Block until completion
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
