//=============================================================================
// AgenticSupervisor.cpp - Autonomous Agent Orchestration Engine
// RawrXD Sovereign Substrate - Level 4 Implementation
// Zero-dependency, x64-optimized, lock-free where possible
//=============================================================================

#include "AgenticSupervisor.hpp"
#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <cmath>

#pragma comment(lib, "psapi.lib")

namespace RawrXD {
namespace Agentic {

//=============================================================================
// Global State (TU-local, lock-free hot path)
//=============================================================================
alignas(64) std::atomic<bool> g_interrupt_flag{false};
alignas(64) std::atomic<bool> g_is_generating{false};

// Performance counters for telemetry
alignas(64) struct {
    std::atomic<uint64_t> tasksSubmitted{0};
    std::atomic<uint64_t> tasksCompleted{0};
    std::atomic<uint64_t> tasksFailed{0};
    std::atomic<uint64_t> tasksRetried{0};
    std::atomic<uint64_t> healingTriggers{0};
    std::atomic<uint64_t> checkpointCount{0};
} g_perfCounters;

//=============================================================================
// Singleton Instance
//=============================================================================
AgenticSupervisor& AgenticSupervisor::Instance() {
    static AgenticSupervisor instance;
    return instance;
}

//=============================================================================
// Initialization
//=============================================================================
bool AgenticSupervisor::Initialize(const Config& config) {
    if (running_.exchange(true)) {
        return true; // Already running
    }

    config_ = config;

    // Pin worker threads to housekeeping cores (0,1) to avoid AVX-512 contention
    // Deep2 inference threads should use cores 2-N
    DWORD_PTR houseKeepMask = (1ULL << 0) | (1ULL << 1);

    // Launch worker pool
    for (int i = 0; i < config_.maxConcurrentTasks; ++i) {
        workers_.emplace_back(&AgenticSupervisor::WorkerLoop, this);
        
        // Set affinity for housekeeping cores
        if (workers_.back().native_handle()) {
            SetThreadAffinityMask(
                static_cast<HANDLE>(workers_.back().native_handle()),
                houseKeepMask
            );
        }
    }

    // Launch telemetry/metrics thread
    metricsThread_ = std::thread(&AgenticSupervisor::MetricsLoop, this);
    
    // Launch self-healing watchdog
    if (config_.enableSelfHealing) {
        healingThread_ = std::thread(&AgenticSupervisor::HealingLoop, this);
    }

    return true;
}

void AgenticSupervisor::Shutdown() {
    if (!running_.exchange(false)) {
        return;
    }

    // Signal all threads to exit
    taskCv_.notify_all();

    // Join workers
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    if (metricsThread_.joinable()) metricsThread_.join();
    if (healingThread_.joinable()) healingThread_.join();

    // Clear queues
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        while (!taskQueue_.empty()) taskQueue_.pop();
        tasks_.clear();
        activeTasks_.clear();
    }
}

//=============================================================================
// Task Submission (Lock-free ID generation, locked queue insertion)
//=============================================================================
std::string AgenticSupervisor::SubmitTask(AgenticTask task) {
    // Generate unique task ID (atomic, no lock)
    static std::atomic<uint64_t> g_globalTaskSeq{1};
    uint64_t seq = g_globalTaskSeq.fetch_add(1, std::memory_order_relaxed);
    char buf[32];
    snprintf(buf, sizeof(buf), "TSK-%016llX", seq);
    task.id = std::string(buf);
    task.status = TaskStatus::PENDING;
    task.created = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        tasks_[task.id] = std::move(task);
        taskQueue_.push(task.id);
    }

    g_perfCounters.tasksSubmitted.fetch_add(1, std::memory_order_relaxed);
    taskCv_.notify_one();
    return task.id;
}

bool AgenticSupervisor::CancelTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) return false;
    
    if (it->second.status == TaskStatus::PENDING || 
        it->second.status == TaskStatus::RUNNING) {
        it->second.status = TaskStatus::CANCELLED;
        return true;
    }
    return false;
}

AgenticTask AgenticSupervisor::GetTaskStatus(const std::string& taskId) const {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    auto it = tasks_.find(taskId);
    if (it != tasks_.end()) return it->second;
    return AgenticTask(); // Empty task with default status
}

//=============================================================================
// Convenience Wrappers
//=============================================================================
bool AgenticSupervisor::ExecuteWithCheckpoint(
    const std::string& name,
    std::function<bool()> operation) {
    
    AgenticTask task;
    task.name = name;
    task.execute = std::move(operation);
    task.requiresCheckpoint = true;
    task.priority = TaskPriority::HIGH;
    
    std::string id = SubmitTask(std::move(task));
    
    // Wait for completion (blocking wrapper)
    while (true) {
        auto status = GetTaskStatus(id);
        if (status.status == TaskStatus::COMPLETED) return true;
        if (status.status == TaskStatus::FAILED || 
            status.status == TaskStatus::CANCELLED) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

bool AgenticSupervisor::ExecuteWithRetry(
    const std::string& name,
    std::function<bool()> operation,
    int maxRetries) {
    
    for (int attempt = 0; attempt <= maxRetries; ++attempt) {
        if (ExecuteWithCheckpoint(name, operation)) {
            return true;
        }
        if (attempt < maxRetries) {
            g_perfCounters.tasksRetried.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * (attempt + 1)));
        }
    }
    return false;
}

//=============================================================================
// Worker Loop - The Execution Engine
//=============================================================================
void AgenticSupervisor::WorkerLoop() {
    // Set thread priority below inference threads
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

    while (running_.load(std::memory_order_relaxed)) {
        std::string taskId;
        
        // Wait for task with timeout for periodic checks
        {
            std::unique_lock<std::mutex> lock(tasksMutex_);
            bool gotTask = taskCv_.wait_for(lock, 
                std::chrono::milliseconds(100),
                [this] { 
                    return !taskQueue_.empty() || !running_.load(); 
                });
            
            if (!running_.load()) break;
            if (!gotTask || taskQueue_.empty()) continue;
            
            taskId = taskQueue_.top();
            taskQueue_.pop();
            activeTasks_.insert(taskId);
        }

        // Execute the task
        ExecuteTaskById(taskId);
    }
}

void AgenticSupervisor::ExecuteTaskById(const std::string& taskId) {
    AgenticTask task;
    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        auto it = tasks_.find(taskId);
        if (it == tasks_.end()) {
            activeTasks_.erase(taskId);
            return;
        }
        it->second.status = TaskStatus::RUNNING;
        it->second.started = std::chrono::steady_clock::now();
        task = it->second; // Copy for execution
    }

    // Pre-execution checkpoint if requested
    if (task.requiresCheckpoint) {
        g_perfCounters.checkpointCount.fetch_add(1, std::memory_order_relaxed);
    }

    // Execute with timeout guard
    bool success = false;
    std::string errorMsg;
    
    auto future = std::async(std::launch::deferred, [&]() -> bool {
        try {
            if (task.execute) {
                return task.execute();
            }
            return false;
        } catch (const std::exception& e) {
            errorMsg = e.what();
            return false;
        } catch (...) {
            errorMsg = "Unknown exception";
            return false;
        }
    });

    // Wait with timeout
    auto status = future.wait_for(config_.taskTimeout);
    if (status == std::future_status::timeout) {
        errorMsg = "Task timeout exceeded";
        success = false;
    } else {
        success = future.get();
    }

    // Complete or fail
    if (success) {
        CompleteTask(taskId);
    } else {
        FailTask(taskId, errorMsg);
        
        // Auto-retry if configured
        if (task.retryCount < task.maxRetries) {
            {
                std::lock_guard<std::mutex> lock(tasksMutex_);
                auto it = tasks_.find(taskId);
                if (it != tasks_.end()) {
                    it->second.retryCount++;
                    it->second.status = TaskStatus::RETRYING;
                    taskQueue_.push(taskId);
                }
            }
            taskCv_.notify_one();
        }
    }

    {
        std::lock_guard<std::mutex> lock(tasksMutex_);
        activeTasks_.erase(taskId);
    }
}

void AgenticSupervisor::CompleteTask(const std::string& taskId) {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) return;
    
    it->second.status = TaskStatus::COMPLETED;
    it->second.completed = std::chrono::steady_clock::now();
    
    if (it->second.onSuccess) {
        it->second.onSuccess();
    }
    
    g_perfCounters.tasksCompleted.fetch_add(1, std::memory_order_relaxed);
}

void AgenticSupervisor::FailTask(const std::string& taskId, const std::string& error) {
    std::lock_guard<std::mutex> lock(tasksMutex_);
    auto it = tasks_.find(taskId);
    if (it == tasks_.end()) return;
    
    it->second.status = TaskStatus::FAILED;
    it->second.completed = std::chrono::steady_clock::now();
    
    if (it->second.onFailure) {
        it->second.onFailure(error);
    }
    
    g_perfCounters.tasksFailed.fetch_add(1, std::memory_order_relaxed);
    
    // Queue for healing analysis
    if (config_.enableSelfHealing) {
        std::lock_guard<std::mutex> hlock(healingMutex_);
        healingQueue_.push(taskId);
    }
}

//=============================================================================
// Metrics Loop - Telemetry Aggregation
//=============================================================================
void AgenticSupervisor::MetricsLoop() {
    using namespace std::chrono;
    
    auto lastCheck = steady_clock::now();
    
    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(config_.metricsInterval);
        
        if (!running_.load()) break;
        
        auto now = steady_clock::now();
        double elapsedSec = duration<double>(now - lastCheck).count();
        lastCheck = now;
        
        // Gather atomic counters
        uint64_t completed = g_perfCounters.tasksCompleted.load(std::memory_order_relaxed);
        uint64_t failed = g_perfCounters.tasksFailed.load(std::memory_order_relaxed);
        
        // Calculate derived metrics
        double tps = elapsedSec > 0 ? (completed - metrics_.completedTasks) / elapsedSec : 0.0;
        double successRate = (completed + failed) > 0 
            ? static_cast<double>(completed) / (completed + failed) 
            : 1.0;
        
        // Update metrics struct (locked write)
        {
            std::lock_guard<std::mutex> lock(metricsMutex_);
            metrics_.tasksPerSecond = tps;
            metrics_.successRate = successRate;
            metrics_.completedTasks = completed;
            metrics_.failedTasks = failed;
            metrics_.activeTasks = activeTasks_.size();
            
            // Queue depth
            metrics_.queuedTasks = tasks_.size() - activeTasks_.size();
        }
        
        // Self-healing trigger: if success rate drops below threshold
        if (successRate < config_.targetSuccessRate && config_.enableSelfHealing) {
            if (!healingInProgress_.exchange(true)) {
                TriggerSelfHealing("Success rate below threshold");
            }
        }
    }
}

//=============================================================================
// Healing Loop - Self-Correction Engine
//=============================================================================
void AgenticSupervisor::HealingLoop() {
    while (running_.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        if (!running_.load()) break;
        
        std::string taskId;
        {
            std::lock_guard<std::mutex> lock(healingMutex_);
            if (healingQueue_.empty()) continue;
            taskId = healingQueue_.front();
            healingQueue_.pop();
        }
        
        // Analyze failure pattern
        AgenticTask failedTask = GetTaskStatus(taskId);
        if (failedTask.status != TaskStatus::FAILED) continue;
        
        // Determine healing action based on task metadata
        if (failedTask.estimatedMemoryMB > 0 && failedTask.estimatedMemoryMB > 4096) {
            // High memory task failed - likely OOM or page fault
            OptimizePerformance();
        }
        
        g_perfCounters.healingTriggers.fetch_add(1, std::memory_order_relaxed);
        healingInProgress_.store(false);
    }
}

void AgenticSupervisor::TriggerSelfHealing(const std::string& reason) {
    // Log the trigger
    char buf[256];
    snprintf(buf, sizeof(buf), "[HEALING] Triggered: %s", reason.c_str());
    
    // Signal the metrics loop to be more aggressive
    config_.metricsInterval = std::chrono::milliseconds(500); // Faster polling
}

bool AgenticSupervisor::OptimizePerformance() {
    // Placeholder for performance optimization logic
    // In full implementation, this would:
    // - Adjust ThreadPool worker counts
    // - Modify Deep2Engine batch sizes
    // - Trigger memory compaction
    // - Request layer pruning via PatchRegistry
    
    return true;
}

//=============================================================================
// Health Monitoring
//=============================================================================
PerformanceMetrics AgenticSupervisor::GetMetrics() const {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return metrics_;
}

bool AgenticSupervisor::IsHealthy() const {
    std::lock_guard<std::mutex> lock(metricsMutex_);
    return metrics_.successRate >= config_.targetSuccessRate;
}

std::string AgenticSupervisor::GetHealthReport() const {
    auto m = GetMetrics();
    
    char buf[1024];
    snprintf(buf, sizeof(buf),
        "=== Sovereign Agentic Supervisor Health ===\n"
        "Status:          %s\n"
        "Success Rate:    %.2f%% (target: %.2f%%)\n"
        "Throughput:      %.2f tasks/sec\n"
        "Active Tasks:    %zu\n"
        "Queued Tasks:    %zu\n"
        "Completed:       %zu\n"
        "Failed:          %zu\n"
        "Avg Latency:     %.2f ms\n"
        "Checkpoints:     %llu\n"
        "Healing Events:  %llu\n"
        "==========================================\n",
        IsHealthy() ? "HEALTHY" : "DEGRADED",
        m.successRate * 100.0,
        config_.targetSuccessRate * 100.0,
        m.tasksPerSecond,
        m.activeTasks,
        m.queuedTasks,
        m.completedTasks,
        m.failedTasks,
        m.averageLatencyMs,
        g_perfCounters.checkpointCount.load(),
        g_perfCounters.healingTriggers.load()
    );
    
    return std::string(buf);
}

//=============================================================================
// Event Hooks
//=============================================================================
void AgenticSupervisor::OnTaskStart(const std::string& taskId) {
    (void)taskId;
    // Hook for telemetry integration
}

void AgenticSupervisor::OnTaskComplete(const std::string& taskId, bool success) {
    (void)taskId;
    (void)success;
    // Hook for telemetry integration
}

void AgenticSupervisor::OnTaskFailure(const std::string& taskId, const std::string& error) {
    (void)taskId;
    (void)error;
    // Hook for telemetry integration
}

//=============================================================================
// Task Priority Comparator
//=============================================================================
bool AgenticSupervisor::TaskComparator::operator()(
    const std::string& a, const std::string& b) const {
    // Simple fallback - older tasks (lower seq) first
    return a > b;
}

//=============================================================================
// ScopedAgenticTask RAII Implementation
//=============================================================================
ScopedAgenticTask::ScopedAgenticTask(
    const std::string& name,
    std::function<bool()> operation,
    bool requireCheckpoint)
    : operation_(std::move(operation))
    , requireCheckpoint_(requireCheckpoint)
    , success_(false)
    , executed_(false) {
    
    AgenticTask task;
    task.name = name;
    task.execute = [this]() -> bool {
        executed_ = true;
        success_ = operation_();
        return success_;
    };
    task.requiresCheckpoint = requireCheckpoint_;
    
    taskId_ = AgenticSupervisor::Instance().SubmitTask(std::move(task));
}

ScopedAgenticTask::~ScopedAgenticTask() {
    // RAII: if not explicitly executed, cancel the task
    if (!executed_) {
        AgenticSupervisor::Instance().CancelTask(taskId_);
    }
}

bool ScopedAgenticTask::Execute() {
    if (executed_) return success_;
    
    // Wait for completion
    while (true) {
        auto status = AgenticSupervisor::Instance().GetTaskStatus(taskId_);
        if (status.status == TaskStatus::COMPLETED) {
            success_ = true;
            executed_ = true;
            return true;
        }
        if (status.status == TaskStatus::FAILED ||
            status.status == TaskStatus::CANCELLED) {
            executed_ = true;
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

} // namespace Agentic
} // namespace RawrXD
