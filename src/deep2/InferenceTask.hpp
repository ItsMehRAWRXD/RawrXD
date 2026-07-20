// ============================================================================
// InferenceTask.hpp - Task Wrapper for Deep2 Inference
// Bridges Deep2Engine to AgenticSupervisor without blocking UI thread
// ============================================================================

#pragma once

#include "Deep2Engine.h"
#include "KernelDispatcher.hpp"
#include <cstdint>
#include <cstddef>
#include <functional>
#include <future>
#include <memory>

namespace Deep2 {

// Forward declaration
class AgenticSupervisor;

// ============================================================================
// Inference Task Types
// ============================================================================
enum class InferenceOp {
    LINEAR,           // Matrix-vector multiply
    LINEAR_PARALLEL,  // Parallel GEMV
    ATTENTION,        // Full attention forward
    FFN,              // Feed-forward network
    TRANSFORMER_LAYER // Complete transformer layer
};

// Task priority for scheduling
enum class TaskPriority {
    CRITICAL = 0,     // UI-blocking, must complete immediately
    HIGH = 1,         // User-visible, low latency
    NORMAL = 2,       // Background inference
    LOW = 3           // Prefetch, warmup
};

// Task status
enum class TaskStatus {
    PENDING,      // Queued but not started
    RUNNING,      // Currently executing
    COMPLETED,    // Finished successfully
    FAILED,       // Error during execution
    CANCELLED     // Cancelled before completion
};

// ============================================================================
// InferenceTask - Encapsulates a single inference operation
// ============================================================================
struct InferenceTask {
    // Operation type
    InferenceOp op = InferenceOp::LINEAR;
    
    // Weight tensor index (for LINEAR ops)
    int weightIdx = -1;
    
    // Input/output buffers
    const float* input = nullptr;
    float* output = nullptr;
    size_t outDim = 0;
    
    // Optional bias
    const float* bias = nullptr;
    
    // Execution options
    bool useParallel = true;
    TaskPriority priority = TaskPriority::NORMAL;
    
    // For transformer layer ops
    size_t layerIdx = 0;
    size_t seqLen = 1;
    
    // Callback for completion
    std::function<void(const InferenceTask&, TaskStatus)> onComplete;
    
    // Result
    TaskStatus status = TaskStatus::PENDING;
    double executionTimeMs = 0.0;
    char errorMsg[256] = {0};
    
    // Future for async waiting
    std::shared_ptr<std::promise<bool>> completionPromise;
    
    // Constructor helpers
    static InferenceTask CreateLinear(
        int weightIdx,
        const float* input,
        float* output,
        size_t outDim,
        const float* bias = nullptr,
        bool parallel = true
    );
    
    static InferenceTask CreateTransformerLayer(
        size_t layerIdx,
        const float* input,
        float* output,
        size_t hiddenDim,
        size_t seqLen = 1
    );
    
    // Wait for completion (blocking)
    bool Wait(int timeoutMs = -1);
    
    // Check if completed
    bool IsComplete() const {
        return status == TaskStatus::COMPLETED || 
               status == TaskStatus::FAILED ||
               status == TaskStatus::CANCELLED;
    }
    
    // Get result status
    bool Success() const { return status == TaskStatus::COMPLETED; }
};

// ============================================================================
// InferenceTaskQueue - Thread-safe task queue
// ============================================================================
class InferenceTaskQueue {
public:
    InferenceTaskQueue();
    ~InferenceTaskQueue();
    
    // Add task to queue
    void Enqueue(InferenceTask&& task);
    
    // Get next task (blocking with timeout)
    // Returns false if queue is shutting down
    bool Dequeue(InferenceTask& task, int timeoutMs = -1);
    
    // Get queue size
    size_t Size() const;
    
    // Clear all pending tasks
    void Clear();
    
    // Signal shutdown
    void Shutdown();
    
    // Check if shutting down
    bool IsShuttingDown() const { return shuttingDown; }

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// InferenceExecutor - Background thread for inference
// ============================================================================
class InferenceExecutor {
public:
    InferenceExecutor(Deep2Engine& engine);
    ~InferenceExecutor();
    
    // Start executor thread
    void Start();
    
    // Stop executor (graceful shutdown)
    void Stop();
    
    // Check if running
    bool IsRunning() const { return running; }
    
    // Get task queue for submitting work
    InferenceTaskQueue& GetQueue() { return queue; }
    
    // Execute task immediately (blocking)
    static bool ExecuteTask(InferenceTask& task, Deep2Engine& engine);

private:
    Deep2Engine& engine;
    InferenceTaskQueue queue;
    std::thread workerThread;
    std::atomic<bool> running{false};
    
    void WorkerLoop();
};

// ============================================================================
// SovereignInferenceBridge - Main bridge between AgenticSupervisor and Deep2
// ============================================================================
class SovereignInferenceBridge {
public:
    // Singleton access
    static SovereignInferenceBridge& Instance();
    
    // Initialize with engine
    bool Initialize(Deep2Engine* engine);
    
    // Shutdown
    void Shutdown();
    
    // Check if initialized
    bool IsInitialized() const { return initialized; }
    
    // Dispatch inference task (non-blocking)
    // Returns task ID (>=0) or -1 on error
    int DispatchTask(InferenceTask&& task);
    
    // Dispatch and wait for completion (blocking)
    bool DispatchAndWait(InferenceTask& task, int timeoutMs = -1);
    
    // Dispatch linear layer (convenience)
    int DispatchLinear(
        int weightIdx,
        const float* input,
        float* output,
        size_t outDim,
        const float* bias = nullptr,
        bool parallel = true,
        TaskPriority priority = TaskPriority::NORMAL
    );
    
    // Dispatch transformer layer (convenience)
    int DispatchTransformerLayer(
        size_t layerIdx,
        const float* input,
        float* output,
        size_t hiddenDim,
        TaskPriority priority = TaskPriority::NORMAL
    );
    
    // Get task status
    TaskStatus GetTaskStatus(int taskId);
    
    // Cancel pending task
    bool CancelTask(int taskId);
    
    // Wait for all pending tasks
    void WaitAll();
    
    // Get engine
    Deep2Engine* GetEngine() { return engine; }
    
    // Get executor
    InferenceExecutor* GetExecutor() { return executor.get(); }
    
    // Performance stats
    struct Stats {
        uint64_t tasksSubmitted = 0;
        uint64_t tasksCompleted = 0;
        uint64_t tasksFailed = 0;
        double avgLatencyMs = 0.0;
        double peakThroughputTps = 0.0;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    SovereignInferenceBridge() = default;
    ~SovereignInferenceBridge() = default;
    
    SovereignInferenceBridge(const SovereignInferenceBridge&) = delete;
    SovereignInferenceBridge& operator=(const SovereignInferenceBridge&) = delete;
    
    bool initialized = false;
    Deep2Engine* engine = nullptr;
    std::unique_ptr<InferenceExecutor> executor;
    
    // Task tracking
    std::atomic<int> nextTaskId{1};
    std::unordered_map<int, std::shared_ptr<InferenceTask>> activeTasks;
    mutable std::mutex taskMutex;
    
    // Stats
    mutable std::mutex statsMutex;
    Stats stats;
    
    void UpdateStats(const InferenceTask& task);
};

// ============================================================================
// Convenience Macros for Agentic Integration
// ============================================================================

// Dispatch linear operation via bridge
#define SOVEREIGN_LINEAR(weightIdx, input, output, outDim) \
    Deep2::SovereignInferenceBridge::Instance().DispatchLinear( \
        weightIdx, input, output, outDim, nullptr, true, Deep2::TaskPriority::NORMAL)

// Dispatch with bias
#define SOVEREIGN_LINEAR_BIAS(weightIdx, input, bias, output, outDim) \
    Deep2::SovereignInferenceBridge::Instance().DispatchLinear( \
        weightIdx, input, output, outDim, bias, true, Deep2::TaskPriority::NORMAL)

// Dispatch critical (UI-blocking) operation
#define SOVEREIGN_LINEAR_CRITICAL(weightIdx, input, output, outDim) \
    Deep2::SovereignInferenceBridge::Instance().DispatchLinear( \
        weightIdx, input, output, outDim, nullptr, false, Deep2::TaskPriority::CRITICAL)

// Wait for all pending inference
#define SOVEREIGN_SYNC() \
    Deep2::SovereignInferenceBridge::Instance().WaitAll()

} // namespace Deep2
