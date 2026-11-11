// ============================================================================
// MultiGPUScheduler.h - Phase 2: Multi-GPU Scheduler
// Workload scheduling and execution across multiple GPUs
// ============================================================================

#ifndef MULTI_GPU_SCHEDULER_H
#define MULTI_GPU_SCHEDULER_H

#include "GPUDeviceRegistry.h"
#include "VRAMAllocator.h"
#include <string>
#include <vector>
#include <queue>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>

namespace Deep2 {
namespace MultiGPU {

// ============================================================================
// Execution Mode
// ============================================================================
enum class ExecutionMode {
    SINGLE_GPU,           // Use one GPU
    MODEL_PARALLEL,       // Split model across GPUs
    TENSOR_PARALLEL,      // Split tensors across GPUs
    PIPELINE_PARALLEL,    // Pipeline layers across GPUs
    HYBRID                // Mix based on workload
};

// ============================================================================
// Workload Type
// ============================================================================
enum class WorkloadType {
    INFERENCE,            // Token generation
    EMBEDDING,            // Token embedding
    ATTENTION,            // Attention computation
    FFN,                  // Feed-forward network
    KV_CACHE_UPDATE,      // KV cache management
    SPECULATIVE_DECODING  // Draft model execution
};

// ============================================================================
// Execution Plan
// ============================================================================
struct ExecutionPlan {
    int primaryDevice = -1;
    int secondaryDevice = -1;
    ExecutionMode mode = ExecutionMode::SINGLE_GPU;
    
    // Layer distribution (for model parallel)
    int layerStart = 0;
    int layerEnd = 0;
    
    // Tensor sharding (for tensor parallel)
    int tensorShard = 0;
    int numShards = 1;
    
    // Memory allocation
    uint64_t estimatedVRAM = 0;
    uint64_t kvCacheSize = 0;
    
    // Performance prediction
    float predictedLatencyMs = 0.0f;
    float predictedThroughput = 0.0f;
};

// ============================================================================
// Workload Task
// ============================================================================
struct WorkloadTask {
    uint64_t id = 0;
    WorkloadType type = WorkloadType::INFERENCE;
    int priority = 0;
    
    // Input
    std::vector<float> input;
    int layerIndex = 0;
    int tokenPosition = 0;
    
    // Output
    std::vector<float> output;
    bool completed = false;
    std::string error;
    
    // Execution
    ExecutionPlan plan;
    std::chrono::steady_clock::time_point submitTime;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
};

// ============================================================================
// Scheduler Telemetry
// ============================================================================
struct SchedulerTelemetry {
    uint64_t totalTasksSubmitted = 0;
    uint64_t totalTasksCompleted = 0;
    uint64_t totalTasksFailed = 0;
    uint64_t activeTasks = 0;
    uint64_t queuedTasks = 0;
    
    double avgLatencyMs = 0.0;
    double avgThroughput = 0.0;
    double gpuUtilization = 0.0;
    double memoryUtilization = 0.0;
    
    std::chrono::steady_clock::time_point uptime;
};

// ============================================================================
// Multi-GPU Scheduler
// Manages workload distribution across multiple GPUs
// ============================================================================
class MultiGPUScheduler {
public:
    MultiGPUScheduler();
    ~MultiGPUScheduler();
    
    // Initialization
    bool Initialize(ExecutionMode defaultMode = ExecutionMode::HYBRID);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Configuration
    void SetExecutionMode(ExecutionMode mode);
    ExecutionMode GetExecutionMode() const;
    
    // Workload submission
    std::future<bool> SubmitTask(const WorkloadTask& task);
    bool SubmitTaskAsync(const WorkloadTask& task, 
                         std::function<void(const WorkloadTask&)> callback);
    
    // Execution planning
    ExecutionPlan PlanExecution(WorkloadType type, uint64_t estimatedSize);
    ExecutionPlan PlanLayerExecution(int layerIndex, int numLayers);
    ExecutionPlan PlanTensorExecution(uint64_t tensorSize);
    
    // Query
    size_t GetQueueDepth() const;
    size_t GetActiveTaskCount() const;
    SchedulerTelemetry GetTelemetry() const;
    
    // Device management
    bool SetDeviceRole(int deviceIndex, const std::string& role);
    std::string GetDeviceRole(int deviceIndex) const;
    
    // Performance optimization
    void OptimizeForLatency();
    void OptimizeForThroughput();
    void OptimizeForMemory();
    
    // Events
    using TaskCompleteCallback = std::function<void(const WorkloadTask&)>;
    void SetTaskCompleteCallback(TaskCompleteCallback cb);

private:
    bool initialized_ = false;
    ExecutionMode defaultMode_ = ExecutionMode::HYBRID;
    
    std::unique_ptr<VRAMAllocator> allocator_;
    
    // Task queue
    mutable std::mutex queueMutex_;
    std::condition_variable queueCV_;
    std::queue<WorkloadTask> taskQueue_;
    std::unordered_map<uint64_t, std::shared_ptr<std::promise<bool>>> taskPromises_;
    
    // Active tasks
    mutable std::mutex activeMutex_;
    std::unordered_map<uint64_t, WorkloadTask> activeTasks_;
    
    // Worker threads
    std::vector<std::thread> workerThreads_;
    bool stopWorkers_ = false;
    
    // Telemetry
    mutable std::mutex telemetryMutex_;
    SchedulerTelemetry telemetry_;
    
    TaskCompleteCallback onTaskComplete_;
    
    // Internal methods
    void WorkerLoop(int deviceIndex);
    bool ExecuteTask(WorkloadTask& task);
    bool ExecuteOnDevice(WorkloadTask& task, int deviceIndex);
    
    // Planning
    ExecutionMode SelectBestMode(WorkloadType type, uint64_t size);
    int SelectPrimaryDevice(WorkloadType type);
    int SelectSecondaryDevice(WorkloadType type);
    
    // Update telemetry
    void RecordTaskSubmit();
    void RecordTaskStart(const WorkloadTask& task);
    void RecordTaskComplete(const WorkloadTask& task);
    void RecordTaskFail(const WorkloadTask& task);
};

// ============================================================================
// C API
// ============================================================================
extern "C" {

__declspec(dllexport) void* MultiGPUScheduler_Create();
__declspec(dllexport) void MultiGPUScheduler_Destroy(void* scheduler);
__declspec(dllexport) bool MultiGPUScheduler_Initialize(void* scheduler);
__declspec(dllexport) bool MultiGPUScheduler_SubmitTask(void* scheduler, 
                                                          const WorkloadTask* task);
__declspec(dllexport) SchedulerTelemetry MultiGPUScheduler_GetTelemetry(void* scheduler);

} // extern "C"

} // namespace MultiGPU
} // namespace Deep2

#endif // MULTI_GPU_SCHEDULER_H
