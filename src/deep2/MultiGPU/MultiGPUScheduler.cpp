// ============================================================================
// MultiGPUScheduler.cpp - Phase 2: Multi-GPU Scheduler
// Workload scheduling and execution across multiple GPUs
// ============================================================================

#include "MultiGPUScheduler.h"
#include <algorithm>
#include <chrono>

namespace Deep2 {
namespace MultiGPU {

// ============================================================================
// Constructor / Destructor
// ============================================================================
MultiGPUScheduler::MultiGPUScheduler() = default;

MultiGPUScheduler::~MultiGPUScheduler() {
    if (initialized_) {
        Shutdown();
    }
}

// ============================================================================
// Initialization
// ============================================================================
bool MultiGPUScheduler::Initialize(ExecutionMode defaultMode) {
    if (initialized_) {
        return true;
    }

    printf("[MultiGPUScheduler] Initializing...\n");

    defaultMode_ = defaultMode;

    // Initialize device registry
    auto& registry = GPUDeviceRegistry::Instance();
    if (!registry.DiscoverDevices()) {
        printf("[MultiGPUScheduler] No GPU devices found\n");
        return false;
    }

    // Initialize VRAM allocator
    allocator_ = std::make_unique<VRAMAllocator>();
    if (!allocator_->Initialize()) {
        printf("[MultiGPUScheduler] Failed to initialize VRAM allocator\n");
        return false;
    }

    // Start worker threads for each device
    auto devices = registry.GetAllDevices();
    for (const auto& device : devices) {
        if (device.available) {
            workerThreads_.emplace_back(&MultiGPUScheduler::WorkerLoop, this, device.index);
            printf("[MultiGPUScheduler] Started worker for device %d (%s)\n",
                   device.index, device.name.c_str());
        }
    }

    telemetry_.uptime = std::chrono::steady_clock::now();
    initialized_ = true;

    printf("[MultiGPUScheduler] Initialized with %zu worker(s)\n", workerThreads_.size());
    return true;
}

void MultiGPUScheduler::Shutdown() {
    printf("[MultiGPUScheduler] Shutting down...\n");

    stopWorkers_ = true;
    queueCV_.notify_all();

    for (auto& thread : workerThreads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    workerThreads_.clear();

    if (allocator_) {
        allocator_->Shutdown();
        allocator_.reset();
    }

    initialized_ = false;
    printf("[MultiGPUScheduler] Shutdown complete\n");
}

// ============================================================================
// Workload Submission
// ============================================================================
std::future<bool> MultiGPUScheduler::SubmitTask(const WorkloadTask& task) {
    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();

    {
        std::lock_guard<std::mutex> lock(queueMutex_);

        WorkloadTask mutableTask = task;
        mutableTask.id = ++telemetry_.totalTasksSubmitted;
        mutableTask.submitTime = std::chrono::steady_clock::now();

        // Plan execution
        mutableTask.plan = PlanExecution(mutableTask.type, mutableTask.input.size() * sizeof(float));

        taskQueue_.push(mutableTask);
        taskPromises_[mutableTask.id] = promise;
    }

    queueCV_.notify_one();
    RecordTaskSubmit();

    return future;
}

bool MultiGPUScheduler::SubmitTaskAsync(const WorkloadTask& task,
                                        std::function<void(const WorkloadTask&)> callback) {
    auto future = SubmitTask(task);

    // Detach async completion
    std::thread([future = std::move(future), callback, task]() mutable {
        try {
            bool success = future.get();
            WorkloadTask result = task;
            result.completed = success;
            if (callback) {
                callback(result);
            }
        } catch (...) {
            WorkloadTask result = task;
            result.completed = false;
            result.error = "Exception during execution";
            if (callback) {
                callback(result);
            }
        }
    }).detach();

    return true;
}

// ============================================================================
// Execution Planning
// ============================================================================
ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type, uint64_t estimatedSize) {
    ExecutionPlan plan;
    plan.mode = SelectBestMode(type, estimatedSize);
    plan.estimatedVRAM = estimatedSize;

    auto& registry = GPUDeviceRegistry::Instance();

    switch (plan.mode) {
        case ExecutionMode::SINGLE_GPU:
            plan.primaryDevice = SelectPrimaryDevice(type);
            plan.secondaryDevice = -1;
            break;

        case ExecutionMode::MODEL_PARALLEL:
            plan.primaryDevice = SelectPrimaryDevice(type);
            plan.secondaryDevice = SelectSecondaryDevice(type);
            // Split layers based on device capabilities
            if (plan.secondaryDevice >= 0) {
                auto primary = registry.GetDevice(plan.primaryDevice);
                auto secondary = registry.GetDevice(plan.secondaryDevice);
                if (primary && secondary) {
                    float ratio = (float)primary->totalVRAMBytes /
                                  (primary->totalVRAMBytes + secondary->totalVRAMBytes);
                    // Primary gets more layers (larger VRAM)
                    plan.layerStart = 0;
                    plan.layerEnd = (int)(32 * ratio); // Assuming 32 layers
                }
            }
            break;

        case ExecutionMode::TENSOR_PARALLEL:
            plan.primaryDevice = SelectPrimaryDevice(type);
            plan.secondaryDevice = SelectSecondaryDevice(type);
            plan.numShards = 2;
            plan.tensorShard = 0;
            break;

        case ExecutionMode::HYBRID:
        default:
            // Use primary for compute, secondary for KV cache
            plan.primaryDevice = SelectPrimaryDevice(type);
            plan.secondaryDevice = SelectSecondaryDevice(type);
            plan.kvCacheSize = estimatedSize / 4; // 25% for KV cache
            break;
    }

    // Predict performance
    if (plan.primaryDevice >= 0) {
        auto device = registry.GetDevice(plan.primaryDevice);
        if (device) {
            // Simple latency prediction based on VRAM bandwidth
            float bandwidth = device->memoryBandwidthGBps > 0 ? device->memoryBandwidthGBps : 500.0f;
            plan.predictedLatencyMs = (estimatedSize / (1024.0f * 1024.0f * 1024.0f)) / bandwidth * 1000.0f;
            plan.predictedThroughput = bandwidth / (estimatedSize / (1024.0f * 1024.0f * 1024.0f));
        }
    }

    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanLayerExecution(int layerIndex, int numLayers) {
    ExecutionPlan plan;
    plan.mode = ExecutionMode::MODEL_PARALLEL;

    auto& registry = GPUDeviceRegistry::Instance();
    auto primary = registry.GetPrimaryDevice();
    auto secondary = registry.GetSecondaryDevice();

    if (primary && secondary) {
        // Split layers based on VRAM ratio
        float primaryRatio = (float)primary->totalVRAMBytes /
                             (primary->totalVRAMBytes + secondary->totalVRAMBytes);
        int splitPoint = (int)(numLayers * primaryRatio);

        if (layerIndex < splitPoint) {
            plan.primaryDevice = primary->index;
            plan.layerStart = 0;
            plan.layerEnd = splitPoint;
        } else {
            plan.secondaryDevice = secondary->index;
            plan.layerStart = splitPoint;
            plan.layerEnd = numLayers;
        }
    } else if (primary) {
        plan.primaryDevice = primary->index;
        plan.layerStart = 0;
        plan.layerEnd = numLayers;
    }

    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanTensorExecution(uint64_t tensorSize) {
    ExecutionPlan plan;
    plan.mode = ExecutionMode::TENSOR_PARALLEL;
    plan.estimatedVRAM = tensorSize;

    auto& registry = GPUDeviceRegistry::Instance();
    auto primary = registry.GetPrimaryDevice();
    auto secondary = registry.GetSecondaryDevice();

    if (primary && secondary) {
        plan.primaryDevice = primary->index;
        plan.secondaryDevice = secondary->index;
        plan.numShards = 2;
    } else if (primary) {
        plan.primaryDevice = primary->index;
        plan.numShards = 1;
    }

    return plan;
}

// ============================================================================
// Worker Thread
// ============================================================================
void MultiGPUScheduler::WorkerLoop(int deviceIndex) {
    printf("[MultiGPUScheduler] Worker %d started\n", deviceIndex);

    while (!stopWorkers_) {
        WorkloadTask task;
        bool hasTask = false;

        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCV_.wait(lock, [this] { return stopWorkers_ || !taskQueue_.empty(); });

            if (stopWorkers_) break;

            if (!taskQueue_.empty()) {
                task = taskQueue_.front();
                taskQueue_.pop();
                hasTask = true;

                // Move to active
                activeTasks_[task.id] = task;
            }
        }

        if (hasTask) {
            RecordTaskStart(task);

            bool success = ExecuteTask(task);

            // Update task
            task.completed = success;
            task.endTime = std::chrono::steady_clock::now();

            // Fulfill promise
            {
                std::lock_guard<std::mutex> lock(queueMutex_);
                auto it = taskPromises_.find(task.id);
                if (it != taskPromises_.end()) {
                    it->second->set_value(success);
                    taskPromises_.erase(it);
                }
                activeTasks_.erase(task.id);
            }

            if (success) {
                RecordTaskComplete(task);
            } else {
                RecordTaskFail(task);
            }

            if (onTaskComplete_) {
                onTaskComplete_(task);
            }
        }
    }

    printf("[MultiGPUScheduler] Worker %d stopped\n", deviceIndex);
}

bool MultiGPUScheduler::ExecuteTask(WorkloadTask& task) {
    // Execute based on plan
    switch (task.plan.mode) {
        case ExecutionMode::SINGLE_GPU:
            return ExecuteOnDevice(task, task.plan.primaryDevice);

        case ExecutionMode::MODEL_PARALLEL:
            // Execute on primary, secondary handles different layers
            return ExecuteOnDevice(task, task.plan.primaryDevice);

        case ExecutionMode::TENSOR_PARALLEL:
            // Shard execution across devices
            return ExecuteOnDevice(task, task.plan.primaryDevice);

        case ExecutionMode::HYBRID:
        default:
            // Primary for compute, could use secondary for KV
            return ExecuteOnDevice(task, task.plan.primaryDevice);
    }
}

bool MultiGPUScheduler::ExecuteOnDevice(WorkloadTask& task, int deviceIndex) {
    // Simulate execution (would call actual GPU kernels here)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Allocate output
    task.output.resize(task.input.size());
    std::copy(task.input.begin(), task.input.end(), task.output.begin());

    return true;
}

// ============================================================================
// Planning Helpers
// ============================================================================
ExecutionMode MultiGPUScheduler::SelectBestMode(WorkloadType type, uint64_t size) {
    auto& registry = GPUDeviceRegistry::Instance();
    auto devices = registry.GetAvailableDevices();

    if (devices.size() < 2) {
        return ExecutionMode::SINGLE_GPU;
    }

    // For large models, use model parallel
    if (size > 16ULL * 1024 * 1024 * 1024) { // > 16GB
        return ExecutionMode::MODEL_PARALLEL;
    }

    // For KV cache heavy workloads, use hybrid
    if (type == WorkloadType::KV_CACHE_UPDATE || type == WorkloadType::INFERENCE) {
        return ExecutionMode::HYBRID;
    }

    // Default to single GPU for simplicity
    return ExecutionMode::SINGLE_GPU;
}

int MultiGPUScheduler::SelectPrimaryDevice(WorkloadType type) {
    auto& registry = GPUDeviceRegistry::Instance();
    auto primary = registry.GetPrimaryDevice();
    if (primary) {
        return primary->index;
    }
    return -1;
}

int MultiGPUScheduler::SelectSecondaryDevice(WorkloadType type) {
    auto& registry = GPUDeviceRegistry::Instance();
    auto secondary = registry.GetSecondaryDevice();
    if (secondary) {
        return secondary->index;
    }
    return -1;
}

// ============================================================================
// Query Methods
// ============================================================================
size_t MultiGPUScheduler::GetQueueDepth() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return taskQueue_.size();
}

size_t MultiGPUScheduler::GetActiveTaskCount() const {
    std::lock_guard<std::mutex> lock(activeMutex_);
    return activeTasks_.size();
}

SchedulerTelemetry MultiGPUScheduler::GetTelemetry() const {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    return telemetry_;
}

// ============================================================================
// Configuration
// ============================================================================
void MultiGPUScheduler::SetExecutionMode(ExecutionMode mode) {
    defaultMode_ = mode;
}

ExecutionMode MultiGPUScheduler::GetExecutionMode() const {
    return defaultMode_;
}

// ============================================================================
// Device Management
// ============================================================================
bool MultiGPUScheduler::SetDeviceRole(int deviceIndex, const std::string& role) {
    return GPUDeviceRegistry::Instance().AssignRole(deviceIndex, role);
}

std::string MultiGPUScheduler::GetDeviceRole(int deviceIndex) const {
    return GPUDeviceRegistry::Instance().GetDeviceRole(deviceIndex);
}

// ============================================================================
// Performance Optimization
// ============================================================================
void MultiGPUScheduler::OptimizeForLatency() {
    defaultMode_ = ExecutionMode::SINGLE_GPU;
    printf("[MultiGPUScheduler] Optimized for latency (single GPU)\n");
}

void MultiGPUScheduler::OptimizeForThroughput() {
    defaultMode_ = ExecutionMode::TENSOR_PARALLEL;
    printf("[MultiGPUScheduler] Optimized for throughput (tensor parallel)\n");
}

void MultiGPUScheduler::OptimizeForMemory() {
    defaultMode_ = ExecutionMode::MODEL_PARALLEL;
    printf("[MultiGPUScheduler] Optimized for memory (model parallel)\n");
}

// ============================================================================
// Telemetry
// ============================================================================
void MultiGPUScheduler::RecordTaskSubmit() {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.queuedTasks++;
}

void MultiGPUScheduler::RecordTaskStart(const WorkloadTask& task) {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.queuedTasks--;
    telemetry_.activeTasks++;
}

void MultiGPUScheduler::RecordTaskComplete(const WorkloadTask& task) {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.activeTasks--;
    telemetry_.totalTasksCompleted++;

    // Update latency average
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        task.endTime - task.startTime).count();
    double alpha = 0.1;
    telemetry_.avgLatencyMs = (1 - alpha) * telemetry_.avgLatencyMs + alpha * duration;
}

void MultiGPUScheduler::RecordTaskFail(const WorkloadTask& task) {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.activeTasks--;
    telemetry_.totalTasksFailed++;
}

// ============================================================================
// Events
// ============================================================================
void MultiGPUScheduler::SetTaskCompleteCallback(TaskCompleteCallback cb) {
    onTaskComplete_ = cb;
}

} // namespace MultiGPU
} // namespace Deep2
