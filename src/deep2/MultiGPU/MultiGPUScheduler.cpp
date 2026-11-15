// ============================================================================
// MultiGPUScheduler.cpp - Phase 2: Multi-GPU Scheduler
// Workload scheduling and execution across multiple GPUs
// ============================================================================

#include "MultiGPUScheduler.h"
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <condition_variable>

namespace Deep2 {
namespace MultiGPU {

MultiGPUScheduler::MultiGPUScheduler()
    : initialized_(false)
    , maxConcurrentWorkers_(std::thread::hardware_concurrency())
{
    if (maxConcurrentWorkers_ == 0) {
        maxConcurrentWorkers_ = 4;
    }
}

MultiGPUScheduler::~MultiGPUScheduler() {
    Shutdown();
}

bool MultiGPUScheduler::Initialize() {
    std::lock_guard<std::mutex> lock(workerMutex_);
    
    if (initialized_) {
        return true;
    }
    
    // Initialize device registry
    gpuRegistry_ = &GPUDeviceRegistry::Instance();
    if (!gpuRegistry_->DiscoverDevices()) {
        return false;
    }
    
    initialized_ = true;
    return true;
}

void MultiGPUScheduler::Shutdown() {
    {
        std::lock_guard<std::mutex> lock(workerMutex_);
        stop_ = true;
        queueCV_.notify_all();
    }
    
    for (auto& t : workerThreads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    
    initialized_ = false;
}

bool MultiGPUScheduler::SubmitTask(const WorkloadTask& task) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    // Clone the task to assign a unique ID
    WorkloadTask taskCopy = task;
    taskCopy.id = nextTaskId_++;
    taskCopy.submitTime = std::chrono::steady_clock::now();
    
    taskQueue_.push(taskCopy);
    queueCV_.notify_one();
    
    return true;
}

bool MultiGPUScheduler::SubmitTaskAsync(const WorkloadTask& task,
                                         std::function<void(const WorkloadTask&)> callback) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    WorkloadTask taskCopy = task;
    taskCopy.id = nextTaskId_++;
    taskCopy.submitTime = std::chrono::steady_clock::now();
    
    taskQueue_.push(taskCopy);
    
    // Store callback for this task
    taskCallbacks_[taskCopy.id] = callback;
    
    queueCV_.notify_one();
    
    return true;
}

ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type, uint64_t estimatedSize) {
    ExecutionPlan plan;
    plan.status = WorkerStatus::PENDING;
    
    // Get available devices
    auto devices = gpuRegistry_->GetAvailableDevices();
    
    if (devices.empty()) {
        plan.status = WorkerStatus::FAILED;
        return plan;
    }
    
    // Determine mode based on available devices and workload size
    if (devices.size() >= 2) {
        // For large workloads, use model parallel
        if (estimatedSize > 1024 * 1024 * 1024) { // > 1GB
            plan.mode = ExecutionMode::MODEL_PARALLEL;
        } else {
            plan.mode = ExecutionMode::CONCURRENT;
        }
    } else {
        plan.mode = ExecutionMode::SINGLE_GPU;
    }
    
    // Plan the execution
    plan = PlanExecutionInternal(type, plan.mode);
    
    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanExecutionInternal(WorkloadType type, ExecutionMode mode) {
    ExecutionPlan plan;
    plan.mode = mode;
    
    auto devices = gpuRegistry_->GetAvailableDevices();
    if (devices.empty()) {
        plan.status = WorkerStatus::FAILED;
        return plan;
    }
    
    if (mode == ExecutionMode::SINGLE_GPU) {
        // Use only primary device
        auto primary = gpuRegistry_->GetPrimaryDevice();
        if (primary) {
            plan.primaryDevice = primary->ProcessId;
            plan.workerDevices.push_back(primary->index);
        }
        plan.status = WorkerStatus::READY;
    } else if (mode == ExecutionMode::MODEL_PARALLEL) {
        // Split model across devices
        auto devices = gpuRegistry_->GetAvailableDevices();
        if (devices.size() >= 2) {
            plan.primaryDevice = devices[0].index;
            plan.secondaryDevice = devices[1].index;
            
            // Split layers
            uint32_t totalLayers = 64; // Default assumption
            plan.layerStart = 0;
            plan.layerEnd = totalLayers / 2;
            plan.secondaryDevice = devices[1].index;
        }
        plan.status = WorkerStatus::READY;
    } else if (mode == ExecutionMode::TENSOR_PARALLEL) {
        auto devices = gpuRegistry_->GetAvailableDevices();
        if (devices.size() >= 2) {
            plan.primaryDevice = devices[0].index;
            plan.secondaryDevice = devices[1].index;
            plan.tensorSplit = 0;
            plan.numShards = devices.size();
        }
        plan.status = WorkerStatus::READY;
    }
    
    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type,
                                               uint64_t modelSize) {
    return PlanExecutionInternal(type, mode_);
}

ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type,
                                               uint64_t modelSize,
                                               int numWorkers) {
    ExecutionPlan plan;
    
    // Clamp numWorkers to available devices
    auto devices = gpuRegistry_->GetAvailableDevices();
    int maxWorkers = static_cast<int>(devices.size());
    if (numWorkers > static_cast<int>(devices.size())) {
        numWorkers = static_cast<int>(devices.size());
    }
    
    plan.numWorkers = numWorkers;
    plan.deviceIds.resize(numWorkers);
    
    // Distribute workers across devices
    for (uint32_t i = 0; i < numWorkers; ++i) {
        plan.deviceIds[i] = devices[i % devices.size()].index;
    }
    
    return plan;
}

std::future<bool> MultiGPUScheduler::SubmitTask(const WorkloadTask& task) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    // Create a promise for this task
    auto taskPromise = std::make_shared<std::promise<bool>>();
    auto taskFuture = taskPromise->get_future();
    
    // Add to queue
    taskQueue_.push(task);
    queueCV_.notify_one();
    
    return taskFuture;
}

bool MultiGPUScheduler::SubmitTaskAsync(const WorkloadTask& task,
                                         std::function<void(const WorkloadTask&)> callback) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    
    WorkloadTask taskCopy = task;
    taskCopy.id = nextTaskId_++;
    taskCopy.submitTime = std::chrono::steady_clock::now();
    
    taskQueue_.push(taskCopy);
    
    // Store callback for this task
    taskCallbacks_[taskCopy.id] = callback;
    
    queueCV_.notify_one();
    
    return true;
}

ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type,
                                               uint64_t modelSize) {
    ExecutionPlan plan;
    
    // Get available devices
    auto devices = gpuRegistry_->GetAvailableDevices();
    
    if (devices.empty()) {
        plan.status = WorkerStatus::FAILED;
        return plan;
    }
    
    // Determine mode based on available devices and workload size
    if (devices.size() >= 2) {
        // For large workloads, use model parallel
        if (modelSize > 1024 * 1024 * 1024) { // > 1GB
            plan.mode = ExecutionMode::MODEL_PARALLEL;
        } else {
            plan.mode = ExecutionMode::CONCURRENT;
        }
    } else {
        plan.mode = ExecutionMode::SINGLE_GPU;
    }
    
    // Plan the execution
    plan = PlanExecutionInternal(type, plan.mode);
    
    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanExecutionInternal(WorkloadType type,
                                                       ExecutionMode mode) {
    ExecutionPlan plan;
    plan.mode = mode;
    
    auto devices = gpuRegistry_->GetAvailableDevices();
    if (devices.empty()) {
        plan.status = WorkerStatus::FAILED;
        return plan;
    }
    
    if (mode == ExecutionMode::SINGLE_GPU) {
        // Use only primary device
        auto primary = gpuRegistry_->GetPrimaryDevice();
        if (primary) {
            plan.primaryDevice = primary->index;
        }
        plan.status = WorkerStatus::READY;
    } else if (mode == ExecutionMode::MODEL_PARALLEL) {
        // Split model across devices
        auto devices = gpuRegistry_->GetAvailableDevices();
        if (devices.size() >= 2) {
            plan.primaryDevice = devices[0].index;
            plan.secondaryDevice = devices[1].index;
            
            // Split layers
            uint32_t totalLayers = 64; // Default assumption
            plan.layerStart = 0;
            plan.layerEnd = totalLayers / 2;
            plan.secondaryDevice = devices[1].index;
        }
        plan.status = WorkerStatus::READY;
    } else if (mode == ExecutionMode::TENSOR_PARALLEL) {
        auto devices = gpuRegistry_->GetAvailableDevices();
        if (devices.size() >= 2) {
            plan.primaryDevice = devices[0].index;
            plan.secondaryDevice = devices[1].index;
            plan.tensorSplit = 0;
            plan.numShards = devices.size();
        }
        plan.status = WorkerStatus::READY;
    }
    
    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type,
                                               uint64_t modelSize,
                                               int numWorkers) {
    ExecutionPlan plan;
    
    // Clamp numWorkers to available devices
    auto devices = gpuRegistry_->GetAvailableDevices();
    int maxWorkers = static_cast<int>(devices.size());
    if (numWorkers > maxWorkers) {
        numWorkers = maxWorkers;
    }
    
    plan.numWorkers = numWorkers;
    
    // Distribute workers across devices
    for (int i = 0; i < numWorkers; ++i) {
        plan.deviceIds.push_back(devices[i % devices.size()].index);
    }
    
    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type,
                                               uint64_t modelSize,
                                               int numWorkers) {
    ExecutionPlan plan;
    
    // Clamp numWorkers to available devices
    auto devices = gpuRegistry_->GetAvailableDevices();
    int maxWorkers = static_cast<int>(devices.size());
    if (numWorkers > maxWorkers) {
        numWorkers = maxWorkers;
    }
    
    plan.numWorkers = numWorkers;
    
    // Distribute workers across devices
    for (int i = 0; i < numWorkers; ++i) {
        plan.deviceIds.push_back(devices[i % devices.size()].index);
    }
    
    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanExecution(WorkloadType type,
                                               uint64_t modelSize) {
    ExecutionPlan plan;
    
    // Get available devices
    auto devices = gpuRegistry_->GetAvailableDevices();
    
    if (devices.empty()) {
        plan.status = WorkerStatus::FAILED;
        return plan;
    }
    
    // Determine mode based on available devices and workload size
    if (devices.size() >= 2) {
        // For large workloads, use model parallel
        if (modelSize > 1024 * 1024 * 1024) { // > 1GB
            plan.mode = ExecutionMode::MODEL_PARALLEL;
        } else {
            plan.mode = ExecutionMode::CONCURRENT;
        }
    } else {
        plan.mode = ExecutionMode::SINGLE_GPU;
    }
    
    // Plan the execution
    plan = PlanExecutionInternal(type, plan.mode);
    
    return plan;
}

ExecutionPlan MultiGPUScheduler::PlanExecutionInternal(WorkloadType type,
                                                       ExecutionMode mode) {
    ExecutionPlan plan;
    plan.mode = mode;
    
    auto devices = gpuRegistry_->GetAvailableDevices();
    if (devices.empty()) {
        plan.status = WorkerStatus::FAILED;
        return plan;
    }
    
    if (mode == ExecutionMode::SINGLE_GPU) {
        // Use only primary device
        auto primary = gpuRegistry_->GetPrimaryDevice();
        if (primary) {
            plan.primaryDevice = primary->index;
        }
        plan.status = WorkerStatus::READY;
    } else if (mode == ExecutionMode::MODEL_PARALLEL) {
        // Split model across devices
        auto devices = gpuRegistry_->GetAvailableDevices();
        if (devices.size() >= 2) {
            plan.primaryDevice = devices[0].index;
            plan.secondaryDevice = devices[1].index;
            
            // Split layers
            uint32_t totalLayers = 64; // Default assumption
            plan.layerStart = 0;
            plan.layerEnd = totalLayers / 2;
            plan.secondaryDevice = devices[1].index;
        }
        plan.status = WorkerStatus::READY;
    } else if (mode == ExecutionMode::TENSOR_PARALLEL) {
        auto devices = gpuRegistry_->GetAvailableDevices();
        if (devices.size() >= 2) {
            plan.primaryDevice = devices[0].index;
            plan.secondaryDevice = devices[1].index;
            plan.tensorSplit = 0;
            plan.numShards = devices.size();
        }
        plan.status = WorkerStatus::READY;
    }
    
    return plan;
}

// ... rest of the implementation