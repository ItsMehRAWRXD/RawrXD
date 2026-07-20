// ============================================================================
// InferenceTask.cpp - Task Wrapper Implementation
// ============================================================================

#include "InferenceTask.hpp"
#include <cstdio>
#include <chrono>
#include <queue>
#include <condition_variable>
#include <unordered_map>
#include <thread>

namespace Deep2 {

// ============================================================================
// InferenceTask Implementation
// ============================================================================
InferenceTask InferenceTask::CreateLinear(
    int weightIdx,
    const float* input,
    float* output,
    size_t outDim,
    const float* bias,
    bool parallel
) {
    InferenceTask task;
    task.op = parallel ? InferenceOp::LINEAR_PARALLEL : InferenceOp::LINEAR;
    task.weightIdx = weightIdx;
    task.input = input;
    task.output = output;
    task.outDim = outDim;
    task.bias = bias;
    task.useParallel = parallel;
    task.completionPromise = std::make_shared<std::promise<bool>>();
    return task;
}

InferenceTask InferenceTask::CreateTransformerLayer(
    size_t layerIdx,
    const float* input,
    float* output,
    size_t hiddenDim,
    size_t seqLen
) {
    InferenceTask task;
    task.op = InferenceOp::TRANSFORMER_LAYER;
    task.layerIdx = layerIdx;
    task.input = input;
    task.output = output;
    task.outDim = hiddenDim;
    task.seqLen = seqLen;
    task.completionPromise = std::make_shared<std::promise<bool>>();
    return task;
}

bool InferenceTask::Wait(int timeoutMs) {
    if (!completionPromise) return false;
    
    auto future = completionPromise->get_future();
    if (timeoutMs < 0) {
        future.wait();
        return future.get();
    } else {
        auto status = future.wait_for(std::chrono::milliseconds(timeoutMs));
        return status == std::future_status::ready && future.get();
    }
}

// ============================================================================
// InferenceTaskQueue Implementation
// ============================================================================
class InferenceTaskQueue::Impl {
public:
    std::queue<InferenceTask> tasks;
    mutable std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> shuttingDown{false};
};

InferenceTaskQueue::InferenceTaskQueue() : pImpl(std::make_unique<Impl>()) {}
InferenceTaskQueue::~InferenceTaskQueue() = default;

void InferenceTaskQueue::Enqueue(InferenceTask&& task) {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    pImpl->tasks.push(std::move(task));
    pImpl->cv.notify_one();
}

bool InferenceTaskQueue::Dequeue(InferenceTask& task, int timeoutMs) {
    std::unique_lock<std::mutex> lock(pImpl->mutex);
    
    if (timeoutMs < 0) {
        pImpl->cv.wait(lock, [this] { 
            return !pImpl->tasks.empty() || pImpl->shuttingDown; 
        });
    } else {
        bool hasTask = pImpl->cv.wait_for(lock, std::chrono::milliseconds(timeoutMs), 
            [this] { return !pImpl->tasks.empty() || pImpl->shuttingDown; });
        if (!hasTask) return false;
    }
    
    if (pImpl->shuttingDown && pImpl->tasks.empty()) {
        return false;
    }
    
    task = std::move(pImpl->tasks.front());
    pImpl->tasks.pop();
    return true;
}

size_t InferenceTaskQueue::Size() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    return pImpl->tasks.size();
}

void InferenceTaskQueue::Clear() {
    std::lock_guard<std::mutex> lock(pImpl->mutex);
    while (!pImpl->tasks.empty()) {
        pImpl->tasks.pop();
    }
}

void InferenceTaskQueue::Shutdown() {
    pImpl->shuttingDown = true;
    pImpl->cv.notify_all();
}

// ============================================================================
// InferenceExecutor Implementation
// ============================================================================
InferenceExecutor::InferenceExecutor(Deep2Engine& eng) : engine(eng) {}
InferenceExecutor::~InferenceExecutor() {
    Stop();
}

void InferenceExecutor::Start() {
    if (running) return;
    running = true;
    workerThread = std::thread(&InferenceExecutor::WorkerLoop, this);
    printf("[InferenceExecutor] Started\n");
}

void InferenceExecutor::Stop() {
    if (!running) return;
    running = false;
    queue.Shutdown();
    if (workerThread.joinable()) {
        workerThread.join();
    }
    printf("[InferenceExecutor] Stopped\n");
}

void InferenceExecutor::WorkerLoop() {
    while (running) {
        InferenceTask task;
        if (queue.Dequeue(task, 100)) {  // 100ms timeout
            task.status = TaskStatus::RUNNING;
            
            auto start = std::chrono::high_resolution_clock::now();
            bool success = ExecuteTask(task, engine);
            auto end = std::chrono::high_resolution_clock::now();
            
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            task.executionTimeMs = duration.count() / 1000.0;
            
            task.status = success ? TaskStatus::COMPLETED : TaskStatus::FAILED;
            
            // Complete the promise
            if (task.completionPromise) {
                task.completionPromise->set_value(success);
            }
            
            // Call callback if set
            if (task.onComplete) {
                task.onComplete(task, task.status);
            }
        }
    }
}

bool InferenceExecutor::ExecuteTask(InferenceTask& task, Deep2Engine& engine) {
    switch (task.op) {
        case InferenceOp::LINEAR:
        case InferenceOp::LINEAR_PARALLEL:
            if (task.weightIdx < 0 || !task.input || !task.output) {
                snprintf(task.errorMsg, sizeof(task.errorMsg), "Invalid linear task parameters");
                return false;
            }
            
            // Execute via KernelDispatcher
            KernelDispatcher::ExecuteLinear(
                task.weightIdx,
                task.input,
                task.bias,
                task.output,
                task.outDim,
                task.useParallel,
                &engine
            );
            return true;
            
        case InferenceOp::ATTENTION:
            // TODO: Implement attention forward
            snprintf(task.errorMsg, sizeof(task.errorMsg), "Attention not yet implemented");
            return false;
            
        case InferenceOp::FFN:
            // TODO: Implement FFN forward
            snprintf(task.errorMsg, sizeof(task.errorMsg), "FFN not yet implemented");
            return false;
            
        case InferenceOp::TRANSFORMER_LAYER:
            // TODO: Implement full transformer layer
            snprintf(task.errorMsg, sizeof(task.errorMsg), "Transformer layer not yet implemented");
            return false;
            
        default:
            snprintf(task.errorMsg, sizeof(task.errorMsg), "Unknown operation");
            return false;
    }
}

// ============================================================================
// SovereignInferenceBridge Implementation
// ============================================================================
SovereignInferenceBridge& SovereignInferenceBridge::Instance() {
    static SovereignInferenceBridge instance;
    return instance;
}

bool SovereignInferenceBridge::Initialize(Deep2Engine* eng) {
    if (initialized) return true;
    if (!eng) return false;
    
    engine = eng;
    executor = std::make_unique<InferenceExecutor>(*engine);
    executor->Start();
    
    // Initialize KernelDispatcher
    KernelDispatcher::Initialize();
    
    initialized = true;
    printf("[SovereignInferenceBridge] Initialized\n");
    return true;
}

void SovereignInferenceBridge::Shutdown() {
    if (!initialized) return;
    
    WaitAll();
    
    if (executor) {
        executor->Stop();
        executor.reset();
    }
    
    engine = nullptr;
    initialized = false;
    printf("[SovereignInferenceBridge] Shutdown complete\n");
}

int SovereignInferenceBridge::DispatchTask(InferenceTask&& task) {
    if (!initialized) {
        printf("[SovereignInferenceBridge] ERROR: Not initialized\n");
        return -1;
    }
    
    int taskId = nextTaskId++;
    
    {
        std::lock_guard<std::mutex> lock(taskMutex);
        auto taskPtr = std::make_shared<InferenceTask>(std::move(task));
        activeTasks[taskId] = taskPtr;
        executor->GetQueue().Enqueue(std::move(*taskPtr));
    }
    
    {
        std::lock_guard<std::mutex> lock(statsMutex);
        stats.tasksSubmitted++;
    }
    
    return taskId;
}

bool SovereignInferenceBridge::DispatchAndWait(InferenceTask& task, int timeoutMs) {
    if (!initialized) return false;
    
    // Execute directly (blocking)
    task.status = TaskStatus::RUNNING;
    
    auto start = std::chrono::high_resolution_clock::now();
    bool success = InferenceExecutor::ExecuteTask(task, *engine);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    task.executionTimeMs = duration.count() / 1000.0;
    task.status = success ? TaskStatus::COMPLETED : TaskStatus::FAILED;
    
    UpdateStats(task);
    return success;
}

int SovereignInferenceBridge::DispatchLinear(
    int weightIdx,
    const float* input,
    float* output,
    size_t outDim,
    const float* bias,
    bool parallel,
    TaskPriority priority
) {
    auto task = InferenceTask::CreateLinear(weightIdx, input, output, outDim, bias, parallel);
    task.priority = priority;
    return DispatchTask(std::move(task));
}

int SovereignInferenceBridge::DispatchTransformerLayer(
    size_t layerIdx,
    const float* input,
    float* output,
    size_t hiddenDim,
    TaskPriority priority
) {
    auto task = InferenceTask::CreateTransformerLayer(layerIdx, input, output, hiddenDim);
    task.priority = priority;
    return DispatchTask(std::move(task));
}

TaskStatus SovereignInferenceBridge::GetTaskStatus(int taskId) {
    std::lock_guard<std::mutex> lock(taskMutex);
    auto it = activeTasks.find(taskId);
    if (it == activeTasks.end()) {
        return TaskStatus::FAILED;
    }
    return it->second->status;
}

bool SovereignInferenceBridge::CancelTask(int taskId) {
    // TODO: Implement cancellation
    return false;
}

void SovereignInferenceBridge::WaitAll() {
    if (!executor) return;
    
    while (executor->GetQueue().Size() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

SovereignInferenceBridge::Stats SovereignInferenceBridge::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex);
    return stats;
}

void SovereignInferenceBridge::ResetStats() {
    std::lock_guard<std::mutex> lock(statsMutex);
    stats = Stats();
}

void SovereignInferenceBridge::UpdateStats(const InferenceTask& task) {
    std::lock_guard<std::mutex> lock(statsMutex);
    
    if (task.status == TaskStatus::COMPLETED) {
        stats.tasksCompleted++;
    } else if (task.status == TaskStatus::FAILED) {
        stats.tasksFailed++;
    }
    
    // Update rolling average latency
    if (stats.tasksCompleted > 0) {
        double alpha = 0.1;  // EMA factor
        stats.avgLatencyMs = (1.0 - alpha) * stats.avgLatencyMs + alpha * task.executionTimeMs;
    } else {
        stats.avgLatencyMs = task.executionTimeMs;
    }
}

} // namespace Deep2
