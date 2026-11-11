// ============================================================================
// DualGPUBackend.cpp - MARS: Memory Allocation + Routing System
// ============================================================================

#include "DualGPUBackend.hpp"
#include <chrono>
#include <cstdio>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Constructor / Destructor
// ============================================================================
DualGPUBackend::DualGPUBackend() = default;

DualGPUBackend::~DualGPUBackend() {
    if (initialized_) {
        Shutdown();
    }
}

// ============================================================================
// Lifecycle
// ============================================================================
bool DualGPUBackend::Initialize() {
    if (initialized_) return true;

    printf("[DualGPUBackend] Initializing dual-GPU queues...\n");

    stopWorkers_ = false;
    worker0_ = std::thread(&DualGPUBackend::WorkerLoop0, this);
    worker1_ = std::thread(&DualGPUBackend::WorkerLoop1, this);

    initialized_ = true;
    printf("[DualGPUBackend] Queues ready\n");
    return true;
}

void DualGPUBackend::Shutdown() {
    if (!initialized_) return;

    printf("[DualGPUBackend] Shutting down...\n");
    stopWorkers_ = true;
    queue0CV_.notify_all();
    queue1CV_.notify_all();

    if (worker0_.joinable()) worker0_.join();
    if (worker1_.joinable()) worker1_.join();

    initialized_ = false;
    printf("[DualGPUBackend] Shutdown complete\n");
}

// ============================================================================
// Queue Submission
// ============================================================================
std::future<bool> DualGPUBackend::SubmitToQueue0(const ComputeTask& task) {
    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();

    {
        std::lock_guard<std::mutex> lock(queue0Mutex_);
        ComputeTask mutableTask = task;
        mutableTask.id = nextTaskId_++;
        mutableTask.submitTime = std::chrono::steady_clock::now();
        mutableTask.targetGPU = 0;
        queue0_.push(mutableTask);
        queue0Promises_.push(promise);
    }

    queue0CV_.notify_one();
    RecordTaskSubmit(0);
    return future;
}

std::future<bool> DualGPUBackend::SubmitToQueue1(const ComputeTask& task) {
    auto promise = std::make_shared<std::promise<bool>>();
    auto future = promise->get_future();

    {
        std::lock_guard<std::mutex> lock(queue1Mutex_);
        ComputeTask mutableTask = task;
        mutableTask.id = nextTaskId_++;
        mutableTask.submitTime = std::chrono::steady_clock::now();
        mutableTask.targetGPU = 1;
        queue1_.push(mutableTask);
        queue1Promises_.push(promise);
    }

    queue1CV_.notify_one();
    RecordTaskSubmit(1);
    return future;
}

std::future<bool> DualGPUBackend::SubmitAuto(const ComputeTask& task) {
    // Select less loaded GPU
    int target = SelectLessLoadedGPU();
    if (target == 0) {
        return SubmitToQueue0(task);
    } else {
        return SubmitToQueue1(task);
    }
}

bool DualGPUBackend::SubmitAsync(const ComputeTask& task,
                                  std::function<void(const ComputeTask&, bool)> callback) {
    auto future = SubmitAuto(task);

    std::thread([future = std::move(future), callback, task]() mutable {
        try {
            bool success = future.get();
            if (callback) {
                callback(task, success);
            }
        } catch (...) {
            if (callback) {
                callback(task, false);
            }
        }
    }).detach();

    return true;
}

// ============================================================================
// Synchronization
// ============================================================================
void DualGPUBackend::SynchronizeQueue0() {
    std::unique_lock<std::mutex> lock(queue0Mutex_);
    queue0CV_.wait(lock, [this] { return queue0_.empty(); });
}

void DualGPUBackend::SynchronizeQueue1() {
    std::unique_lock<std::mutex> lock(queue1Mutex_);
    queue1CV_.wait(lock, [this] { return queue1_.empty(); });
}

void DualGPUBackend::SynchronizeAll() {
    SynchronizeQueue0();
    SynchronizeQueue1();
}

void DualGPUBackend::Barrier() {
    // Submit no-op tasks and wait
    ComputeTask noop;
    noop.kernelName = "noop";
    auto f0 = SubmitToQueue0(noop);
    auto f1 = SubmitToQueue1(noop);
    f0.wait();
    f1.wait();
}

// ============================================================================
// Cross-GPU Operations
// ============================================================================
bool DualGPUBackend::CopyTensorPeer(uint64_t tensorId, int fromGPU, int toGPU, size_t bytes) {
    // In production: P2P copy via DMA
    // For now: simulate
    (void)tensorId;
    (void)bytes;
    printf("[DualGPUBackend] P2P copy tensor %llu GPU %d -> GPU %d (%zu bytes)\n",
           (unsigned long long)tensorId, fromGPU, toGPU, bytes);
    return true;
}

bool DualGPUBackend::BroadcastTensor(uint64_t tensorId, size_t bytes) {
    // Copy to both GPUs
    bool ok0 = CopyTensorPeer(tensorId, -1, 0, bytes);
    bool ok1 = CopyTensorPeer(tensorId, -1, 1, bytes);
    return ok0 && ok1;
}

// ============================================================================
// Queries
// ============================================================================
size_t DualGPUBackend::GetQueue0Depth() const {
    std::lock_guard<std::mutex> lock(queue0Mutex_);
    return queue0_.size();
}

size_t DualGPUBackend::GetQueue1Depth() const {
    std::lock_guard<std::mutex> lock(queue1Mutex_);
    return queue1_.size();
}

QueueTelemetry DualGPUBackend::GetQueue0Telemetry() const {
    std::lock_guard<std::mutex> lock(telemetry0Mutex_);
    return telemetry0_;
}

QueueTelemetry DualGPUBackend::GetQueue1Telemetry() const {
    std::lock_guard<std::mutex> lock(telemetry1Mutex_);
    return telemetry1_;
}

bool DualGPUBackend::IsQueue0Idle() const {
    return GetQueue0Depth() == 0;
}

bool DualGPUBackend::IsQueue1Idle() const {
    return GetQueue1Depth() == 0;
}

// ============================================================================
// GPU Health
// ============================================================================
void DualGPUBackend::MarkGPUFailed(int gpu) {
    if (gpu == 0) gpu0Healthy_ = false;
    if (gpu == 1) gpu1Healthy_ = false;
    printf("[DualGPUBackend] GPU %d marked as failed\n", gpu);
}

// ============================================================================
// Performance
// ============================================================================
float DualGPUBackend::GetQueue0Load() const {
    auto tel = GetQueue0Telemetry();
    return tel.currentDepth > 0 ? 1.0f : 0.0f;
}

float DualGPUBackend::GetQueue1Load() const {
    auto tel = GetQueue1Telemetry();
    return tel.currentDepth > 0 ? 1.0f : 0.0f;
}

int DualGPUBackend::SelectLessLoadedGPU() const {
    float load0 = GetQueue0Load();
    float load1 = GetQueue1Load();
    if (!gpu0Healthy_) return 1;
    if (!gpu1Healthy_) return 0;
    return (load0 <= load1) ? 0 : 1;
}

// ============================================================================
// Worker Loops
// ============================================================================
void DualGPUBackend::WorkerLoop0() {
    printf("[DualGPUBackend] Worker 0 started\n");
    while (!stopWorkers_) {
        ComputeTask task;
        std::shared_ptr<std::promise<bool>> promise;
        bool hasTask = false;

        {
            std::unique_lock<std::mutex> lock(queue0Mutex_);
            queue0CV_.wait(lock, [this] { return stopWorkers_ || !queue0_.empty(); });
            if (stopWorkers_) break;
            if (!queue0_.empty()) {
                task = queue0_.front();
                queue0_.pop();
                promise = queue0Promises_.front();
                queue0Promises_.pop();
                hasTask = true;
            }
        }

        if (hasTask) {
            bool success = ExecuteOnGPU0(task);
            promise->set_value(success);
            RecordTaskComplete(0, task, success);
        }
    }
    printf("[DualGPUBackend] Worker 0 stopped\n");
}

void DualGPUBackend::WorkerLoop1() {
    printf("[DualGPUBackend] Worker 1 started\n");
    while (!stopWorkers_) {
        ComputeTask task;
        std::shared_ptr<std::promise<bool>> promise;
        bool hasTask = false;

        {
            std::unique_lock<std::mutex> lock(queue1Mutex_);
            queue1CV_.wait(lock, [this] { return stopWorkers_ || !queue1_.empty(); });
            if (stopWorkers_) break;
            if (!queue1_.empty()) {
                task = queue1_.front();
                queue1_.pop();
                promise = queue1Promises_.front();
                queue1Promises_.pop();
                hasTask = true;
            }
        }

        if (hasTask) {
            bool success = ExecuteOnGPU1(task);
            promise->set_value(success);
            RecordTaskComplete(1, task, success);
        }
    }
    printf("[DualGPUBackend] Worker 1 stopped\n");
}

// ============================================================================
// Execution Stubs (would call real GPU kernels)
// ============================================================================
bool DualGPUBackend::ExecuteOnGPU0(const ComputeTask& task) {
    // Simulate kernel execution
    (void)task;
    std::this_thread::sleep_for(std::chrono::microseconds(100));
    return gpu0Healthy_.load();
}

bool DualGPUBackend::ExecuteOnGPU1(const ComputeTask& task) {
    // Simulate kernel execution
    (void)task;
    std::this_thread::sleep_for(std::chrono::microseconds(100));
    return gpu1Healthy_.load();
}

// ============================================================================
// Telemetry
// ============================================================================
void DualGPUBackend::RecordTaskSubmit(int queue) {
    if (queue == 0) {
        std::lock_guard<std::mutex> lock(telemetry0Mutex_);
        telemetry0_.tasksSubmitted++;
        telemetry0_.currentDepth++;
    } else {
        std::lock_guard<std::mutex> lock(telemetry1Mutex_);
        telemetry1_.tasksSubmitted++;
        telemetry1_.currentDepth++;
    }
}

void DualGPUBackend::RecordTaskComplete(int queue, const ComputeTask& task, bool success) {
    auto now = std::chrono::steady_clock::now();
    double latencyMs = 0.0;
    if (task.startTime.time_since_epoch().count() > 0) {
        latencyMs = std::chrono::duration<double, std::milli>(now - task.startTime).count();
    }

    if (queue == 0) {
        std::lock_guard<std::mutex> lock(telemetry0Mutex_);
        if (success) telemetry0_.tasksCompleted++;
        else telemetry0_.tasksFailed++;
        telemetry0_.currentDepth--;
        telemetry0_.avgLatencyMs =
            (telemetry0_.avgLatencyMs * (telemetry0_.tasksCompleted - 1) + latencyMs)
            / telemetry0_.tasksCompleted;
    } else {
        std::lock_guard<std::mutex> lock(telemetry1Mutex_);
        if (success) telemetry1_.tasksCompleted++;
        else telemetry1_.tasksFailed++;
        telemetry1_.currentDepth--;
        telemetry1_.avgLatencyMs =
            (telemetry1_.avgLatencyMs * (telemetry1_.tasksCompleted - 1) + latencyMs)
            / telemetry1_.tasksCompleted;
    }
}

} // namespace MARS
} // namespace Deep2
