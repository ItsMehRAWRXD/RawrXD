// ============================================================================
// DualGPUBackend.hpp - MARS: Memory Allocation + Routing System
// Queue0, Queue1, Synchronizer for dual-GPU compute.
// ============================================================================

#pragma once

#include "VRAMLease.hpp"
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <atomic>

namespace Deep2 {
namespace MARS {

// ============================================================================
// Compute Task
// ============================================================================
struct ComputeTask {
    uint64_t id = 0;
    int targetGPU = -1;          // -1 = auto-select
    std::string kernelName;
    std::vector<uint64_t> inputTensorIds;
    uint64_t outputTensorId = 0;
    size_t workSize = 0;
    int priority = 0;
    bool syncRequired = false;

    // Timing
    std::chrono::steady_clock::time_point submitTime;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
};

// ============================================================================
// Queue Telemetry
// ============================================================================
struct QueueTelemetry {
    uint64_t tasksSubmitted = 0;
    uint64_t tasksCompleted = 0;
    uint64_t tasksFailed = 0;
    double avgLatencyMs = 0.0;
    double avgQueueDepth = 0.0;
    uint64_t currentDepth = 0;
};

// ============================================================================
// Dual GPU Backend
// Manages compute queues and synchronization for two GPUs.
// ============================================================================
class DualGPUBackend {
public:
    DualGPUBackend();
    ~DualGPUBackend();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // ------------------------------------------------------------------------
    // Queue Management
    // ------------------------------------------------------------------------
    // Submit task to a specific GPU queue
    std::future<bool> SubmitToQueue0(const ComputeTask& task);
    std::future<bool> SubmitToQueue1(const ComputeTask& task);

    // Submit to either queue (auto-select based on load)
    std::future<bool> SubmitAuto(const ComputeTask& task);

    // Submit with callback
    bool SubmitAsync(const ComputeTask& task,
                     std::function<void(const ComputeTask&, bool)> callback);

    // ------------------------------------------------------------------------
    // Synchronization
    // ------------------------------------------------------------------------
    void SynchronizeQueue0();
    void SynchronizeQueue1();
    void SynchronizeAll();
    void Barrier(); // Wait for both queues to drain

    // ------------------------------------------------------------------------
    // Cross-GPU Operations
    // ------------------------------------------------------------------------
    // Copy tensor between GPUs (P2P if supported)
    bool CopyTensorPeer(uint64_t tensorId, int fromGPU, int toGPU, size_t bytes);

    // Broadcast tensor to both GPUs
    bool BroadcastTensor(uint64_t tensorId, size_t bytes);

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    size_t GetQueue0Depth() const;
    size_t GetQueue1Depth() const;
    QueueTelemetry GetQueue0Telemetry() const;
    QueueTelemetry GetQueue1Telemetry() const;
    bool IsQueue0Idle() const;
    bool IsQueue1Idle() const;

    // ------------------------------------------------------------------------
    // GPU Health
    // ------------------------------------------------------------------------
    bool IsGPU0Healthy() const { return gpu0Healthy_; }
    bool IsGPU1Healthy() const { return gpu1Healthy_; }
    void MarkGPUFailed(int gpu);

    // ------------------------------------------------------------------------
    // Performance
    // ------------------------------------------------------------------------
    float GetQueue0Load() const;
    float GetQueue1Load() const;
    int   SelectLessLoadedGPU() const;

private:
    bool initialized_ = false;
    std::atomic<bool> gpu0Healthy_{true};
    std::atomic<bool> gpu1Healthy_{true};

    // Queue 0
    mutable std::mutex queue0Mutex_;
    std::condition_variable queue0CV_;
    std::queue<ComputeTask> queue0_;
    std::queue<std::shared_ptr<std::promise<bool>>> queue0Promises_;
    QueueTelemetry telemetry0_;
    mutable std::mutex telemetry0Mutex_;
    std::thread worker0_;

    // Queue 1
    mutable std::mutex queue1Mutex_;
    std::condition_variable queue1CV_;
    std::queue<ComputeTask> queue1_;
    std::queue<std::shared_ptr<std::promise<bool>>> queue1Promises_;
    QueueTelemetry telemetry1_;
    mutable std::mutex telemetry1Mutex_;
    std::thread worker1_;

    std::atomic<bool> stopWorkers_{false};
    std::atomic<uint64_t> nextTaskId_{1};

    // Worker loops
    void WorkerLoop0();
    void WorkerLoop1();

    // Execute task on GPU
    bool ExecuteOnGPU0(const ComputeTask& task);
    bool ExecuteOnGPU1(const ComputeTask& task);

    // Update telemetry
    void RecordTaskSubmit(int queue);
    void RecordTaskComplete(int queue, const ComputeTask& task, bool success);
};

} // namespace MARS
} // namespace Deep2
