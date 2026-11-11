// ============================================================================
// WorkStealingScheduler.hpp - Work-Stealing Thread Pool Scheduler
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <deque>

namespace Sovereign {

class WorkStealingScheduler {
public:
    WorkStealingScheduler();
    ~WorkStealingScheduler();

    bool Initialize(uint32_t numWorkers = 0);
    void Shutdown();

    void Submit(const std::string& queue, std::function<void()> task);
    void SubmitGlobal(std::function<void()> task);
    void WaitAll();
    uint32_t GetWorkerCount() const { return numWorkers_; }

    struct SchedulerStats {
        uint64_t totalTasks;
        uint64_t stolenTasks;
        uint64_t completedTasks;
        double avgQueueWaitUs;
    };
    SchedulerStats GetStats() const { return stats_; }

private:
    uint32_t numWorkers_;
    std::atomic<bool> running_{false};
    SchedulerStats stats_;
    
    struct Worker {
        std::deque<std::function<void()>> queue;
        std::mutex mutex;
        uint64_t tasksProcessed;
    };
    std::vector<std::unique_ptr<Worker>> workers_;
    std::deque<std::function<void()>> globalQueue_;
    std::mutex globalMutex_;
    std::condition_variable cv_;
    
    std::vector<std::thread> threads_;
    
    void WorkerLoop(uint32_t workerId);
    bool StealTask(uint32_t thiefId, std::function<void()>& task);
};

} // namespace Sovereign
