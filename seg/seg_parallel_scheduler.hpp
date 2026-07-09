#pragma once
// ============================================================================
// SEG Parallel Scheduler (C7) - Multi-threaded Node Execution
// ============================================================================
// Parallelizes independent nodes across CPU cores
// Uses work-stealing queue for load balancing
// ============================================================================

#include "seg_scheduler.hpp"
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>

namespace seg {

// Work item for thread pool
struct WorkItem {
    NodeId node_id;
    uint32_t priority;
    
    bool operator<(const WorkItem& other) const {
        return priority < other.priority;  // Higher priority first
    }
};

// Thread-local work queue (work-stealing)
class WorkStealingQueue {
public:
    void Push(WorkItem item);
    bool Pop(WorkItem& item);      // Owner thread
    bool Steal(WorkItem& item);    // Other threads
    bool Empty() const;
    size_t Size() const;
    
private:
    std::vector<WorkItem> items_;
    mutable std::mutex mutex_;
};

// Parallel scheduler extends base Scheduler
class ParallelScheduler : public Scheduler {
public:
    ParallelScheduler();
    explicit ParallelScheduler(uint32_t num_threads);
    ~ParallelScheduler() override;
    
    // Initialize thread pool
    void Initialize(uint32_t num_threads);
    
    // Schedule graph execution with parallel dispatch
    void ScheduleParallel(Graph& graph, Executor& executor);
    
    // Wait for all tasks to complete
    void WaitForCompletion();
    
    // Get number of worker threads
    uint32_t GetNumThreads() const { return num_threads_; }
    
    // Get number of completed tasks
    uint64_t GetCompletedTasks() const { return completed_tasks_.load(); }
    
    // Get number of stolen tasks
    uint64_t GetStolenTasks() const { return stolen_tasks_.load(); }

protected:
    // Worker thread function
    void WorkerThread(uint32_t thread_id);
    
    // Try to get work from own queue or steal from others
    bool GetWork(WorkItem& item, uint32_t thread_id);
    
    // Execute a single node
    void ExecuteNode(Graph& graph, Executor& executor, NodeId node_id);
    
    // Check if node's dependencies are satisfied
    bool DependenciesSatisfied(const Graph& graph, NodeId node_id);
    
    // Mark node as completed and notify dependents
    void MarkCompleted(Graph& graph, NodeId node_id);

private:
    uint32_t num_threads_ = 0;
    std::vector<std::thread> workers_;
    std::vector<WorkStealingQueue> work_queues_;
    
    // Global queue for initial work distribution
    std::priority_queue<WorkItem> global_queue_;
    std::mutex global_mutex_;
    std::condition_variable global_cv_;
    
    // Synchronization
    std::atomic<bool> shutdown_{false};
    std::atomic<uint64_t> active_tasks_{0};
    std::atomic<uint64_t> completed_tasks_{0};
    std::atomic<uint64_t> stolen_tasks_{0};
    
    // Node completion tracking
    std::unordered_map<NodeId, std::atomic<uint32_t>*, NodeIdHash> remaining_deps_;
    std::mutex deps_mutex_;
    
    // Graph and executor references (valid during ScheduleParallel)
    Graph* current_graph_ = nullptr;
    Executor* current_executor_ = nullptr;
};

// Utility: Get optimal thread count based on hardware
uint32_t GetOptimalThreadCount();

// Utility: Pin thread to specific CPU core (for NUMA optimization)
void PinThreadToCore(uint32_t thread_id, uint32_t core_id);

} // namespace seg
