// RawrXD Priority Task Queue
// Phase O.2: Multi-level priority queue with aging and preemption
// Ensures fair scheduling across different task priorities

#pragma once

#include <vector>
#include <queue>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Distributed {

// Priority levels (lower number = higher priority)
enum class TaskPriorityLevel : uint8_t {
    CRITICAL = 0,   // System-critical (e.g., health checks)
    HIGH = 1,       // User-facing high priority
    NORMAL = 2,     // Standard requests
    LOW = 3,        // Background tasks
    BACKGROUND = 4  // Maintenance tasks
};

// Priority task
struct PriorityTask {
    std::string taskId;
    TaskPriorityLevel priority;
    uint64_t sequenceNumber;        // For FIFO within same priority
    
    // Timing
    std::chrono::steady_clock::time_point submitTime;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point deadline;
    
    // Aging
    uint32_t ageBoosts;             // Number of times priority was boosted
    std::chrono::steady_clock::time_point lastBoostTime;
    
    // Preemption
    bool preemptible;
    uint32_t maxPreemptions;
    uint32_t preemptionCount;
    
    // Task info
    std::string taskType;
    size_t estimatedDurationMs;
    size_t estimatedMemoryBytes;
    
    // User info
    std::string userId;
    std::string tenantId;
    uint32_t userPriority;          // User-specific priority
    
    // Payload
    std::vector<uint8_t> payload;
    
    PriorityTask() : priority(TaskPriorityLevel::NORMAL), sequenceNumber(0),
                     ageBoosts(0), preemptible(true), maxPreemptions(3),
                     preemptionCount(0), estimatedDurationMs(0),
                     estimatedMemoryBytes(0), userPriority(0) {}
};

// Priority queue configuration
struct PriorityQueueConfig {
    // Aging
    bool enableAging = true;
    uint32_t agingIntervalMs = 60000;      // Boost priority every minute
    uint32_t maxAgeBoosts = 2;             // Max 2 priority boosts
    
    // Preemption
    bool enablePreemption = true;
    uint32_t preemptionCheckIntervalMs = 100;
    float preemptionThreshold = 0.8f;      // Preempt if higher priority task waiting
    
    // Fairness
    bool enableFairSharing = true;
    uint32_t maxTasksPerUser = 100;        // Per-user queue limit
    float fairShareWeight = 0.2f;          // Weight for fair share calculation
    
    // Deadlines
    bool enableDeadlineScheduling = true;
    uint32_t deadlineSlackMs = 100;        // Allowable deadline miss
    
    // Quotas
    std::map<TaskPriorityLevel, uint32_t> priorityQuotas;  // Max % for each priority
};

// Fair share tracker
class FairShareTracker {
public:
    FairShareTracker(uint32_t maxTasksPerUser);
    
    bool canAcceptTask(const std::string& userId);
    void recordTaskSubmitted(const std::string& userId);
    void recordTaskCompleted(const std::string& userId);
    
    float getUserShare(const std::string& userId) const;
    std::vector<std::string> getOverQuotaUsers() const;
    
    void reset();
    
private:
    uint32_t maxTasksPerUser_;
    std::map<std::string, uint32_t> userTaskCounts_;
    mutable std::mutex mutex_;
};

// Deadline-aware comparator
struct DeadlineComparator {
    bool operator()(const PriorityTask& a, const PriorityTask& b) const {
        // Earlier deadline = higher priority
        return a.deadline > b.deadline;
    }
};

// Multi-level priority queue
class PriorityTaskQueue {
public:
    PriorityTaskQueue();
    ~PriorityTaskQueue();
    
    // Initialization
    bool initialize(const PriorityQueueConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Task submission
    std::string enqueue(PriorityTask&& task);
    bool enqueueBatch(std::vector<PriorityTask>&& tasks);
    
    // Task retrieval
    bool dequeue(PriorityTask& task);
    bool dequeueWithTimeout(PriorityTask& task, uint32_t timeoutMs);
    bool peek(PriorityTask& task) const;
    
    // Priority management
    bool boostPriority(const std::string& taskId);
    bool lowerPriority(const std::string& taskId);
    TaskPriorityLevel getTaskPriority(const std::string& taskId) const;
    
    // Preemption
    bool shouldPreempt(const PriorityTask& runningTask, const PriorityTask& waitingTask) const;
    std::vector<PriorityTask> getPreemptibleTasks() const;
    bool markPreempted(const std::string& taskId);
    
    // Aging
    void applyAging();
    
    // Deadline management
    std::vector<std::string> getExpiredDeadlines() const;
    bool extendDeadline(const std::string& taskId, uint32_t extensionMs);
    
    // Queue status
    size_t size() const;
    size_t sizeForPriority(TaskPriorityLevel priority) const;
    bool empty() const;
    void clear();
    
    // Statistics
    struct PriorityStats {
        uint64_t tasksSubmitted;
        uint64_t tasksExecuted;
        uint64_t tasksPreempted;
        uint64_t tasksExpired;
        uint64_t tasksBoosted;
        
        double avgWaitTimeMs;
        double avgExecutionTimeMs;
        double deadlineMissRate;
        
        std::map<TaskPriorityLevel, uint64_t> tasksByPriority;
        std::map<std::string, uint64_t> tasksByUser;
    };
    PriorityStats getStats() const;
    void resetStats();
    
    // Configuration
    PriorityQueueConfig getConfig() const { return config_; }
    bool updateConfig(const PriorityQueueConfig& config);
    
private:
    // Internal methods
    void agingLoop();
    void deadlineLoop();
    
    uint64_t getNextSequenceNumber();
    void updateWaitTimeStats(const PriorityTask& task);
    
    // Queue selection
    std::priority_queue<PriorityTask, std::vector<PriorityTask>, DeadlineComparator>*
        selectQueue(TaskPriorityLevel priority);
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread agingThread_;
    std::thread deadlineThread_;
    mutable std::mutex mutex_;
    
    // Priority queues (one per priority level)
    std::map<TaskPriorityLevel, std::priority_queue<PriorityTask, 
             std::vector<PriorityTask>, DeadlineComparator>> queues_;
    
    // Task tracking
    std::map<std::string, PriorityTask> taskMap_;
    std::map<std::string, TaskPriorityLevel> taskPriorityMap_;
    
    // Configuration
    PriorityQueueConfig config_;
    
    // Fair share tracking
    std::unique_ptr<FairShareTracker> fairShareTracker_;
    
    // Sequence number generator
    std::atomic<uint64_t> sequenceNumber_{0};
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> tasksSubmitted{0};
        std::atomic<uint64_t> tasksExecuted{0};
        std::atomic<uint64_t> tasksPreempted{0};
        std::atomic<uint64_t> tasksExpired{0};
        std::atomic<uint64_t> tasksBoosted{0};
        std::atomic<double> totalWaitTimeMs{0.0};
        std::atomic<double> totalExecutionTimeMs{0.0};
        std::atomic<uint64_t> deadlineMisses{0};
        std::atomic<uint64_t> deadlineChecks{0};
    } stats_;
};

// Preemptive scheduler
class PreemptiveScheduler {
public:
    PreemptiveScheduler(std::shared_ptr<PriorityTaskQueue> taskQueue);
    
    // Task execution
    bool startTask(const PriorityTask& task);
    bool preemptTask(const std::string& taskId);
    bool resumeTask(const std::string& taskId);
    bool completeTask(const std::string& taskId);
    
    // Preemption check
    bool checkPreemptionNeeded();
    std::vector<std::string> getTasksToPreempt();
    
    // Running tasks
    std::vector<PriorityTask> getRunningTasks() const;
    PriorityTask getRunningTask(const std::string& taskId) const;
    
private:
    std::shared_ptr<PriorityTaskQueue> taskQueue_;
    std::map<std::string, PriorityTask> runningTasks_;
    mutable std::mutex mutex_;
};

} // namespace Distributed
} // namespace RawrXD
