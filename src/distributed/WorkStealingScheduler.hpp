// RawrXD Work Stealing Scheduler
// Phase O.2: Advanced task scheduling with work stealing for load balancing
// Enables idle nodes to steal tasks from busy nodes

#pragma once

#include <vector>
#include <queue>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <thread>
#include <random>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class ClusterManager;
class DistributedScheduler;

// Work stealing task
struct StealableTask {
    std::string taskId;
    std::string ownerNodeId;
    uint32_t priority;
    std::chrono::steady_clock::time_point submitTime;
    std::chrono::steady_clock::time_point stealTime;
    uint32_t stealCount;
    
    // Task payload
    std::vector<uint8_t> payload;
    size_t estimatedDurationMs;
    size_t estimatedMemoryBytes;
    
    // Affinity
    std::vector<std::string> preferredNodes;
    std::vector<std::string> forbiddenNodes;
    
    StealableTask() : priority(0), stealCount(0), estimatedDurationMs(0), 
                      estimatedMemoryBytes(0) {}
};

// Task queue with work stealing support
class WorkStealingQueue {
public:
    WorkStealingQueue(const std::string& nodeId);
    ~WorkStealingQueue();
    
    // Local operations (owner only)
    void pushLocal(StealableTask&& task);
    bool popLocal(StealableTask& task);
    bool peekLocal(StealableTask& task) const;
    
    // Stealing operations (other nodes)
    bool steal(StealableTask& task);
    size_t stealMultiple(std::vector<StealableTask>& tasks, size_t maxCount);
    
    // Status
    size_t size() const;
    bool empty() const;
    void clear();
    
    // Statistics
    struct QueueStats {
        uint64_t tasksPushed;
        uint64_t tasksPopped;
        uint64_t tasksStolen;
        uint64_t stealAttempts;
        uint64_t failedSteals;
        double avgQueueDepth;
    };
    QueueStats getStats() const;
    void resetStats();
    
private:
    // Chase-Lev deque for work stealing
    std::deque<StealableTask> tasks_;
    mutable std::mutex mutex_;
    std::string nodeId_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> tasksPushed{0};
        std::atomic<uint64_t> tasksPopped{0};
        std::atomic<uint64_t> tasksStolen{0};
        std::atomic<uint64_t> stealAttempts{0};
        std::atomic<uint64_t> failedSteals{0};
    } stats_;
};

// Work stealing configuration
struct WorkStealingConfig {
    // Stealing behavior
    bool enableWorkStealing = true;
    uint32_t stealIntervalMs = 100;
    uint32_t maxStealsPerAttempt = 3;
    uint32_t maxStealChainLength = 5;  // Prevent infinite stealing
    
    // Victim selection
    enum class VictimSelection {
        RANDOM,         // Random victim
        LARGEST_QUEUE,  // Steal from largest queue
        NEIGHBOR,       // Steal from neighbor nodes
        LOAD_BASED      // Steal from most loaded nodes
    } victimSelection = VictimSelection::LOAD_BASED;
    
    // Throttling
    uint32_t minQueueSizeToSteal = 2;
    float stealThreshold = 0.2f;  // Steal if victim has 20%+ more work
    
    // Backoff
    uint32_t emptyQueueBackoffMs = 10;
    uint32_t failedStealBackoffMs = 50;
    uint32_t maxBackoffMs = 1000;
    
    // Affinity
    bool respectAffinity = true;
    bool allowCrossRegionStealing = false;
    
    // Statistics
    bool collectDetailedStats = true;
};

// Victim selection strategy
class VictimSelector {
public:
    VictimSelector(WorkStealingConfig::VictimSelection strategy);
    
    void updateQueueSizes(const std::map<std::string, size_t>& sizes);
    std::string selectVictim(const std::string& thiefId, 
                              const std::vector<std::string>& candidates);
    
    void recordStealSuccess(const std::string& victimId);
    void recordStealFailure(const std::string& victimId);
    
private:
    WorkStealingConfig::VictimSelection strategy_;
    std::map<std::string, size_t> queueSizes_;
    std::map<std::string, uint32_t> successCount_;
    std::map<std::string, uint32_t> failureCount_;
    mutable std::mutex mutex_;
    std::mt19937 rng_;
};

// Work stealing scheduler
class WorkStealingScheduler {
public:
    WorkStealingScheduler(std::shared_ptr<ClusterManager> clusterManager);
    ~WorkStealingScheduler();
    
    // Initialization
    bool initialize(const WorkStealingConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Task submission
    std::string submitTask(StealableTask&& task);
    bool cancelTask(const std::string& taskId);
    
    // Local queue operations
    bool popTask(StealableTask& task);
    bool tryPopTask(StealableTask& task, uint32_t timeoutMs);
    
    // Work stealing
    bool stealTask(StealableTask& task);
    size_t stealTasks(std::vector<StealableTask>& tasks, size_t maxCount);
    
    // Victim management
    void registerVictim(const std::string& nodeId);
    void unregisterVictim(const std::string& nodeId);
    std::vector<std::string> getVictims() const;
    
    // Load balancing
    bool isUnderloaded() const;
    bool isOverloaded() const;
    float getLoadRatio() const;
    void triggerRebalancing();
    
    // Statistics
    struct StealingStats {
        uint64_t tasksSubmitted;
        uint64_t tasksExecuted;
        uint64_t tasksStolen;
        uint64_t stealAttempts;
        uint64_t successfulSteals;
        uint64_t failedSteals;
        
        double avgStealLatencyMs;
        double avgStealChainLength;
        uint32_t maxStealChainLength;
        
        std::map<std::string, uint64_t> stealsFromNode;
        std::map<std::string, uint64_t> stealsToNode;
    };
    StealingStats getStats() const;
    void resetStats();
    
    // Configuration
    WorkStealingConfig getConfig() const { return config_; }
    bool updateConfig(const WorkStealingConfig& config);
    
private:
    // Internal methods
    void stealingLoop();
    void rebalancingLoop();
    std::string selectVictim();
    bool attemptSteal(const std::string& victimId, StealableTask& task);
    size_t attemptStealMultiple(const std::string& victimId, 
                                 std::vector<StealableTask>& tasks, 
                                 size_t maxCount);
    
    void updateVictimList();
    void backoff(uint32_t& currentBackoffMs);
    
    std::string generateTaskId();
    
    // Threading
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    std::thread stealingThread_;
    std::thread rebalancingThread_;
    
    // State
    WorkStealingConfig config_;
    std::string localNodeId_;
    
    // Task queue
    std::unique_ptr<WorkStealingQueue> localQueue_;
    
    // Victim management
    std::vector<std::string> victims_;
    mutable std::mutex victimsMutex_;
    std::unique_ptr<VictimSelector> victimSelector_;
    
    // Task tracking
    std::map<std::string, StealableTask> activeTasks_;
    mutable std::mutex tasksMutex_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> tasksSubmitted{0};
        std::atomic<uint64_t> tasksExecuted{0};
        std::atomic<uint64_t> tasksStolen{0};
        std::atomic<uint64_t> stealAttempts{0};
        std::atomic<uint64_t> successfulSteals{0};
        std::atomic<uint64_t> failedSteals{0};
        std::atomic<double> totalStealLatencyMs{0.0};
        std::atomic<uint64_t> stealCount{0};
        std::map<std::string, std::atomic<uint64_t>> stealsFromNode;
        std::map<std::string, std::atomic<uint64_t>> stealsToNode;
    } stats_;
    
    // Dependencies
    std::shared_ptr<ClusterManager> clusterManager_;
    
    // Task ID counter
    std::atomic<uint64_t> taskIdCounter_{0};
    
    // Backoff state
    uint32_t currentBackoffMs_ = 0;
};

// Hierarchical work stealing (for multi-level topologies)
class HierarchicalWorkStealing {
public:
    struct Level {
        std::string name;
        std::vector<std::string> nodes;
        std::unique_ptr<WorkStealingScheduler> scheduler;
    };
    
    HierarchicalWorkStealing(std::shared_ptr<ClusterManager> clusterManager);
    
    bool initialize(const std::vector<Level>& levels);
    
    // Task routing
    std::string submitTask(StealableTask&& task);
    bool popTask(StealableTask& task);
    
    // Cross-level stealing
    bool stealFromParent(StealableTask& task);
    bool stealFromChild(const std::string& childLevel, StealableTask& task);
    
private:
    std::shared_ptr<ClusterManager> clusterManager_;
    std::vector<Level> levels_;
    std::string localLevel_;
};

} // namespace Distributed
} // namespace RawrXD
