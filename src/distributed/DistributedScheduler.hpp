// RawrXD Distributed Scheduler
// Phase O.2: Task Graph Scheduling with Resource Awareness
// Routes inference requests to optimal nodes based on resources and latency

#pragma once

#include <vector>
#include <queue>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <future>

namespace RawrXD {
namespace Distributed {

// Forward declarations
class ClusterManager;
class ModelResidencyManager;

// Task types
enum class TaskType {
    INFERENCE,      // Standard inference request
    EMBEDDING,    // Embedding generation
    TRAINING,     // Fine-tuning task
    EVALUATION,   // Model evaluation
    BENCHMARK     // Performance benchmark
};

// Task priority levels
enum class TaskPriority : uint8_t {
    CRITICAL = 0,   // System-critical tasks
    HIGH = 1,       // User-facing high priority
    NORMAL = 2,     // Standard requests
    LOW = 3,        // Background tasks
    BACKGROUND = 4  // Maintenance tasks
};

// Task specification
struct TaskSpec {
    std::string taskId;
    TaskType type;
    TaskPriority priority;
    
    // Model requirements
    std::string modelId;
    std::string modelFormat;
    size_t modelSize;           // Estimated model size in bytes
    
    // Resource requirements
    struct Requirements {
        size_t minVRAM;         // Minimum GPU memory required
        size_t preferredVRAM;   // Preferred GPU memory
        size_t minRAM;          // Minimum system RAM
        uint32_t minCpuCores;   // Minimum CPU cores
        bool requiresGPU;       // Must have GPU
        bool supportsQuantized; // Can use quantized models
        bool requiresStreaming; // Needs streaming support
    } requirements;
    
    // Execution constraints
    struct Constraints {
        uint32_t maxLatencyMs;      // Maximum acceptable latency
        uint32_t timeoutMs;         // Task timeout
        std::vector<std::string> preferredNodes;  // Preferred node IDs
        std::vector<std::string> excludedNodes;   // Nodes to exclude
        bool allowQueueing;         // Can be queued if no resources
    } constraints;
    
    // Payload
    std::vector<uint8_t> payload;
    size_t payloadSize;
    
    // Timing
    std::chrono::steady_clock::time_point submittedAt;
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point completedAt;
    
    TaskSpec() : type(TaskType::INFERENCE), priority(TaskPriority::NORMAL), 
                   modelSize(0), payloadSize(0) {}
};

// Scheduling decision
struct SchedulingDecision {
    std::string taskId;
    std::string nodeId;
    std::string nodeAddress;
    bool canExecute;
    std::string reason;         // Reason for decision
    uint32_t estimatedLatencyMs;
    uint32_t queuePosition;     // Position in queue (0 = immediate)
    
    // Alternative options if primary fails
    std::vector<std::string> fallbackNodes;
};

// Node scoring factors
struct NodeScore {
    std::string nodeId;
    float totalScore;
    
    // Component scores (0-1)
    float resourceScore;        // Resource availability
    float latencyScore;         // Network latency
    float queueScore;           // Queue depth
    float affinityScore;        // Model affinity (already loaded)
    float capabilityScore;      // Hardware capabilities
    float healthScore;          // Health status
    
    // Details
    size_t availableVRAM;
    uint32_t queueDepth;
    uint32_t latencyMs;
    bool hasModelLoaded;
};

// Scheduling policy
enum class SchedulingPolicy {
    ROUND_ROBIN,        // Simple round-robin
    LEAST_LOADED,       // Least loaded node
    LATENCY_OPTIMIZED,  // Minimize latency
    THROUGHPUT_OPTIMIZED, // Maximize throughput
    COST_OPTIMIZED,     // Minimize cost
    AFFINITY_BASED      // Prefer nodes with model loaded
};

// Scheduler configuration
struct SchedulerConfig {
    SchedulingPolicy policy = SchedulingPolicy::AFFINITY_BASED;
    
    // Queue settings
    uint32_t maxQueueDepth = 1000;
    uint32_t maxQueueDepthPerNode = 100;
    uint32_t defaultTimeoutMs = 30000;
    
    // Resource weights for scoring
    float resourceWeight = 0.25f;
    float latencyWeight = 0.20f;
    float queueWeight = 0.20f;
    float affinityWeight = 0.25f;
    float capabilityWeight = 0.10f;
    
    // Latency thresholds
    uint32_t lowLatencyThresholdMs = 50;
    uint32_t highLatencyThresholdMs = 200;
    
    // Retry settings
    uint32_t maxRetries = 3;
    uint32_t retryDelayMs = 1000;
    
    // Load balancing
    bool enableLoadBalancing = true;
    uint32_t rebalanceIntervalMs = 60000;
    float rebalanceThreshold = 0.2f;  // Trigger if imbalance > 20%
};

// Task queue entry
struct QueuedTask {
    TaskSpec task;
    std::chrono::steady_clock::time_point queuedAt;
    uint32_t retryCount;
    std::vector<std::string> attemptedNodes;
};

// Execution result
struct ExecutionResult {
    std::string taskId;
    bool success;
    std::string nodeId;
    std::chrono::milliseconds duration;
    std::vector<uint8_t> output;
    std::string errorMessage;
    uint32_t tokensGenerated;
    uint32_t tokensPerSecond;
};

// Task completion callback
using TaskCompletionCallback = std::function<void(const ExecutionResult&)>;

// Distributed scheduler class
class DistributedScheduler {
public:
    DistributedScheduler(std::shared_ptr<ClusterManager> clusterManager);
    ~DistributedScheduler();
    
    // Initialization
    bool initialize(const SchedulerConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Task submission
    std::future<ExecutionResult> submitTask(const TaskSpec& task);
    std::string submitTaskAsync(const TaskSpec& task, TaskCompletionCallback callback);
    
    // Task management
    bool cancelTask(const std::string& taskId);
    TaskSpec getTaskStatus(const std::string& taskId) const;
    std::vector<TaskSpec> getQueuedTasks() const;
    std::vector<TaskSpec> getRunningTasks() const;
    
    // Scheduling
    SchedulingDecision scheduleTask(const TaskSpec& task);
    std::vector<NodeScore> scoreNodesForTask(const TaskSpec& task);
    std::vector<std::string> getCandidateNodes(const TaskSpec& task);
    
    // Queue management
    size_t getQueueDepth() const;
    size_t getQueueDepthForNode(const std::string& nodeId) const;
    void clearQueue();
    
    // Statistics
    struct SchedulerStats {
        uint64_t tasksSubmitted;
        uint64_t tasksExecuted;
        uint64_t tasksFailed;
        uint64_t tasksCancelled;
        uint64_t tasksQueued;
        
        double avgLatencyMs;
        double avgQueueTimeMs;
        double avgExecutionTimeMs;
        
        uint32_t currentQueueDepth;
        uint32_t currentRunningTasks;
        
        std::map<std::string, uint64_t> tasksByNode;
        std::map<TaskType, uint64_t> tasksByType;
    };
    SchedulerStats getStats() const;
    void resetStats();
    
    // Configuration
    SchedulerConfig getConfig() const { return config_; }
    bool updateConfig(const SchedulerConfig& config);
    
    // Load balancing
    void triggerRebalancing();
    bool isRebalancing() const { return isRebalancing_; }
    
private:
    // Internal methods
    void schedulerLoop();
    void rebalancingLoop();
    void executeTask(const QueuedTask& queuedTask);
    void completeTask(const std::string& taskId, const ExecutionResult& result);
    void failTask(const std::string& taskId, const std::string& error);
    
    float calculateNodeScore(const NodeInfo& node, const TaskSpec& task);
    float calculateResourceScore(const NodeInfo& node, const TaskSpec& task);
    float calculateLatencyScore(const NodeInfo& node);
    float calculateQueueScore(const NodeInfo& node);
    float calculateAffinityScore(const NodeInfo& node, const TaskSpec& task);
    float calculateCapabilityScore(const NodeInfo& node, const TaskSpec& task);
    
    bool canNodeExecuteTask(const NodeInfo& node, const TaskSpec& task);
    bool meetsRequirements(const NodeInfo& node, const TaskSpec::Requirements& req);
    
    std::string generateTaskId();
    void cleanupCompletedTasks();
    
    // Threading
    std::atomic<bool> running_;
    std::thread schedulerThread_;
    std::thread rebalancingThread_;
    mutable std::mutex tasksMutex_;
    mutable std::mutex queueMutex_;
    
    // State
    std::atomic<bool> initialized_;
    std::atomic<bool> isRebalancing_;
    SchedulerConfig config_;
    
    // Task tracking
    std::map<std::string, QueuedTask> tasks_;
    std::queue<std::string> taskQueue_;
    std::set<std::string> runningTasks_;
    std::map<std::string, ExecutionResult> completedTasks_;
    
    // Callbacks
    std::map<std::string, TaskCompletionCallback> callbacks_;
    mutable std::mutex callbacksMutex_;
    
    // Promises for async tasks
    std::map<std::string, std::shared_ptr<std::promise<ExecutionResult>>> promises_;
    mutable std::mutex promisesMutex_;
    
    // Statistics
    struct Stats {
        std::atomic<uint64_t> tasksSubmitted{0};
        std::atomic<uint64_t> tasksExecuted{0};
        std::atomic<uint64_t> tasksFailed{0};
        std::atomic<uint64_t> tasksCancelled{0};
        std::atomic<uint64_t> tasksQueued{0};
        
        std::atomic<double> totalLatencyMs{0.0};
        std::atomic<double> totalQueueTimeMs{0.0};
        std::atomic<double> totalExecutionTimeMs{0.0};
        
        std::map<std::string, std::atomic<uint64_t>> tasksByNode;
        std::map<TaskType, std::atomic<uint64_t>> tasksByType;
    } stats_;
    
    // Dependencies
    std::shared_ptr<ClusterManager> clusterManager_;
    std::shared_ptr<ModelResidencyManager> residencyManager_;
    
    // Task ID counter
    std::atomic<uint64_t> taskIdCounter_{0};
};

// Task graph for complex workflows
class TaskGraph {
public:
    struct Node {
        std::string id;
        TaskSpec task;
        std::vector<std::string> dependencies;
        std::vector<std::string> dependents;
        bool executed;
        bool failed;
        ExecutionResult result;
    };
    
    TaskGraph();
    ~TaskGraph();
    
    // Graph construction
    std::string addTask(const TaskSpec& task);
    bool addDependency(const std::string& taskId, const std::string& dependsOn);
    bool removeTask(const std::string& taskId);
    
    // Execution
    std::vector<std::string> getReadyTasks() const;
    std::vector<std::string> getExecutionOrder() const;
    bool markExecuted(const std::string& taskId, const ExecutionResult& result);
    bool markFailed(const std::string& taskId, const std::string& error);
    
    // Status
    bool isComplete() const;
    bool hasFailed() const;
    size_t getTotalTasks() const;
    size_t getCompletedTasks() const;
    size_t getRemainingTasks() const;
    
private:
    std::map<std::string, Node> nodes_;
    mutable std::mutex mutex_;
};

} // namespace Distributed
} // namespace RawrXD
