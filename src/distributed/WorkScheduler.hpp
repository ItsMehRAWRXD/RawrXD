/**
 * WorkScheduler.hpp
 *
 * Phase D.3 Batch 4/5: Work Distribution & Load Balancing
 *
 * Distributed task scheduling and load balancing across cluster nodes.
 * Optimizes resource utilization and minimizes latency.
 */

#pragma once

#include "ConsensusEngine.hpp"
#include <queue>
#include <functional>

namespace Distributed {

// ============================================================================
// Forward Declarations
// ============================================================================

class WorkScheduler;
class LoadBalancer;
class TaskDistributor;

// ============================================================================
// Task Types
// ============================================================================

enum class TaskPriority {
    CRITICAL = 0,   // System-critical tasks
    HIGH = 1,       // User-facing urgent tasks
    NORMAL = 2,     // Standard tasks
    LOW = 3,        // Background tasks
    BATCH = 4       // Batch processing
};

enum class TaskState {
    PENDING,      // Waiting to be scheduled
    SCHEDULED,  // Assigned to a node
    RUNNING,    // Currently executing
    COMPLETED,  // Finished successfully
    FAILED,     // Failed execution
    CANCELLED   // Cancelled before completion
};

enum class TaskType {
    INFERENCE,      // Model inference
    TRAINING,       // Model training
    EVALUATION,     // Model evaluation
    DATA_PROCESSING, // Data preprocessing
    AGENT_TASK,     // Agent execution
    SYSTEM_TASK,    // System maintenance
    CUSTOM          // User-defined
};

std::string TaskPriorityToString(TaskPriority priority);
std::string TaskStateToString(TaskState state);
std::string TaskTypeToString(TaskType type);

// ============================================================================
// Task Specification
// ============================================================================

/**
 * Resource requirements for a task.
 */
struct ResourceRequirements {
    uint32_t cpuCores = 1;           // Required CPU cores
    uint64_t memoryBytes = 0;        // Required memory
    uint64_t gpuMemoryBytes = 0;     // Required GPU memory
    uint32_t gpuCount = 0;           // Required GPUs
    uint64_t diskBytes = 0;          // Required disk space
    uint64_t networkBandwidth = 0;   // Required bandwidth
    
    // Check if requirements can be satisfied
    bool CanBeSatisfiedBy(const ResourceRequirements& available) const;
    
    std::string ToJson() const;
};

/**
 * Task specification.
 */
struct TaskSpec {
    std::string taskId;              // Unique task ID
    TaskType type;                   // Task type
    TaskPriority priority;           // Task priority
    ResourceRequirements resources;  // Resource requirements
    std::string payload;             // Task payload (JSON)
    std::string nodeAffinity;        // Preferred node (optional)
    std::vector<std::string> nodeAntiAffinity; // Avoid these nodes
    uint64_t maxRuntimeMs;           // Maximum runtime
    uint64_t deadlineMs;             // Deadline timestamp
    uint32_t maxRetries;             // Max retry attempts
    std::vector<std::string> dependencies; // Task dependencies
    
    std::string ToJson() const;
    static TaskSpec FromJson(const std::string& json);
};

// ============================================================================
// Task Status
// ============================================================================

/**
 * Current status of a task.
 */
struct TaskStatus {
    std::string taskId;
    TaskState state;
    std::string assignedNode;
    uint64_t createdTime;
    uint64_t scheduledTime;
    uint64_t startedTime;
    uint64_t completedTime;
    uint32_t retryCount;
    std::string errorMessage;
    float progress;  // 0.0 - 1.0
    std::string result;
    
    std::string ToJson() const;
};

// ============================================================================
// Node Capacity
// ============================================================================

/**
 * Available capacity on a node.
 */
struct NodeCapacity {
    std::string nodeId;
    ResourceRequirements total;
    ResourceRequirements used;
    ResourceRequirements available;
    float cpuUtilization;
    float memoryUtilization;
    float gpuUtilization;
    uint32_t activeTasks;
    uint64_t lastUpdateTime;
    bool isHealthy;
    
    ResourceRequirements GetAvailable() const;
    bool CanAccept(const ResourceRequirements& requirements) const;
    float GetUtilizationScore() const;
    
    std::string ToJson() const;
};

// ============================================================================
// Scheduling Policy
// ============================================================================

/**
 * Policy for task scheduling decisions.
 */
struct SchedulingPolicy {
    enum class Strategy {
        ROUND_ROBIN,        // Distribute evenly
        LEAST_LOADED,       // Prefer least loaded nodes
        MOST_LOCALITY,      // Prefer data locality
        PRIORITY_QUEUE,     // Strict priority ordering
        FAIR_SHARE,         // Fair resource sharing
        BIN_PACKING         // Optimize resource packing
    };
    
    Strategy strategy = Strategy::LEAST_LOADED;
    bool enablePreemption = false;           // Allow task preemption
    bool enableGangScheduling = false;       // Schedule task groups
    bool enableBackfilling = true;          // Fill gaps with small tasks
    uint64_t reservationTimeoutMs = 30000;   // Reservation timeout
    uint32_t maxQueueDepth = 10000;          // Max pending tasks
    float loadBalanceThreshold = 0.2f;       // Rebalance threshold
};

// ============================================================================
// Task Queue
// ============================================================================

/**
 * Priority queue for pending tasks.
 */
class TaskQueue {
public:
    TaskQueue();
    ~TaskQueue();
    
    // Add task to queue
    void Enqueue(const TaskSpec& task);
    
    // Get next task
    std::optional<TaskSpec> Dequeue();
    std::optional<TaskSpec> Dequeue(const NodeCapacity& nodeCapacity);
    
    // Peek at next task
    std::optional<TaskSpec> Peek() const;
    
    // Remove task
    bool Remove(const std::string& taskId);
    
    // Query
    bool Contains(const std::string& taskId) const;
    size_t Size() const;
    bool IsEmpty() const;
    size_t CountByPriority(TaskPriority priority) const;
    
    // Get all tasks
    std::vector<TaskSpec> GetAll() const;
    std::vector<TaskSpec> GetByType(TaskType type) const;
    
    // Clear
    void Clear();
    
private:
    struct QueuedTask {
        TaskSpec spec;
        uint64_t enqueueTime;
        
        bool operator<(const QueuedTask& other) const;
    };
    
    std::priority_queue<QueuedTask> queue_;
    std::map<std::string, TaskSpec> taskMap_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Load Balancer
// ============================================================================

/**
 * Balances load across cluster nodes.
 */
class LoadBalancer {
public:
    explicit LoadBalancer(const SchedulingPolicy& policy);
    ~LoadBalancer();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Update node capacity
    void UpdateNodeCapacity(const NodeCapacity& capacity);
    void RemoveNode(const std::string& nodeId);
    
    // Get node capacity
    std::optional<NodeCapacity> GetNodeCapacity(const std::string& nodeId);
    std::vector<NodeCapacity> GetAllNodeCapacities();
    
    // Select node for task
    std::optional<std::string> SelectNode(const TaskSpec& task);
    std::vector<std::string> SelectNodes(const TaskSpec& task, size_t count);
    
    // Check if rebalancing needed
    bool NeedsRebalancing();
    
    // Get rebalance recommendations
    std::vector<std::pair<std::string, std::string>> GetRebalanceRecommendations();
    
    // Calculate cluster statistics
    float GetAverageUtilization() const;
    float GetUtilizationVariance() const;
    bool IsBalanced() const;
    
    // Status
    std::string GetStatusJson() const;
    
private:
    SchedulingPolicy policy_;
    std::map<std::string, NodeCapacity> nodes_;
    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
    
    // Selection strategies
    std::optional<std::string> SelectRoundRobin(const TaskSpec& task);
    std::optional<std::string> SelectLeastLoaded(const TaskSpec& task);
    std::optional<std::string> SelectByLocality(const TaskSpec& task);
    std::optional<std::string> SelectByFairShare(const TaskSpec& task);
    std::optional<std::string> SelectByBinPacking(const TaskSpec& task);
    
    // Utility
    float CalculateNodeScore(const NodeCapacity& node, const TaskSpec& task);
    std::vector<std::string> GetEligibleNodes(const TaskSpec& task);
};

// ============================================================================
// Task Distributor
// ============================================================================

/**
 * Distributes tasks to assigned nodes.
 */
class TaskDistributor {
public:
    TaskDistributor(
        std::shared_ptr<CommunicationManager> commManager,
        std::shared_ptr<LoadBalancer> loadBalancer
    );
    ~TaskDistributor();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Submit task
    bool SubmitTask(const TaskSpec& task);
    bool SubmitTasks(const std::vector<TaskSpec>& tasks);
    
    // Cancel task
    bool CancelTask(const std::string& taskId);
    
    // Get task status
    std::optional<TaskStatus> GetTaskStatus(const std::string& taskId);
    std::vector<TaskStatus> GetAllTaskStatus();
    std::vector<TaskStatus> GetTasksByState(TaskState state);
    
    // Wait for task completion
    bool WaitForTask(const std::string& taskId, uint64_t timeoutMs);
    bool WaitForAllTasks(uint64_t timeoutMs);
    
    // Callbacks
    using TaskCompleteCallback = std::function<void(const TaskStatus&)>;
    void OnTaskComplete(TaskCompleteCallback callback);
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    std::shared_ptr<LoadBalancer> loadBalancer_;
    
    std::map<std::string, TaskStatus> taskStatus_;
    std::map<std::string, TaskSpec> taskSpecs_;
    mutable std::mutex mutex_;
    
    TaskCompleteCallback completeCallback_;
    std::mutex callbackMutex_;
    
    std::atomic<bool> running_{false};
    std::thread monitorThread_;
    
    // Message handlers
    void HandleTaskStatusUpdate(const Message& message);
    void HandleTaskComplete(const Message& message);
    
    // Monitor loop
    void MonitorLoop();
    
    // Utility
    void NotifyTaskComplete(const TaskStatus& status);
    bool SendTaskToNode(const TaskSpec& task, const std::string& nodeId);
};

// ============================================================================
// Work Scheduler
// ============================================================================

/**
 * Main work scheduler coordinating task scheduling.
 */
class WorkScheduler {
public:
    using TaskResultCallback = std::function<void(const std::string& taskId, const std::string& result)>;
    
    WorkScheduler(
        std::shared_ptr<CommunicationManager> commManager,
        const SchedulingPolicy& policy = SchedulingPolicy{}
    );
    ~WorkScheduler();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Task submission
    std::string SubmitTask(const TaskSpec& task);
    std::vector<std::string> SubmitTasks(const std::vector<TaskSpec>& tasks);
    
    // Task control
    bool CancelTask(const std::string& taskId);
    bool PauseTask(const std::string& taskId);
    bool ResumeTask(const std::string& taskId);
    
    // Task queries
    std::optional<TaskStatus> GetTaskStatus(const std::string& taskId);
    std::optional<TaskSpec> GetTaskSpec(const std::string& taskId);
    std::vector<TaskStatus> GetTasksByState(TaskState state);
    std::vector<TaskStatus> GetTasksByNode(const std::string& nodeId);
    
    // Wait for completion
    bool WaitForTask(const std::string& taskId, uint64_t timeoutMs);
    bool WaitForTasks(const std::vector<std::string>& taskIds, uint64_t timeoutMs);
    
    // Results
    std::optional<std::string> GetTaskResult(const std::string& taskId);
    void OnTaskComplete(TaskResultCallback callback);
    
    // Node management
    void RegisterNode(const std::string& nodeId, const NodeCapacity& capacity);
    void UnregisterNode(const std::string& nodeId);
    void UpdateNodeCapacity(const std::string& nodeId, const NodeCapacity& capacity);
    std::vector<std::string> GetActiveNodes();
    
    // Scheduling control
    void PauseScheduling();
    void ResumeScheduling();
    bool IsSchedulingPaused() const;
    
    // Statistics
    struct Statistics {
        uint64_t totalTasksSubmitted;
        uint64_t totalTasksCompleted;
        uint64_t totalTasksFailed;
        uint64_t totalTasksCancelled;
        uint64_t averageQueueTimeMs;
        uint64_t averageExecutionTimeMs;
        float clusterUtilization;
        size_t pendingTasks;
        size_t runningTasks;
    };
    
    Statistics GetStatistics() const;
    std::string GetStatisticsJson() const;
    
    // Status
    std::string GetStatusJson() const;
    bool IsHealthy() const;
    
private:
    std::shared_ptr<CommunicationManager> commManager_;
    SchedulingPolicy policy_;
    
    std::unique_ptr<TaskQueue> taskQueue_;
    std::unique_ptr<LoadBalancer> loadBalancer_;
    std::unique_ptr<TaskDistributor> distributor_;
    
    std::map<std::string, TaskStatus> taskStatus_;
    std::map<std::string, TaskSpec> taskSpecs_;
    std::map<std::string, std::string> taskResults_;
    
    mutable std::mutex stateMutex_;
    std::atomic<bool> running_{false};
    std::atomic<bool> schedulingPaused_{false};
    
    // Background threads
    std::thread schedulerThread_;
    std::thread rebalanceThread_;
    
    // Statistics
    Statistics stats_{};
    mutable std::mutex statsMutex_;
    
    // Callbacks
    TaskResultCallback resultCallback_;
    std::mutex callbackMutex_;
    
    // Background loops
    void SchedulerLoop();
    void RebalanceLoop();
    
    // Internal methods
    void ProcessQueue();
    bool ScheduleTask(const TaskSpec& task);
    void UpdateTaskStatus(const TaskStatus& status);
    void HandleTaskCompletion(const TaskStatus& status);
    void RebalanceIfNeeded();
    
    // ID generation
    std::string GenerateTaskId();
};

// ============================================================================
// Distributed Executor
// ============================================================================

/**
 * High-level distributed task execution API.
 */
class DistributedExecutor {
public:
    DistributedExecutor(
        std::shared_ptr<CommunicationManager> commManager,
        const SchedulingPolicy& policy = SchedulingPolicy{}
    );
    ~DistributedExecutor();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Simple execution
    std::future<std::string> Execute(
        const std::string& command,
        const ResourceRequirements& resources = ResourceRequirements{}
    );
    
    std::future<std::string> ExecuteJson(
        const std::string& jsonCommand,
        const ResourceRequirements& resources = ResourceRequirements{}
    );
    
    // Batch execution
    std::vector<std::future<std::string>> ExecuteBatch(
        const std::vector<std::string>& commands,
        const ResourceRequirements& resources = ResourceRequirements{}
    );
    
    // Map-reduce style
    std::future<std::string> MapReduce(
        const std::vector<std::string>& inputs,
        const std::string& mapFunction,
        const std::string& reduceFunction
    );
    
    // Status
    std::string GetStatusJson() const;
    
private:
    std::unique_ptr<WorkScheduler> scheduler_;
};

} // namespace Distributed
