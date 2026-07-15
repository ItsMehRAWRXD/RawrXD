/**
 * SovereignExecutionPlanner.hpp
 * 
 * Phase B.4 Batch 3/5: Execution Planner
 * 
 * Advanced execution planning with:
 * - Parallel-safe execution scheduling
 * - Failure isolation and recovery
 * - Critical path analysis
 * - Dynamic load balancing
 * - Resource allocation
 */

#pragma once

#include "SovereignExecutionGraph.hpp"
#include <future>
#include <thread>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <chrono>

namespace Sovereign {
namespace SEG {

/**
 * Execution stage containing nodes that can run in parallel
 */
struct ExecutionStage {
    int stageNumber{0};
    std::vector<NodeId> nodes;
    std::chrono::milliseconds estimatedDuration{0};
    std::chrono::milliseconds actualDuration{0};
    bool isComplete{false};
    bool hasFailures{false};
};

/**
 * Execution metrics for monitoring and optimization
 */
struct ExecutionMetrics {
    std::chrono::milliseconds totalDuration{0};
    std::chrono::milliseconds planningDuration{0};
    int stagesExecuted{0};
    int nodesExecuted{0};
    int nodesFailed{0};
    int nodesSkipped{0};
    int maxParallelism{0};
    double averageStageDuration{0.0};
    double parallelismEfficiency{0.0}; // Actual parallelism / Max possible
};

/**
 * Resource requirements for node execution
 */
struct ResourceRequirements {
    int cpuCores{1};
    size_t memoryBytes{0};
    bool requiresGPU{false};
    int gpuMemoryMB{0};
};

/**
 * Node execution result
 */
struct NodeExecutionResult {
    NodeId nodeId{0};
    bool success{false};
    std::string errorMessage;
    std::chrono::milliseconds executionTime{0};
    int retryCount{0};
    ResourceRequirements resourcesUsed;
};

/**
 * Execution configuration
 */
struct ExecutionConfig {
    int maxConcurrency{static_cast<int>(std::thread::hardware_concurrency())};
    int maxRetries{3};
    std::chrono::milliseconds nodeTimeout{30000}; // 30 seconds
    std::chrono::milliseconds stageTimeout{300000}; // 5 minutes
    bool continueOnFailure{false}; // Whether to continue if a node fails
    bool enableRetries{true};
    bool enableMetrics{true};
    bool enableResourceTracking{false};
};

/**
 * Enhanced Execution Planner with parallel execution support
 */
class SovereignExecutionPlanner {
public:
    // Plan creation
    struct ExecutionPlan {
        std::vector<ExecutionStage> stages;
        std::vector<NodeId> criticalPath;
        std::map<NodeId, ResourceRequirements> resourceMap;
        int estimatedTotalTimeMs{0};
        int maxParallelism{0};
        int criticalPathLength{0};
    };
    
    ExecutionPlan CreatePlan(const ExecutionGraph& graph);
    ExecutionPlan CreateOptimizedPlan(const ExecutionGraph& graph, const ExecutionConfig& config);
    
    // Critical path analysis
    std::vector<NodeId> CalculateCriticalPath(const ExecutionGraph& graph);
    std::vector<NodeId> CalculateCriticalPath(const ExecutionGraph& graph, NodeId start, NodeId end);
    int CalculatePathLength(const ExecutionGraph& graph, const std::vector<NodeId>& path);
    
    // Resource planning
    void AssignResources(ExecutionPlan& plan, const ExecutionGraph& graph);
    bool ValidateResourceConstraints(const ExecutionPlan& plan, const ExecutionConfig& config);
    
    // Plan analysis
    ExecutionMetrics AnalyzePlan(const ExecutionPlan& plan);
    int EstimateExecutionTime(const ExecutionPlan& plan, int avgNodeTimeMs);
    double CalculateParallelismEfficiency(const ExecutionPlan& plan);
};

/**
 * Parallel executor with failure isolation
 */
class SovereignParallelExecutor {
public:
    using NodeExecutor = std::function<NodeExecutionResult(ExecutionNode&)>;
    using StageCallback = std::function<void(int stageNumber, const ExecutionStage&)>;
    using NodeCallback = std::function<void(NodeId, const NodeExecutionResult&)>;
    using CompletionCallback = std::function<void(bool success, const ExecutionMetrics&)>;
    
    SovereignParallelExecutor();
    ~SovereignParallelExecutor();
    
    // Configuration
    void SetConfig(const ExecutionConfig& config) { config_ = config; }
    void SetNodeExecutor(NodeType type, NodeExecutor executor);
    void SetStageCallback(StageCallback callback) { stageCallback_ = callback; }
    void SetNodeCallback(NodeCallback callback) { nodeCallback_ = callback; }
    void SetCompletionCallback(CompletionCallback callback) { completionCallback_ = callback; }
    
    // Execution
    bool Execute(ExecutionGraph& graph, const SovereignExecutionPlanner::ExecutionPlan& plan);
    bool ExecuteSequential(ExecutionGraph& graph);
    bool ExecuteParallel(ExecutionGraph& graph, int maxConcurrency);
    
    // Execution control
    void Pause();
    void Resume();
    void Cancel();
    bool IsRunning() const { return isRunning_.load(); }
    bool IsPaused() const { return isPaused_.load(); }
    
    // Status
    ExecutionMetrics GetMetrics() const { return metrics_; }
    int GetCurrentStage() const { return currentStage_.load(); }
    int GetCompletedNodes() const { return completedNodes_.load(); }
    int GetFailedNodes() const { return failedNodes_.load(); }
    
    // Failure recovery
    bool RetryNode(ExecutionGraph& graph, NodeId nodeId);
    bool SkipNode(ExecutionGraph& graph, NodeId nodeId);
    void MarkNodeFailed(ExecutionGraph& graph, NodeId nodeId, const std::string& error);
    
private:
    ExecutionConfig config_;
    std::map<NodeType, NodeExecutor> nodeExecutors_;
    StageCallback stageCallback_;
    NodeCallback nodeCallback_;
    CompletionCallback completionCallback_;
    
    std::atomic<bool> isRunning_{false};
    std::atomic<bool> isPaused_{false};
    std::atomic<bool> shouldCancel_{false};
    std::atomic<int> currentStage_{0};
    std::atomic<int> completedNodes_{0};
    std::atomic<int> failedNodes_{0};
    
    ExecutionMetrics metrics_;
    mutable std::mutex metricsMutex_;
    
    // Thread pool
    std::vector<std::thread> workerThreads_;
    std::queue<std::function<void()>> taskQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCondition_;
    std::atomic<bool> stopWorkers_{false};
    
    // Execution helpers
    void InitializeWorkers(int numWorkers);
    void ShutdownWorkers();
    NodeExecutionResult ExecuteNode(ExecutionNode& node);
    bool ExecuteStage(ExecutionGraph& graph, ExecutionStage& stage);
    void UpdateMetrics(const NodeExecutionResult& result);
    void UpdateNodeState(ExecutionGraph& graph, NodeId nodeId, ExecutionState state);
};

/**
 * Execution monitor for real-time monitoring
 */
class ExecutionMonitor {
public:
    struct MonitorSnapshot {
        int currentStage{0};
        int totalStages{0};
        int completedNodes{0};
        int totalNodes{0};
        int failedNodes{0};
        std::chrono::milliseconds elapsedTime{0};
        std::chrono::milliseconds estimatedRemaining{0};
        double progressPercent{0.0};
        std::vector<NodeId> currentlyRunning;
        std::vector<NodeId> readyToRun;
    };
    
    void AttachToExecutor(SovereignParallelExecutor* executor);
    void AttachToGraph(ExecutionGraph* graph);
    
    MonitorSnapshot GetSnapshot() const;
    std::string GetSnapshotJson() const;
    
    // Callbacks
    using SnapshotCallback = std::function<void(const MonitorSnapshot&)>;
    void SetSnapshotCallback(SnapshotCallback callback) { snapshotCallback_ = callback; }
    void SetSnapshotInterval(std::chrono::milliseconds interval) { snapshotInterval_ = interval; }
    
    // Start/stop monitoring
    void StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const { return isMonitoring_.load(); }
    
private:
    SovereignParallelExecutor* executor_{nullptr};
    ExecutionGraph* graph_{nullptr};
    SnapshotCallback snapshotCallback_;
    std::chrono::milliseconds snapshotInterval_{1000}; // 1 second default
    
    std::atomic<bool> isMonitoring_{false};
    std::thread monitorThread_;
    
    void MonitorLoop();
};

/**
 * Checkpoint manager for execution persistence
 */
class ExecutionCheckpointManager {
public:
    struct Checkpoint {
        std::string id;
        std::chrono::system_clock::time_point timestamp;
        std::vector<NodeId> completedNodes;
        std::vector<NodeId> failedNodes;
        std::map<NodeId, ExecutionState> nodeStates;
        ExecutionMetrics metrics;
    };
    
    void SetCheckpointDirectory(const std::string& path) { checkpointDir_ = path; }
    
    // Checkpoint operations
    std::string CreateCheckpoint(const ExecutionGraph& graph, const ExecutionMetrics& metrics);
    bool RestoreFromCheckpoint(ExecutionGraph& graph, ExecutionMetrics& metrics, const std::string& checkpointId);
    bool DeleteCheckpoint(const std::string& checkpointId);
    std::vector<std::string> ListCheckpoints() const;
    
    // Auto-checkpointing
    void EnableAutoCheckpoint(bool enable) { autoCheckpoint_ = enable; }
    void SetAutoCheckpointInterval(std::chrono::milliseconds interval) { autoCheckpointInterval_ = interval; }
    
private:
    std::string checkpointDir_{"./checkpoints"};
    bool autoCheckpoint_{false};
    std::chrono::milliseconds autoCheckpointInterval_{60000}; // 1 minute
    
    std::string SerializeCheckpoint(const Checkpoint& checkpoint) const;
    Checkpoint DeserializeCheckpoint(const std::string& data) const;
};

} // namespace SEG
} // namespace Sovereign
