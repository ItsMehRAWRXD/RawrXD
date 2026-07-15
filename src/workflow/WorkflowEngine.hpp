/**
 * WorkflowEngine.hpp
 *
 * Phase O Batch 1/5: Workflow Engine Core
 *
 * Comprehensive workflow engine with activity orchestration, state management,
 * and support for long-running workflows.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <future>
#include <any>

namespace Workflow {

// ============================================================================
// Forward Declarations
// ============================================================================

class Activity;
class Workflow;
class WorkflowInstance;
class WorkflowEngine;
class ActivityScheduler;

// ============================================================================
// Activity Result
// ============================================================================

enum class ActivityStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED,
    COMPENSATED,
    SKIPPED
};

/**
 * Activity execution result.
 */
struct ActivityResult {
    ActivityStatus status;
    std::optional<std::any> output;
    std::optional<std::string> error;
    std::chrono::milliseconds duration;
    std::map<std::string, std::string> metadata;
    
    static ActivityResult Success(std::any output = {});
    static ActivityResult Failure(const std::string& error);
    static ActivityResult Cancelled();
};

// ============================================================================
// Activity Context
// ============================================================================

/**
 * Context passed to activity execution.
 */
class ActivityContext {
public:
    explicit ActivityContext(const std::string& workflowId,
                              const std::string& activityId,
                              const std::map<std::string, std::any>& input,
                              const std::map<std::string, std::any>& workflowState);
    
    // Input
    template<typename T>
    std::optional<T> GetInput(const std::string& name) const;
    const std::map<std::string, std::any>& GetInputs() const { return input_; }
    
    // Workflow state
    template<typename T>
    std::optional<T> GetState(const std::string& name) const;
    void SetState(const std::string& name, std::any value);
    
    // Activity info
    const std::string& GetWorkflowId() const { return workflowId_; }
    const std::string& GetActivityId() const { return activityId_; }
    
    // Cancellation
    bool IsCancellationRequested() const { return cancellationRequested_; }
    void RequestCancellation() { cancellationRequested_ = true; }
    
    // Heartbeat
    void SendHeartbeat();
    void SendHeartbeat(const std::map<std::string, std::any>& details);
    
    // Logging
    void LogInfo(const std::string& message);
    void LogWarning(const std::string& message);
    void LogError(const std::string& message);
    
private:
    std::string workflowId_;
    std::string activityId_;
    std::map<std::string, std::any> input_;
    std::map<std::string, std::any> workflowState_;
    std::atomic<bool> cancellationRequested_;
};

// ============================================================================
// Activity
// ============================================================================

/**
 * Workflow activity definition.
 */
class Activity {
public:
    using ActivityFunction = std::function<ActivityResult(ActivityContext&)>;
    using CompensationFunction = std::function<ActivityResult(ActivityContext&)>;
    
    struct Config {
        std::string id;
        std::string name;
        std::string description;
        ActivityFunction function;
        std::optional<CompensationFunction> compensation;
        std::chrono::seconds timeout;
        std::optional<uint32_t> maxRetries;
        std::chrono::seconds retryInterval;
        std::vector<std::string> dependencies;
        std::map<std::string, std::string> metadata;
        bool async;
        bool skippable;
    };
    
    explicit Activity(const Config& config);
    
    // Execution
    ActivityResult Execute(ActivityContext& context);
    ActivityResult Compensate(ActivityContext& context);
    
    // Configuration
    const Config& GetConfig() const { return config_; }
    const std::string& GetId() const { return config_.id; }
    const std::string& GetName() const { return config_.name; }
    
    // Dependencies
    const std::vector<std::string>& GetDependencies() const { return config_.dependencies; }
    bool HasDependency(const std::string& activityId) const;
    
    // Properties
    bool IsAsync() const { return config_.async; }
    bool IsSkippable() const { return config_.skippable; }
    bool HasCompensation() const { return config_.compensation.has_value(); }
    
private:
    Config config_;
};

// ============================================================================
// Workflow Definition
// ============================================================================

/**
 * Workflow definition.
 */
class Workflow {
public:
    enum class ExecutionMode {
        SEQUENTIAL,
        PARALLEL,
        DAG
    };
    
    struct Config {
        std::string id;
        std::string name;
        std::string version;
        std::string description;
        ExecutionMode mode;
        std::vector<std::shared_ptr<Activity>> activities;
        std::map<std::string, std::any> defaultInput;
        std::chrono::seconds timeout;
        bool enableCompensation;
        std::map<std::string, std::string> metadata;
    };
    
    explicit Workflow(const Config& config);
    
    // Activities
    void AddActivity(std::shared_ptr<Activity> activity);
    void RemoveActivity(const std::string& activityId);
    std::shared_ptr<Activity> GetActivity(const std::string& activityId) const;
    std::vector<std::shared_ptr<Activity>> GetActivities() const;
    
    // Validation
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    
    // Execution order
    std::vector<std::string> GetExecutionOrder() const;
    std::vector<std::vector<std::string>> GetParallelGroups() const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    const std::string& GetId() const { return config_.id; }
    const std::string& GetVersion() const { return config_.version; }
    
    // Serialization
    std::string ToJson() const;
    static Workflow FromJson(const std::string& json);
    std::string ToGraphviz() const;
    
private:
    Config config_;
    mutable std::mutex mutex_;
    
    bool HasCycle() const;
    bool HasDuplicateIds() const;
    bool HasMissingDependencies() const;
    std::vector<std::string> TopologicalSort() const;
};

// ============================================================================
// Workflow Instance
// ============================================================================

/**
 * Running workflow instance.
 */
class WorkflowInstance {
public:
    enum class Status {
        PENDING,
        RUNNING,
        PAUSED,
        COMPLETED,
        FAILED,
        CANCELLED,
        COMPENSATING,
        COMPENSATED
    };
    
    struct ActivityState {
        ActivityStatus status;
        std::optional<std::any> output;
        std::optional<std::string> error;
        std::chrono::system_clock::time_point startTime;
        std::optional<std::chrono::system_clock::time_point> endTime;
        uint32_t attemptCount;
    };
    
    struct Config {
        std::string instanceId;
        std::string workflowId;
        std::map<std::string, std::any> input;
        std::map<std::string, std::any> state;
        Status status;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> startedAt;
        std::optional<std::chrono::system_clock::time_point> completedAt;
        std::optional<std::string> parentInstanceId;
        std::optional<std::string> correlationId;
    };
    
    explicit WorkflowInstance(const Config& config,
                               std::shared_ptr<Workflow> workflow);
    
    // Lifecycle
    void Start();
    void Pause();
    void Resume();
    void Cancel();
    void Complete();
    void Fail(const std::string& error);
    
    // Activity management
    void StartActivity(const std::string& activityId);
    void CompleteActivity(const std::string& activityId, const ActivityResult& result);
    void FailActivity(const std::string& activityId, const std::string& error);
    void CompensateActivity(const std::string& activityId);
    
    // State
    ActivityState GetActivityState(const std::string& activityId) const;
    std::map<std::string, ActivityState> GetAllActivityStates() const;
    bool IsActivityCompleted(const std::string& activityId) const;
    std::vector<std::string> GetCompletedActivities() const;
    std::vector<std::string> GetPendingActivities() const;
    std::vector<std::string> GetReadyActivities() const;
    
    // Output
    void SetOutput(const std::string& activityId, std::any value);
    std::optional<std::any> GetOutput(const std::string& activityId) const;
    std::map<std::string, std::any> GetAllOutputs() const;
    
    // Status
    Status GetStatus() const { return config_.status; }
    bool IsRunning() const { return config_.status == Status::RUNNING; }
    bool IsCompleted() const { return config_.status == Status::COMPLETED; }
    bool IsFailed() const { return config_.status == Status::FAILED; }
    
    // Accessors
    const Config& GetConfig() const { return config_.; }
    const std::string& GetInstanceId() const { return config_.instanceId; }
    std::shared_ptr<Workflow> GetWorkflow() const { return workflow_; }
    
    // Compensation
    void EnableCompensation();
    void Compensate();
    std::vector<std::string> GetCompensationOrder() const;
    
    // Serialization
    std::string ToJson() const;
    static WorkflowInstance FromJson(const std::string& json);
    
private:
    Config config_;
    std::shared_ptr<Workflow> workflow_;
    std::map<std::string, ActivityState> activityStates_;
    mutable std::mutex mutex_;
    
    void UpdateStatus(Status newStatus);
    bool CanStartActivity(const std::string& activityId) const;
};

// ============================================================================
// Workflow Engine
// ============================================================================

/**
 * Central workflow engine.
 */
class WorkflowEngine {
public:
    struct Config {
        uint32_t maxConcurrentWorkflows;
        uint32_t maxConcurrentActivities;
        std::chrono::seconds activityHeartbeatTimeout;
        std::chrono::seconds workflowTimeout;
        bool enablePersistence;
        std::string persistencePath;
        bool enableMetrics;
    };
    
    explicit WorkflowEngine(const Config& config);
    ~WorkflowEngine();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Workflow registration
    void RegisterWorkflow(std::shared_ptr<Workflow> workflow);
    void UnregisterWorkflow(const std::string& workflowId);
    std::shared_ptr<Workflow> GetWorkflow(const std::string& workflowId) const;
    std::vector<std::shared_ptr<Workflow>> GetWorkflows() const;
    
    // Instance management
    std::shared_ptr<WorkflowInstance> StartWorkflow(const std::string& workflowId);
    std::shared_ptr<WorkflowInstance> StartWorkflow(const std::string& workflowId,
                                                          const std::map<std::string, std::any>& input);
    std::shared_ptr<WorkflowInstance> StartWorkflow(const std::string& workflowId,
                                                          const std::map<std::string, std::any>& input,
                                                          const std::string& correlationId);
    
    std::optional<std::shared_ptr<WorkflowInstance>> GetInstance(const std::string& instanceId);
    std::vector<std::shared_ptr<WorkflowInstance>> GetInstances(const std::string& workflowId);
    std::vector<std::shared_ptr<WorkflowInstance>> GetActiveInstances();
    
    // Instance control
    bool PauseInstance(const std::string& instanceId);
    bool ResumeInstance(const std::string& instanceId);
    bool CancelInstance(const std::string& instanceId);
    bool SignalInstance(const std::string& instanceId,
                        const std::string& signalName,
                        std::any data);
    
    // Activity execution
    void ExecuteActivity(std::shared_ptr<WorkflowInstance> instance,
                         const std::string& activityId);
    void CompleteActivity(const std::string& instanceId,
                          const std::string& activityId,
                          const ActivityResult& result);
    void FailActivity(const std::string& instanceId,
                      const std::string& activityId,
                      const std::string& error);
    
    // External events
    void RaiseEvent(const std::string& eventName, std::any data);
    void SubscribeToEvent(const std::string& eventName,
                          const std::string& instanceId);
    
    // Compensation
    void CompensateInstance(const std::string& instanceId);
    
    // Statistics
    struct EngineStats {
        uint32_t activeWorkflows;
        uint32_t activeActivities;
        uint64_t totalWorkflowsStarted;
        uint64_t totalWorkflowsCompleted;
        uint64_t totalWorkflowsFailed;
        uint64_t totalActivitiesExecuted;
        double averageWorkflowDurationMs;
        double averageActivityDurationMs;
    };
    EngineStats GetStats() const;
    void ResetStats();
    
    // Health check
    bool HealthCheck() const;
    
private:
    Config config_;
    bool initialized_;
    
    std::map<std::string, std::shared_ptr<Workflow>> workflows_;
    std::map<std::string, std::shared_ptr<WorkflowInstance>> instances_;
    mutable std::mutex mutex_;
    
    std::map<std::string, std::vector<std::string>> eventSubscriptions_;
    mutable std::mutex eventMutex_;
    
    EngineStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread schedulerThread_;
    std::atomic<bool> stopScheduler_;
    std::queue<std::function<void()>> taskQueue_;
    std::condition_variable taskCondition_;
    mutable std::mutex taskMutex_;
    
    void SchedulerLoop();
    void ProcessInstance(std::shared_ptr<WorkflowInstance> instance);
    void ProcessActivity(std::shared_ptr<WorkflowInstance> instance,
                         const std::string& activityId);
    void PersistInstance(const WorkflowInstance& instance);
    void LoadInstance(const std::string& instanceId);
};

// ============================================================================
// Activity Scheduler
// ============================================================================

/**
 * Activity scheduler for workflow execution.
 */
class ActivityScheduler {
public:
    struct Config {
        uint32_t workerCount;
        std::chrono::seconds pollInterval;
        std::chrono::seconds activityTimeout;
        bool enablePrioritization;
    };
    
    struct ScheduledActivity {
        std::string instanceId;
        std::string activityId;
        std::chrono::system_clock::time_point scheduledAt;
        std::optional<std::chrono::system_clock::time_point> executeAfter;
        uint32_t priority;
    };
    
    explicit ActivityScheduler(const Config& config,
                                std::shared_ptr<WorkflowEngine> engine);
    
    // Lifecycle
    void Start();
    void Stop();
    bool IsRunning() const;
    
    // Scheduling
    void Schedule(const ScheduledActivity& activity);
    void ScheduleDelayed(const ScheduledActivity& activity, std::chrono::seconds delay);
    void Cancel(const std::string& instanceId, const std::string& activityId);
    
    // Queue management
    size_t GetQueueSize() const;
    std::vector<ScheduledActivity> GetQueue() const;
    void ClearQueue();
    
    // Statistics
    struct SchedulerStats {
        uint64_t activitiesScheduled;
        uint64_t activitiesExecuted;
        uint64_t activitiesCancelled;
        uint64_t activitiesTimedOut;
        double averageQueueTimeMs;
    };
    SchedulerStats GetStats() const;
    
private:
    Config config_;
    std::shared_ptr<WorkflowEngine> engine_;
    std::atomic<bool> running_;
    
    std::priority_queue<ScheduledActivity> queue_;
    mutable std::mutex queueMutex_;
    
    SchedulerStats stats_;
    mutable std::mutex statsMutex_;
    
    std::vector<std::thread> workerThreads_;
    
    void WorkerLoop();
    void ProcessActivity(const ScheduledActivity& activity);
};

} // namespace Workflow
