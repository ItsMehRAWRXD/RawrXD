/**
 * WorkflowPatterns.hpp
 *
 * Phase O Batch 4/5: Workflow Patterns & Compensation
 *
 * Common workflow patterns including saga, compensation, and
 * distributed transaction patterns.
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

namespace Workflow {

// ============================================================================
// Forward Declarations
// ============================================================================

class Compensation;
class Saga;
class SagaOrchestrator;
class DistributedTransaction;
class WorkflowPatterns;

// ============================================================================
// Compensation Action
// ============================================================================

/**
 * Compensation action for undoing work.
 */
class CompensationAction {
public:
    using ActionFunction = std::function<bool()>;
    using CompensationFunction = std::function<bool()>;
    
    struct Config {
        std::string id;
        std::string name;
        ActionFunction action;
        CompensationFunction compensation;
        std::chrono::seconds timeout;
        uint32_t maxRetries;
        bool idempotent;
        std::map<std::string, std::any> metadata;
    };
    
    explicit CompensationAction(const Config& config);
    
    // Execution
    bool Execute();
    bool Compensate();
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const std::string& GetName() const { return config_.name; }
    bool IsIdempotent() const { return config_.idempotent; }
    
    // State
    bool IsExecuted() const { return executed_; }
    bool IsCompensated() const { return compensated_; }
    
private:
    Config config_;
    bool executed_;
    bool compensated_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Compensation Scope
// ============================================================================

/**
 * Scope for managing compensations.
 */
class CompensationScope {
public:
    enum class Strategy {
        IMMEDIATE,      // Compensate immediately on failure
        DEFERRED,       // Collect all compensations, execute at end
        MANUAL          // Manual compensation trigger
    };
    
    struct Config {
        std::string scopeId;
        Strategy strategy;
        bool parallelCompensation;
        std::chrono::seconds compensationTimeout;
    };
    
    explicit CompensationScope(const Config& config);
    ~CompensationScope();
    
    // Registration
    void RegisterAction(std::shared_ptr<CompensationAction> action);
    void RegisterAction(const std::string& id,
                        const CompensationAction::ActionFunction& action,
                        const CompensationAction::CompensationFunction& compensation);
    
    // Execution
    bool ExecuteAction(const std::string& actionId);
    bool ExecuteAll();
    
    // Compensation
    bool Compensate();
    bool Compensate(const std::string& actionId);
    bool CompensateAll();
    
    // Status
    bool IsComplete() const;
    bool NeedsCompensation() const;
    std::vector<std::string> GetExecutedActions() const;
    std::vector<std::string> GetCompensatedActions() const;
    
private:
    Config config_;
    std::vector<std::shared_ptr<CompensationAction>> actions_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Saga Step
// ============================================================================

/**
 * Step in a saga.
 */
class SagaStep {
public:
    enum class Type {
        ACTION,
        COMPENSATION,
        PARALLEL,
        COMPENSABLE
    };
    
    struct Config {
        std::string id;
        std::string name;
        Type type;
        std::function<bool()> action;
        std::optional<std::function<bool()>> compensation;
        std::vector<std::string> dependencies;
        std::chrono::seconds timeout;
        uint32_t maxRetries;
        bool continueOnFailure;
    };
    
    explicit SagaStep(const Config& config);
    
    // Execution
    bool Execute();
    bool Compensate();
    
    // Dependencies
    const std::vector<std::string>& GetDependencies() const { return config_.dependencies; }
    bool HasDependency(const std::string& stepId) const;
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const std::string& GetName() const { return config_.name; }
    Type GetType() const { return config_.type; }
    bool HasCompensation() const { return config_.compensation.has_value(); }
    
    // State
    bool IsExecuted() const { return executed_; }
    bool IsCompensated() const { return compensated_; }
    bool IsFailed() const { return failed_; }
    
private:
    Config config_;
    bool executed_;
    bool compensated_;
    bool failed_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Saga
// ============================================================================

/**
 * Saga pattern for distributed transactions.
 */
class Saga {
public:
    enum class ExecutionMode {
        SEQUENTIAL,
        PARALLEL,
        MIXED
    };
    
    enum class CompensationOrder {
        REVERSE,        // Compensate in reverse order
        FORWARD,        // Compensate in forward order
        CUSTOM          // Custom compensation order
    };
    
    struct Config {
        std::string sagaId;
        std::string name;
        ExecutionMode mode;
        CompensationOrder compensationOrder;
        bool continueOnFailure;
        std::chrono::seconds stepTimeout;
        std::chrono::seconds sagaTimeout;
    };
    
    struct SagaResult {
        bool success;
        std::vector<std::string> completedSteps;
        std::vector<std::string> failedSteps;
        std::vector<std::string> compensatedSteps;
        std::optional<std::string> error;
        std::chrono::milliseconds duration;
    };
    
    explicit Saga(const Config& config);
    
    // Step management
    void AddStep(std::shared_ptr<SagaStep> step);
    void RemoveStep(const std::string& stepId);
    std::shared_ptr<SagaStep> GetStep(const std::string& stepId) const;
    std::vector<std::shared_ptr<SagaStep>> GetSteps() const;
    
    // Execution
    SagaResult Execute();
    std::future<SagaResult> ExecuteAsync();
    
    // Compensation
    bool Compensate();
    bool Compensate(const std::vector<std::string>& stepIds);
    
    // Status
    bool IsRunning() const;
    bool IsComplete() const;
    bool IsFailed() const;
    bool IsCompensating() const;
    
    // Accessors
    const std::string& GetSagaId() const { return config_.sagaId; }
    
private:
    Config config_;
    std::vector<std::shared_ptr<SagaStep>> steps_;
    std::atomic<bool> running_;
    std::atomic<bool> compensating_;
    mutable std::mutex mutex_;
    
    SagaResult ExecuteSequential();
    SagaResult ExecuteParallel();
    SagaResult ExecuteMixed();
    std::vector<std::shared_ptr<SagaStep>> GetExecutionOrder() const;
    std::vector<std::shared_ptr<SagaStep>> GetCompensationOrder() const;
};

// ============================================================================
// Saga Orchestrator
// ============================================================================

/**
 * Orchestrator for managing multiple sagas.
 */
class SagaOrchestrator {
public:
    struct Config {
        uint32_t maxConcurrentSagas;
        bool enablePersistence;
        std::string persistencePath;
        bool enableMetrics;
    };
    
    explicit SagaOrchestrator(const Config& config);
    ~SagaOrchestrator();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Saga management
    std::string StartSaga(std::shared_ptr<Saga> saga);
    bool CancelSaga(const std::string& sagaId);
    bool CompensateSaga(const std::string& sagaId);
    
    std::optional<std::shared_ptr<Saga>> GetSaga(const std::string& sagaId);
    std::vector<std::shared_ptr<Saga>> GetActiveSagas() const;
    std::vector<std::shared_ptr<Saga>> GetCompletedSagas() const;
    std::vector<std::shared_ptr<Saga>> GetFailedSagas() const;
    
    // Persistence
    void PersistSaga(const std::string& sagaId);
    void RestoreSaga(const std::string& sagaId);
    
    // Statistics
    struct OrchestratorStats {
        uint32_t activeSagas;
        uint64_t totalSagasStarted;
        uint64_t totalSagasCompleted;
        uint64_t totalSagasFailed;
        uint64_t totalSagasCompensated;
        double averageSagaDurationMs;
    };
    OrchestratorStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    std::map<std::string, std::shared_ptr<Saga>> sagas_;
    mutable std::mutex mutex_;
    
    OrchestratorStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread monitorThread_;
    std::atomic<bool> stopMonitor_;
    
    void MonitorLoop();
};

// ============================================================================
// Distributed Transaction
// ============================================================================

/**
 * Two-phase commit distributed transaction.
 */
class DistributedTransaction {
public:
    enum class Status {
        PENDING,
        PREPARING,
        PREPARED,
        COMMITTING,
        COMMITTED,
        ABORTING,
        ABORTED,
        FAILED
    };
    
    enum class ParticipantStatus {
        UNKNOWN,
        READY,
        PREPARED,
        COMMITTED,
        ABORTED,
        FAILED
    };
    
    struct Participant {
        std::string id;
        std::string name;
        std::function<bool()> prepare;
        std::function<bool()> commit;
        std::function<bool()> abort;
        ParticipantStatus status;
        std::optional<std::string> error;
    };
    
    struct Config {
        std::string transactionId;
        std::chrono::seconds prepareTimeout;
        std::chrono::seconds commitTimeout;
        std::chrono::seconds abortTimeout;
        bool failOnAnyAbort;
    };
    
    explicit DistributedTransaction(const Config& config);
    
    // Participant management
    void AddParticipant(const Participant& participant);
    void RemoveParticipant(const std::string& participantId);
    std::vector<Participant> GetParticipants() const;
    
    // Transaction lifecycle
    bool Begin();
    bool Prepare();
    bool Commit();
    bool Abort();
    
    // Status
    Status GetStatus() const { return status_; }
    bool IsComplete() const;
    bool IsSuccessful() const;
    
    // Results
    std::map<std::string, ParticipantStatus> GetParticipantStatuses() const;
    std::vector<std::string> GetFailedParticipants() const;
    
private:
    Config config_;
    std::vector<Participant> participants_;
    std::atomic<Status> status_;
    mutable std::mutex mutex_;
    
    bool PrepareParticipant(Participant& participant);
    bool CommitParticipant(Participant& participant);
    bool AbortParticipant(Participant& participant);
};

// ============================================================================
// Workflow Patterns
// ============================================================================

/**
 * Common workflow patterns.
 */
class WorkflowPatterns {
public:
    // Sequential execution
    template<typename... Actions>
    static bool Sequence(Actions... actions);
    
    // Parallel execution
    template<typename... Actions>
    static bool Parallel(Actions... actions);
    
    // Fork-Join pattern
    template<typename T>
    static std::vector<T> ForkJoin(const std::vector<std::function<T()>>& actions);
    
    // Split-Join pattern
    template<typename T, typename R>
    static R SplitJoin(const std::vector<T>& inputs,
                       std::function<R(const T&)> mapper,
                       std::function<R(const std::vector<R>&)> reducer);
    
    // Scatter-Gather pattern
    template<typename T>
    static std::vector<T> ScatterGather(
        const std::vector<std::function<T()>>& actions,
        std::chrono::milliseconds timeout);
    
    // Circuit Breaker pattern
    template<typename T>
    static std::optional<T> CircuitBreaker(
        std::function<T()> action,
        std::function<bool(const std::exception&)> isFailure,
        uint32_t failureThreshold,
        std::chrono::seconds recoveryTime);
    
    // Retry pattern
    template<typename T>
    static T Retry(std::function<T()> action,
                   uint32_t maxRetries,
                   std::chrono::milliseconds delay,
                   std::function<bool(const std::exception&)> shouldRetry);
    
    // Timeout pattern
    template<typename T>
    static std::optional<T> Timeout(std::function<T()> action,
                                        std::chrono::milliseconds timeout);
    
    // Throttle pattern
    template<typename T>
    static T Throttle(std::function<T()> action,
                      std::chrono::milliseconds minInterval);
    
    // Debounce pattern
    template<typename T>
    static std::function<T()> Debounce(std::function<T()> action,
                                        std::chrono::milliseconds delay);
    
    // Cache-Aside pattern
    template<typename K, typename V>
    static V CacheAside(const K& key,
                        std::function<V()> loader,
                        std::function<std::optional<V>(const K&)> cacheGet,
                        std::function<void(const K&, const V&)> cachePut);
    
    // Bulkhead pattern
    template<typename T>
    static T Bulkhead(std::function<T()> action,
                      uint32_t maxConcurrent,
                      std::chrono::milliseconds timeout);
    
    // Pipeline pattern
    template<typename T>
    static T Pipeline(const T& input,
                      const std::vector<std::function<T(const T&)>>& stages);
    
    // Fan-Out/Fan-In pattern
    template<typename T, typename R>
    static std::vector<R> FanOutFanIn(
        const std::vector<T>& inputs,
        std::function<R(const T&)> processor,
        uint32_t maxConcurrency);
    
    // Priority Queue pattern
    template<typename T>
    static std::vector<T> PriorityProcess(
        const std::vector<T>& items,
        std::function<int(const T&)> priorityFn,
        std::function<void(const T&)> processor);
    
    // Event-Driven pattern
    template<typename Event, typename Result>
    static Result EventDriven(
        const std::vector<Event>& events,
        std::function<void(const Event&)> eventHandler,
        std::function<Result()> resultProvider);
    
    // Saga pattern helper
    static std::shared_ptr<Saga> CreateSaga(
        const std::string& name,
        const std::vector<std::pair<
            std::function<bool()>,
            std::optional<std::function<bool()>>
        >>& steps);
    
    // Outbox pattern
    static bool OutboxPattern(
        std::function<bool()> businessOperation,
        std::function<bool(const std::vector<std::string>&)> messagePublisher,
        std::function<void(const std::string&)> outboxStore);
    
    // Inbox pattern
    static bool InboxPattern(
        const std::string& messageId,
        std::function<bool(const std::string&)> idempotencyCheck,
        std::function<bool()> messageHandler);
};

// ============================================================================
// Transaction Outbox
// ============================================================================

/**
 * Outbox pattern for reliable message publishing.
 */
class TransactionOutbox {
public:
    struct Message {
        std::string id;
        std::string topic;
        std::string payload;
        std::map<std::string, std::string> headers;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> processedAt;
        uint32_t retryCount;
        std::optional<std::string> error;
    };
    
    struct Config {
        std::string storagePath;
        std::chrono::seconds pollInterval;
        uint32_t maxRetries;
        std::chrono::seconds retryInterval;
        uint32_t batchSize;
    };
    
    explicit TransactionOutbox(const Config& config);
    ~TransactionOutbox();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Message storage
    void StoreMessage(const Message& message);
    void StoreMessages(const std::vector<Message>& messages);
    
    // Processing
    void StartProcessing();
    void StopProcessing();
    void ProcessBatch();
    
    // Message retrieval
    std::vector<Message> GetPendingMessages(uint32_t limit);
    std::vector<Message> GetFailedMessages();
    
    // Publisher registration
    void RegisterPublisher(const std::string& topic,
                           std::function<bool(const Message&)> publisher);
    
    // Statistics
    struct OutboxStats {
        uint64_t messagesStored;
        uint64_t messagesPublished;
        uint64_t messagesFailed;
        uint64_t messagesRetried;
        uint32_t pendingMessages;
    };
    OutboxStats GetStats() const;
    
private:
    Config config_;
    bool initialized_;
    std::atomic<bool> processing_;
    
    std::vector<Message> messages_;
    mutable std::mutex messagesMutex_;
    
    std::map<std::string, std::function<bool(const Message&)>> publishers_;
    mutable std::mutex publishersMutex_;
    
    OutboxStats stats_;
    mutable std::mutex statsMutex_;
    
    std::thread processorThread_;
    
    void ProcessLoop();
    bool PublishMessage(const Message& message);
    void MarkAsProcessed(const std::string& messageId);
    void MarkAsFailed(const std::string& messageId, const std::string& error);
};

} // namespace Workflow
