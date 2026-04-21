#pragma once
/**
 * ExecutionStatePersistence - Days 1-2: Workflow state serialization/deserialization
 * 
 * Production-grade persistence layer for agent execution state.
 * Enables workflows to survive restarts and resume from checkpoints.
 */

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <filesystem>

class AgenticLoopState;
class AgenticMemorySystem;
class AgenticExecutor;

/**
 * @class ExecutionCheckpoint
 * @brief Single checkpoint within a workflow (progress marker)
 */
class ExecutionCheckpoint {
public:
    std::string checkpointId;
    std::string label;
    int sequenceNumber = 0;
    std::string timestamp;
    nlohmann::json stateSnapshot;
    bool isRecoveryPoint = false;
    std::string recoveryReason;

    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);
};

/**
 * @class WorkflowExecution
 * @brief Complete workflow execution state (all checkpoints + metadata)
 */
class WorkflowExecution {
public:
    std::string executionId;
    std::string workflowName;
    std::string goal;
    std::string status;  // "in-progress", "completed", "failed", "paused"
    std::string startTime;
    std::string lastUpdateTime;
    std::string completionTime;
    
    int currentCheckpointIndex = 0;
    std::vector<ExecutionCheckpoint> checkpoints;
    nlohmann::json globalContext;
    nlohmann::json metadata;
    std::vector<std::string> errorLog;
    
    nlohmann::json toJson() const;
    void fromJson(const nlohmann::json& j);
};

/**
 * @class ExecutionStatePersistence
 * @brief Production execution state serialization/deserialization engine
 * 
 * Guarantees:
 * - Safe JSON serialization of all state artifacts
 * - Atomic write operations (temp + move pattern)
 * - Corruption detection and rollback capability
 * - Automatic compression for large states
 * - Memory-efficient incremental snapshots
 */
class ExecutionStatePersistence {
public:
    explicit ExecutionStatePersistence(const std::filesystem::path& persistenceRoot);
    ~ExecutionStatePersistence();

    // ===== Persistence API =====
    
    /**
     * Save complete workflow execution state to disk
     * @param execution Workflow execution to persist
     * @return execution ID if successful, empty string on failure
     */
    std::string persistWorkflowExecution(const WorkflowExecution& execution);

    /**
     * Load workflow execution state from disk
     * @param executionId ID of execution to restore
     * @return loaded execution or nullptr if not found
     */
    std::unique_ptr<WorkflowExecution> loadWorkflowExecution(const std::string& executionId) const;

    /**
     * Save checkpoint within active workflow
     * @param checkpoint Checkpoint to persist
     * @param executionId Parent execution ID
     * @return checkpoint ID if successful
     */
    std::string createCheckpoint(
        const std::string& executionId,
        const std::string& label,
        const nlohmann::json& stateSnapshot);

    // ===== Workflow Recovery =====

    /**
     * List all persisted workflow executions
     * @return vector of execution IDs
     */
    std::vector<std::string> listExecutions() const;

    /**
     * Check if execution exists and is valid
     */
    bool hasValidExecution(const std::string& executionId) const;

    /**
     * Get the last incomplete execution (for resumption)
     */
    std::unique_ptr<WorkflowExecution> getLastIncompleteExecution();

    /**
     * Resume execution from checkpoint
     * @param executionId Execution to resume
     * @param checkpointIndex Which checkpoint to resume from (default: last)
     * @return resumed execution state
     */
    std::unique_ptr<WorkflowExecution> resumeFromCheckpoint(
        const std::string& executionId,
        int checkpointIndex = -1);

    /**
     * Restore persisted subsystem state from a workflow execution envelope.
     */
    bool restoreExecutionState(
        const WorkflowExecution& execution,
        AgenticLoopState* loopState,
        AgenticMemorySystem* memorySystem) const;

    /**
     * Restore persisted subsystem state from a checkpoint snapshot.
     */
    bool restoreCheckpointState(
        const ExecutionCheckpoint& checkpoint,
        AgenticLoopState* loopState,
        AgenticMemorySystem* memorySystem) const;

    // ===== State Capture from Live Systems =====

    /**
     * Capture current agent state into workflow execution
     * Snapshots loop state, memory system, and executor context
     */
    WorkflowExecution captureCurrentExecution(
        const std::string& workflowName,
        const std::string& goal,
        AgenticLoopState* loopState,
        AgenticMemorySystem* memorySystem,
        AgenticExecutor* executor);

    // ===== Error Recovery =====

    /**
     * Validate persisted state for corruption
     * @return error message if corrupted, empty string if valid
     */
    std::string validateExecution(const std::string& executionId) const;

    /**
     * Recover from corrupt state (rollback to last valid checkpoint)
     */
    bool recoverFromCorruption(const std::string& executionId);

    /**
     * Remove persisted execution (cleanup)
     */
    bool deleteExecution(const std::string& executionId);

    // ===== Statistics =====

    struct PersistenceStats {
        size_t totalExecutions = 0;
        size_t activeExecutions = 0;
        size_t completedExecutions = 0;
        size_t failedExecutions = 0;
        size_t totalCheckpoints = 0;
        size_t diskUsageBytes = 0;
    };

    PersistenceStats getStatistics() const;

    /**
     * Cleanup old executions (retention policy)
     * @param maxAgeHours Delete executions older than this (0 = no limit)
     * @return number of deleted executions
     */
    int cleanupOldExecutions(int maxAgeHours = 0);

private:
    std::filesystem::path m_persistenceRoot;
    std::string generateExecutionId();
    std::string getExecutionPath(const std::string& executionId) const;
    bool ensurePersistenceRoot();
    
    // Atomic write with rollback pattern
    bool atomicWrite(
        const std::filesystem::path& target,
        const std::string& content) const;

    // Validation and corruption detection
    bool validateJsonSchema(const nlohmann::json& j) const;
    int findResumableCheckpointIndex(const WorkflowExecution& execution, int requestedIndex) const;
    bool restoreStatePayload(
        const nlohmann::json& payload,
        AgenticLoopState* loopState,
        AgenticMemorySystem* memorySystem) const;
};
