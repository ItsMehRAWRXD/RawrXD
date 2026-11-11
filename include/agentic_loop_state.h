#pragma once

#include <string>
#include <vector>
#include <deque>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <cstdint>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * @class AgenticLoopState
 * @brief Complete state management for iterative reasoning loops with full context
 * 
 * Manages:
 * - Reasoning iterations and history
 * - Agent state (current goal, progress, constraints)
 * - Execution context and environment
 * - Error tracking and recovery state
 * - Decision history for reflection
 * - Memory management with context windows
 * - Checkpoints for resumption
 */
class AgenticLoopState {
public:
    // Iteration result status
    enum class IterationStatus {
        NotStarted,
        InProgress,
        Completed,
        Failed,
        Recovering,
        MaxAttemptsReached
    };

    // Reasoning phase
    enum class ReasoningPhase {
        Analysis,
        Planning,
        Execution,
        Verification,
        Reflection,
        Adjustment
    };

    // Agent decision record
    struct Decision {
        std::chrono::system_clock::time_point timestamp;
        ReasoningPhase phase;
        std::string description;
        json reasoning;
        json outcome;
        float confidence;
        bool success;
        int retryCount = 0;
        std::string recoveryAction;
    };

    // Iteration record
    struct Iteration {
        int iterationNumber;
        std::chrono::system_clock::time_point startTime;
        std::chrono::system_clock::time_point endTime;
        ReasoningPhase currentPhase;
        IterationStatus status;
        std::vector<Decision> decisions;
        std::string goalStatement;
        json contextSnapshot;
        std::string resultSummary;
        float successScore;
        int errorCount = 0;
        std::vector<std::string> appliedStrategies;
    };

    // Error recovery record
    struct ErrorRecord {
        std::chrono::system_clock::time_point timestamp;
        std::string errorType;
        std::string errorMessage;
        std::string stackTrace;
        ReasoningPhase phase;
        std::string recoveryStrategy;
        bool recoverySucceeded;
        int recoveryAttempt;
        json context;
    };

public:
    AgenticLoopState();
    ~AgenticLoopState();

    // ===== ITERATION MANAGEMENT =====
    void startIteration(const std::string& goal);
    void endIteration(IterationStatus status, const std::string& result);
    Iteration* getCurrentIteration();
    const std::vector<Iteration>& getIterationHistory() const { return m_iterations; }

    // ===== PHASE MANAGEMENT =====
    void setCurrentPhase(ReasoningPhase phase);
    ReasoningPhase getCurrentPhase() const { return m_currentPhase; }
    float getPhaseProgress() const;
    std::vector<std::string> getAllPhaseTransitions() const;

    // ===== DECISION TRACKING =====
    void recordDecision(
        const std::string& description,
        const json& reasoning,
        float confidence
    );
    void recordDecisionOutcome(
        int decisionIndex,
        const json& outcome,
        bool success
    );
    std::vector<Decision> getDecisionHistory(int limit = -1) const;
    Decision* getCurrentDecision();
    float getAverageDecisionConfidence() const;
    float getDecisionSuccessRate() const;

    // ===== ERROR TRACKING AND RECOVERY =====
    void recordError(
        const std::string& errorType,
        const std::string& message,
        const std::string& stackTrace = ""
    );
    void recordErrorRecovery(
        int errorIndex,
        const std::string& strategy,
        bool succeeded
    );
    const std::deque<ErrorRecord>& getErrorHistory(size_t limit = 50) const;
    int getTotalErrorCount() const { return (int)m_errorHistory.size(); }
    float getErrorRate() const;
    std::string generateErrorAnalysis() const;

    // ===== STATE SNAPSHOTS (CHECKPOINTING) =====
    json takeSnapshot();
    bool restoreFromSnapshot(const json& snapshot);
    json getLastSnapshot() const { return m_lastSnapshot; }

    // ===== MEMORY AND CONTEXT WINDOW =====
    void addToMemory(const std::string& key, const json& value);
    json getFromMemory(const std::string& key);
    void removeFromMemory(const std::string& key);
    json getAllMemory() const;
    void clearMemoryExcept(const std::vector<std::string>& keysToKeep);
    
    // Context window management - keep last N iterations in context
    void setContextWindowSize(int size);
    json getContextWindow() const;
    std::string formatContextForModel() const;

    // ===== GOAL AND PROGRESS TRACKING =====
    void setGoal(const std::string& goal) { m_currentGoal = goal; }
    std::string getGoal() const { return m_currentGoal; }
    void updateProgress(int current, int total);
    float getProgressPercentage() const;
    json getProgressInfo() const;

    // ===== CONSTRAINT MANAGEMENT =====
    void addConstraint(const std::string& key, const std::string& constraint);
    void removeConstraint(const std::string& key);
    json getAllConstraints() const { return m_constraints; }
    bool validateAgainstConstraints(const json& action) const;

    // ===== STRATEGY TRACKING =====
    void recordAppliedStrategy(const std::string& strategy);
    std::vector<std::string> getAppliedStrategies() const { return m_appliedStrategies; }
    std::vector<std::string> getSuggestedStrategies() const { return m_suggestedStrategies; }
    void setSuggestedStrategies(const std::vector<std::string>& strategies);

    // ===== OVERALL STATE METRICS =====
    json getMetrics() const;
    int getTotalIterations() const { return (int)m_iterations.size(); }
    int getCompletedIterations() const;
    int getFailedIterations() const;
    float getOverallSuccessRate() const;
    std::string getStateAsSummary() const;

    // ===== SERIALIZATION =====
    std::string serializeState() const;
    bool deserializeState(const std::string& jsonStr);

    // ===== DEBUGGING =====
    std::string generateDebugReport() const;
    void setDebugMode(bool enabled) { m_debugMode = enabled; }
    bool isDebugMode() const { return m_debugMode; }

private:
    // State data
    std::vector<Iteration> m_iterations;
    std::deque<ErrorRecord> m_errorHistory;
    std::deque<Iteration> m_contextWindow;
    
    ReasoningPhase m_currentPhase;
    IterationStatus m_currentStatus;
    std::string m_currentGoal;
    
    std::chrono::system_clock::time_point m_stateStartTime;
    std::chrono::system_clock::time_point m_lastUpdateTime;
    
    int m_progressCurrent = 0;
    int m_progressTotal = 0;
    int m_contextWindowSize = 5;
    
    // Memory store
    std::unordered_map<std::string, json> m_memory;
    json m_constraints;
    
    // Strategy tracking
    std::vector<std::string> m_appliedStrategies;
    std::vector<std::string> m_suggestedStrategies;
    
    // Snapshots for recovery
    json m_lastSnapshot;
    std::vector<json> m_snapshotHistory;
    
    // Debug
    bool m_debugMode = false;

    // Helper methods
    std::string phaseToString(ReasoningPhase phase) const;
    ReasoningPhase stringToPhase(const std::string& str) const;
    std::string statusToString(IterationStatus status) const;
    IterationStatus stringToStatus(const std::string& str) const;
};
