/**
 * SovereignState.hpp
 *
 * Phase D.1 Batch 2/5: State Consistency Layer
 *
 * Single source of truth for system state.
 * Prevents subsystem disagreement.
 */

#pragma once

#include <string>
#include <map>
#include <cstdint>
#include <vector>

namespace Core {

/**
 * Execution modes
 */
enum class ExecutionMode {
    IDLE,           // No execution
    MANUAL,         // Human-controlled
    ASSISTED,       // Human-supervised autonomous
    AUTONOMOUS,     // Full autonomous
    SELF_OPTIMIZING // Autonomous with self-modification
};

std::string ExecutionModeToString(ExecutionMode mode);
ExecutionMode StringToExecutionMode(const std::string& str);

/**
 * Runtime state snapshot
 */
struct RuntimeState {
    bool isRunning{false};
    bool isPaused{false};
    int cycleCount{0};
    int64_t uptimeMs{0};
    double cpuUtilization{0.0};
    double memoryUsageMB{0.0};
    int activeThreads{0};
    int64_t lastCheckpointMs{0};
    
    std::string ToJson() const;
};

/**
 * SEG state snapshot
 */
struct SEGState {
    int nodeCount{0};
    int edgeCount{0};
    int activeExecutions{0};
    int pendingExecutions{0};
    double averageExecutionTimeMs{0.0};
    int completedExecutions{0};
    int failedExecutions{0};
    
    std::string ToJson() const;
};

/**
 * Engine state snapshot
 */
struct EngineState {
    bool isInitialized{false};
    int activeCycles{0};
    double tokensPerSecond{0.0};
    double averageLatencyMs{0.0};
    int totalTokensGenerated{0};
    int failedCycles{0};
    
    std::string ToJson() const;
};

/**
 * Swarm state snapshot
 */
struct SwarmState {
    int totalWorkers{0};
    int activeWorkers{0};
    int idleWorkers{0};
    int failedWorkers{0};
    int tasksCompleted{0};
    int tasksFailed{0};
    double averageTaskTimeMs{0.0};
    
    std::string ToJson() const;
};

/**
 * Emergent layer state
 */
struct EmergentState {
    int patternsDetected{0};
    int rolesAssigned{0};
    int intentsActive{0};
    int correctionsApplied{0};
    double systemStability{1.0};
    double convergenceScore{0.0};
    
    std::string ToJson() const;
};

/**
 * Autonomy state
 */
struct AutonomyState {
    ExecutionMode mode{ExecutionMode::IDLE};
    int decisionsPending{0};
    int decisionsExecuted{0};
    int decisionsFailed{0};
    double averageDecisionConfidence{0.0};
    bool emergencyStopped{false};
    
    std::string ToJson() const;
};

/**
 * Unified Sovereign State
 *
 * Single source of truth that aggregates all subsystem states.
 */
struct SovereignState {
    // Metadata
    std::string phase{"UNINITIALIZED"};
    int64_t timestampMs{0};
    std::string version{"1.0.0"};
    
    // Aggregated metrics
    double stability{0.0};
    double convergence{0.0};
    double performance{0.0};
    size_t activeNodes{0};
    size_t activeWorkers{0};
    ExecutionMode mode{ExecutionMode::IDLE};
    
    // Subsystem states
    RuntimeState runtime;
    SEGState seg;
    EngineState engine;
    SwarmState swarm;
    EmergentState emergent;
    AutonomyState autonomy;
    
    // Health
    int activeSubsystems{0};
    int healthySubsystems{0};
    std::vector<std::string> errors;
    
    // Methods
    std::string ToJson() const;
    void Print() const;
    bool IsHealthy() const;
    double CalculateOverallHealth() const;
    
    // Update methods
    void UpdateFromRuntime(const RuntimeState& state);
    void UpdateFromSEG(const SEGState& state);
    void UpdateFromEngine(const EngineState& state);
    void UpdateFromSwarm(const SwarmState& state);
    void UpdateFromEmergent(const EmergentState& state);
    void UpdateFromAutonomy(const AutonomyState& state);
};

/**
 * State manager
 */
class SovereignStateManager {
public:
    /**
     * Get current state
     */
    SovereignState GetCurrentState() const;
    
    /**
     * Update state from subsystem
     */
    void UpdateRuntime(const RuntimeState& state);
    void UpdateSEG(const SEGState& state);
    void UpdateEngine(const EngineState& state);
    void UpdateSwarm(const SwarmState& state);
    void UpdateEmergent(const EmergentState& state);
    void UpdateAutonomy(const AutonomyState& state);
    
    /**
     * Set phase
     */
    void SetPhase(const std::string& phase);
    
    /**
     * Add error
     */
    void AddError(const std::string& subsystem, const std::string& error);
    
    /**
     * Clear errors
     */
    void ClearErrors();
    
    /**
     * Get state history
     */
    std::vector<SovereignState> GetHistory(int count = 100) const;
    
    /**
     * Detect state drift
     */
    bool DetectStateDrift(const SovereignState& previous, const SovereignState& current) const;
    
private:
    mutable std::mutex mutex_;
    SovereignState currentState_;
    std::vector<SovereignState> history_;
    static constexpr size_t MAX_HISTORY = 1000;
};

} // namespace Core
