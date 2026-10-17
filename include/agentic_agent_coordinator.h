#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

class AgenticLoopState;
class AgenticIterativeReasoning;
class AgenticEngine;
class InferenceEngine;

/**
 * @class AgenticAgentCoordinator
 * @brief Multi-agent coordination for complex problem solving
 * 
 * Manages multiple reasoning agents working together:
 * - Task decomposition across agents
 * - Agent specialization (analyzer, planner, executor, verifier)
 * - State synchronization between agents
 * - Resource allocation
 * - Conflict resolution
 * - Consensus building
 * 
 * Enables parallel reasoning and task execution while maintaining
 * coherent state and preventing conflicts.
 */
class AgenticAgentCoordinator {
public:
    enum class AgentRole {
        Analyzer,      // Problem analysis and context gathering
        Planner,       // Strategy generation and planning
        Executor,      // Action execution
        Verifier,      // Result verification
        Optimizer,     // Performance optimization
        Learner        // Experience management
    };

    struct AgentInstance {
        std::string agentId;
        AgentRole role;
        std::unique_ptr<AgenticIterativeReasoning> reasoner;
        std::unique_ptr<AgenticLoopState> state;
        std::string currentTask;
        bool isAvailable;
        float utilization;
        int tasksCompleted;
        std::string lastResult;
        std::chrono::system_clock::time_point lastActive;
    };

    struct TaskAssignment {
        std::string taskId;
        std::string assignedAgentId;
        AgentRole requiredRole;
        std::string description;
        json parameters;
        std::chrono::system_clock::time_point assignedTime;
        std::chrono::system_clock::time_point completionTime;
        std::string status;
        json result;
        float estimatedComplexity;
    };

    struct AgentConflict {
        std::string conflictId;
        std::string agent1Id;
        std::string agent2Id;
        std::string conflictReason;
        json state1;
        json state2;
        std::string resolution;
        std::chrono::system_clock::time_point timestamp;
    };

public:
    AgenticAgentCoordinator();
    ~AgenticAgentCoordinator();

    void initialize(AgenticEngine* engine, InferenceEngine* inference);

    // ===== AGENT MANAGEMENT =====
    std::string createAgent(AgentRole role);
    void removeAgent(const std::string& agentId);
    AgentInstance* getAgent(const std::string& agentId);
    std::vector<AgentInstance*> getAvailableAgents(AgentRole role);
    std::vector<std::string> getAllAgentIds() const;
    json getAgentStatus(const std::string& agentId);
    json getAllAgentStatuses();

    // ===== TASK ASSIGNMENT AND EXECUTION =====
    std::string assignTask(
        const std::string& taskDescription,
        const json& parameters,
        AgentRole requiredRole
    );
    bool executeAssignedTask(const std::string& taskId);
    std::string getTaskStatus(const std::string& taskId);
    json getTaskResult(const std::string& taskId);
    json getAllTaskStatuses();

    // ===== COORDINATION MECHANISMS =====
    
    // Decompose complex task across multiple agents
    json decomposeLargeTask(const std::string& goal);
    
    // Synchronize state across agents
    void synchronizeAgentStates();
    bool detectStateConflict(const std::string& agentId1, const std::string& agentId2);
    std::string resolveStateConflict(const std::string& agentId1, const std::string& agentId2);
    
    // Consensus building
    bool buildConsensus(const std::vector<std::string>& agentIds, const std::string& question);
    std::string getAgentOpinion(const std::string& agentId, const std::string& question);
    std::string resolveDisagreement(const std::vector<std::string>& agentIds);
    
    // Resource allocation
    void allocateResources(const std::string& agentId, float cpuShare, float memoryShare);
    void rebalanceResources();

    // ===== MONITORING AND METRICS =====
    json getCoordinationMetrics() const;
    float getTotalUtilization() const;
    int getTotalTasksCompleted() const;
    float getAverageTaskDuration() const;
    int getConflictCount() const { return (int)m_conflicts.size(); }
    json getConflictHistory();
    
    // ===== LOAD BALANCING =====
    std::string selectBestAgentForTask(const std::string& taskDescription);
    void rebalanceWorkload();

    // ===== STATE MANAGEMENT =====
    json getGlobalState();
    bool restoreGlobalState(const json& state);
    void saveCheckpoint();
    bool restoreFromCheckpoint();

    // Callbacks (replaces Qt signals)
    using AgentCreatedCallback = std::function<void(const std::string&, const std::string&)>;
    using AgentRemovedCallback = std::function<void(const std::string&)>;
    using TaskAssignedCallback = std::function<void(const std::string&, const std::string&)>;
    using TaskCompletedCallback = std::function<void(const std::string&)>;
    using TaskFailedCallback = std::function<void(const std::string&, const std::string&)>;
    using StateConflictDetectedCallback = std::function<void(const std::string&, const std::string&)>;
    using StateConflictResolvedCallback = std::function<void(const std::string&)>;
    using AgentStatusChangedCallback = std::function<void(const std::string&, const std::string&)>;
    using CoordinationMetricsUpdatedCallback = std::function<void()>;
    
    void setOnAgentCreated(AgentCreatedCallback cb) { m_onAgentCreated = cb; }
    void setOnAgentRemoved(AgentRemovedCallback cb) { m_onAgentRemoved = cb; }
    void setOnTaskAssigned(TaskAssignedCallback cb) { m_onTaskAssigned = cb; }
    void setOnTaskCompleted(TaskCompletedCallback cb) { m_onTaskCompleted = cb; }
    void setOnTaskFailed(TaskFailedCallback cb) { m_onTaskFailed = cb; }
    void setOnStateConflictDetected(StateConflictDetectedCallback cb) { m_onStateConflictDetected = cb; }
    void setOnStateConflictResolved(StateConflictResolvedCallback cb) { m_onStateConflictResolved = cb; }
    void setOnAgentStatusChanged(AgentStatusChangedCallback cb) { m_onAgentStatusChanged = cb; }
    void setOnCoordinationMetricsUpdated(CoordinationMetricsUpdatedCallback cb) { m_onCoordinationMetricsUpdated = cb; }

private:
    // Internal helpers
    void syncStateWithAgent(const std::string& agentId);
    std::string reconcileConflictingStates(
        const json& state1,
        const json& state2
    );
    std::string selectResolutionStrategy(const std::string& conflictReason);
    void recordConflict(
        const std::string& agent1,
        const std::string& agent2,
        const std::string& reason,
        const std::string& resolution
    );
    void updateAgentMetrics(const std::string& agentId);

    // Agent pool
    std::unordered_map<std::string, std::unique_ptr<AgentInstance>> m_agents;
    std::unordered_map<std::string, std::unique_ptr<TaskAssignment>> m_assignments;
    std::vector<AgentConflict> m_conflicts;
    
    // Configuration
    AgenticEngine* m_engine = nullptr;
    InferenceEngine* m_inferenceEngine = nullptr;
    
    // Metrics
    std::chrono::system_clock::time_point m_coordinationStartTime;
    int m_totalTasksAssigned = 0;
    int m_totalTasksCompleted = 0;
    int m_totalConflicts = 0;
    std::vector<std::pair<std::string, int>> m_taskDurations;
    
    // Checkpointing
    json m_lastCheckpoint;
    std::chrono::system_clock::time_point m_lastCheckpointTime;

    // Callbacks
    AgentCreatedCallback m_onAgentCreated;
    AgentRemovedCallback m_onAgentRemoved;
    TaskAssignedCallback m_onTaskAssigned;
    TaskCompletedCallback m_onTaskCompleted;
    TaskFailedCallback m_onTaskFailed;
    StateConflictDetectedCallback m_onStateConflictDetected;
    StateConflictResolvedCallback m_onStateConflictResolved;
    AgentStatusChangedCallback m_onAgentStatusChanged;
    CoordinationMetricsUpdatedCallback m_onCoordinationMetricsUpdated;
};
