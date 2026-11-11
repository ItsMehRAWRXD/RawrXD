// ============================================================================
// MetaAgentLayer.hpp - Agents that Manage Agents
// Mission Director, Scheduler, Negotiator, Critic, Teacher, Resource Manager
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <queue>
#include <map>

namespace RawrXD {
namespace Executive {

// Forward declarations
class ExecutiveDirector;
class MissionContext;

// ============================================================================
// Agent Capability
// ============================================================================
struct AgentCapability {
    std::string name;
    std::string description;
    float performanceScore = 1.0f;  // Historical success rate
    double averageExecutionTimeMs = 0.0;
    std::vector<std::string> domains;  // What domains this agent works in
};

// ============================================================================
// Agent Registration
// ============================================================================
struct RegisteredAgent {
    std::string agentId;
    std::string agentType;
    std::string name;
    std::vector<AgentCapability> capabilities;
    bool isAvailable = true;
    int currentLoad = 0;
    int maxConcurrentTasks = 1;
    
    // Callback to actually invoke the agent
    std::function<void(const MissionContext&)> invokeCallback;
};

// ============================================================================
// Task Assignment
// ============================================================================
struct TaskAssignment {
    std::string taskId;
    std::string missionId;
    std::string agentId;
    std::string taskDescription;
    float priority = 1.0f;
    std::chrono::steady_clock::time_point assignedAt;
    std::chrono::steady_clock::time_point deadline;
    std::string status = "pending";  // pending, running, completed, failed
};

// ============================================================================
// Meta-Agent Base Interface
// ============================================================================
class MetaAgent {
public:
    virtual ~MetaAgent() = default;
    virtual std::string GetName() const = 0;
    virtual void Initialize(ExecutiveDirector* director) = 0;
    virtual void Execute() = 0;  // One cycle of operation
    virtual void Shutdown() = 0;
};

// ============================================================================
// Mission Director - Decides what missions to pursue
// ============================================================================
class MissionDirector : public MetaAgent {
public:
    std::string GetName() const override { return "MissionDirector"; }
    void Initialize(ExecutiveDirector* director) override;
    void Execute() override;
    void Shutdown() override;
    
    // Mission evaluation
    float EvaluateMissionPriority(const MissionContext& mission);
    bool ShouldPursueMission(const MissionContext& mission);
    std::vector<std::string> SelectMissionsForExecution(const std::vector<MissionContext>& candidates);
    
    // Mission lifecycle
    void OnMissionSubmitted(const MissionContext& mission);
    void OnMissionCompleted(const std::string& missionId, bool success);
    void OnMissionFailed(const std::string& missionId, const std::string& reason);
    
private:
    ExecutiveDirector* director_ = nullptr;
    std::map<std::string, float> domainSuccessRates_;
};

// ============================================================================
// Scheduler - Decides when and in what order to execute
// ============================================================================
class Scheduler : public MetaAgent {
public:
    std::string GetName() const override { return "Scheduler"; }
    void Initialize(ExecutiveDirector* director) override;
    void Execute() override;
    void Shutdown() override;
    
    // Scheduling algorithms
    void UsePriorityScheduling();
    void UseDeadlineScheduling();
    void UseFairScheduling();
    void UseLearningBasedScheduling();  // Learns from past performance
    
    // Task queue management
    void EnqueueMission(const MissionContext& mission);
    std::optional<MissionContext> DequeueNextMission();
    void ReprioritizeMission(const std::string& missionId, float newPriority);
    
    // Preemption
    bool CanPreempt(const MissionContext& running, const MissionContext& candidate);
    void PreemptMission(const std::string& missionId);
    
private:
    ExecutiveDirector* director_ = nullptr;
    std::priority_queue<MissionContext> missionQueue_;
    std::string currentAlgorithm_ = "priority";
};

// ============================================================================
// Negotiator - Handles conflicts between agents/missions
// ============================================================================
class Negotiator : public MetaAgent {
public:
    std::string GetName() const override { return "Negotiator"; }
    void Initialize(ExecutiveDirector* director) override;
    void Execute() override;
    void Shutdown() override;
    
    // Conflict resolution
    struct Conflict {
        std::string conflictId;
        std::string missionId1;
        std::string missionId2;
        std::string conflictType;  // "resource", "goal", "dependency"
        std::string description;
    };
    
    std::vector<Conflict> DetectConflicts();
    std::string ResolveConflict(const Conflict& conflict);
    
    // Resource negotiation
    bool NegotiateResourceAccess(const std::string& missionId, const std::string& resourceId);
    
    // Compromise generation
    struct Compromise {
        std::string missionId1;
        std::string missionId2;
        std::string adjustedPlan;
        float satisfactionScore1 = 0.0f;
        float satisfactionScore2 = 0.0f;
    };
    Compromise GenerateCompromise(const Conflict& conflict);

private:
    ExecutiveDirector* director_ = nullptr;
};

// ============================================================================
// Critic - Evaluates performance and identifies issues
// ============================================================================
class Critic : public MetaAgent {
public:
    std::string GetName() const override { return "Critic"; }
    void Initialize(ExecutiveDirector* director) override;
    void Execute() override;
    void Shutdown() override;
    
    // Performance evaluation
    struct PerformanceReview {
        std::string missionId;
        float efficiencyScore = 0.0f;      // Speed vs optimal
        float qualityScore = 0.0f;         // Result quality
        float resourceEfficiency = 0.0f;   // Resource usage
        std::vector<std::string> issues;
        std::vector<std::string> strengths;
        std::vector<std::string> recommendations;
    };
    
    PerformanceReview EvaluateMission(const std::string& missionId);
    std::vector<PerformanceReview> EvaluateRecentMissions(size_t count = 10);
    
    // Issue detection
    std::vector<std::string> DetectPerformanceIssues();
    std::vector<std::string> DetectResourceWaste();
    std::vector<std::string> DetectRepeatedFailures();
    
    // System health
    struct SystemHealth {
        float overallHealth = 1.0f;
        std::vector<std::string> criticalIssues;
        std::vector<std::string> warnings;
        std::vector<std::string> suggestions;
    };
    SystemHealth AssessSystemHealth();

private:
    ExecutiveDirector* director_ = nullptr;
};

// ============================================================================
// Teacher - Improves agents through feedback and training
// ============================================================================
class Teacher : public MetaAgent {
public:
    std::string GetName() const override { return "Teacher"; }
    void Initialize(ExecutiveDirector* director) override;
    void Execute() override;
    void Shutdown() override;
    
    // Learning from experience
    void ExtractLessons(const std::string& missionId);
    void UpdateAgentModel(const std::string& agentId, const std::vector<std::string>& lessons);
    
    // Skill transfer
    void TransferSkills(const std::string& fromAgentId, const std::string& toAgentId);
    void GeneralizeWorkflow(const std::string& specificWorkflowId);
    
    // Training generation
    struct TrainingExample {
        std::string input;
        std::string expectedOutput;
        std::string context;
        float importance = 1.0f;
    };
    std::vector<TrainingExample> GenerateTrainingSet(const std::string& agentId);

private:
    ExecutiveDirector* director_ = nullptr;
};

// ============================================================================
// Resource Manager - Manages computational resources
// ============================================================================
class ResourceManager : public MetaAgent {
public:
    std::string GetName() const override { return "ResourceManager"; }
    void Initialize(ExecutiveDirector* director) override;
    void Execute() override;
    void Shutdown() override;
    
    // Resource tracking
    struct ResourceAllocation {
        std::string resourceId;
        std::string resourceType;  // "cpu", "gpu", "memory", "disk"
        std::string allocatedTo;
        size_t amount = 0;
        std::chrono::steady_clock::time_point allocatedAt;
    };
    
    bool AllocateResource(const std::string& missionId, const std::string& resourceType, size_t amount);
    void ReleaseResource(const std::string& allocationId);
    std::vector<ResourceAllocation> GetActiveAllocations();
    
    // Resource availability
    bool IsResourceAvailable(const std::string& resourceType, size_t amount);
    size_t GetAvailableResource(const std::string& resourceType);
    
    // Optimization
    void RebalanceResources();
    void PredictResourceNeeds(const std::string& missionId);

private:
    ExecutiveDirector* director_ = nullptr;
    std::map<std::string, size_t> totalResources_;
    std::map<std::string, size_t> usedResources_;
};

// ============================================================================
// Meta Agent Layer - Container for all meta-agents
// ============================================================================
class MetaAgentLayer {
public:
    MetaAgentLayer();
    ~MetaAgentLayer();

    bool Initialize(ExecutiveDirector* director);
    void ExecuteAll();  // One cycle of all meta-agents
    void Shutdown();
    
    // Access individual meta-agents
    MissionDirector* GetMissionDirector() { return &missionDirector_; }
    Scheduler* GetScheduler() { return &scheduler_; }
    Negotiator* GetNegotiator() { return &negotiator_; }
    Critic* GetCritic() { return &critic_; }
    Teacher* GetTeacher() { return &teacher_; }
    ResourceManager* GetResourceManager() { return &resourceManager_; }
    
    // Agent registration (for specialist agents)
    void RegisterAgent(const RegisteredAgent& agent);
    void UnregisterAgent(const std::string& agentId);
    std::vector<RegisteredAgent> FindAgentsForCapability(const std::string& capability);
    std::vector<RegisteredAgent> GetAllAgents();

private:
    MissionDirector missionDirector_;
    Scheduler scheduler_;
    Negotiator negotiator_;
    Critic critic_;
    Teacher teacher_;
    ResourceManager resourceManager_;
    
    std::vector<RegisteredAgent> registeredAgents_;
    ExecutiveDirector* director_ = nullptr;
};

} // namespace Executive
} // namespace RawrXD
