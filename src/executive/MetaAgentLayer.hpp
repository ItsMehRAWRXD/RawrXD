// ============================================================
// MetaAgentLayer.hpp - Agents that Manage Agents
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <map>
#include <optional>
#include <algorithm>
#include <mutex>
#include <atomic>

namespace RawrXD::Executive {

class ExecutiveDirector;
struct Mission;

struct AgentCapability {
    std::string name;
    std::string description;
    float performanceScore = 1.0f;
    double averageExecutionTimeMs = 0.0;
    std::vector<std::string> domains;
};

struct RegisteredAgent {
    uint64_t agentId;
    std::string agentType;
    std::string name;
    std::vector<AgentCapability> capabilities;
    bool isAvailable = true;
    int currentLoad = 0;
    int maxConcurrentTasks = 1;
    std::function<void(const Mission&)> invokeCallback;
};

struct TaskAssignment {
    uint64_t taskId;
    uint64_t missionId;
    uint64_t agentId;
    std::string taskDescription;
    float priority = 1.0f;
    uint64_t assignedAtMs = 0;
    uint64_t deadlineMs = 0;
    std::string status = "pending";
};

class MetaAgent {
public:
    virtual ~MetaAgent() = default;
    virtual std::string getName() const = 0;
    virtual void initialize(ExecutiveDirector* director) = 0;
    virtual void execute() = 0;
    virtual void shutdown() = 0;
};

class MissionDirector : public MetaAgent {
public:
    std::string getName() const override { return "MissionDirector"; }
    void initialize(ExecutiveDirector* director) override;
    void execute() override;
    void shutdown() override;
    
    float evaluateMissionPriority(const Mission& mission);
    bool shouldPursueMission(const Mission& mission);
    std::vector<uint64_t> selectMissionsForExecution(const std::vector<Mission>& candidates);
    
    void onMissionSubmitted(const Mission& mission);
    void onMissionCompleted(uint64_t missionId, bool success);
    void onMissionFailed(uint64_t missionId, const std::string& reason);
    
private:
    ExecutiveDirector* director_ = nullptr;
    std::map<std::string, float> domainSuccessRates_;
};

class Scheduler : public MetaAgent {
public:
    std::string getName() const override { return "Scheduler"; }
    void initialize(ExecutiveDirector* director) override;
    void execute() override;
    void shutdown() override;
    
    void usePriorityScheduling();
    void useDeadlineScheduling();
    void useFairScheduling();
    void useLearningBasedScheduling();
    
    void enqueueMission(const Mission& mission);
    std::optional<Mission> dequeueNextMission();
    void reprioritizeMission(uint64_t missionId, float newPriority);
    
    bool canPreempt(const Mission& running, const Mission& candidate);
    void preemptMission(uint64_t missionId);
    
private:
    ExecutiveDirector* director_ = nullptr;
    std::vector<Mission> missionQueue_;
    std::string currentAlgorithm_ = "priority";
    mutable std::mutex mutex_;
};

class Negotiator : public MetaAgent {
public:
    std::string getName() const override { return "Negotiator"; }
    void initialize(ExecutiveDirector* director) override;
    void execute() override;
    void shutdown() override;
    
    struct Conflict {
        uint64_t conflictId;
        uint64_t missionId1;
        uint64_t missionId2;
        std::string conflictType;
        std::string description;
    };
    
    std::vector<Conflict> detectConflicts();
    std::string resolveConflict(const Conflict& conflict);
    bool negotiateResourceAccess(uint64_t missionId, const std::string& resourceId);
    
    struct Compromise {
        uint64_t missionId1;
        uint64_t missionId2;
        std::string adjustedPlan;
        float satisfactionScore1 = 0.0f;
        float satisfactionScore2 = 0.0f;
    };
    Compromise generateCompromise(const Conflict& conflict);

private:
    ExecutiveDirector* director_ = nullptr;
    std::atomic<uint64_t> nextConflictId_{1};
};

class Critic : public MetaAgent {
public:
    std::string getName() const override { return "Critic"; }
    void initialize(ExecutiveDirector* director) override;
    void execute() override;
    void shutdown() override;
    
    struct PerformanceReview {
        uint64_t missionId;
        float efficiencyScore = 0.0f;
        float qualityScore = 0.0f;
        float resourceEfficiency = 0.0f;
        std::vector<std::string> issues;
        std::vector<std::string> strengths;
        std::vector<std::string> recommendations;
    };
    
    PerformanceReview evaluateMission(uint64_t missionId);
    std::vector<PerformanceReview> evaluateRecentMissions(size_t count = 10);
    
    std::vector<std::string> detectPerformanceIssues();
    std::vector<std::string> detectResourceWaste();
    std::vector<std::string> detectRepeatedFailures();
    
    struct SystemHealth {
        float overallScore = 1.0f;
        std::vector<std::string> warnings;
        std::vector<std::string> criticalIssues;
    };
    SystemHealth assessSystemHealth();

private:
    ExecutiveDirector* director_ = nullptr;
};

class Teacher : public MetaAgent {
public:
    std::string getName() const override { return "Teacher"; }
    void initialize(ExecutiveDirector* director) override;
    void execute() override;
    void shutdown() override;
    
    void extractLessons(uint64_t missionId);
    void updateAgentModel(uint64_t agentId, const std::vector<std::string>& lessons);
    void transferSkills(uint64_t fromAgentId, uint64_t toAgentId);
    void generalizeWorkflow(const std::string& specificWorkflowId);
    
    struct TrainingExample {
        std::string input;
        std::string expectedOutput;
        float weight = 1.0f;
    };
    std::vector<TrainingExample> generateTrainingSet(uint64_t agentId);

private:
    ExecutiveDirector* director_ = nullptr;
};

class ResourceManager : public MetaAgent {
public:
    std::string getName() const override { return "ResourceManager"; }
    void initialize(ExecutiveDirector* director) override;
    void execute() override;
    void shutdown() override;
    
    bool allocateResource(uint64_t missionId, const std::string& resourceType, size_t amount);
    void releaseResource(uint64_t allocationId);
    
    struct ResourceAllocation {
        uint64_t allocationId;
        uint64_t missionId;
        std::string resourceType;
        size_t amount;
        uint64_t allocatedAtMs;
    };
    std::vector<ResourceAllocation> getActiveAllocations();
    bool isResourceAvailable(const std::string& resourceType, size_t amount);
    size_t getAvailableResource(const std::string& resourceType);
    void rebalanceResources();
    void predictResourceNeeds(uint64_t missionId);

private:
    ExecutiveDirector* director_ = nullptr;
    std::vector<ResourceAllocation> allocations_;
    std::atomic<uint64_t> nextAllocationId_{1};
    mutable std::mutex mutex_;
};

class MetaAgentLayer {
public:
    MetaAgentLayer() = default;
    ~MetaAgentLayer() = default;

    bool initialize(ExecutiveDirector* director);
    void executeAll();
    void shutdown();
    
    void registerAgent(const RegisteredAgent& agent);
    void unregisterAgent(uint64_t agentId);
    std::vector<RegisteredAgent> findAgentsForCapability(const std::string& capability);
    std::vector<RegisteredAgent> getAllAgents();
    
    MissionDirector& getMissionDirector() { return missionDirector_; }
    Scheduler& getScheduler() { return scheduler_; }
    Negotiator& getNegotiator() { return negotiator_; }
    Critic& getCritic() { return critic_; }
    Teacher& getTeacher() { return teacher_; }
    ResourceManager& getResourceManager() { return resourceManager_; }

private:
    ExecutiveDirector* director_ = nullptr;
    MissionDirector missionDirector_;
    Scheduler scheduler_;
    Negotiator negotiator_;
    Critic critic_;
    Teacher teacher_;
    ResourceManager resourceManager_;
    std::vector<RegisteredAgent> registeredAgents_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Executive
