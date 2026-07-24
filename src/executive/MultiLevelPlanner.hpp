// ============================================================
// MultiLevelPlanner.hpp - Hierarchical Planning System
// Strategic → Operational → Tactical
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace RawrXD::Executive {

class ExecutiveDirector;

enum class PlanLevel {
    STRATEGIC,
    OPERATIONAL,
    TACTICAL
};

struct PlanStep {
    uint64_t stepId;
    std::string description;
    std::string actionType;
    std::string targetId;
    std::unordered_map<std::string, std::string> parameters;
    std::vector<uint64_t> dependsOn;
    std::vector<uint64_t> enables;
    std::string status = "pending";
    float progress = 0.0f;
    std::vector<std::string> expectedOutputs;
    float expectedSuccessRate = 0.8f;
    double estimatedDurationMs = 0.0;
    std::vector<std::string> actualOutputs;
    double actualDurationMs = 0.0;
};

struct Plan {
    uint64_t id;
    uint64_t missionId;
    PlanLevel level;
    std::string objective;
    uint64_t parentPlanId = 0;
    std::vector<uint64_t> subPlanIds;
    std::vector<PlanStep> steps;
    std::string status = "draft";
    float overallProgress = 0.0f;
    uint64_t createdAtMs = 0;
    uint64_t startedAtMs = 0;
    uint64_t completedAtMs = 0;
    uint64_t deadlineMs = 0;
    double estimatedTotalDurationMs = 0.0;
    double actualDurationMs = 0.0;
};

struct PlanningContext {
    uint64_t missionId;
    std::string objective;
    PlanLevel level = PlanLevel::OPERATIONAL;
    uint64_t deadlineMs = 0;
    std::vector<std::string> availableResources;
    std::vector<std::string> requiredCapabilities;
    uint64_t parentPlanId = 0;
    std::vector<uint64_t> previousPlans;
};

struct ReplanTrigger {
    std::string triggerType;
    std::string description;
    uint64_t affectedPlanId = 0;
    float severity = 0.5f;
};

class MultiLevelPlanner {
public:
    MultiLevelPlanner() = default;
    ~MultiLevelPlanner() = default;

    bool initialize(ExecutiveDirector* director);
    void shutdown();
    
    Plan createStrategicPlan(const PlanningContext& context);
    Plan createOperationalPlan(const PlanningContext& context);
    Plan createTacticalPlan(const PlanningContext& context);
    
    void decomposeStrategicToOperational(uint64_t strategicPlanId);
    void decomposeOperationalToTactical(uint64_t operationalPlanId);
    
    void startPlan(uint64_t planId);
    void updateStepStatus(uint64_t planId, uint64_t stepId, 
                          const std::string& status, float progress = 0.0f);
    void completePlan(uint64_t planId, bool success);
    
    bool shouldReplan(uint64_t planId);
    ReplanTrigger detectReplanNeed(uint64_t planId);
    Plan replan(uint64_t planId, const ReplanTrigger& trigger);
    
    std::optional<Plan> getPlan(uint64_t planId);
    std::vector<Plan> getActivePlans();
    std::vector<Plan> getPlansForMission(uint64_t missionId);
    
    void optimizePlan(uint64_t planId);
    void parallelizeSteps(uint64_t planId);
    void pruneUnnecessarySteps(uint64_t planId);
    
    void learnFromPlanExecution(uint64_t planId);
    std::vector<std::string> suggestPlanImprovements(uint64_t planId);

private:
    ExecutiveDirector* director_ = nullptr;
    std::unordered_map<uint64_t, Plan> plans_;
    std::atomic<uint64_t> nextPlanId_{1};
    std::atomic<uint64_t> nextStepId_{1};
    mutable std::mutex mutex_;
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
