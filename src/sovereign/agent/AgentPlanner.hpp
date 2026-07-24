// ============================================================================
// AgentPlanner.hpp - Autonomous Task Planner
// Decomposes goals into executable action graphs
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

// Plan step
struct PlanStep {
    std::string id;
    std::string description;
    std::string agent;
    std::string tool;
    std::string input;
    std::vector<std::string> dependencies;
    bool requiresApproval;
    int estimatedCost;
    std::string rollbackAction;
};

// Task plan
struct TaskPlan {
    std::string goal;
    std::vector<PlanStep> steps;
    std::string workspace;
    int totalEstimatedCost;
    bool requiresHumanApproval;
    std::vector<std::string> risks;
};

// Planner configuration
struct PlannerConfig {
    size_t maxSteps = 20;
    bool enableParallelSteps = true;
    bool enableRollback = true;
    int maxCost = 1000;
    bool requireApprovalForWrite = true;
    bool requireApprovalForExecute = true;
};

// Agent planner
class AgentPlanner {
public:
    AgentPlanner();
    ~AgentPlanner();

    // Configure
    void Configure(const PlannerConfig& config);
    const PlannerConfig& GetConfig() const { return config_; }

    // Plan generation
    TaskPlan GeneratePlan(const std::string& goal, const std::string& workspace);
    TaskPlan GeneratePlanWithContext(const std::string& goal, const std::string& workspace,
                                      const std::vector<std::string>& availableTools);

    // Plan analysis
    std::vector<std::string> AnalyzeRisks(const TaskPlan& plan);
    int EstimateCost(const TaskPlan& plan);
    bool RequiresApproval(const TaskPlan& plan);

    // Plan optimization
    TaskPlan OptimizeParallelism(const TaskPlan& plan);
    TaskPlan OptimizeCost(const TaskPlan& plan);

    // Plan validation
    bool ValidatePlan(const TaskPlan& plan);
    std::vector<std::string> GetValidationErrors(const TaskPlan& plan);

    // Plan serialization
    std::string SerializePlan(const TaskPlan& plan);
    TaskPlan DeserializePlan(const std::string& json);

    // Common plan templates
    TaskPlan CreateAuditPlan(const std::string& workspace);
    TaskPlan CreateBuildPlan(const std::string& workspace);
    TaskPlan CreateTestPlan(const std::string& workspace);
    TaskPlan CreateRefactorPlan(const std::string& workspace, const std::string& target);
    TaskPlan CreateDebugPlan(const std::string& workspace, const std::string& issue);

private:
    PlannerConfig config_;
    
    // Decomposition strategies
    std::vector<PlanStep> DecomposeGoal(const std::string& goal, const std::string& workspace);
    std::vector<PlanStep> DecomposeAudit(const std::string& workspace);
    std::vector<PlanStep> DecomposeBuild(const std::string& workspace);
    std::vector<PlanStep> DecomposeTest(const std::string& workspace);
    std::vector<PlanStep> DecomposeRefactor(const std::string& workspace, const std::string& target);
    std::vector<PlanStep> DecomposeDebug(const std::string& workspace, const std::string& issue);
    
    // Dependency analysis
    void AddDependencies(std::vector<PlanStep>& steps);
    void DetectParallelizable(std::vector<PlanStep>& steps);
};

} // namespace Sovereign
