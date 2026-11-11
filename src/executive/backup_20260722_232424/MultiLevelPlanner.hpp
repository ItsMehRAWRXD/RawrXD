// ============================================================================
// MultiLevelPlanner.hpp - Hierarchical Planning System
// Strategic (long-term) → Operational (medium-term) → Tactical (immediate)
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <chrono>

namespace RawrXD {
namespace Executive {

// Forward declarations
class ExecutiveDirector;
class MissionContext;

// ============================================================================
// Plan Types
// ============================================================================
enum class PlanLevel {
    STRATEGIC,    // Long-term goals (hours to days)
    OPERATIONAL,  // Medium-term objectives (minutes to hours)
    TACTICAL      // Immediate actions (seconds to minutes)
};

// ============================================================================
// Plan Step
// ============================================================================
struct PlanStep {
    std::string stepId;
    std::string description;
    std::string actionType;        // "invoke_agent", "use_tool", "wait", "decide"
    
    // Target
    std::string targetId;          // Agent ID, tool ID, etc.
    std::unordered_map<std::string, std::string> parameters;
    
    // Dependencies
    std::vector<std::string> dependsOn;  // Step IDs that must complete first
    std::vector<std::string> enables;    // Steps this enables
    
    // State
    std::string status = "pending";  // pending, ready, executing, completed, failed
    float progress = 0.0f;
    
    // Expected outcomes
    std::vector<std::string> expectedOutputs;
    float expectedSuccessRate = 0.8f;
    double estimatedDurationMs = 0.0;
    
    // Actual outcomes (filled after execution)
    std::vector<std::string> actualOutputs;
    double actualDurationMs = 0.0;
};

// ============================================================================
// Plan
// ============================================================================
struct Plan {
    std::string planId;
    std::string missionId;
    PlanLevel level;
    std::string objective;
    
    // Hierarchy
    std::string parentPlanId;      // For operational/tactical plans
    std::vector<std::string> subPlanIds;
    
    // Steps
    std::vector<PlanStep> steps;
    
    // State
    std::string status = "draft";
    float overallProgress = 0.0f;
    
    // Temporal
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point startedAt;
    std::chrono::steady_clock::time_point completedAt;
    std::chrono::steady_clock::time_point deadline;
    
    // Metrics
    double estimatedTotalDurationMs = 0.0;
    double actualDurationMs = 0.0;
};

// ============================================================================
// Planning Context
// ============================================================================
struct PlanningContext {
    std::string missionId;
    std::string objective;
    PlanLevel level = PlanLevel::OPERATIONAL;
    
    // Constraints
    std::chrono::steady_clock::time_point deadline;
    std::vector<std::string> availableResources;
    std::vector<std::string> requiredCapabilities;
    
    // Context from higher levels
    std::string parentPlanId;
    std::vector<std::string> previousPlans;  // For learning
};

// ============================================================================
// Replan Trigger
// ============================================================================
struct ReplanTrigger {
    std::string triggerType;       // "failure", "opportunity", "deadline", "resource_change"
    std::string description;
    std::string affectedPlanId;
    float severity = 0.5f;       // 0-1
};

// ============================================================================
// Multi-Level Planner - Hierarchical Planning System
// ============================================================================
class MultiLevelPlanner {
public:
    MultiLevelPlanner();
    ~MultiLevelPlanner();

    bool Initialize(ExecutiveDirector* director);
    void Shutdown();
    
    // Plan creation
    Plan CreateStrategicPlan(const PlanningContext& context);
    Plan CreateOperationalPlan(const PlanningContext& context);
    Plan CreateTacticalPlan(const PlanningContext& context);
    
    // Plan refinement
    void DecomposeStrategicToOperational(const std::string& strategicPlanId);
    void DecomposeOperationalToTactical(const std::string& operationalPlanId);
    
    // Plan execution tracking
    void StartPlan(const std::string& planId);
    void UpdateStepStatus(const std::string& planId, const std::string& stepId, 
                          const std::string& status, float progress = 0.0f);
    void CompletePlan(const std::string& planId, bool success);
    
    // Replanning
    bool ShouldReplan(const std::string& planId);
    ReplanTrigger DetectReplanNeed(const std::string& planId);
    Plan Replan(const std::string& planId, const ReplanTrigger& trigger);
    
    // Plan retrieval
    std::optional<Plan> GetPlan(const std::string& planId);
    std::vector<Plan> GetActivePlans();
    std::vector<Plan> GetPlansForMission(const std::string& missionId);
    
    // Plan optimization
    void OptimizePlan(const std::string& planId);
    void ParallelizeSteps(const std::string& planId);
    void PruneUnnecessarySteps(const std::string& planId);
    
    // Learning integration
    void LearnFromPlanExecution(const std::string& planId);
    std::vector<std::string> SuggestPlanImprovements(const std::string& planId);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
