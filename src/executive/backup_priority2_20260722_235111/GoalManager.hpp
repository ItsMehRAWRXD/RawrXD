// ============================================================================
// GoalManager.hpp - Goal Decomposition and Reprioritization
// Manages hierarchical goals and their dynamic adjustment
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

// ============================================================================
// Goal Types
// ============================================================================
enum class GoalType {
    ACHIEVE,      // Reach a state (e.g., "analyze binary")
    MAINTAIN,     // Keep a condition (e.g., "keep memory usage < 80%")
    AVOID,        // Prevent a state (e.g., "don't crash")
    OPTIMIZE      // Maximize/minimize a metric (e.g., "maximize throughput")
};

// ============================================================================
// Goal Priority
// ============================================================================
enum class GoalPriority {
    CRITICAL,     // Must be satisfied
    HIGH,         // Should be satisfied
    MEDIUM,       // Nice to have
    LOW,          // If resources permit
    BACKGROUND    // Opportunistic
};

// ============================================================================
// Goal State
// ============================================================================
enum class GoalState {
    PENDING,      // Not yet started
    ACTIVE,       // Currently pursuing
    SATISFIED,    // Achieved
    FAILED,       // Could not achieve
    ABANDONED,    // Explicitly dropped
    BLOCKED       // Waiting for dependencies
};

// ============================================================================
// Goal
// ============================================================================
struct Goal {
    std::string goalId;
    std::string description;
    GoalType type = GoalType::ACHIEVE;
    GoalPriority priority = GoalPriority::MEDIUM;
    GoalState state = GoalState::PENDING;
    
    // Hierarchy
    std::string parentGoalId;
    std::vector<std::string> subGoalIds;
    
    // Success criteria
    std::string successCondition;  // Evaluable condition
    float targetValue = 1.0f;
    float currentValue = 0.0f;
    float tolerance = 0.05f;
    
    // Temporal
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point deadline;
    std::chrono::steady_clock::time_point completedAt;
    
    // Resources
    std::vector<std::string> requiredResources;
    std::vector<std::string> requiredCapabilities;
    
    // Dependencies
    std::vector<std::string> dependsOnGoals;  // Must complete first
    std::vector<std::string> conflictsWith;    // Mutually exclusive
    
    // Progress
    float progress = 0.0f;
    std::vector<std::string> milestones;
    std::vector<bool> milestonesCompleted;
};

// ============================================================================
// Goal Conflict
// ============================================================================
struct GoalConflict {
    std::string goalId1;
    std::string goalId2;
    std::string conflictType;  // "resource", "logical", "temporal"
    std::string description;
    float severity = 0.5f;
};

// ============================================================================
// Goal Manager - Hierarchical Goal Management
// ============================================================================
class GoalManager {
public:
    GoalManager();
    ~GoalManager();

    bool Initialize(ExecutiveDirector* director);
    void Shutdown();
    
    // Goal creation
    std::string CreateGoal(const std::string& description, GoalType type, GoalPriority priority);
    void SetGoalParent(const std::string& goalId, const std::string& parentId);
    void AddSubGoal(const std::string& parentId, const std::string& subGoalId);
    
    // Goal lifecycle
    void ActivateGoal(const std::string& goalId);
    void UpdateGoalProgress(const std::string& goalId, float progress);
    void MarkGoalSatisfied(const std::string& goalId);
    void MarkGoalFailed(const std::string& goalId, const std::string& reason);
    void AbandonGoal(const std::string& goalId, const std::string& reason);
    
    // Goal retrieval
    std::optional<Goal> GetGoal(const std::string& goalId);
    std::vector<Goal> GetActiveGoals();
    std::vector<Goal> GetGoalsByPriority(GoalPriority minPriority);
    std::vector<Goal> GetGoalsByState(GoalState state);
    std::vector<Goal> GetSubGoals(const std::string& parentId);
    
    // Prioritization
    void ReprioritizeGoal(const std::string& goalId, GoalPriority newPriority);
    void AdjustPrioritiesBasedOnUrgency();
    std::vector<Goal> GetPrioritizedGoals();
    
    // Conflict detection and resolution
    std::vector<GoalConflict> DetectConflicts();
    std::string ResolveConflict(const GoalConflict& conflict);
    
    // Decomposition
    std::vector<Goal> DecomposeGoal(const std::string& goalId);
    bool CanDecompose(const std::string& goalId);
    
    // Evaluation
    bool IsGoalSatisfied(const std::string& goalId);
    bool IsGoalAchievable(const std::string& goalId);
    float CalculateGoalUtility(const std::string& goalId);
    
    // Statistics
    struct Stats {
        size_t totalGoals = 0;
        size_t activeGoals = 0;
        size_t satisfiedGoals = 0;
        size_t failedGoals = 0;
        float averageGoalCompletionTimeMs = 0.0;
        float goalSuccessRate = 0.0f;
    };
    Stats GetStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
