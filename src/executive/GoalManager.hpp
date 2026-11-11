// ============================================================
// GoalManager.hpp - Goal Decomposition and Reprioritization
// Manages hierarchical goals and their dynamic adjustment
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace RawrXD::Executive {

// Forward declarations
class ExecutiveDirector;

// ============================================================
// Goal Types
// ============================================================
enum class GoalType {
    ACHIEVE,      // Reach a state (e.g., "analyze binary")
    MAINTAIN,     // Keep a condition (e.g., "keep memory usage < 80%")
    AVOID,        // Prevent a state (e.g., "don't crash")
    OPTIMIZE      // Maximize/minimize a metric (e.g., "maximize throughput")
};

// ============================================================
// Goal Priority
// ============================================================
enum class GoalPriority {
    CRITICAL,     // Must be satisfied
    HIGH,         // Should be satisfied
    MEDIUM,       // Nice to have
    LOW,          // If resources permit
    BACKGROUND    // Opportunistic
};

// ============================================================
// Goal State
// ============================================================
enum class GoalState {
    PENDING,      // Not yet started
    ACTIVE,       // Currently pursuing
    SATISFIED,    // Achieved
    FAILED,       // Could not achieve
    ABANDONED,    // Explicitly dropped
    BLOCKED       // Waiting for dependencies
};

// ============================================================
// Goal
// ============================================================
struct Goal {
    uint64_t id;
    std::string description;
    GoalType type = GoalType::ACHIEVE;
    GoalPriority priority = GoalPriority::MEDIUM;
    GoalState state = GoalState::PENDING;
    
    // Hierarchy
    uint64_t parentGoalId = 0;
    std::vector<uint64_t> subGoalIds;
    
    // Success criteria
    std::string successCondition;
    float targetValue = 1.0f;
    float currentValue = 0.0f;
    float tolerance = 0.05f;
    
    // Temporal (milliseconds since epoch)
    uint64_t createdAtMs = 0;
    uint64_t deadlineMs = 0;
    uint64_t completedAtMs = 0;
    
    // Resources
    std::vector<std::string> requiredResources;
    std::vector<std::string> requiredCapabilities;
    
    // Dependencies
    std::vector<uint64_t> dependsOnGoals;
    std::vector<uint64_t> conflictsWith;
    
    // Progress
    float progress = 0.0f;
    std::vector<std::string> milestones;
    std::vector<bool> milestonesCompleted;
};

// ============================================================
// Goal Conflict
// ============================================================
struct GoalConflict {
    uint64_t goalId1;
    uint64_t goalId2;
    std::string conflictType;
    std::string description;
    float severity = 0.5f;
};

// ============================================================
// Goal Manager
// ============================================================
class GoalManager {
public:
    GoalManager() = default;
    ~GoalManager() = default;

    bool initialize(ExecutiveDirector* director);
    void shutdown();
    
    uint64_t createGoal(const std::string& description, GoalType type, GoalPriority priority);
    void setGoalParent(uint64_t goalId, uint64_t parentId);
    void addSubGoal(uint64_t parentId, uint64_t subGoalId);
    
    void activateGoal(uint64_t goalId);
    void updateGoalProgress(uint64_t goalId, float progress);
    void markGoalSatisfied(uint64_t goalId);
    void markGoalFailed(uint64_t goalId, const std::string& reason);
    void abandonGoal(uint64_t goalId, const std::string& reason);
    
    std::optional<Goal> getGoal(uint64_t goalId);
    std::vector<Goal> getActiveGoals();
    std::vector<Goal> getGoalsByPriority(GoalPriority minPriority);
    std::vector<Goal> getGoalsByState(GoalState state);
    std::vector<Goal> getSubGoals(uint64_t parentId);
    
    void reprioritizeGoal(uint64_t goalId, GoalPriority newPriority);
    void adjustPrioritiesBasedOnUrgency();
    std::vector<Goal> getPrioritizedGoals();
    
    std::vector<GoalConflict> detectConflicts();
    std::string resolveConflict(const GoalConflict& conflict);
    
    std::vector<Goal> decomposeGoal(uint64_t goalId);
    bool canDecompose(uint64_t goalId);
    
    bool isGoalSatisfied(uint64_t goalId);
    bool isGoalAchievable(uint64_t goalId);
    float calculateGoalUtility(uint64_t goalId);
    
    struct Stats {
        size_t totalGoals = 0;
        size_t activeGoals = 0;
        size_t satisfiedGoals = 0;
        size_t failedGoals = 0;
        float averageGoalCompletionTimeMs = 0.0f;
        float goalSuccessRate = 0.0f;
    };
    Stats getStats() const;

private:
    ExecutiveDirector* director_ = nullptr;
    std::unordered_map<uint64_t, Goal> goals_;
    std::atomic<uint64_t> nextGoalId_{1};
    size_t satisfiedCount_ = 0;
    size_t failedCount_ = 0;
    mutable std::mutex mutex_;
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
