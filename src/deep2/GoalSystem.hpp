// ============================================================================
// GoalSystem.hpp - Priority-Based Goal Management
//
// Features:
//   - Priority levels (Low, Medium, High, Critical)
//   - Dependency tracking
//   - Automatic reprioritization based on dependents
//   - Integration with The Bottle for dynamic optimization
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#ifndef DEEP2_GOAL_SYSTEM_HPP
#define DEEP2_GOAL_SYSTEM_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <functional>

namespace Deep2 {

// ============================================================================
// Goal Priority Levels
// ============================================================================

enum class Priority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
};

// ============================================================================
// Goal Structure
// ============================================================================

struct Goal {
    std::string id;
    std::string name;
    std::string description;
    Priority priority;
    
    // Dependencies
    std::vector<std::string> dependsOn;    // Goals this depends on
    std::vector<std::string> dependents;     // Goals that depend on this
    
    // Status
    enum class Status {
        Pending,
        InProgress,
        Blocked,      // Waiting for dependencies
        Completed,
        Failed
    };
    Status status;
    
    // Metadata
    uint64_t createdAt;
    uint64_t startedAt;
    uint64_t completedAt;
    uint64_t estimatedTokens;  // Estimated token cost
    uint64_t actualTokens;     // Actual tokens used
    
    // Progress
    float progress;  // 0.0 to 1.0
    
    // Bottleneck detection
    bool isBottleneck;
    uint32_t dependentCount;
    
    Goal() : priority(Priority::Medium), status(Status::Pending),
             createdAt(0), startedAt(0), completedAt(0),
             estimatedTokens(0), actualTokens(0),
             progress(0.0f), isBottleneck(false), dependentCount(0) {}
};

// ============================================================================
// Goal Manager
// ============================================================================

class GoalManager {
public:
    GoalManager();
    ~GoalManager();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // =========================================================================
    // Goal CRUD
    // =========================================================================
    
    // Create a new goal
    std::string CreateGoal(const std::string& name,
                           const std::string& description,
                           Priority priority = Priority::Medium);
    
    // Get goal by ID
    bool GetGoal(const std::string& id, Goal& out) const;
    
    // Update goal
    bool UpdateGoal(const std::string& id, const Goal& goal);
    
    // Delete goal
    bool DeleteGoal(const std::string& id);
    
    // =========================================================================
    // Dependencies
    // =========================================================================
    
    // Add dependency: goalId depends on dependencyId
    bool AddDependency(const std::string& goalId, const std::string& dependencyId);
    
    // Remove dependency
    bool RemoveDependency(const std::string& goalId, const std::string& dependencyId);
    
    // Get dependencies
    std::vector<std::string> GetDependencies(const std::string& goalId) const;
    
    // Get dependents (goals that depend on this one)
    std::vector<std::string> GetDependents(const std::string& goalId) const;
    
    // Check if adding dependency would create cycle
    bool WouldCreateCycle(const std::string& goalId, const std::string& dependencyId) const;
    
    // =========================================================================
    // Priority Management
    // =========================================================================
    
    // Set priority
    bool SetPriority(const std::string& id, Priority priority);
    
    // Get priority
    Priority GetPriority(const std::string& id) const;
    
    // Auto-reprioritize based on dependents
    // FIXED: Now correctly boosts priority for goals with many dependents
    void ReprioritizeBasedOnDependents();
    
    // Boost priority of goals blocking many others
    void UnblockCriticalPaths();
    
    // =========================================================================
    // Status Management
    // =========================================================================
    
    // Set status
    bool SetStatus(const std::string& id, Goal::Status status);
    
    // Get status
    Goal::Status GetStatus(const std::string& id) const;
    
    // Update progress
    bool SetProgress(const std::string& id, float progress);
    
    // =========================================================================
    // Query
    // =========================================================================
    
    // Get all goals
    std::vector<std::string> GetAllGoals() const;
    
    // Get goals by priority
    std::vector<std::string> GetGoalsByPriority(Priority priority) const;
    
    // Get goals by status
    std::vector<std::string> GetGoalsByStatus(Goal::Status status) const;
    
    // Get ready goals (dependencies satisfied)
    std::vector<std::string> GetReadyGoals() const;
    
    // Get bottleneck goals
    std::vector<std::string> GetBottlenecks() const;
    
    // Get next goal to work on (highest priority, ready)
    std::string GetNextGoal() const;
    
    // =========================================================================
    // Statistics
    // =========================================================================
    
    struct Stats {
        size_t totalGoals;
        size_t pending;
        size_t inProgress;
        size_t completed;
        size_t failed;
        size_t blocked;
        size_t criticalPathLength;
        uint64_t totalEstimatedTokens;
        uint64_t totalActualTokens;
    };
    
    Stats GetStats() const;
    void PrintStatus() const;
    
    // =========================================================================
    // Integration with The Bottle
    // =========================================================================
    
    // Optimize goal execution using HotPatcher
    void OptimizeGoal(const std::string& goalId);
    
    // Apply cached optimizations for similar goals
    bool ApplyCachedOptimization(const std::string& goalId);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Global Instance
// ============================================================================

GoalManager& GetGoalManager();

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick goal creation
std::string CreateGoal(const std::string& name, Priority priority = Priority::Medium);

// Mark goal complete
bool CompleteGoal(const std::string& goalId, uint64_t actualTokens = 0);

// Get next work item
std::string GetNextWorkItem();

} // namespace Deep2

#endif // DEEP2_GOAL_SYSTEM_HPP
