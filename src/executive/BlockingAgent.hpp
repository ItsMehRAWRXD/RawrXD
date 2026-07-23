// ============================================================================
// BlockingAgent.hpp - Priority-Based Goal Blocking Evaluation
// Evaluates if a goal blocks Critical/High priority goals through dependency analysis
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <chrono>
#include <mutex>

namespace RawrXD {
namespace Executive {

// Forward declarations
class GoalManager;

// ============================================================================
// Priority Vote Structure
// ============================================================================
struct PriorityVote {
    std::string goalId;
    int priority;           // Higher = more urgent (Critical=3, High=2, Medium=1, Low=0)
    double confidence;      // 0.0-1.0 confidence in this vote
    std::string reason;     // Explanation for the vote
    
    PriorityVote() : priority(0), confidence(0.0) {}
    PriorityVote(const std::string& id, int pri, double conf, const std::string& r)
        : goalId(id), priority(pri), confidence(conf), reason(r) {}
};

// ============================================================================
// Blocking Evaluation Result
// ============================================================================
struct BlockingEvaluation {
    std::string evaluatedGoalId;
    bool isBlocking;                    // Does this goal block others?
    int blockedCriticalCount;           // Number of Critical goals blocked
    int blockedHighCount;               // Number of High priority goals blocked
    std::vector<std::string> blockedGoalIds;  // IDs of goals being blocked
    double blockingScore;               // Composite score (0.0-1.0)
    std::string recommendation;         // "ACCELERATE", "MAINTAIN", "DEPRIORITIZE"
    std::chrono::steady_clock::time_point evaluatedAt;
    
    BlockingEvaluation() 
        : isBlocking(false), blockedCriticalCount(0), blockedHighCount(0), 
          blockingScore(0.0), evaluatedAt(std::chrono::steady_clock::now()) {}
};

// ============================================================================
// Dependency Graph Node
// ============================================================================
struct DependencyNode {
    std::string goalId;
    int priority;                       // Goal's own priority
    std::vector<std::string> dependencies;   // Goals this depends on
    std::vector<std::string> dependents;     // Goals that depend on this
    bool isActive;
    std::chrono::steady_clock::time_point createdAt;
    
    DependencyNode() : priority(0), isActive(true), 
                     createdAt(std::chrono::steady_clock::now()) {}
};

// ============================================================================
// Blocking Agent - Evaluates goal blocking for priority-based scheduling
// ============================================================================
class BlockingAgent {
public:
    BlockingAgent();
    ~BlockingAgent();

    // Initialization
    bool Initialize(GoalManager* goalManager);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Core blocking evaluation
    BlockingEvaluation EvaluateBlocking(const std::string& goalId);
    
    // Check if a goal blocks Critical priority goals
    bool BlocksCriticalGoals(const std::string& goalId);
    
    // Check if a goal blocks High priority goals
    bool BlocksHighGoals(const std::string& goalId);
    
    // Get all goals blocked by this goal
    std::vector<std::string> GetBlockedGoals(const std::string& goalId);
    
    // Priority voting based on blocking analysis
    PriorityVote VoteOnPriority(const std::string& goalId);
    
    // Batch evaluation for multiple goals
    std::vector<BlockingEvaluation> EvaluateBatch(const std::vector<std::string>& goalIds);
    
    // Find the most critical blockers (goals blocking many high-priority goals)
    std::vector<std::string> FindCriticalBlockers(int minBlockedGoals = 3);
    
    // Suggest execution order based on blocking analysis
    std::vector<std::string> SuggestExecutionOrder(const std::vector<std::string>& goalIds);

    // Dependency graph management
    void UpdateDependencyGraph();
    void AddDependency(const std::string& goalId, const std::string& dependsOn);
    void RemoveDependency(const std::string& goalId, const std::string& dependsOn);
    void RegisterGoal(const std::string& goalId, int priority, 
                      const std::vector<std::string>& dependencies);
    void UnregisterGoal(const std::string& goalId);
    
    // Graph queries
    bool HasDependency(const std::string& goalId, const std::string& dependencyId) const;
    bool WouldCreateCycle(const std::string& goalId, const std::string& dependencyId) const;
    std::vector<std::string> GetDependencyChain(const std::string& goalId) const;
    std::vector<std::string> GetDependentChain(const std::string& goalId) const;

    // Statistics
    size_t GetRegisteredGoalCount() const;
    size_t GetDependencyEdgeCount() const;
    void ClearDependencyGraph();

    // Configuration
    void SetCriticalThreshold(int threshold) { criticalThreshold_ = threshold; }
    void SetHighThreshold(int threshold) { highThreshold_ = threshold; }
    int GetCriticalThreshold() const { return criticalThreshold_; }
    int GetHighThreshold() const { return highThreshold_; }

private:
    // Internal evaluation methods
    void CollectBlockedGoals(const std::string& goalId, 
                            std::vector<std::string>& blockedGoals,
                            std::unordered_set<std::string>& visited) const;
    double CalculateBlockingScore(int blockedCritical, int blockedHigh, int totalBlocked);
    std::string GenerateRecommendation(double blockingScore, int blockedCritical, int blockedHigh);
    
    // Graph traversal
    void TraverseDependents(const std::string& goalId, 
                           std::vector<std::string>& dependents,
                           std::unordered_set<std::string>& visited,
                           int depth = 0) const;
    void TraverseDependencies(const std::string& goalId,
                             std::vector<std::string>& dependencies,
                             std::unordered_set<std::string>& visited,
                             int depth = 0) const;

    // Member variables
    bool initialized_;
    GoalManager* goalManager_;
    std::unordered_map<std::string, DependencyNode> dependencyGraph_;
    mutable std::mutex mutex_;
    
    // Thresholds
    int criticalThreshold_;  // Priority level considered "Critical"
    int highThreshold_;      // Priority level considered "High"
    
    // Statistics
    size_t evaluationsPerformed_;
    size_t criticalBlockersFound_;
};

} // namespace Executive
} // namespace RawrXD
