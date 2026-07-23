// ============================================================================
// BlockingAgent.cpp - Implementation
// Evaluates if a goal blocks Critical/High priority goals through dependency analysis
// ============================================================================

#include "BlockingAgent.hpp"
#include "GoalManager.hpp"
#include <algorithm>
#include <unordered_set>
#include <queue>
#include <mutex>

namespace RawrXD {
namespace Executive {

// ============================================================================
// Constructor / Destructor
// ============================================================================

BlockingAgent::BlockingAgent() 
    : initialized_(false)
    , goalManager_(nullptr)
    , criticalThreshold_(3)    // Priority level 3 = Critical
    , highThreshold_(2)          // Priority level 2 = High
    , evaluationsPerformed_(0)
    , criticalBlockersFound_(0) {
}

BlockingAgent::~BlockingAgent() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================

bool BlockingAgent::Initialize(GoalManager* goalManager) {
    if (initialized_) {
        return true;
    }
    
    goalManager_ = goalManager;
    initialized_ = true;
    
    // Build initial dependency graph from GoalManager
    UpdateDependencyGraph();
    
    return true;
}

void BlockingAgent::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    dependencyGraph_.clear();
    goalManager_ = nullptr;
    initialized_ = false;
}

// ============================================================================
// Core Blocking Evaluation
// ============================================================================

BlockingEvaluation BlockingAgent::EvaluateBlocking(const std::string& goalId) {
    BlockingEvaluation result;
    result.evaluatedGoalId = goalId;
    
    if (!initialized_) {
        result.recommendation = "ERROR: Not initialized";
        return result;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if goal exists in dependency graph
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        result.recommendation = "ERROR: Goal not found";
        return result;
    }
    
    // Collect all goals blocked by this goal
    std::vector<std::string> blockedGoals;
    std::unordered_set<std::string> visited;
    CollectBlockedGoals(goalId, blockedGoals, visited);
    
    // Count blocked goals by priority
    int blockedCritical = 0;
    int blockedHigh = 0;
    
    for (const auto& blockedId : blockedGoals) {
        auto blockedIt = dependencyGraph_.find(blockedId);
        if (blockedIt != dependencyGraph_.end()) {
            if (blockedIt->second.priority >= criticalThreshold_) {
                blockedCritical++;
            } else if (blockedIt->second.priority >= highThreshold_) {
                blockedHigh++;
            }
        }
    }
    
    // Populate result
    result.isBlocking = !blockedGoals.empty();
    result.blockedCriticalCount = blockedCritical;
    result.blockedHighCount = blockedHigh;
    result.blockedGoalIds = blockedGoals;
    result.blockingScore = CalculateBlockingScore(blockedCritical, blockedHigh, 
                                                    static_cast<int>(blockedGoals.size()));
    result.recommendation = GenerateRecommendation(result.blockingScore, blockedCritical, blockedHigh);
    result.evaluatedAt = std::chrono::steady_clock::now();
    
    evaluationsPerformed_++;
    if (blockedCritical > 0) {
        criticalBlockersFound_++;
    }
    
    return result;
}

bool BlockingAgent::BlocksCriticalGoals(const std::string& goalId) {
    if (!initialized_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        return false;
    }
    
    // Check all dependents
    for (const auto& dependentId : it->second.dependents) {
        auto depIt = dependencyGraph_.find(dependentId);
        if (depIt != dependencyGraph_.end()) {
            if (depIt->second.priority >= criticalThreshold_) {
                return true;
            }
        }
    }
    
    return false;
}

bool BlockingAgent::BlocksHighGoals(const std::string& goalId) {
    if (!initialized_) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        return false;
    }
    
    // Check all dependents
    for (const auto& dependentId : it->second.dependents) {
        auto depIt = dependencyGraph_.find(dependentId);
        if (depIt != dependencyGraph_.end()) {
            if (depIt->second.priority >= highThreshold_) {
                return true;
            }
        }
    }
    
    return false;
}

std::vector<std::string> BlockingAgent::GetBlockedGoals(const std::string& goalId) {
    std::vector<std::string> blockedGoals;
    
    if (!initialized_) {
        return blockedGoals;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_set<std::string> visited;
    CollectBlockedGoals(goalId, blockedGoals, visited);
    
    return blockedGoals;
}

PriorityVote BlockingAgent::VoteOnPriority(const std::string& goalId) {
    PriorityVote vote;
    vote.goalId = goalId;
    
    if (!initialized_) {
        vote.reason = "ERROR: Not initialized";
        return vote;
    }
    
    // Get blocking evaluation
    BlockingEvaluation eval = EvaluateBlocking(goalId);
    
    // Calculate priority boost based on blocking
    int basePriority = 0;
    auto it = dependencyGraph_.find(goalId);
    if (it != dependencyGraph_.end()) {
        basePriority = it->second.priority;
    }
    
    // Boost priority if blocking critical/high goals
    int boost = 0;
    if (eval.blockedCriticalCount > 0) {
        boost = 2;  // Significant boost for blocking critical goals
    } else if (eval.blockedHighCount > 0) {
        boost = 1;  // Moderate boost for blocking high goals
    }
    
    vote.priority = basePriority + boost;
    vote.confidence = eval.blockingScore;
    
    // Generate reason
    if (eval.blockedCriticalCount > 0) {
        vote.reason = "Blocks " + std::to_string(eval.blockedCriticalCount) + 
                     " Critical and " + std::to_string(eval.blockedHighCount) + 
                     " High priority goals";
    } else if (eval.blockedHighCount > 0) {
        vote.reason = "Blocks " + std::to_string(eval.blockedHighCount) + 
                     " High priority goals";
    } else if (eval.isBlocking) {
        vote.reason = "Blocks " + std::to_string(eval.blockedGoalIds.size()) + 
                     " lower priority goals";
    } else {
        vote.reason = "Does not block any goals";
    }
    
    return vote;
}

std::vector<BlockingEvaluation> BlockingAgent::EvaluateBatch(const std::vector<std::string>& goalIds) {
    std::vector<BlockingEvaluation> results;
    results.reserve(goalIds.size());
    
    for (const auto& goalId : goalIds) {
        results.push_back(EvaluateBlocking(goalId));
    }
    
    return results;
}

std::vector<std::string> BlockingAgent::FindCriticalBlockers(int minBlockedGoals) {
    std::vector<std::string> criticalBlockers;
    
    if (!initialized_) {
        return criticalBlockers;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (const auto& [goalId, node] : dependencyGraph_) {
        // Count how many goals this blocks
        std::vector<std::string> blockedGoals;
        std::unordered_set<std::string> visited;
        CollectBlockedGoals(goalId, blockedGoals, visited);
        
        // Count critical/high blocked
        int criticalBlocked = 0;
        int highBlocked = 0;
        
        for (const auto& blockedId : blockedGoals) {
            auto it = dependencyGraph_.find(blockedId);
            if (it != dependencyGraph_.end()) {
                if (it->second.priority >= criticalThreshold_) {
                    criticalBlocked++;
                } else if (it->second.priority >= highThreshold_) {
                    highBlocked++;
                }
            }
        }
        
        // If blocking enough goals, especially critical ones
        if (criticalBlocked > 0 || (criticalBlocked + highBlocked) >= minBlockedGoals) {
            criticalBlockers.push_back(goalId);
        }
    }
    
    // Sort by number of blocked critical goals (descending)
    std::sort(criticalBlockers.begin(), criticalBlockers.end(),
              [this](const std::string& a, const std::string& b) {
                  int aCritical = 0, bCritical = 0;
                  auto aIt = dependencyGraph_.find(a);
                  auto bIt = dependencyGraph_.find(b);
                  
                  if (aIt != dependencyGraph_.end()) {
                      for (const auto& dep : aIt->second.dependents) {
                          auto depIt = dependencyGraph_.find(dep);
                          if (depIt != dependencyGraph_.end() && 
                              depIt->second.priority >= criticalThreshold_) {
                              aCritical++;
                          }
                      }
                  }
                  
                  if (bIt != dependencyGraph_.end()) {
                      for (const auto& dep : bIt->second.dependents) {
                          auto depIt = dependencyGraph_.find(dep);
                          if (depIt != dependencyGraph_.end() && 
                              depIt->second.priority >= criticalThreshold_) {
                              bCritical++;
                          }
                      }
                  }
                  
                  return aCritical > bCritical;
              });
    
    return criticalBlockers;
}

std::vector<std::string> BlockingAgent::SuggestExecutionOrder(const std::vector<std::string>& goalIds) {
    // Create a scoring system based on blocking analysis
    struct GoalScore {
        std::string goalId;
        double score;
        int blockedCritical;
        int blockedHigh;
    };
    
    std::vector<GoalScore> scores;
    scores.reserve(goalIds.size());
    
    for (const auto& goalId : goalIds) {
        BlockingEvaluation eval = EvaluateBlocking(goalId);
        GoalScore gs;
        gs.goalId = goalId;
        gs.score = eval.blockingScore;
        gs.blockedCritical = eval.blockedCriticalCount;
        gs.blockedHigh = eval.blockedHighCount;
        scores.push_back(gs);
    }
    
    // Sort by score descending (highest blocking first)
    std::sort(scores.begin(), scores.end(), 
              [](const GoalScore& a, const GoalScore& b) {
                  // First by critical blocked
                  if (a.blockedCritical != b.blockedCritical) {
                      return a.blockedCritical > b.blockedCritical;
                  }
                  // Then by high blocked
                  if (a.blockedHigh != b.blockedHigh) {
                      return a.blockedHigh > b.blockedHigh;
                  }
                  // Then by score
                  return a.score > b.score;
              });
    
    std::vector<std::string> ordered;
    ordered.reserve(scores.size());
    for (const auto& gs : scores) {
        ordered.push_back(gs.goalId);
    }
    
    return ordered;
}

// ============================================================================
// Dependency Graph Management
// ============================================================================

void BlockingAgent::UpdateDependencyGraph() {
    if (!goalManager_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Clear existing graph
    dependencyGraph_.clear();
    
    // Populate from GoalManager active goals
    auto activeGoals = goalManager_->getActiveGoals();
    for (const auto& goal : activeGoals) {
        DependencyNode node;
        node.goalId = std::to_string(goal.id);
        node.priority = static_cast<int>(goal.priority);
        
        // Convert uint64_t dependency IDs to strings
        for (const auto& depId : goal.dependsOnGoals) {
            node.dependencies.push_back(std::to_string(depId));
        }
        
        node.isActive = (goal.state == GoalState::ACTIVE);
        dependencyGraph_[node.goalId] = node;
    }
    
    // Build reverse dependency links (dependents)
    for (auto& [goalId, node] : dependencyGraph_) {
        for (const auto& depId : node.dependencies) {
            auto depIt = dependencyGraph_.find(depId);
            if (depIt != dependencyGraph_.end()) {
                auto& dependents = depIt->second.dependents;
                if (std::find(dependents.begin(), dependents.end(), goalId) == dependents.end()) {
                    dependents.push_back(goalId);
                }
            }
        }
    }
}

void BlockingAgent::AddDependency(const std::string& goalId, const std::string& dependsOn) {
    if (!initialized_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = dependencyGraph_.find(goalId);
    if (it != dependencyGraph_.end()) {
        // Add to dependencies if not already present
        auto& deps = it->second.dependencies;
        if (std::find(deps.begin(), deps.end(), dependsOn) == deps.end()) {
            deps.push_back(dependsOn);
        }
    }
    
    // Update the dependsOn node's dependents
    auto depIt = dependencyGraph_.find(dependsOn);
    if (depIt != dependencyGraph_.end()) {
        auto& dependents = depIt->second.dependents;
        if (std::find(dependents.begin(), dependents.end(), goalId) == dependents.end()) {
            dependents.push_back(goalId);
        }
    }
}

void BlockingAgent::RemoveDependency(const std::string& goalId, const std::string& dependsOn) {
    if (!initialized_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = dependencyGraph_.find(goalId);
    if (it != dependencyGraph_.end()) {
        auto& deps = it->second.dependencies;
        deps.erase(std::remove(deps.begin(), deps.end(), dependsOn), deps.end());
    }
    
    // Update the dependsOn node's dependents
    auto depIt = dependencyGraph_.find(dependsOn);
    if (depIt != dependencyGraph_.end()) {
        auto& dependents = depIt->second.dependents;
        dependents.erase(std::remove(dependents.begin(), dependents.end(), goalId), 
                        dependents.end());
    }
}

void BlockingAgent::RegisterGoal(const std::string& goalId, int priority, 
                                  const std::vector<std::string>& dependencies) {
    if (!initialized_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    DependencyNode node;
    node.goalId = goalId;
    node.priority = priority;
    node.dependencies = dependencies;
    node.isActive = true;
    
    dependencyGraph_[goalId] = node;
    
    // Update dependents for each dependency
    for (const auto& depId : dependencies) {
        auto depIt = dependencyGraph_.find(depId);
        if (depIt != dependencyGraph_.end()) {
            auto& dependents = depIt->second.dependents;
            if (std::find(dependents.begin(), dependents.end(), goalId) == dependents.end()) {
                dependents.push_back(goalId);
            }
        }
    }
}

void BlockingAgent::UnregisterGoal(const std::string& goalId) {
    if (!initialized_) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        return;
    }
    
    // Remove this goal from all dependencies' dependents lists
    for (const auto& depId : it->second.dependencies) {
        auto depIt = dependencyGraph_.find(depId);
        if (depIt != dependencyGraph_.end()) {
            auto& dependents = depIt->second.dependents;
            dependents.erase(std::remove(dependents.begin(), dependents.end(), goalId),
                            dependents.end());
        }
    }
    
    // Remove this goal from all dependents' dependencies lists
    for (const auto& dependentId : it->second.dependents) {
        auto depIt = dependencyGraph_.find(dependentId);
        if (depIt != dependencyGraph_.end()) {
            auto& deps = depIt->second.dependencies;
            deps.erase(std::remove(deps.begin(), deps.end(), goalId), deps.end());
        }
    }
    
    dependencyGraph_.erase(it);
}

bool BlockingAgent::HasDependency(const std::string& goalId, const std::string& dependencyId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        return false;
    }
    
    const auto& deps = it->second.dependencies;
    return std::find(deps.begin(), deps.end(), dependencyId) != deps.end();
}

bool BlockingAgent::WouldCreateCycle(const std::string& goalId, const std::string& dependencyId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if dependencyId depends on goalId (directly or transitively)
    std::unordered_set<std::string> visited;
    std::queue<std::string> toVisit;
    toVisit.push(dependencyId);
    
    while (!toVisit.empty()) {
        std::string current = toVisit.front();
        toVisit.pop();
        
        if (current == goalId) {
            return true;  // Cycle detected
        }
        
        if (visited.count(current)) {
            continue;
        }
        visited.insert(current);
        
        auto it = dependencyGraph_.find(current);
        if (it != dependencyGraph_.end()) {
            for (const auto& dep : it->second.dependencies) {
                toVisit.push(dep);
            }
        }
    }
    
    return false;
}

std::vector<std::string> BlockingAgent::GetDependencyChain(const std::string& goalId) const {
    std::vector<std::string> chain;
    std::unordered_set<std::string> visited;
    
    std::lock_guard<std::mutex> lock(mutex_);
    TraverseDependencies(goalId, chain, visited, 0);
    
    return chain;
}

std::vector<std::string> BlockingAgent::GetDependentChain(const std::string& goalId) const {
    std::vector<std::string> chain;
    std::unordered_set<std::string> visited;
    
    std::lock_guard<std::mutex> lock(mutex_);
    TraverseDependents(goalId, chain, visited, 0);
    
    return chain;
}

// ============================================================================
// Statistics
// ============================================================================

size_t BlockingAgent::GetRegisteredGoalCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return dependencyGraph_.size();
}

size_t BlockingAgent::GetDependencyEdgeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    size_t count = 0;
    for (const auto& [goalId, node] : dependencyGraph_) {
        count += node.dependencies.size();
    }
    
    return count;
}

void BlockingAgent::ClearDependencyGraph() {
    std::lock_guard<std::mutex> lock(mutex_);
    dependencyGraph_.clear();
}

// ============================================================================
// Internal Evaluation Methods
// ============================================================================

void BlockingAgent::CollectBlockedGoals(const std::string& goalId, 
                                         std::vector<std::string>& blockedGoals,
                                         std::unordered_set<std::string>& visited) const {
    if (visited.count(goalId)) {
        return;
    }
    visited.insert(goalId);
    
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        return;
    }
    
    // All dependents are blocked by this goal
    for (const auto& dependentId : it->second.dependents) {
        if (!visited.count(dependentId)) {
            blockedGoals.push_back(dependentId);
            // Recursively collect goals blocked by this dependent
            CollectBlockedGoals(dependentId, blockedGoals, visited);
        }
    }
}

double BlockingAgent::CalculateBlockingScore(int blockedCritical, int blockedHigh, int totalBlocked) {
    // Weight critical goals heavily
    double criticalWeight = 10.0;
    double highWeight = 3.0;
    double normalWeight = 1.0;
    
    int normalBlocked = totalBlocked - blockedCritical - blockedHigh;
    
    double score = (blockedCritical * criticalWeight + 
                   blockedHigh * highWeight + 
                   normalBlocked * normalWeight) / 100.0;
    
    // Cap at 1.0
    return std::min(score, 1.0);
}

std::string BlockingAgent::GenerateRecommendation(double blockingScore, int blockedCritical, int blockedHigh) {
    if (blockedCritical > 0) {
        return "ACCELERATE";  // Critical blocker - execute immediately
    } else if (blockedHigh >= 3 || blockingScore > 0.5) {
        return "ACCELERATE";  // Significant blocker
    } else if (blockedHigh > 0 || blockingScore > 0.2) {
        return "MAINTAIN";    // Moderate blocker - normal priority
    } else if (blockingScore > 0.0) {
        return "MAINTAIN";    // Minor blocker
    } else {
        return "DEPRIORITIZE"; // Not blocking anything - can wait
    }
}

void BlockingAgent::TraverseDependents(const std::string& goalId, 
                                        std::vector<std::string>& dependents,
                                        std::unordered_set<std::string>& visited,
                                        int depth) const {
    if (depth > 100) {  // Prevent infinite recursion
        return;
    }
    
    if (visited.count(goalId)) {
        return;
    }
    visited.insert(goalId);
    
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        return;
    }
    
    for (const auto& dependentId : it->second.dependents) {
        dependents.push_back(dependentId);
        TraverseDependents(dependentId, dependents, visited, depth + 1);
    }
}

void BlockingAgent::TraverseDependencies(const std::string& goalId,
                                        std::vector<std::string>& dependencies,
                                        std::unordered_set<std::string>& visited,
                                        int depth) const {
    if (depth > 100) {  // Prevent infinite recursion
        return;
    }
    
    if (visited.count(goalId)) {
        return;
    }
    visited.insert(goalId);
    
    auto it = dependencyGraph_.find(goalId);
    if (it == dependencyGraph_.end()) {
        return;
    }
    
    for (const auto& depId : it->second.dependencies) {
        dependencies.push_back(depId);
        TraverseDependencies(depId, dependencies, visited, depth + 1);
    }
}

} // namespace Executive
} // namespace RawrXD
