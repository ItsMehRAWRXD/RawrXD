// ============================================================
// GoalManager.cpp - Implementation
// ============================================================

#include "GoalManager.hpp"
#include "ExecutiveDirector.hpp"
#include <algorithm>

namespace RawrXD::Executive {

bool GoalManager::initialize(ExecutiveDirector* director) {
    director_ = director;
    printf("[GoalManager] Initialized\n");
    return true;
}

void GoalManager::shutdown() {
    printf("[GoalManager] Shutdown\n");
}

uint64_t GoalManager::createGoal(const std::string& description, GoalType type, GoalPriority priority) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Goal goal;
    goal.id = nextGoalId_++;
    goal.description = description;
    goal.type = type;
    goal.priority = priority;
    goal.createdAtMs = currentTimeMs();
    goal.state = GoalState::PENDING;
    
    goals_[goal.id] = goal;
    
    printf("[GoalManager] Goal #%llu created: %s\n",
           (unsigned long long)goal.id, description.c_str());
    
    return goal.id;
}

void GoalManager::setGoalParent(uint64_t goalId, uint64_t parentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        it->second.parentGoalId = parentId;
    }
}

void GoalManager::addSubGoal(uint64_t parentId, uint64_t subGoalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(parentId);
    if (it != goals_.end()) {
        it->second.subGoalIds.push_back(subGoalId);
    }
}

void GoalManager::activateGoal(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        it->second.state = GoalState::ACTIVE;
        printf("[GoalManager] Goal #%llu ACTIVATED\n", (unsigned long long)goalId);
    }
}

void GoalManager::updateGoalProgress(uint64_t goalId, float progress) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        it->second.progress = progress;
    }
}

void GoalManager::markGoalSatisfied(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        it->second.state = GoalState::SATISFIED;
        it->second.progress = 1.0f;
        it->second.completedAtMs = currentTimeMs();
        satisfiedCount_++;
        printf("[GoalManager] Goal #%llu SATISFIED\n", (unsigned long long)goalId);
    }
}

void GoalManager::markGoalFailed(uint64_t goalId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        it->second.state = GoalState::FAILED;
        failedCount_++;
        printf("[GoalManager] Goal #%llu FAILED: %s\n", (unsigned long long)goalId, reason.c_str());
    }
}

void GoalManager::abandonGoal(uint64_t goalId, const std::string& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        it->second.state = GoalState::ABANDONED;
        printf("[GoalManager] Goal #%llu ABANDONED: %s\n", (unsigned long long)goalId, reason.c_str());
    }
}

std::optional<Goal> GoalManager::getGoal(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Goal> GoalManager::getActiveGoals() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Goal> results;
    for (const auto& [id, goal] : goals_) {
        if (goal.state == GoalState::ACTIVE) {
            results.push_back(goal);
        }
    }
    return results;
}

std::vector<Goal> GoalManager::getGoalsByPriority(GoalPriority minPriority) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Goal> results;
    for (const auto& [id, goal] : goals_) {
        if (static_cast<int>(goal.priority) <= static_cast<int>(minPriority)) {
            results.push_back(goal);
        }
    }
    return results;
}

std::vector<Goal> GoalManager::getGoalsByState(GoalState state) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Goal> results;
    for (const auto& [id, goal] : goals_) {
        if (goal.state == state) {
            results.push_back(goal);
        }
    }
    return results;
}

std::vector<Goal> GoalManager::getSubGoals(uint64_t parentId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Goal> results;
    auto it = goals_.find(parentId);
    if (it != goals_.end()) {
        for (uint64_t subId : it->second.subGoalIds) {
            auto subIt = goals_.find(subId);
            if (subIt != goals_.end()) {
                results.push_back(subIt->second);
            }
        }
    }
    return results;
}

void GoalManager::reprioritizeGoal(uint64_t goalId, GoalPriority newPriority) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it != goals_.end()) {
        it->second.priority = newPriority;
    }
}

void GoalManager::adjustPrioritiesBasedOnUrgency() {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t now = currentTimeMs();
    for (auto& [id, goal] : goals_) {
        if (goal.state == GoalState::ACTIVE && goal.deadlineMs > 0) {
            uint64_t remaining = goal.deadlineMs > now ? goal.deadlineMs - now : 0;
            if (remaining < 60000 && goal.priority > GoalPriority::HIGH) {
                goal.priority = GoalPriority::HIGH;
                printf("[GoalManager] Goal #%llu urgency-bumped to HIGH\n", (unsigned long long)id);
            }
        }
    }
}

std::vector<Goal> GoalManager::getPrioritizedGoals() {
    auto goals = getActiveGoals();
    std::sort(goals.begin(), goals.end(), [](const Goal& a, const Goal& b) {
        return static_cast<int>(a.priority) < static_cast<int>(b.priority);
    });
    return goals;
}

std::vector<GoalConflict> GoalManager::detectConflicts() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<GoalConflict> conflicts;
    for (const auto& [id1, g1] : goals_) {
        for (const auto& [id2, g2] : goals_) {
            if (id1 >= id2) continue;
            // Resource conflict
            for (const auto& r1 : g1.requiredResources) {
                for (const auto& r2 : g2.requiredResources) {
                    if (r1 == r2 && g1.state == GoalState::ACTIVE && g2.state == GoalState::ACTIVE) {
                        conflicts.push_back({
                            .goalId1 = id1, .goalId2 = id2,
                            .conflictType = "resource",
                            .description = "Both goals require: " + r1,
                            .severity = 0.6f
                        });
                    }
                }
            }
        }
    }
    return conflicts;
}

std::string GoalManager::resolveConflict(const GoalConflict& conflict) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it1 = goals_.find(conflict.goalId1);
    auto it2 = goals_.find(conflict.goalId2);
    if (it1 == goals_.end() || it2 == goals_.end()) return "invalid";
    
    // Lower priority wins (higher enum value = lower priority)
    if (static_cast<int>(it1->second.priority) < static_cast<int>(it2->second.priority)) {
        it2->second.state = GoalState::BLOCKED;
        return "blocked_" + std::to_string(conflict.goalId2);
    } else {
        it1->second.state = GoalState::BLOCKED;
        return "blocked_" + std::to_string(conflict.goalId1);
    }
}

std::vector<Goal> GoalManager::decomposeGoal(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Goal> subGoals;
    auto it = goals_.find(goalId);
    if (it == goals_.end()) return subGoals;
    
    // Simple decomposition: create sub-goals for each milestone
    for (size_t i = 0; i < it->second.milestones.size(); ++i) {
        Goal sub;
        sub.id = nextGoalId_++;
        sub.description = it->second.milestones[i];
        sub.parentGoalId = goalId;
        sub.priority = it->second.priority;
        sub.state = GoalState::PENDING;
        sub.createdAtMs = currentTimeMs();
        goals_[sub.id] = sub;
        it->second.subGoalIds.push_back(sub.id);
        subGoals.push_back(sub);
    }
    return subGoals;
}

bool GoalManager::canDecompose(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it == goals_.end()) return false;
    return !it->second.milestones.empty() && it->second.subGoalIds.empty();
}

bool GoalManager::isGoalSatisfied(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it == goals_.end()) return false;
    return it->second.state == GoalState::SATISFIED;
}

bool GoalManager::isGoalAchievable(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it == goals_.end()) return false;
    if (it->second.state == GoalState::FAILED || it->second.state == GoalState::ABANDONED) {
        return false;
    }
    // Check dependencies
    for (uint64_t depId : it->second.dependsOnGoals) {
        auto depIt = goals_.find(depId);
        if (depIt == goals_.end() || depIt->second.state != GoalState::SATISFIED) {
            return false;
        }
    }
    return true;
}

float GoalManager::calculateGoalUtility(uint64_t goalId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = goals_.find(goalId);
    if (it == goals_.end()) return 0.0f;
    
    float priorityWeight = 1.0f - (static_cast<int>(it->second.priority) / 4.0f);
    float progressBonus = it->second.progress * 0.5f;
    return priorityWeight + progressBonus;
}

GoalManager::Stats GoalManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats s;
    s.totalGoals = goals_.size();
    s.satisfiedGoals = satisfiedCount_;
    s.failedGoals = failedCount_;
    s.activeGoals = 0;
    for (const auto& [id, g] : goals_) {
        if (g.state == GoalState::ACTIVE) s.activeGoals++;
    }
    s.goalSuccessRate = s.totalGoals > 0 ? 
        static_cast<float>(s.satisfiedGoals) / s.totalGoals : 0.0f;
    return s;
}

uint64_t GoalManager::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

} // namespace RawrXD::Executive
