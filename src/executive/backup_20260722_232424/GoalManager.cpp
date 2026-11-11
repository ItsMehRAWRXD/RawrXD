// ============================================================================
// GoalManager.cpp - Implementation
// ============================================================================

#include "GoalManager.hpp"
#include "ExecutiveDirector.hpp"

namespace RawrXD {
namespace Executive {

struct GoalManager::Impl {
    ExecutiveDirector* director = nullptr;
    std::unordered_map<std::string, Goal> goals;
    size_t totalGoals = 0;
    size_t satisfiedGoals = 0;
    size_t failedGoals = 0;
};

GoalManager::GoalManager() : pImpl_(std::make_unique<Impl>()) {}
GoalManager::~GoalManager() = default;

bool GoalManager::Initialize(ExecutiveDirector* director) {
    pImpl_->director = director;
    return true;
}

void GoalManager::Shutdown() {}

std::string GoalManager::CreateGoal(const std::string& description, GoalType type, GoalPriority priority) {
    Goal goal;
    goal.goalId = "goal_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    goal.description = description;
    goal.type = type;
    goal.priority = priority;
    goal.createdAt = std::chrono::steady_clock::now();
    goal.state = GoalState::PENDING;
    
    pImpl_->goals[goal.goalId] = goal;
    pImpl_->totalGoals++;
    
    return goal.goalId;
}

void GoalManager::SetGoalParent(const std::string& goalId, const std::string& parentId) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        it->second.parentGoalId = parentId;
    }
}

void GoalManager::AddSubGoal(const std::string& parentId, const std::string& subGoalId) {
    auto it = pImpl_->goals.find(parentId);
    if (it != pImpl_->goals.end()) {
        it->second.subGoalIds.push_back(subGoalId);
    }
}

void GoalManager::ActivateGoal(const std::string& goalId) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        it->second.state = GoalState::ACTIVE;
    }
}

void GoalManager::UpdateGoalProgress(const std::string& goalId, float progress) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        it->second.progress = progress;
    }
}

void GoalManager::MarkGoalSatisfied(const std::string& goalId) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        it->second.state = GoalState::SATISFIED;
        it->second.progress = 1.0f;
        it->second.completedAt = std::chrono::steady_clock::now();
        pImpl_->satisfiedGoals++;
    }
}

void GoalManager::MarkGoalFailed(const std::string& goalId, const std::string& reason) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        it->second.state = GoalState::FAILED;
        pImpl_->failedGoals++;
    }
}

void GoalManager::AbandonGoal(const std::string& goalId, const std::string& reason) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        it->second.state = GoalState::ABANDONED;
    }
}

std::optional<Goal> GoalManager::GetGoal(const std::string& goalId) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Goal> GoalManager::GetActiveGoals() {
    std::vector<Goal> results;
    for (const auto& [id, goal] : pImpl_->goals) {
        if (goal.state == GoalState::ACTIVE) {
            results.push_back(goal);
        }
    }
    return results;
}

std::vector<Goal> GoalManager::GetGoalsByPriority(GoalPriority minPriority) {
    std::vector<Goal> results;
    for (const auto& [id, goal] : pImpl_->goals) {
        if (static_cast<int>(goal.priority) <= static_cast<int>(minPriority)) {
            results.push_back(goal);
        }
    }
    return results;
}

std::vector<Goal> GoalManager::GetGoalsByState(GoalState state) {
    std::vector<Goal> results;
    for (const auto& [id, goal] : pImpl_->goals) {
        if (goal.state == state) {
            results.push_back(goal);
        }
    }
    return results;
}

std::vector<Goal> GoalManager::GetSubGoals(const std::string& parentId) {
    std::vector<Goal> results;
    auto it = pImpl_->goals.find(parentId);
    if (it != pImpl_->goals.end()) {
        for (const auto& subId : it->second.subGoalIds) {
            auto subIt = pImpl_->goals.find(subId);
            if (subIt != pImpl_->goals.end()) {
                results.push_back(subIt->second);
            }
        }
    }
    return results;
}

void GoalManager::ReprioritizeGoal(const std::string& goalId, GoalPriority newPriority) {
    auto it = pImpl_->goals.find(goalId);
    if (it != pImpl_->goals.end()) {
        it->second.priority = newPriority;
    }
}

void GoalManager::AdjustPrioritiesBasedOnUrgency() {}

std::vector<Goal> GoalManager::GetPrioritizedGoals() {
    auto goals = GetActiveGoals();
    std::sort(goals.begin(), goals.end(), [](const Goal& a, const Goal& b) {
        return static_cast<int>(a.priority) < static_cast<int>(b.priority);
    });
    return goals;
}

std::vector<GoalConflict> GoalManager::DetectConflicts() { return {}; }
std::string GoalManager::ResolveConflict(const GoalConflict& conflict) { return ""; }
std::vector<Goal> GoalManager::DecomposeGoal(const std::string& goalId) { return {}; }
bool GoalManager::CanDecompose(const std::string& goalId) { return false; }
bool GoalManager::IsGoalSatisfied(const std::string& goalId) { return false; }
bool GoalManager::IsGoalAchievable(const std::string& goalId) { return true; }
float GoalManager::CalculateGoalUtility(const std::string& goalId) { return 0.5f; }

GoalManager::Stats GoalManager::GetStats() const {
    Stats s;
    s.totalGoals = pImpl_->totalGoals;
    s.satisfiedGoals = pImpl_->satisfiedGoals;
    s.failedGoals = pImpl_->failedGoals;
    s.activeGoals = pImpl_->totalGoals - pImpl_->satisfiedGoals - pImpl_->failedGoals;
    s.goalSuccessRate = pImpl_->totalGoals > 0 ? 
        static_cast<float>(pImpl_->satisfiedGoals) / pImpl_->totalGoals : 0.0f;
    return s;
}

} // namespace Executive
} // namespace RawrXD
