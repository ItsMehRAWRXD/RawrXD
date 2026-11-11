#include "identity/GoalPersistence.hpp"
#include "identity/IdentityModel.hpp"
#include <unordered_map>

static std::unordered_map<std::string, nlohmann::json> persistentGoals;
static std::vector<nlohmann::json> archivedGoals;

void GoalPersistence::Init() {
    persistentGoals.clear();
    archivedGoals.clear();
}

void GoalPersistence::PersistGoal(const nlohmann::json& goal) {
    if (goal.contains("id")) {
        std::string id = goal["id"];
        persistentGoals[id] = goal;
    }
}

std::vector<nlohmann::json> GoalPersistence::GetPersistentGoals() {
    std::vector<nlohmann::json> goals;
    for (auto& [id, goal] : persistentGoals) {
        goals.push_back(goal);
    }
    return goals;
}

void GoalPersistence::ArchiveCompleted(const std::string& goalId) {
    auto it = persistentGoals.find(goalId);
    if (it != persistentGoals.end()) {
        archivedGoals.push_back(it->second);
        persistentGoals.erase(it);
    }
}

void GoalPersistence::AlignGoalsWithIdentity() {
    auto identity = IdentityModel::GetCoreIdentity();
    
    // Remove goals that violate identity constraints
    std::vector<std::string> toRemove;
    for (auto& [id, goal] : persistentGoals) {
        if (goal.contains("violates_identity") && goal["violates_identity"]) {
            toRemove.push_back(id);
        }
    }
    
    for (auto& id : toRemove) {
        persistentGoals.erase(id);
    }
}
