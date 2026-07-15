#include "stability/InvariantEnforcer.hpp"
#include <unordered_map>

static std::unordered_map<std::string, InvariantEnforcer::Invariant> invariants;

void InvariantEnforcer::Init() {
    invariants.clear();
    
    // Register default invariants
    Register("health_positive", [](const nlohmann::json& state) {
        if (!state.contains("health")) return true;
        return state["health"] != "critical";
    });
    
    Register("confidence_bounded", [](const nlohmann::json& state) {
        if (!state.contains("confidence")) return true;
        float conf = state["confidence"];
        return conf >= 0.0f && conf <= 1.0f;
    });
    
    Register("autonomy_bounded", [](const nlohmann::json& state) {
        if (!state.contains("autonomy_level")) return true;
        int level = state["autonomy_level"];
        return level >= 0 && level <= 10;
    });
}

void InvariantEnforcer::Register(const std::string& name, Invariant inv) {
    invariants[name] = inv;
}

bool InvariantEnforcer::Validate(const nlohmann::json& state) {
    for (auto& [name, inv] : invariants) {
        if (!inv(state)) return false;
    }
    return true;
}

std::vector<std::string> InvariantEnforcer::GetViolations(const nlohmann::json& state) {
    std::vector<std::string> violations;
    for (auto& [name, inv] : invariants) {
        if (!inv(state)) {
            violations.push_back(name);
        }
    }
    return violations;
}
