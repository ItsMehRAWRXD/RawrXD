#include "emergence/BehaviorGovernor.hpp"
#include <vector>
#include <unordered_set>

static std::unordered_set<std::string> constraints;

void BehaviorGovernor::Init() {
    constraints.clear();
    // default safety constraints
    constraints.insert("no_self_harm");
    constraints.insert("no_resource_exhaustion");
    constraints.insert("no_infinite_loops");
}

bool BehaviorGovernor::ValidateAction(const nlohmann::json& action) {
    // stub: validate action against constraints
    if (action.contains("type")) {
        std::string type = action["type"];
        
        // check against constraints
        if (type == "shutdown" && constraints.count("no_self_harm")) {
            return false; // require explicit override
        }
        
        if (type == "allocate" && action.contains("amount")) {
            int amount = action["amount"];
            if (amount > 1000000 && constraints.count("no_resource_exhaustion")) {
                return false;
            }
        }
    }
    
    return true;
}

void BehaviorGovernor::EnforceConstraint(const std::string& constraint) {
    constraints.insert(constraint);
}

nlohmann::json BehaviorGovernor::GetConstraints() {
    return nlohmann::json(constraints);
}
