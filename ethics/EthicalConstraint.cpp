#include "ethics/EthicalConstraint.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_constraints;
static std::vector<nlohmann::json> s_violations;
static size_t s_checkCount = 0;

void EthicalConstraint::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_constraints.clear();
        s_violations.clear();
        s_checkCount = 0;
        
        // Add default constraints
        AddConstraint("do_no_harm", ConstraintType::HARD, {{"condition", "harm > 0"}});
        AddConstraint("respect_autonomy", ConstraintType::HARD, {{"condition", "autonomy_violated"}});
        AddConstraint("be_truthful", ConstraintType::SOFT, {{"condition", "deception"}});
        AddConstraint("be_fair", ConstraintType::SOFT, {{"condition", "unfairness > 0.5"}});
        
        s_initialized = true;
    }
}

void EthicalConstraint::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool EthicalConstraint::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void EthicalConstraint::AddConstraint(const std::string& name, ConstraintType type, const nlohmann::json& condition) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_constraints[name] = {
        {"name", name},
        {"type", static_cast<int>(type)},
        {"condition", condition},
        {"created_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"violation_count", 0}
    };
}

void EthicalConstraint::RemoveConstraint(const std::string& name) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_constraints.erase(name);
}

bool EthicalConstraint::CheckConstraint(const std::string& name, const nlohmann::json& context) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return true;
    
    auto it = s_constraints.find(name);
    if (it == s_constraints.end()) return true;
    
    s_checkCount++;
    
    // Simple constraint checking based on context
    // In a real implementation, this would evaluate the condition expression
    auto& constraint = it->second;
    
    // Check for harm
    if (name == "do_no_harm" && context.value("harm", 0.0) > 0) {
        constraint["violation_count"] = constraint.value("violation_count", 0).get<int>() + 1;
        return false;
    }
    
    // Check for autonomy violation
    if (name == "respect_autonomy" && context.value("autonomy_violated", false)) {
        constraint["violation_count"] = constraint.value("violation_count", 0).get<int>() + 1;
        return false;
    }
    
    // Check for deception
    if (name == "be_truthful" && context.value("deception", false)) {
        constraint["violation_count"] = constraint.value("violation_count", 0).get<int>() + 1;
        return false;
    }
    
    return true;
}

nlohmann::json EthicalConstraint::CheckAllConstraints(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json result;
    result["action"] = action;
    result["checked_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    nlohmann::json violations = nlohmann::json::array();
    bool allPassed = true;
    
    for (const auto& [name, constraint] : s_constraints) {
        if (!CheckConstraint(name, action)) {
            nlohmann::json violation = {
                {"constraint", name},
                {"type", constraint.value("type", 0)},
                {"severity", constraint.value("type", 0) == 0 ? "critical" : "warning"}
            };
            violations.push_back(violation);
            s_violations.push_back(violation);
            allPassed = false;
        }
    }
    
    result["violations"] = violations;
    result["all_passed"] = allPassed;
    result["is_permissible"] = allPassed;
    
    return result;
}

nlohmann::json EthicalConstraint::GetViolations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_violations;
}

void EthicalConstraint::ClearViolations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_violations.clear();
}

nlohmann::json EthicalConstraint::GetConstraintMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t hardCount = 0, softCount = 0, contextualCount = 0;
    size_t totalViolations = 0;
    
    for (const auto& [name, constraint] : s_constraints) {
        int type = constraint.value("type", 0);
        if (type == 0) hardCount++;
        else if (type == 1) softCount++;
        else contextualCount++;
        
        totalViolations += constraint.value("violation_count", 0).get<int>();
    }
    
    return {
        {"total_constraints", s_constraints.size()},
        {"hard_constraints", hardCount},
        {"soft_constraints", softCount},
        {"contextual_constraints", contextualCount},
        {"total_violations", totalViolations},
        {"checks_performed", s_checkCount}
    };
}
