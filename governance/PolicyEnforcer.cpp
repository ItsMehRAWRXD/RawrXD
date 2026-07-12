#include "governance/PolicyEnforcer.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct Policy {
    std::string id;
    nlohmann::json rules;
    int64_t createdAt;
    int64_t lastModified;
    bool active;
};

static std::map<std::string, Policy> s_policies;
static size_t s_evaluationCount = 0;
static size_t s_violationCount = 0;
static size_t s_allowCount = 0;

void PolicyEnforcer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_policies.clear();
        s_evaluationCount = 0;
        s_violationCount = 0;
        s_allowCount = 0;
        
        // Initialize default policies
        s_policies["default"] = {
            "default",
            {
                {"max_request_size", 1048576},
                {"allowed_operations", nlohmann::json::array({"read", "write", "delete"})},
                {"require_authentication", true}
            },
            std::chrono::system_clock::now().time_since_epoch().count(),
            std::chrono::system_clock::now().time_since_epoch().count(),
            true
        };
        
        s_initialized = true;
    }
}

void PolicyEnforcer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic policy validation
    for (auto& [id, policy] : s_policies) {
        if (policy.active) {
            // Validate policy rules
        }
    }
}

bool PolicyEnforcer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void PolicyEnforcer::DefinePolicy(const std::string& policyId, const nlohmann::json& rules) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    
    auto it = s_policies.find(policyId);
    if (it != s_policies.end()) {
        it->second.rules = rules;
        it->second.lastModified = now;
    } else {
        Policy policy;
        policy.id = policyId;
        policy.rules = rules;
        policy.createdAt = now;
        policy.lastModified = now;
        policy.active = true;
        s_policies[policyId] = policy;
    }
}

nlohmann::json PolicyEnforcer::GetPolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_policies.find(policyId);
    if (it != s_policies.end()) {
        return {
            {"id", it->second.id},
            {"rules", it->second.rules},
            {"created_at", it->second.createdAt},
            {"last_modified", it->second.lastModified},
            {"active", it->second.active}
        };
    }
    return nlohmann::json{};
}

nlohmann::json PolicyEnforcer::GetAllPolicies() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, policy] : s_policies) {
        result.push_back({
            {"id", policy.id},
            {"active", policy.active},
            {"rule_count", policy.rules.size()}
        });
    }
    return result;
}

void PolicyEnforcer::DeletePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_policies.erase(policyId);
}

nlohmann::json PolicyEnforcer::EvaluateAction(const std::string& action, const nlohmann::json& context) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_evaluationCount++;
    
    // Check against default policy
    auto it = s_policies.find("default");
    if (it != s_policies.end()) {
        auto allowedOps = it->second.rules.value("allowed_operations", nlohmann::json::array());
        bool allowed = false;
        for (const auto& op : allowedOps) {
            if (op.get<std::string>() == action) {
                allowed = true;
                break;
            }
        }
        
        if (!allowed) {
            s_violationCount++;
            return {
                {"action", action},
                {"allowed", false},
                {"reason", "operation_not_allowed"},
                {"policy", "default"}
            };
        }
    }
    
    s_allowCount++;
    return {
        {"action", action},
        {"allowed", true},
        {"policy", "default"}
    };
}

bool PolicyEnforcer::IsActionAllowed(const std::string& action, const nlohmann::json& context) {
    auto result = EvaluateAction(action, context);
    return result.value("allowed", false);
}

nlohmann::json PolicyEnforcer::GetPolicyMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t activeCount = 0;
    for (const auto& [id, policy] : s_policies) {
        if (policy.active) activeCount++;
    }
    
    return {
        {"total_policies", s_policies.size()},
        {"active_policies", activeCount},
        {"evaluations", s_evaluationCount},
        {"violations", s_violationCount},
        {"allowed", s_allowCount},
        {"violation_rate", s_evaluationCount > 0 ? (double)s_violationCount / s_evaluationCount : 0.0}
    };
}
