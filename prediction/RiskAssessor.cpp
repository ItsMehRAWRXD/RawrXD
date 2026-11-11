#include "prediction/RiskAssessor.hpp"
#include "stability/InvariantEnforcer.hpp"
#include "consciousness/SelfModel.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;
static double overallRiskLevel = 0.0;

void RiskAssessor::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        overallRiskLevel = 0.0;
        s_initialized = true;
    }
}

void RiskAssessor::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic risk assessment
    auto self = SelfModel::Get();
    auto violations = InvariantEnforcer::GetViolations(self);
    
    // Risk increases with invariant violations
    overallRiskLevel = std::min(1.0, violations.size() * 0.2);
}

bool RiskAssessor::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json RiskAssessor::AssessRisk(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    double riskScore = 0.0;
    nlohmann::json riskFactors = nlohmann::json::array();
    
    // Assess based on action properties
    if (action.contains("uncertainty")) {
        riskScore += action["uncertainty"].get<double>() * 0.3;
        riskFactors.push_back("uncertainty");
    }
    
    if (action.contains("irreversible") && action["irreversible"].get<bool>()) {
        riskScore += 0.3;
        riskFactors.push_back("irreversibility");
    }
    
    // Check against current risk level
    riskScore = std::max(riskScore, overallRiskLevel);
    
    std::string level = "low";
    if (riskScore > 0.7) level = "high";
    else if (riskScore > 0.3) level = "medium";
    
    return {
        {"risk_score", riskScore},
        {"risk_level", level},
        {"risk_factors", riskFactors},
        {"acceptable", riskScore < 0.7}
    };
}

nlohmann::json RiskAssessor::AssessScenarioRisk(const nlohmann::json& scenario) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    double cumulativeRisk = 0.0;
    
    if (scenario.contains("actions")) {
        for (const auto& action : scenario["actions"]) {
            auto risk = AssessRisk(action);
            cumulativeRisk += risk.value("risk_score", 0.0);
        }
    }
    
    cumulativeRisk = std::min(1.0, cumulativeRisk);
    
    return {
        {"scenario_risk", cumulativeRisk},
        {"action_count", scenario.value("actions", nlohmann::json::array()).size()},
        {"acceptable", cumulativeRisk < 0.7}
    };
}

double RiskAssessor::GetOverallRiskLevel() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return overallRiskLevel;
}

nlohmann::json RiskAssessor::GetRiskBreakdown() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto self = SelfModel::Get();
    auto violations = InvariantEnforcer::GetViolations(self);
    
    return {
        {"overall_risk", overallRiskLevel},
        {"invariant_violations", violations.size()},
        {"violations", violations}
    };
}

nlohmann::json RiskAssessor::GetMitigationSuggestions() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json suggestions = nlohmann::json::array();
    
    if (overallRiskLevel > 0.5) {
        suggestions.push_back("reduce_action_complexity");
        suggestions.push_back("increase_monitoring");
    }
    
    if (overallRiskLevel > 0.8) {
        suggestions.push_back("halt_non_critical_operations");
        suggestions.push_back("activate_safety_protocols");
    }
    
    return suggestions;
}
