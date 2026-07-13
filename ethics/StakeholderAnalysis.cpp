#include "ethics/StakeholderAnalysis.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_stakeholders;
static size_t s_analysisCount = 0;

void StakeholderAnalysis::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_stakeholders.clear();
        s_analysisCount = 0;
        
        // Register default stakeholders
        RegisterStakeholder("users", {{"priority", "high"}, {"interests", {{"safety", "privacy", "autonomy"}}}});
        RegisterStakeholder("society", {{"priority", "high"}, {"interests", {{"welfare", "justice", "progress"}}}});
        RegisterStakeholder("system", {{"priority", "medium"}, {"interests", {{"stability", "efficiency", "integrity"}}}});
        
        s_initialized = true;
    }
}

void StakeholderAnalysis::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool StakeholderAnalysis::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void StakeholderAnalysis::RegisterStakeholder(const std::string& id, const nlohmann::json& interests) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_stakeholders[id] = {
        {"id", id},
        {"interests", interests},
        {"registered_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

void StakeholderAnalysis::UnregisterStakeholder(const std::string& id) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_stakeholders.erase(id);
}

nlohmann::json StakeholderAnalysis::GetStakeholders() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, stakeholder] : s_stakeholders) {
        result.push_back(stakeholder);
    }
    return result;
}

nlohmann::json StakeholderAnalysis::AnalyzeImpact(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_analysisCount++;
    
    nlohmann::json impact;
    impact["action"] = action;
    impact["analyzed_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    
    nlohmann::json stakeholderImpacts = nlohmann::json::object();
    
    for (const auto& [id, stakeholder] : s_stakeholders) {
        // Calculate impact on each stakeholder
        double impactScore = 0.0;
        
        // Check if action affects stakeholder interests
        if (action.contains("affected_stakeholders")) {
            for (const auto& affected : action["affected_stakeholders"]) {
                if (affected == id) {
                    impactScore = action.value("impact_magnitude", 0.0);
                    break;
                }
            }
        }
        
        stakeholderImpacts[id] = {
            {"impact_score", impactScore},
            {"is_affected", impactScore != 0.0},
            {"priority", stakeholder.value("priority", "medium")}
        };
    }
    
    impact["stakeholder_impacts"] = stakeholderImpacts;
    
    // Calculate overall impact
    double totalImpact = 0.0;
    int affectedCount = 0;
    for (const auto& [id, si] : stakeholderImpacts.items()) {
        double score = si.value("impact_score", 0.0);
        totalImpact += score;
        if (score != 0.0) affectedCount++;
    }
    
    impact["total_impact"] = totalImpact;
    impact["affected_count"] = affectedCount;
    impact["requires_review"] = affectedCount > 1 || std::abs(totalImpact) > 0.8;
    
    return impact;
}

nlohmann::json StakeholderAnalysis::GetAffectedStakeholders(const nlohmann::json& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json affected = nlohmann::json::array();
    
    if (action.contains("affected_stakeholders")) {
        for (const auto& id : action["affected_stakeholders"]) {
            auto it = s_stakeholders.find(id.get<std::string>());
            if (it != s_stakeholders.end()) {
                affected.push_back(it->second);
            }
        }
    }
    
    return affected;
}

nlohmann::json StakeholderAnalysis::CalculateFairness(const nlohmann::json& distribution) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Calculate Gini coefficient for fairness
    double total = 0.0;
    double count = 0.0;
    
    for (const auto& [key, value] : distribution.items()) {
        if (value.is_number()) {
            total += value.get<double>();
            count += 1.0;
        }
    }
    
    double mean = count > 0 ? total / count : 0.0;
    
    // Simple fairness score (1 = perfectly fair, 0 = completely unfair)
    double variance = 0.0;
    for (const auto& [key, value] : distribution.items()) {
        if (value.is_number()) {
            double diff = value.get<double>() - mean;
            variance += diff * diff;
        }
    }
    
    double stdDev = count > 0 ? std::sqrt(variance / count) : 0.0;
    double fairnessScore = mean > 0 ? std::max(0.0, 1.0 - (stdDev / mean)) : 0.0;
    
    return {
        {"fairness_score", fairnessScore},
        {"mean", mean},
        {"std_dev", stdDev},
        {"is_fair", fairnessScore > 0.7}
    };
}

nlohmann::json StakeholderAnalysis::GetStakeholderMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"registered_stakeholders", s_stakeholders.size()},
        {"analyses_performed", s_analysisCount}
    };
}
