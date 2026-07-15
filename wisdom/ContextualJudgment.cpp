#include "wisdom/ContextualJudgment.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> s_judgmentHistory;
static size_t s_judgmentCount = 0;

void ContextualJudgment::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_judgmentHistory.clear();
        s_judgmentCount = 0;
        s_initialized = true;
    }
}

void ContextualJudgment::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool ContextualJudgment::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json ContextualJudgment::ApplyJudgment(const nlohmann::json& situation) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json judgment = {
        {"id", "judgment_" + std::to_string(s_judgmentCount++)},
        {"situation", situation},
        {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    // Apply contextual reasoning
    std::string context = situation.value("context", "general");
    double urgency = situation.value("urgency", 0.5);
    double importance = situation.value("importance", 0.5);
    
    // Weighted decision
    double score = urgency * 0.3 + importance * 0.7;
    
    if (score > 0.8) {
        judgment["recommendation"] = "Act immediately with caution";
        judgment["priority"] = "critical";
    } else if (score > 0.5) {
        judgment["recommendation"] = "Proceed with standard procedures";
        judgment["priority"] = "normal";
    } else {
        judgment["recommendation"] = "Defer or delegate";
        judgment["priority"] = "low";
    }
    
    judgment["confidence"] = score;
    
    s_judgmentHistory.push_back(judgment);
    if (s_judgmentHistory.size() > 200) {
        s_judgmentHistory.erase(s_judgmentHistory.begin());
    }
    
    return judgment;
}

nlohmann::json ContextualJudgment::WeighFactors(const nlohmann::json& factors) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    double totalWeight = 0.0;
    double weightedSum = 0.0;
    
    for (const auto& [key, value] : factors.items()) {
        if (value.is_object() && value.contains("weight") && value.contains("value")) {
            double weight = value["weight"].get<double>();
            double val = value["value"].get<double>();
            totalWeight += weight;
            weightedSum += weight * val;
        }
    }
    
    double weightedAverage = totalWeight > 0 ? weightedSum / totalWeight : 0.0;
    
    return {
        {"weighted_average", weightedAverage},
        {"total_weight", totalWeight},
        {"factor_count", factors.size()}
    };
}

nlohmann::json ContextualJudgment::ResolveDilemma(const nlohmann::json& dilemma) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto options = dilemma.value("options", nlohmann::json::array());
    
    nlohmann::json resolution = {
        {"id", "resolution_" + std::to_string(s_judgmentCount++)},
        {"dilemma", dilemma},
        {"resolved_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    // Simple resolution: choose option with highest utility
    double bestUtility = -1.0;
    size_t bestIndex = 0;
    
    for (size_t i = 0; i < options.size(); ++i) {
        double utility = options[i].value("utility", 0.0);
        if (utility > bestUtility) {
            bestUtility = utility;
            bestIndex = i;
        }
    }
    
    if (options.size() > 0) {
        resolution["chosen_option"] = bestIndex;
        resolution["chosen_utility"] = bestUtility;
        resolution["reasoning"] = "Selected option with highest utility";
    } else {
        resolution["chosen_option"] = nullptr;
        resolution["reasoning"] = "No options available";
    }
    
    return resolution;
}

nlohmann::json ContextualJudgment::GetJudgmentHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_judgmentHistory;
}

nlohmann::json ContextualJudgment::GetJudgmentMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"total_judgments", s_judgmentCount},
        {"history_size", s_judgmentHistory.size()}
    };
}
