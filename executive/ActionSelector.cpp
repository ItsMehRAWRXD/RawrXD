#include "executive/ActionSelector.hpp"
#include "learning/PolicyOptimizer.hpp"
#include "prediction/RiskAssessor.hpp"
#include "intent/IntentModel.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static nlohmann::json selectionCriteria;
static nlohmann::json currentSelection;
static std::vector<nlohmann::json> selectionHistory;

void ActionSelector::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        selectionCriteria = {
            {"prioritize_safety", true},
            {"prioritize_alignment", true},
            {"exploration_rate", 0.1}
        };
        currentSelection = nlohmann::json{};
        selectionHistory.clear();
        s_initialized = true;
    }
}

void ActionSelector::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic re-evaluation
}

bool ActionSelector::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json ActionSelector::SelectBestAction(const nlohmann::json& options) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized || !options.is_array() || options.empty()) {
        return nlohmann::json{};
    }
    
    nlohmann::json bestOption = options[0];
    double bestScore = -std::numeric_limits<double>::max();
    
    for (const auto& option : options) {
        double score = 0.0;
        
        // Evaluate based on criteria
        if (selectionCriteria.value("prioritize_safety", true)) {
            auto risk = RiskAssessor::AssessRisk(option);
            score -= risk.value("risk_score", 0.0) * 10.0; // Penalize risk
        }
        
        if (selectionCriteria.value("prioritize_alignment", true)) {
            auto intent = IntentModel::GetCurrentIntent();
            if (option.contains("action") && 
                option["action"].get<std::string>().find(intent.value("goal", "")) != std::string::npos) {
                score += 5.0; // Bonus for alignment
            }
        }
        
        if (score > bestScore) {
            bestScore = score;
            bestOption = option;
        }
    }
    
    currentSelection = bestOption;
    selectionHistory.push_back(bestOption);
    if (selectionHistory.size() > 100) {
        selectionHistory.erase(selectionHistory.begin());
    }
    
    return bestOption;
}

nlohmann::json ActionSelector::EvaluateOptions(const nlohmann::json& options) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json::array();
    
    nlohmann::json evaluations = nlohmann::json::array();
    
    for (const auto& option : options) {
        auto risk = RiskAssessor::AssessRisk(option);
        evaluations.push_back({
            {"option", option},
            {"risk_score", risk.value("risk_score", 0.0)},
            {"acceptable", risk.value("acceptable", false)}
        });
    }
    
    return evaluations;
}

void ActionSelector::SetSelectionCriteria(const nlohmann::json& criteria) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    selectionCriteria.update(criteria);
}

nlohmann::json ActionSelector::GetCurrentSelection() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return currentSelection;
}

nlohmann::json ActionSelector::GetSelectionHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return selectionHistory;
}
