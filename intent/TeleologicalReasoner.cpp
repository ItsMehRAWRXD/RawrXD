#include "intent/TeleologicalReasoner.hpp"
#include "intent/IntentModel.hpp"
#include "causal/CausalGraph.hpp"
#include <mutex>

static std::mutex s_mutex;
static bool s_initialized = false;

void TeleologicalReasoner::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    s_initialized = true;
}

void TeleologicalReasoner::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic teleological analysis
}

bool TeleologicalReasoner::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json TeleologicalReasoner::AnalyzeGoalAlignment(const std::string& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto intent = IntentModel::GetCurrentIntent();
    std::string currentGoal = intent.value("goal", "");
    
    if (currentGoal.empty()) {
        return {
            {"action", action},
            {"aligned", false},
            {"reason", "no_active_intent"}
        };
    }
    
    // Simple alignment check: action contains goal keywords
    bool aligned = action.find(currentGoal) != std::string::npos ||
                   currentGoal.find(action) != std::string::npos;
    
    return {
        {"action", action},
        {"current_goal", currentGoal},
        {"aligned", aligned},
        {"alignment_score", aligned ? 1.0 : 0.0}
    };
}

nlohmann::json TeleologicalReasoner::EvaluateMeansEnd(const nlohmann::json& means, const std::string& end) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    // Check if there's a causal path from means to end
    auto edges = CausalGraph::GetEdges();
    bool connected = false;
    
    for (const auto& edge : edges) {
        if (edge.second == end) {
            connected = true;
            break;
        }
    }
    
    return {
        {"means", means},
        {"end", end},
        {"connected", connected},
        {"efficacy", connected ? 0.8 : 0.2}
    };
}

nlohmann::json TeleologicalReasoner::GetPurposeChain(const std::string& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json chain = nlohmann::json::array();
    chain.push_back(action);
    
    // Build chain of purposes
    auto intent = IntentModel::GetCurrentIntent();
    if (!intent.value("goal", "").empty()) {
        chain.push_back("serves: " + intent["goal"].get<std::string>());
    }
    
    return chain;
}

bool TeleologicalReasoner::IsActionAlignedWithIntent(const std::string& action) {
    auto analysis = AnalyzeGoalAlignment(action);
    return analysis.value("aligned", false);
}

nlohmann::json TeleologicalReasoner::SuggestAlignedActions() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto intent = IntentModel::GetCurrentIntent();
    std::string goal = intent.value("goal", "");
    
    nlohmann::json suggestions = nlohmann::json::array();
    
    if (!goal.empty()) {
        suggestions.push_back("optimize_" + goal);
        suggestions.push_back("validate_" + goal);
        suggestions.push_back("checkpoint_" + goal);
    }
    
    return suggestions;
}
