#include "prediction/OutcomeSimulator.hpp"
#include "causal/CausalGraph.hpp"
#include "intent/IntentModel.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> simulationHistory;

void OutcomeSimulator::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        simulationHistory.clear();
        s_initialized = true;
    }
}

void OutcomeSimulator::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic simulation cleanup
}

bool OutcomeSimulator::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json OutcomeSimulator::SimulateAction(const std::string& action, const nlohmann::json& context) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Simple simulation based on causal graph
    auto edges = CausalGraph::GetEdges();
    
    nlohmann::json outcome = {
        {"action", action},
        {"context", context},
        {"simulated", true},
        {"effects", nlohmann::json::array()}
    };
    
    // Find effects of this action in causal graph
    for (const auto& edge : edges) {
        if (edge.first == action || edge.first.find(action) != std::string::npos) {
            outcome["effects"].push_back(edge.second);
        }
    }
    
    // Check alignment with intent
    auto intent = IntentModel::GetCurrentIntent();
    if (!intent.value("goal", "").empty()) {
        bool aligned = (action.find(intent["goal"].get<std::string>()) != std::string::npos);
        outcome["intent_aligned"] = aligned;
    }
    
    // Store simulation
    simulationHistory.push_back(outcome);
    if (simulationHistory.size() > 100) {
        simulationHistory.erase(simulationHistory.begin());
    }
    
    return outcome;
}

nlohmann::json OutcomeSimulator::SimulateScenario(const nlohmann::json& scenario) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json outcome = {
        {"scenario", scenario},
        {"simulated", true},
        {"projected_state", scenario}
    };
    
    // Add projected changes
    if (scenario.contains("actions")) {
        outcome["projected_changes"] = scenario["actions"].size();
    }
    
    simulationHistory.push_back(outcome);
    if (simulationHistory.size() > 100) {
        simulationHistory.erase(simulationHistory.begin());
    }
    
    return outcome;
}

nlohmann::json OutcomeSimulator::CompareOutcomes(const nlohmann::json& actionA, const nlohmann::json& actionB) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto outcomeA = SimulateAction(actionA.value("action", ""), actionA.value("context", nlohmann::json{}));
    auto outcomeB = SimulateAction(actionB.value("action", ""), actionB.value("context", nlohmann::json{}));
    
    int effectsA = outcomeA.value("effects", nlohmann::json::array()).size();
    int effectsB = outcomeB.value("effects", nlohmann::json::array()).size();
    
    return {
        {"action_a", actionA},
        {"action_b", actionB},
        {"outcome_a_effects", effectsA},
        {"outcome_b_effects", effectsB},
        {"preferred", effectsA > effectsB ? "a" : (effectsB > effectsA ? "b" : "equal")}
    };
}

nlohmann::json OutcomeSimulator::GetSimulationHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return simulationHistory;
}

void OutcomeSimulator::ClearSimulations() {
    std::lock_guard<std::mutex> lock(s_mutex);
    simulationHistory.clear();
}
