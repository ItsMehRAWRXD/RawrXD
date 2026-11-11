#include "stability/CoherenceModel.hpp"
#include "consciousness/SelfModel.hpp"
#include <vector>
#include <cmath>

static std::vector<nlohmann::json> incoherences;

void CoherenceModel::Init() {
    incoherences.clear();
}

float CoherenceModel::ComputeCoherence(const nlohmann::json& state) {
    float coherence = 1.0f;
    
    // Check for contradictions in beliefs
    if (state.contains("beliefs") && state["beliefs"].is_array()) {
        auto beliefs = state["beliefs"];
        for (size_t i = 0; i < beliefs.size(); ++i) {
            for (size_t j = i + 1; j < beliefs.size(); ++j) {
                if (beliefs[i].contains("value") && beliefs[j].contains("value")) {
                    if (beliefs[i]["value"] != beliefs[j]["value"]) {
                        coherence *= 0.9f;
                    }
                }
            }
        }
    }
    
    // Check for goal-action alignment
    if (state.contains("goals") && state.contains("actions")) {
        auto goals = state["goals"];
        auto actions = state["actions"];
        // stub: check if actions align with goals
        coherence *= 0.95f;
    }
    
    return coherence;
}

bool CoherenceModel::IsCoherent(const nlohmann::json& state) {
    return ComputeCoherence(state) > 0.7f;
}

nlohmann::json CoherenceModel::GetIncoherences() {
    return nlohmann::json(incoherences);
}
