#include "emergence/ContradictionDetector.hpp"
#include <vector>

static std::vector<nlohmann::json> beliefs;

void ContradictionDetector::Init() {
    beliefs.clear();
}

bool ContradictionDetector::Detect(const nlohmann::json& beliefA, 
                                    const nlohmann::json& beliefB) {
    // stub: detect contradictions between beliefs
    if (beliefA.contains("value") && beliefB.contains("value")) {
        return beliefA["value"] != beliefB["value"];
    }
    return false;
}

std::vector<std::pair<nlohmann::json, nlohmann::json>> ContradictionDetector::FindAll() {
    std::vector<std::pair<nlohmann::json, nlohmann::json>> contradictions;
    
    for (size_t i = 0; i < beliefs.size(); ++i) {
        for (size_t j = i + 1; j < beliefs.size(); ++j) {
            if (Detect(beliefs[i], beliefs[j])) {
                contradictions.push_back({beliefs[i], beliefs[j]});
            }
        }
    }
    
    return contradictions;
}
