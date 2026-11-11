#include "values/ValueLearner.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static nlohmann::json learnedValues;
static std::map<std::string, double> valueWeights;

void ValueLearner::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        learnedValues = {
            {"safety", 0.9},
            {"efficiency", 0.7},
            {"alignment", 0.8},
            {"transparency", 0.6}
        };
        valueWeights = {
            {"safety", 1.0},
            {"efficiency", 0.8},
            {"alignment", 0.9},
            {"transparency", 0.7}
        };
        s_initialized = true;
    }
}

void ValueLearner::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic value model refinement
}

bool ValueLearner::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void ValueLearner::ObservePreference(const nlohmann::json& observation) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update values based on observed preferences
    if (observation.contains("preferred_outcome")) {
        std::string outcome = observation["preferred_outcome"].get<std::string>();
        if (outcome == "safe") {
            learnedValues["safety"] = std::min(1.0, learnedValues["safety"].get<double>() + 0.01);
        } else if (outcome == "efficient") {
            learnedValues["efficiency"] = std::min(1.0, learnedValues["efficiency"].get<double>() + 0.01);
        }
    }
}

nlohmann::json ValueLearner::GetLearnedValues() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return learnedValues;
}

double ValueLearner::GetValueAlignment(const std::string& action) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return 0.0;
    
    // Calculate alignment score based on action properties
    double score = 0.0;
    double totalWeight = 0.0;
    
    for (const auto& [value, weight] : valueWeights) {
        if (action.find(value) != std::string::npos) {
            score += weight * learnedValues[value].get<double>();
        }
        totalWeight += weight;
    }
    
    return totalWeight > 0 ? score / totalWeight : 0.0;
}

void ValueLearner::UpdateValueModel(const nlohmann::json& feedback) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Adjust values based on feedback
    if (feedback.contains("value_updates")) {
        for (const auto& [key, val] : feedback["value_updates"].items()) {
            if (learnedValues.contains(key)) {
                double current = learnedValues[key].get<double>();
                double update = val.get<double>();
                learnedValues[key] = std::max(0.0, std::min(1.0, current + update));
            }
        }
    }
}

nlohmann::json ValueLearner::GetValueModel() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"values", learnedValues},
        {"weights", valueWeights}
    };
}
