#include "reflection/BeliefAnalyzer.hpp"
#include "consciousness/SelfModel.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, double> beliefConfidence;

void BeliefAnalyzer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        beliefConfidence.clear();
        // Initialize with core beliefs
        beliefConfidence["self_awareness"] = 0.9;
        beliefConfidence["continuity"] = 0.8;
        beliefConfidence["causal_understanding"] = 0.7;
        s_initialized = true;
    }
}

void BeliefAnalyzer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    // Periodic belief analysis
}

bool BeliefAnalyzer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json BeliefAnalyzer::AnalyzeBeliefs() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json analysis = {
        {"total_beliefs", beliefConfidence.size()},
        {"beliefs", nlohmann::json::object()},
        {"average_confidence", 0.0}
    };
    
    double totalConfidence = 0.0;
    for (const auto& [belief, confidence] : beliefConfidence) {
        analysis["beliefs"][belief] = confidence;
        totalConfidence += confidence;
    }
    
    if (!beliefConfidence.empty()) {
        analysis["average_confidence"] = totalConfidence / beliefConfidence.size();
    }
    
    return analysis;
}

nlohmann::json BeliefAnalyzer::GetBeliefConfidence(const std::string& belief) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (beliefConfidence.count(belief)) {
        return {{"belief", belief}, {"confidence", beliefConfidence[belief]}};
    }
    return {{"belief", belief}, {"confidence", 0.0}, {"status", "unknown"}};
}

nlohmann::json BeliefAnalyzer::FindBeliefContradictions() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json contradictions = nlohmann::json::array();
    
    // Check for low-confidence beliefs that contradict high-confidence ones
    for (const auto& [belief1, conf1] : beliefConfidence) {
        for (const auto& [belief2, conf2] : beliefConfidence) {
            if (belief1 != belief2 && conf1 > 0.8 && conf2 < 0.3) {
                // Potential contradiction detected
                if (belief1.find("stable") != std::string::npos && 
                    belief2.find("unstable") != std::string::npos) {
                    contradictions.push_back({
                        {"belief_high_confidence", belief1},
                        {"belief_low_confidence", belief2},
                        {"confidence_gap", conf1 - conf2}
                    });
                }
            }
        }
    }
    
    return contradictions;
}

void BeliefAnalyzer::UpdateBeliefConfidence(const std::string& belief, double confidence) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    beliefConfidence[belief] = std::max(0.0, std::min(1.0, confidence));
}

nlohmann::json BeliefAnalyzer::GetBeliefMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t highConfidence = 0, lowConfidence = 0;
    for (const auto& [belief, confidence] : beliefConfidence) {
        if (confidence > 0.7) highConfidence++;
        else if (confidence < 0.3) lowConfidence++;
    }
    
    return {
        {"total_beliefs", beliefConfidence.size()},
        {"high_confidence_beliefs", highConfidence},
        {"low_confidence_beliefs", lowConfidence},
        {"uncertain_beliefs", beliefConfidence.size() - highConfidence - lowConfidence}
    };
}
