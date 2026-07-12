#include "creativity/PatternSynthesizer.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> s_patternLibrary;
static size_t s_synthesisCount = 0;

void PatternSynthesizer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_patternLibrary.clear();
        s_synthesisCount = 0;
        s_initialized = true;
    }
}

void PatternSynthesizer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool PatternSynthesizer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json PatternSynthesizer::SynthesizePattern(const std::vector<nlohmann::json>& observations) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Find common elements across observations
    nlohmann::json synthesized = {
        {"id", "pattern_" + std::to_string(s_patternLibrary.size())},
        {"type", "synthesized"},
        {"observation_count", observations.size()},
        {"synthesized_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"confidence", std::min(1.0, observations.size() / 10.0)}
    };
    
    // Extract common features (simplified)
    if (!observations.empty()) {
        synthesized["features"] = observations[0];
    }
    
    s_patternLibrary.push_back(synthesized);
    s_synthesisCount++;
    
    // Keep library bounded
    if (s_patternLibrary.size() > 500) {
        s_patternLibrary.erase(s_patternLibrary.begin());
    }
    
    return synthesized;
}

nlohmann::json PatternSynthesizer::AbstractPattern(const nlohmann::json& concretePattern) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json abstracted = {
        {"id", "pattern_" + std::to_string(s_patternLibrary.size())},
        {"type", "abstract"},
        {"concrete_source", concretePattern.value("id", "")},
        {"abstracted_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    // Remove specific details to create abstraction
    if (concretePattern.contains("features")) {
        abstracted["general_features"] = concretePattern["features"];
    }
    
    s_patternLibrary.push_back(abstracted);
    return abstracted;
}

nlohmann::json PatternSynthesizer::InstantiatePattern(const nlohmann::json& abstractPattern, const nlohmann::json& context) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json instantiated = {
        {"id", "pattern_" + std::to_string(s_patternLibrary.size())},
        {"type", "instantiated"},
        {"abstract_source", abstractPattern.value("id", "")},
        {"context", context},
        {"instantiated_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
    
    // Apply context to abstract pattern
    if (abstractPattern.contains("general_features")) {
        instantiated["specific_features"] = abstractPattern["general_features"];
    }
    
    return instantiated;
}

void PatternSynthesizer::StorePattern(const nlohmann::json& pattern) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_patternLibrary.push_back(pattern);
    if (s_patternLibrary.size() > 500) {
        s_patternLibrary.erase(s_patternLibrary.begin());
    }
}

nlohmann::json PatternSynthesizer::QueryPatterns(const std::string& criteria) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json results = nlohmann::json::array();
    for (const auto& pattern : s_patternLibrary) {
        std::string patternStr = pattern.dump();
        if (patternStr.find(criteria) != std::string::npos) {
            results.push_back(pattern);
        }
    }
    
    return results;
}

nlohmann::json PatternSynthesizer::GetPatternMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t synthesized = 0, abstract = 0, instantiated = 0;
    for (const auto& pattern : s_patternLibrary) {
        std::string type = pattern.value("type", "");
        if (type == "synthesized") synthesized++;
        else if (type == "abstract") abstract++;
        else if (type == "instantiated") instantiated++;
    }
    
    return {
        {"total_patterns", s_patternLibrary.size()},
        {"synthesized", synthesized},
        {"abstract", abstract},
        {"instantiated", instantiated},
        {"synthesis_count", s_synthesisCount}
    };
}
