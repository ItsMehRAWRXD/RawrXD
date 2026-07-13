#include "wisdom/ExperienceSynthesizer.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> s_wisdomLibrary;
static size_t s_synthesisCount = 0;

void ExperienceSynthesizer::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_wisdomLibrary.clear();
        s_synthesisCount = 0;
        s_initialized = true;
    }
}

void ExperienceSynthesizer::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool ExperienceSynthesizer::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json ExperienceSynthesizer::SynthesizeExperience(const std::vector<nlohmann::json>& experiences) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    // Find common patterns across experiences
    nlohmann::json synthesis = {
        {"id", "synthesis_" + std::to_string(s_synthesisCount++)},
        {"experience_count", experiences.size()},
        {"synthesized_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"type", "experience_synthesis"}
    };
    
    // Extract common elements
    if (!experiences.empty()) {
        // Count successful vs failed outcomes
        int successCount = 0;
        for (const auto& exp : experiences) {
            if (exp.value("outcome", "") == "success") successCount++;
        }
        
        synthesis["success_rate"] = experiences.empty() ? 0.0 : 
                                     static_cast<double>(successCount) / experiences.size();
        synthesis["key_insight"] = "Pattern observed across " + 
                                   std::to_string(experiences.size()) + " experiences";
    }
    
    return synthesis;
}

nlohmann::json ExperienceSynthesizer::ExtractWisdom(const nlohmann::json& experience) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json wisdom = {
        {"id", "wisdom_" + std::to_string(s_wisdomLibrary.size())},
        {"source_experience", experience.value("id", "")},
        {"extracted_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"applicability", "general"}
    };
    
    // Extract lesson from experience
    std::string outcome = experience.value("outcome", "");
    if (outcome == "success") {
        wisdom["lesson"] = "Approach was effective";
        wisdom["recommendation"] = "Apply similar strategy in comparable contexts";
    } else if (outcome == "failure") {
        wisdom["lesson"] = "Approach had limitations";
        wisdom["recommendation"] = "Consider alternative approaches";
    } else {
        wisdom["lesson"] = "Outcome was mixed";
        wisdom["recommendation"] = "Evaluate context carefully";
    }
    
    s_wisdomLibrary.push_back(wisdom);
    
    // Keep library bounded
    if (s_wisdomLibrary.size() > 500) {
        s_wisdomLibrary.erase(s_wisdomLibrary.begin());
    }
    
    return wisdom;
}

nlohmann::json ExperienceSynthesizer::GeneralizePattern(const nlohmann::json& specificCase) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    return {
        {"id", "pattern_" + std::to_string(s_synthesisCount++)},
        {"specific_source", specificCase.value("id", "")},
        {"generalized_at", std::chrono::system_clock::now().time_since_epoch().count()},
        {"scope", "generalized"},
        {"confidence", 0.7}
    };
}

void ExperienceSynthesizer::StoreWisdom(const nlohmann::json& wisdom) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_wisdomLibrary.push_back(wisdom);
    if (s_wisdomLibrary.size() > 500) {
        s_wisdomLibrary.erase(s_wisdomLibrary.begin());
    }
}

nlohmann::json ExperienceSynthesizer::QueryWisdom(const std::string& context) {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json results = nlohmann::json::array();
    
    for (const auto& wisdom : s_wisdomLibrary) {
        std::string wisdomStr = wisdom.dump();
        if (wisdomStr.find(context) != std::string::npos) {
            results.push_back(wisdom);
        }
    }
    
    return results;
}

nlohmann::json ExperienceSynthesizer::GetWisdomMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return {
        {"wisdom_entries", s_wisdomLibrary.size()},
        {"syntheses_performed", s_synthesisCount}
    };
}
