#include "values/PreferenceModel.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> preferences;

void PreferenceModel::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        preferences.clear();
        // Default preferences
        preferences["safety_threshold"] = 0.8;
        preferences["exploration_tolerance"] = 0.2;
        preferences["communication_style"] = "concise";
        s_initialized = true;
    }
}

void PreferenceModel::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool PreferenceModel::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void PreferenceModel::RegisterPreference(const std::string& key, const nlohmann::json& preference) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    preferences[key] = preference;
}

nlohmann::json PreferenceModel::GetPreference(const std::string& key) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (preferences.count(key)) {
        return preferences[key];
    }
    return nlohmann::json{};
}

nlohmann::json PreferenceModel::GetAllPreferences() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return preferences;
}

nlohmann::json PreferenceModel::InferPreferences(const nlohmann::json& behavior) {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json inferred = nlohmann::json::object();
    
    // Infer preferences from observed behavior
    if (behavior.contains("risk_tolerance")) {
        double risk = behavior["risk_tolerance"].get<double>();
        inferred["safety_threshold"] = 1.0 - risk;
    }
    
    return inferred;
}
