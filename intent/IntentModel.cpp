#include "intent/IntentModel.hpp"
#include <mutex>
#include <vector>
#include <chrono>

static nlohmann::json currentIntent;
static std::vector<nlohmann::json> intentHistory;
static std::mutex s_mutex;
static bool s_initialized = false;

void IntentModel::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        currentIntent = {
            {"goal", ""},
            {"parameters", nlohmann::json::object()},
            {"status", "idle"},
            {"progress", 0.0},
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count()}
        };
        intentHistory.clear();
        s_initialized = true;
    }
}

void IntentModel::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Update intent progress based on some metric
    if (currentIntent["status"] == "active") {
        double progress = currentIntent.value("progress", 0.0);
        progress = std::min(1.0, progress + 0.01); // Increment progress
        currentIntent["progress"] = progress;
        
        if (progress >= 1.0) {
            currentIntent["status"] = "completed";
            intentHistory.push_back(currentIntent);
            
            // Limit history
            if (intentHistory.size() > 100) {
                intentHistory.erase(intentHistory.begin());
            }
        }
    }
}

bool IntentModel::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json IntentModel::GetCurrentIntent() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return currentIntent;
}

void IntentModel::SetIntent(const std::string& goal, const nlohmann::json& parameters) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Archive previous intent if active
    if (currentIntent["status"] == "active") {
        currentIntent["status"] = "interrupted";
        intentHistory.push_back(currentIntent);
    }
    
    currentIntent = {
        {"goal", goal},
        {"parameters", parameters},
        {"status", "active"},
        {"progress", 0.0},
        {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()}
    };
}

void IntentModel::ClearIntent() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    if (currentIntent["status"] == "active") {
        currentIntent["status"] = "cancelled";
        intentHistory.push_back(currentIntent);
    }
    
    currentIntent["goal"] = "";
    currentIntent["parameters"] = nlohmann::json::object();
    currentIntent["status"] = "idle";
    currentIntent["progress"] = 0.0;
}

bool IntentModel::HasActiveIntent() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized && currentIntent["status"] == "active";
}

double IntentModel::GetIntentProgress() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return currentIntent.value("progress", 0.0);
}

nlohmann::json IntentModel::GetIntentHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return intentHistory;
}

std::string IntentModel::GetIntentStatus() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return currentIntent.value("status", "unknown");
}
