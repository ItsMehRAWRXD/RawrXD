#include "causal/InterventionModel.hpp"
#include <mutex>
#include <vector>

static nlohmann::json lastIntervention;
static std::vector<nlohmann::json> interventionHistory;
static std::mutex s_mutex;
static bool s_initialized = false;

void InterventionModel::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    lastIntervention = nlohmann::json{};
    interventionHistory.clear();
    s_initialized = true;
}

void InterventionModel::Record(const nlohmann::json& intervention) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    lastIntervention = intervention;
    
    // Limit history size
    if (interventionHistory.size() >= 100) {
        interventionHistory.erase(interventionHistory.begin());
    }
    interventionHistory.push_back(intervention);
}

nlohmann::json InterventionModel::GetLast() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return lastIntervention;
}

nlohmann::json InterventionModel::GetHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return interventionHistory;
}

void InterventionModel::Clear() {
    std::lock_guard<std::mutex> lock(s_mutex);
    interventionHistory.clear();
    lastIntervention = nlohmann::json{};
}
