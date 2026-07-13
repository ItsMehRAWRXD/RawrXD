#include "stability/DriftDetector.hpp"
#include <unordered_map>
#include <cmath>

static std::unordered_map<std::string, nlohmann::json> snapshots;
static std::unordered_map<std::string, float> driftThresholds;

void DriftDetector::Init() {
    snapshots.clear();
    driftThresholds.clear();
    driftThresholds["self_model"] = 0.3f;
    driftThresholds["goals"] = 0.5f;
    driftThresholds["beliefs"] = 0.2f;
}

void DriftDetector::RecordSnapshot(const std::string& key, const nlohmann::json& state) {
    snapshots[key] = state;
}

float DriftDetector::ComputeDrift(const std::string& key, const nlohmann::json& current) {
    auto it = snapshots.find(key);
    if (it == snapshots.end()) return 0.0f;
    
    const auto& previous = it->second;
    
    // Simple drift metric: count changed fields
    float drift = 0.0f;
    int totalFields = 0;
    
    for (auto& [k, v] : previous.items()) {
        totalFields++;
        if (!current.contains(k) || current[k] != v) {
            drift += 1.0f;
        }
    }
    
    for (auto& [k, v] : current.items()) {
        if (!previous.contains(k)) {
            totalFields++;
            drift += 1.0f;
        }
    }
    
    return totalFields > 0 ? drift / totalFields : 0.0f;
}

bool DriftDetector::HasDrifted(const std::string& key, const nlohmann::json& current) {
    float drift = ComputeDrift(key, current);
    float threshold = driftThresholds.count(key) ? driftThresholds[key] : 0.5f;
    return drift > threshold;
}

nlohmann::json DriftDetector::GetDriftReport() {
    nlohmann::json report;
    for (auto& [key, snapshot] : snapshots) {
        report[key] = {
            {"threshold", driftThresholds.count(key) ? driftThresholds[key] : 0.5f},
            {"has_drifted", false} // would need current state to compute
        };
    }
    return report;
}
