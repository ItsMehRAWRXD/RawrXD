#include "security/ThreatDetector.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;

struct Threat {
    std::string id;
    std::string type;
    std::string severity;
    nlohmann::json details;
    int64_t detectedAt;
    bool resolved;
    int64_t resolvedAt;
};

static std::map<std::string, Threat> s_threats;
static std::vector<std::string> s_threatHistory;
static size_t s_threatCounter = 0;

static std::string GenerateThreatId() {
    s_threatCounter++;
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return "threat-" + std::to_string(now) + "-" + std::to_string(s_threatCounter);
}

void ThreatDetector::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_threats.clear();
        s_threatHistory.clear();
        s_threatCounter = 0;
        s_initialized = true;
    }
}

void ThreatDetector::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Auto-detect threats based on patterns
    // In a real implementation, this would analyze system behavior
}

bool ThreatDetector::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json ThreatDetector::DetectThreats() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    nlohmann::json threats = nlohmann::json::array();
    int threatCount = 0;
    
    for (const auto& [id, threat] : s_threats) {
        if (!threat.resolved) {
            threats.push_back({
                {"id", threat.id},
                {"type", threat.type},
                {"severity", threat.severity},
                {"detected_at", threat.detectedAt}
            });
            threatCount++;
        }
    }
    
    return {
        {"threats_detected", threatCount},
        {"threats", threats},
        {"system_secure", threatCount == 0}
    };
}

nlohmann::json ThreatDetector::AnalyzeAnomaly(const nlohmann::json& event) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    std::string eventType = event.value("type", "unknown");
    double anomalyScore = event.value("anomaly_score", 0.0);
    
    std::string severity = "low";
    if (anomalyScore > 0.8) severity = "critical";
    else if (anomalyScore > 0.6) severity = "high";
    else if (anomalyScore > 0.4) severity = "medium";
    
    return {
        {"event_type", eventType},
        {"anomaly_score", anomalyScore},
        {"severity", severity},
        {"requires_investigation", anomalyScore > 0.5}
    };
}

bool ThreatDetector::IsThreatDetected(const std::string& threatId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_threats.find(threatId);
    return it != s_threats.end() && !it->second.resolved;
}

void ThreatDetector::ReportThreat(const std::string& type, const std::string& severity, const nlohmann::json& details) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    Threat threat;
    threat.id = GenerateThreatId();
    threat.type = type;
    threat.severity = severity;
    threat.details = details;
    threat.detectedAt = std::chrono::system_clock::now().time_since_epoch().count();
    threat.resolved = false;
    
    s_threats[threat.id] = threat;
    s_threatHistory.push_back(threat.id);
    
    // Keep history bounded
    if (s_threatHistory.size() > 500) {
        s_threatHistory.erase(s_threatHistory.begin(), s_threatHistory.begin() + 100);
    }
}

void ThreatDetector::ResolveThreat(const std::string& threatId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_threats.find(threatId);
    if (it != s_threats.end()) {
        it->second.resolved = true;
        it->second.resolvedAt = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

nlohmann::json ThreatDetector::GetActiveThreats() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& [id, threat] : s_threats) {
        if (!threat.resolved) {
            result.push_back({
                {"id", threat.id},
                {"type", threat.type},
                {"severity", threat.severity},
                {"detected_at", threat.detectedAt}
            });
        }
    }
    return result;
}

nlohmann::json ThreatDetector::GetThreatHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json result = nlohmann::json::array();
    for (const auto& id : s_threatHistory) {
        auto it = s_threats.find(id);
        if (it != s_threats.end()) {
            result.push_back({
                {"id", it->second.id},
                {"type", it->second.type},
                {"severity", it->second.severity},
                {"resolved", it->second.resolved}
            });
        }
    }
    return result;
}

nlohmann::json ThreatDetector::GetSecurityMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t activeCount = 0;
    size_t criticalCount = 0;
    size_t highCount = 0;
    size_t resolvedCount = 0;
    
    for (const auto& [id, threat] : s_threats) {
        if (!threat.resolved) {
            activeCount++;
            if (threat.severity == "critical") criticalCount++;
            else if (threat.severity == "high") highCount++;
        } else {
            resolvedCount++;
        }
    }
    
    return {
        {"total_threats", s_threats.size()},
        {"active_threats", activeCount},
        {"critical_threats", criticalCount},
        {"high_threats", highCount},
        {"resolved_threats", resolvedCount},
        {"security_score", activeCount == 0 ? 100.0 : (100.0 - (activeCount * 5.0))}
    };
}
