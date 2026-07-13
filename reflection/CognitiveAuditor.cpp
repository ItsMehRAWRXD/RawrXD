#include "reflection/CognitiveAuditor.hpp"
#include "stability/CoherenceModel.hpp"
#include "consciousness/SelfModel.hpp"
#include <mutex>
#include <vector>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::vector<nlohmann::json> auditHistory;

void CognitiveAuditor::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        auditHistory.clear();
        s_initialized = true;
    }
}

void CognitiveAuditor::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool CognitiveAuditor::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json CognitiveAuditor::AuditCognitiveState() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    auto self = SelfModel::Get();
    double coherence = CoherenceModel::ComputeCoherence(self);
    
    nlohmann::json audit = {
        {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()},
        {"coherence", coherence},
        {"is_coherent", CoherenceModel::IsCoherent(self)},
        {"self_model_size", self.size()}
    };
    
    auditHistory.push_back(audit);
    if (auditHistory.size() > 100) {
        auditHistory.erase(auditHistory.begin());
    }
    
    return audit;
}

nlohmann::json CognitiveAuditor::GetAuditHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return auditHistory;
}

nlohmann::json CognitiveAuditor::FindAnomalies() {
    std::lock_guard<std::mutex> lock(s_mutex);
    nlohmann::json anomalies = nlohmann::json::array();
    
    if (auditHistory.size() < 2) return anomalies;
    
    // Check for coherence drops
    for (size_t i = 1; i < auditHistory.size(); ++i) {
        double prevCoherence = auditHistory[i-1]["coherence"].get<double>();
        double currCoherence = auditHistory[i]["coherence"].get<double>();
        
        if (prevCoherence - currCoherence > 0.3) {
            anomalies.push_back({
                {"type", "coherence_drop"},
                {"timestamp", auditHistory[i]["timestamp"]},
                {"drop", prevCoherence - currCoherence}
            });
        }
    }
    
    return anomalies;
}

nlohmann::json CognitiveAuditor::GetCognitiveHealth() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (auditHistory.empty()) {
        return {{"status", "unknown"}, {"health_score", 0.0}};
    }
    
    auto latest = auditHistory.back();
    double coherence = latest.value("coherence", 0.0);
    
    std::string status = "healthy";
    if (coherence < 0.5) status = "critical";
    else if (coherence < 0.7) status = "degraded";
    
    return {
        {"status", status},
        {"health_score", coherence},
        {"last_audit", latest["timestamp"]}
    };
}
