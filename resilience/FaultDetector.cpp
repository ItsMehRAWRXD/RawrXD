#include "resilience/FaultDetector.hpp"
#include <mutex>
#include <map>
#include <chrono>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_componentHealth;
static std::vector<nlohmann::json> s_faultHistory;
static size_t s_detectionCount = 0;

void FaultDetector::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_componentHealth.clear();
        s_faultHistory.clear();
        s_detectionCount = 0;
        
        // Initialize health monitoring for all layers
        std::vector<std::string> components = {
            "fabric", "distributed", "adaptive", "cognition", "consciousness",
            "autonomy", "emergence", "metastability", "identity", "temporal",
            "causal", "intent", "prediction", "learning", "executive",
            "values", "reflection", "communication", "social", "creativity",
            "ethics", "wisdom", "metacognition", "mastery", "quantum"
        };
        
        for (const auto& comp : components) {
            s_componentHealth[comp] = {
                {"component", comp},
                {"status", "healthy"},
                {"last_check", std::chrono::system_clock::now().time_since_epoch().count()},
                {"consecutive_failures", 0}
            };
        }
        
        s_initialized = true;
    }
}

void FaultDetector::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    // Periodic health checks
    for (auto& [comp, health] : s_componentHealth) {
        health["last_check"] = std::chrono::system_clock::now().time_since_epoch().count();
        // In a real implementation, this would perform actual health checks
    }
}

bool FaultDetector::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

nlohmann::json FaultDetector::DetectFaults() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_detectionCount++;
    
    nlohmann::json faults = nlohmann::json::array();
    int faultCount = 0;
    
    // Check each component
    for (const auto& [comp, health] : s_componentHealth) {
        int failures = health.value("consecutive_failures", 0);
        if (failures > 3) {
            nlohmann::json fault = {
                {"component", comp},
                {"severity", failures > 5 ? "critical" : "warning"},
                {"consecutive_failures", failures},
                {"detected_at", std::chrono::system_clock::now().time_since_epoch().count()}
            };
            faults.push_back(fault);
            faultCount++;
            s_faultHistory.push_back(fault);
        }
    }
    
    // Keep history bounded
    if (s_faultHistory.size() > 500) {
        s_faultHistory.erase(s_faultHistory.begin(), s_faultHistory.begin() + 100);
    }
    
    return {
        {"faults_detected", faultCount},
        {"faults", faults},
        {"system_healthy", faultCount == 0},
        {"checked_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

nlohmann::json FaultDetector::AnalyzeFailurePattern(const nlohmann::json& failure) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    std::string component = failure.value("component", "unknown");
    std::string errorType = failure.value("error_type", "unknown");
    
    // Analyze pattern
    int similarFailures = 0;
    for (const auto& fault : s_faultHistory) {
        if (fault.value("component", "") == component &&
            fault.value("error_type", "") == errorType) {
            similarFailures++;
        }
    }
    
    return {
        {"component", component},
        {"error_type", errorType},
        {"similar_failures", similarFailures},
        {"pattern", similarFailures > 3 ? "recurring" : "isolated"},
        {"recommendation", similarFailures > 3 ? "investigate_root_cause" : "monitor"}
    };
}

bool FaultDetector::IsComponentHealthy(const std::string& componentId) {
    std::lock_guard<std::mutex> lock(s_mutex);
    auto it = s_componentHealth.find(componentId);
    if (it != s_componentHealth.end()) {
        return it->second.value("status", "") == "healthy";
    }
    return false;
}

nlohmann::json FaultDetector::GetFaultMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t healthyCount = 0;
    size_t degradedCount = 0;
    size_t criticalCount = 0;
    
    for (const auto& [comp, health] : s_componentHealth) {
        std::string status = health.value("status", "");
        if (status == "healthy") healthyCount++;
        else if (status == "degraded") degradedCount++;
        else if (status == "critical") criticalCount++;
    }
    
    return {
        {"total_components", s_componentHealth.size()},
        {"healthy", healthyCount},
        {"degraded", degradedCount},
        {"critical", criticalCount},
        {"detections_performed", s_detectionCount},
        {"fault_history_size", s_faultHistory.size()}
    };
}

nlohmann::json FaultDetector::GetFaultHistory() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_faultHistory;
}
