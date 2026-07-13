#include "resilience/GracefulDegradation.hpp"
#include <mutex>
#include <map>

static std::mutex s_mutex;
static bool s_initialized = false;
static std::map<std::string, nlohmann::json> s_componentStatus;
static std::map<std::string, nlohmann::json> s_fallbacks;
static size_t s_degradationCount = 0;
static size_t s_fallbackCount = 0;

void GracefulDegradation::Init() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) {
        s_componentStatus.clear();
        s_fallbacks.clear();
        s_degradationCount = 0;
        s_fallbackCount = 0;
        s_initialized = true;
    }
}

void GracefulDegradation::OnTick() {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
}

bool GracefulDegradation::IsAlive() {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_initialized;
}

void GracefulDegradation::TriggerDegradation(const std::string& component, const std::string& level) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_degradationCount++;
    
    s_componentStatus[component] = {
        {"component", component},
        {"status", "degraded"},
        {"degradation_level", level},
        {"degraded_at", std::chrono::system_clock::now().time_since_epoch().count()}
    };
}

void GracefulDegradation::RestoreComponent(const std::string& component) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    auto it = s_componentStatus.find(component);
    if (it != s_componentStatus.end()) {
        it->second["status"] = "restored";
        it->second["restored_at"] = std::chrono::system_clock::now().time_since_epoch().count();
    }
}

nlohmann::json GracefulDegradation::GetDegradationStatus() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    nlohmann::json status = nlohmann::json::object();
    for (const auto& [comp, compStatus] : s_componentStatus) {
        status[comp] = compStatus;
    }
    
    return status;
}

void GracefulDegradation::RegisterFallback(const std::string& component, const nlohmann::json& fallback) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return;
    
    s_fallbacks[component] = fallback;
}

nlohmann::json GracefulDegradation::ExecuteFallback(const std::string& component) {
    std::lock_guard<std::mutex> lock(s_mutex);
    if (!s_initialized) return nlohmann::json{};
    
    s_fallbackCount++;
    
    auto it = s_fallbacks.find(component);
    if (it != s_fallbacks.end()) {
        return {
            {"component", component},
            {"fallback_executed", true},
            {"fallback_type", it->second.value("type", "unknown")},
            {"executed_at", std::chrono::system_clock::now().time_since_epoch().count()}
        };
    }
    
    return {
        {"component", component},
        {"fallback_executed", false},
        {"error", "no_fallback_registered"}
    };
}

nlohmann::json GracefulDegradation::GetDegradationMetrics() {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    size_t degradedCount = 0;
    for (const auto& [comp, status] : s_componentStatus) {
        if (status.value("status", "") == "degraded") {
            degradedCount++;
        }
    }
    
    return {
        {"total_degradations", s_degradationCount},
        {"currently_degraded", degradedCount},
        {"fallbacks_executed", s_fallbackCount},
        {"fallbacks_registered", s_fallbacks.size()}
    };
}
