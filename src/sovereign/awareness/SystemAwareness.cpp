// SystemAwareness.cpp
// Implementation of the Self-Awareness Layer

#include "SystemAwareness.hpp"
#include <algorithm>

namespace Sovereign {

SystemAwareness& SystemAwareness::Instance() {
    static SystemAwareness instance;
    return instance;
}

void SystemAwareness::RegisterComponent(const std::string& name, const std::string& version) {
    ComponentState state;
    state.name = name;
    state.version = version;
    state.health = HealthStatus::HEALTHY;
    state.started = std::chrono::steady_clock::now();
    state.uptime_ms = 0;
    state.error_count = 0;
    state.warning_count = 0;
    components_[name] = state;
}

void SystemAwareness::UpdateComponentHealth(const std::string& name, HealthStatus health) {
    auto it = components_.find(name);
    if (it != components_.end()) {
        it->second.health = health;
    }
}

void SystemAwareness::ReportError(const std::string& component, const std::string& error) {
    auto it = components_.find(component);
    if (it != components_.end()) {
        it->second.last_error = error;
        it->second.error_count++;
        it->second.health = HealthStatus::DEGRADED;
    }
}

void SystemAwareness::ReportWarning(const std::string& component, const std::string& warning) {
    auto it = components_.find(component);
    if (it != components_.end()) {
        it->second.warning_count++;
    }
}

SystemSnapshot SystemAwareness::GetSnapshot() const {
    SystemSnapshot snapshot;
    snapshot.timestamp = std::chrono::steady_clock::now();
    snapshot.overall_health = GetOverallHealth();
    snapshot.total_memory_mb = 0;
    snapshot.used_memory_mb = 0;
    snapshot.cpu_percent = 0;
    snapshot.active_agents = 0;
    snapshot.active_terminals = 0;
    snapshot.active_builds = 0;
    
    for (const auto& [name, comp] : components_) {
        snapshot.components.push_back(comp);
    }
    
    return snapshot;
}

HealthStatus SystemAwareness::GetOverallHealth() const {
    bool has_critical = false;
    bool has_unhealthy = false;
    bool has_degraded = false;
    
    for (const auto& [name, comp] : components_) {
        switch (comp.health) {
            case HealthStatus::CRITICAL:
                has_critical = true;
                break;
            case HealthStatus::UNHEALTHY:
                has_unhealthy = true;
                break;
            case HealthStatus::DEGRADED:
                has_degraded = true;
                break;
            default:
                break;
        }
    }
    
    if (has_critical) return HealthStatus::CRITICAL;
    if (has_unhealthy) return HealthStatus::UNHEALTHY;
    if (has_degraded) return HealthStatus::DEGRADED;
    if (components_.empty()) return HealthStatus::UNKNOWN;
    return HealthStatus::HEALTHY;
}

std::optional<ComponentState> SystemAwareness::GetComponent(const std::string& name) const {
    auto it = components_.find(name);
    if (it != components_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ComponentState> SystemAwareness::GetUnhealthyComponents() const {
    std::vector<ComponentState> unhealthy;
    for (const auto& [name, comp] : components_) {
        if (comp.health != HealthStatus::HEALTHY) {
            unhealthy.push_back(comp);
        }
    }
    return unhealthy;
}

bool SystemAwareness::RunSelfDiagnostics() {
    return GetOverallHealth() != HealthStatus::CRITICAL;
}

std::vector<std::string> SystemAwareness::GetDiagnosticResults() const {
    std::vector<std::string> results;
    for (const auto& [name, comp] : components_) {
        if (comp.last_error.has_value()) {
            results.push_back(name + ": " + comp.last_error.value());
        }
    }
    return results;
}

} // namespace Sovereign
