// SystemAwareness.hpp
// Coordination Primitive #7: Self-Awareness Layer
// System knows its own state, health, and limitations

#pragma once
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <optional>

namespace Sovereign {

// System component health
enum class HealthStatus {
    HEALTHY,
    DEGRADED,
    UNHEALTHY,
    CRITICAL,
    UNKNOWN
};

// Component state
struct ComponentState {
    std::string name;
    HealthStatus health;
    std::string version;
    std::chrono::time_point<std::chrono::steady_clock> started;
    uint64_t uptime_ms;
    std::optional<std::string> last_error;
    uint32_t error_count;
    uint32_t warning_count;
    std::map<std::string, std::string> metrics;
};

// System snapshot
struct SystemSnapshot {
    std::chrono::time_point<std::chrono::steady_clock> timestamp;
    std::vector<ComponentState> components;
    uint64_t total_memory_mb;
    uint64_t used_memory_mb;
    uint32_t cpu_percent;
    uint32_t active_agents;
    uint32_t active_terminals;
    uint32_t active_builds;
    HealthStatus overall_health;
};

// Self-awareness monitor
class SystemAwareness {
public:
    static SystemAwareness& Instance();
    
    // Component registration
    void RegisterComponent(const std::string& name, const std::string& version);
    void UpdateComponentHealth(const std::string& name, HealthStatus health);
    void ReportError(const std::string& component, const std::string& error);
    void ReportWarning(const std::string& component, const std::string& warning);
    
    // Queries
    SystemSnapshot GetSnapshot() const;
    HealthStatus GetOverallHealth() const;
    std::optional<ComponentState> GetComponent(const std::string& name) const;
    std::vector<ComponentState> GetUnhealthyComponents() const;
    
    // Self-diagnostics
    bool RunSelfDiagnostics();
    std::vector<std::string> GetDiagnosticResults() const;

private:
    SystemAwareness() = default;
    std::map<std::string, ComponentState> components_;
};

} // namespace Sovereign
