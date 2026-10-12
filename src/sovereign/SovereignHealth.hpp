// ============================================================================
// SovereignHealth.hpp — Sovereign runtime health monitoring
// ============================================================================
#pragma once

#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <cstdint>

namespace rawrxd {

// ---------------------------------------------------------------------------
// Health status enum
// ---------------------------------------------------------------------------
enum class SovereignHealthStatus : uint8_t {
    Healthy      = 0,  // All systems nominal
    Degraded     = 1,  // Minor issues, operational
    Critical     = 2,  // Major issues, intervention needed
    Emergency    = 3,  // Critical failure, immediate action required
    Unknown      = 255 // Status unknown
};

// ---------------------------------------------------------------------------
// Component health detail
// ---------------------------------------------------------------------------
struct SovereignComponentHealth {
    std::string name;
    std::string status;       // "healthy", "degraded", "critical", "unknown"
    std::string message;      // Human-readable description
    uint64_t lastUpdateNs = 0;
    double temperatureC = 0.0;
    double utilizationPct = 0.0;
    uint64_t errorCount = 0;
    uint64_t warningCount = 0;
    std::string details;
};

// ---------------------------------------------------------------------------
// SovereignHealth aggregate
// ---------------------------------------------------------------------------
struct SovereignHealth {
    SovereignHealthStatus overall = SovereignHealthStatus::Unknown;
    std::vector<SovereignComponentHealth> components;
    uint64_t timestampNs = 0;
    uint64_t uptimeNs = 0;
    uint64_t totalErrors = 0;
    uint64_t totalWarnings = 0;
    double cpuUsagePct = 0.0;
    double gpuUsagePct = 0.0;
    double memoryUsagePct = 0.0;
    double temperatureC = 0.0;
    uint64_t totalErrors = 0;
    uint64_t totalWarnings = 0;
    bool isHealthy() const { return overall == SovereignHealthStatus::Healthy; }
    bool isCritical() const { return overall >= SovereignHealthStatus::Critical; }
};

// ---------------------------------------------------------------------------
// SovereignHealthMonitor - centralized health monitoring
// ---------------------------------------------------------------------------
class SovereignHealthMonitor {
public:
    explicit SovereignHealthMonitor();
    ~SovereignHealthMonitor();

    // Component registration
    void registerComponent(const std::string& name);
    void unregisterComponent(const std::string& name);

    // Health updates
    void reportComponentHealth(const std::string& name, const std::string& status, 
                               const std::string& message = "");
    void reportMetric(const std::string& name, double value, const std::string& unit = "");
    void reportError(const std::string& component, const std::string& message);
    void reportWarning(const std::string& component, const std::string& message);

    // Health queries
    SovereignHealth getHealth() const;
    bool isHealthy() const;
    bool isCritical() const;
    std::string getOverallStatus() const;

    // Component queries
    bool hasComponent(const std::string& name) const;
    std::string getComponentStatus(const std::string& name) const;

    // Configuration
    void setCriticalThreshold(double threshold);
    void setWarningThreshold(double threshold);
    void setHealthCheckIntervalMs(uint32_t ms);

    // Lifecycle
    void startMonitoring();
    void stopMonitoring();
    bool isRunning() const;

private:
    struct ComponentState {
        std::string name;
        std::string status;
        std::string message;
        std::chrono::steady_clock::time_point lastUpdate;
        uint64_t errorCount = 0;
        uint64_t warningCount = 0;
        double lastMetricValue = 0.0;
    };

    std::unordered_map<std::string, ComponentState> m_components;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_shutdown{false};
    std::thread m_monitorThread;
    std::mutex m_mutex;
    std::chrono::milliseconds m_checkInterval{5000};
    double m_criticalThreshold = 0.9;
    double m_warningThreshold = 0.7;

    void monitoringLoop();
    void evaluateHealth();
};

} // namespace rawrxd

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------
namespace rawrxd {
inline SovereignHealthStatus stringToHealthStatus(const std::string& status) {
    if (status == "healthy") return SovereignHealthStatus::Healthy;
    if (status == "degraded") return SovereignHealthStatus::Degraded;
    if (status == "critical") return SovereignHealthStatus::Critical;
    if (status == "emergency") return SovereignHealthStatus::Emergency;
    return SovereignHealthStatus::Unknown;
}

inline std::string healthStatusToString(SovereignHealthStatus status) {
    switch (status) {
        case SovereignHealthStatus::Healthy: return "healthy";
        case SovereignHealthStatus::Degraded: return "degraded";
        case SovereignHealthStatus::Critical: return "critical";
        case SovereignHealthStatus::Emergency: return "emergency";
        default: return "unknown";
    }
}

} // namespace rawrxd