// ============================================================================
// HealthMonitor.hpp — System Health Monitoring and Failure Detection
// ============================================================================
// Mission 2.4: Reliability Interface Layer
//
// The HealthMonitor is the detection layer that:
//   - Monitors component health via probes
//   - Detects failures from events or polling
//   - Publishes FailureEvents to the event bus
//   - Tracks health history for trend analysis
//
// This is the bridge between runtime observations and recovery actions.
// ============================================================================

#pragma once

#include "FailureEvent.hpp"
#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Health Status
// ============================================================================
enum class HealthStatus {
    UNKNOWN = 0,
    HEALTHY,
    DEGRADED,
    UNHEALTHY,
    FAILED
};

const char* HealthStatusToString(HealthStatus status);
HealthStatus HealthStatusFromString(const std::string& str);

// ============================================================================
// Health Probe
// ============================================================================
using HealthProbeFunction = std::function<HealthStatus()>;

struct HealthProbe {
    std::string name;
    std::string component;
    HealthProbeFunction probe;
    std::chrono::milliseconds interval{5000};
    std::chrono::milliseconds timeout{1000};
    int failureThreshold = 3;  // Consecutive failures before reporting
    
    HealthStatus lastResult = HealthStatus::UNKNOWN;
    int consecutiveFailures = 0;
    std::chrono::steady_clock::time_point lastCheck;
};

// ============================================================================
// Component Health State
// ============================================================================
struct ComponentHealth {
    std::string componentName;
    HealthStatus status = HealthStatus::UNKNOWN;
    
    std::chrono::steady_clock::time_point lastHealthy;
    std::chrono::steady_clock::time_point lastCheck;
    
    int totalChecks = 0;
    int healthyChecks = 0;
    int consecutiveFailures = 0;
    
    std::string lastError;
    std::vector<std::string> activeProbes;
    
    double availabilityPercent() const;
    bool isResponsive() const;
    nlohmann::json toJson() const;
};

// ============================================================================
// Health Event Callback
// ============================================================================
using HealthEventCallback = std::function<void(const FailureEvent&)>;
using StatusChangeCallback = std::function<void(const std::string& component, 
                                                   HealthStatus oldStatus,
                                                   HealthStatus newStatus)>;

// ============================================================================
// Health Monitor
// ============================================================================
class HealthMonitor {
public:
    static HealthMonitor& instance();
    
    // Lifecycle
    bool initialize();
    void shutdown();
    bool isRunning() const { return m_running.load(); }
    
    // Probe registration
    void registerProbe(const HealthProbe& probe);
    void unregisterProbe(const std::string& name);
    void clearProbes();
    
    // Manual health reporting
    void reportHealthy(const std::string& component, 
                       const std::string& details = "");
    void reportDegraded(const std::string& component,
                        const std::string& reason,
                        const nlohmann::json& context = {});
    void reportUnhealthy(const std::string& component,
                         const FailureEvent& failure);
    
    // Failure event publishing
    void publishFailure(const FailureEvent& event);
    void publishFailure(FailureEventBuilder&& builder);
    
    // Event subscription
    void subscribeToFailures(const FailureFilter& filter,
                            HealthEventCallback callback);
    void subscribeToStatusChanges(StatusChangeCallback callback);
    void unsubscribe(const std::string& subscriptionId);
    
    // Health queries
    HealthStatus getComponentStatus(const std::string& component) const;
    ComponentHealth getComponentHealth(const std::string& component) const;
    std::vector<ComponentHealth> getAllHealth() const;
    std::vector<std::string> getUnhealthyComponents() const;
    
    // Statistics
    struct Statistics {
        uint64_t totalProbesRun = 0;
        uint64_t totalFailuresDetected = 0;
        uint64_t totalEventsPublished = 0;
        std::chrono::steady_clock::time_point startTime;
        
        double averageProbeLatencyMs = 0.0;
        uint64_t maxProbeLatencyMs = 0;
    };
    Statistics getStatistics() const;
    void resetStatistics();
    
    // Configuration
    void setGlobalProbeInterval(std::chrono::milliseconds interval);
    void setFailureDetectionEnabled(bool enabled);

private:
    HealthMonitor() = default;
    ~HealthMonitor() { shutdown(); }
    
    HealthMonitor(const HealthMonitor&) = delete;
    HealthMonitor& operator=(const HealthMonitor&) = delete;
    
    void monitoringLoop();
    void runProbe(HealthProbe& probe);
    void updateComponentHealth(const std::string& component, 
                                HealthStatus status,
                                const std::string& details);
    void notifySubscribers(const FailureEvent& event);
    void notifyStatusChange(const std::string& component,
                           HealthStatus oldStatus,
                           HealthStatus newStatus);
    
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_detectionEnabled{true};
    std::thread m_monitorThread;
    
    mutable std::mutex m_probesMutex;
    std::map<std::string, HealthProbe> m_probes;
    
    mutable std::mutex m_healthMutex;
    std::map<std::string, ComponentHealth> m_componentHealth;
    
    mutable std::mutex m_subscribersMutex;
    std::map<std::string, std::pair<FailureFilter, HealthEventCallback>> m_subscribers;
    std::vector<StatusChangeCallback> m_statusCallbacks;
    
    Statistics m_stats;
    mutable std::mutex m_statsMutex;
    
    std::chrono::milliseconds m_globalInterval{5000};
};

// ============================================================================
// Scoped Health Reporter
// ============================================================================
// RAII helper for reporting health within a scope
class ScopedHealthReporter {
public:
    ScopedHealthReporter(const std::string& component, 
                         const std::string& operation);
    ~ScopedHealthReporter();
    
    void markSuccess();
    void markFailure(const std::string& reason);
    void markDegraded(const std::string& reason);

private:
    std::string m_component;
    std::string m_operation;
    std::chrono::steady_clock::time_point m_startTime;
    bool m_completed = false;
};

// ============================================================================
// Health Check Macros
// ============================================================================
#define RAWR_HEALTH_CHECK(component, expr) \
    do { \
        if (!(expr)) { \
            RawrXD::Reliability::HealthMonitor::instance().publishFailure( \
                RawrXD::Reliability::FailureEventBuilder( \
                    RawrXD::Reliability::FailureCategory::ASSERTION_FAILURE, \
                    RawrXD::Reliability::FailureSeverity::ERROR) \
                    .component(component) \
                    .message("Health check failed: " #expr) \
                    .location(__FILE__, __LINE__) \
                    .build()); \
        } \
    } while(0)

#define RAWR_HEALTH_CHECK_CRITICAL(component, expr) \
    do { \
        if (!(expr)) { \
            RawrXD::Reliability::HealthMonitor::instance().publishFailure( \
                RawrXD::Reliability::FailureEventBuilder( \
                    RawrXD::Reliability::FailureCategory::ASSERTION_FAILURE, \
                    RawrXD::Reliability::FailureSeverity::CRITICAL) \
                    .component(component) \
                    .message("Critical health check failed: " #expr) \
                    .location(__FILE__, __LINE__) \
                    .build()); \
        } \
    } while(0)

} // namespace Reliability
} // namespace RawrXD