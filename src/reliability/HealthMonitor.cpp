// ============================================================================
// HealthMonitor.cpp — Health Monitoring Implementation
// ============================================================================

#include "reliability/HealthMonitor.hpp"
#include <iostream>
#include <sstream>
#include <random>

namespace RawrXD {
namespace Reliability {

// ============================================================================
// Health Status Conversions
// ============================================================================
const char* HealthStatusToString(HealthStatus status) {
    switch (status) {
        case HealthStatus::HEALTHY: return "HEALTHY";
        case HealthStatus::DEGRADED: return "DEGRADED";
        case HealthStatus::UNHEALTHY: return "UNHEALTHY";
        case HealthStatus::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

HealthStatus HealthStatusFromString(const std::string& str) {
    if (str == "HEALTHY") return HealthStatus::HEALTHY;
    if (str == "DEGRADED") return HealthStatus::DEGRADED;
    if (str == "UNHEALTHY") return HealthStatus::UNHEALTHY;
    if (str == "FAILED") return HealthStatus::FAILED;
    return HealthStatus::UNKNOWN;
}

// ============================================================================
// Component Health Implementation
// ============================================================================
double ComponentHealth::availabilityPercent() const {
    if (totalChecks == 0) return 0.0;
    return (static_cast<double>(healthyChecks) / totalChecks) * 100.0;
}

bool ComponentHealth::isResponsive() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastCheck).count();
    return elapsed < 30;  // Consider unresponsive if no check in 30 seconds
}

nlohmann::json ComponentHealth::toJson() const {
    nlohmann::json j;
    j["component_name"] = componentName;
    j["status"] = HealthStatusToString(status);
    j["total_checks"] = totalChecks;
    j["healthy_checks"] = healthyChecks;
    j["consecutive_failures"] = consecutiveFailures;
    j["availability_percent"] = availabilityPercent();
    j["is_responsive"] = isResponsive();
    j["last_error"] = lastError;
    return j;
}

// ============================================================================
// Health Monitor Implementation
// ============================================================================
HealthMonitor& HealthMonitor::instance() {
    static HealthMonitor instance;
    return instance;
}

bool HealthMonitor::initialize() {
    if (m_running.load()) return true;
    
    m_running.store(true);
    m_monitorThread = std::thread(&HealthMonitor::monitoringLoop, this);
    
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.startTime = std::chrono::steady_clock::now();
    }
    
    return true;
}

void HealthMonitor::shutdown() {
    m_running.store(false);
    m_taskCondition.notify_all();
    
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }
}

void HealthMonitor::monitoringLoop() {
    while (m_running.load()) {
        std::unique_lock<std::mutex> lock(m_probesMutex);
        
        // Wait for interval or shutdown
        auto waitResult = m_taskCondition.wait_for(lock, m_globalInterval);
        
        if (!m_running.load()) break;
        if (!m_detectionEnabled.load()) continue;
        
        // Run all probes
        for (auto& pair : m_probes) {
            runProbe(pair.second);
        }
    }
}

void HealthMonitor::runProbe(HealthProbe& probe) {
    auto now = std::chrono::steady_clock::now();
    
    // Check if it's time to run this probe
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - probe.lastCheck);
    if (elapsed < probe.interval) return;
    
    probe.lastCheck = now;
    
    // Execute probe with timeout
    HealthStatus result = HealthStatus::UNKNOWN;
    try {
        // In real implementation, use async with timeout
        result = probe.probe();
    } catch (...) {
        result = HealthStatus::FAILED;
    }
    
    probe.lastResult = result;
    probe.totalChecks++;
    
    // Update consecutive failures
    if (result == HealthStatus::HEALTHY) {
        probe.consecutiveFailures = 0;
    } else {
        probe.consecutiveFailures++;
    }
    
    // Update component health
    updateComponentHealth(probe.component, result, "");
    
    // Check if we should report a failure
    if (probe.consecutiveFailures >= probe.failureThreshold && 
        result != HealthStatus::HEALTHY) {
        FailureEvent event;
        event.category = FailureCategory::SERVICE_UNRESPONSIVE;
        event.severity = FailureSeverity::ERROR;
        event.sourceComponent = probe.component;
        event.message = "Health probe failed " + 
                       std::to_string(probe.consecutiveFailures) + 
                       " consecutive times";
        event.targetResource = probe.name;
        
        publishFailure(event);
    }
    
    // Update statistics
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.totalProbesRun++;
    }
}

void HealthMonitor::updateComponentHealth(const std::string& component,
                                          HealthStatus status,
                                          const std::string& details) {
    std::lock_guard<std::mutex> lock(m_healthMutex);
    
    auto& health = m_componentHealth[component];
    health.componentName = component;
    
    HealthStatus oldStatus = health.status;
    health.status = status;
    health.lastCheck = std::chrono::steady_clock::now();
    health.totalChecks++;
    
    if (status == HealthStatus::HEALTHY) {
        health.healthyChecks++;
        health.consecutiveFailures = 0;
        health.lastHealthy = std::chrono::steady_clock::now();
    } else {
        health.consecutiveFailures++;
        health.lastError = details;
    }
    
    // Notify status change
    if (oldStatus != status) {
        notifyStatusChange(component, oldStatus, status);
    }
}

void HealthMonitor::registerProbe(const HealthProbe& probe) {
    std::lock_guard<std::mutex> lock(m_probesMutex);
    m_probes[probe.name] = probe;
}

void HealthMonitor::unregisterProbe(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_probesMutex);
    m_probes.erase(name);
}

void HealthMonitor::clearProbes() {
    std::lock_guard<std::mutex> lock(m_probesMutex);
    m_probes.clear();
}

void HealthMonitor::reportHealthy(const std::string& component,
                                   const std::string& details) {
    updateComponentHealth(component, HealthStatus::HEALTHY, details);
}

void HealthMonitor::reportDegraded(const std::string& component,
                                   const std::string& reason,
                                   const nlohmann::json& context) {
    updateComponentHealth(component, HealthStatus::DEGRADED, reason);
}

void HealthMonitor::reportUnhealthy(const std::string& component,
                                    const FailureEvent& failure) {
    updateComponentHealth(component, HealthStatus::UNHEALTHY, failure.message);
    publishFailure(failure);
}

void HealthMonitor::publishFailure(const FailureEvent& event) {
    {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        m_stats.totalFailuresDetected++;
        m_stats.totalEventsPublished++;
    }
    
    notifySubscribers(event);
}

void HealthMonitor::publishFailure(FailureEventBuilder&& builder) {
    publishFailure(builder.build());
}

void HealthMonitor::subscribeToFailures(const FailureFilter& filter,
                                        HealthEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_subscribersMutex);
    
    static std::atomic<uint64_t> subId{0};
    std::string id = "sub-" + std::to_string(++subId);
    m_subscribers[id] = {filter, callback};
}

void HealthMonitor::subscribeToStatusChanges(StatusChangeCallback callback) {
    std::lock_guard<std::mutex> lock(m_subscribersMutex);
    m_statusCallbacks.push_back(callback);
}

void HealthMonitor::unsubscribe(const std::string& subscriptionId) {
    std::lock_guard<std::mutex> lock(m_subscribersMutex);
    m_subscribers.erase(subscriptionId);
}

void HealthMonitor::notifySubscribers(const FailureEvent& event) {
    std::lock_guard<std::mutex> lock(m_subscribersMutex);
    
    for (const auto& pair : m_subscribers) {
        const auto& filter = pair.second.first;
        const auto& callback = pair.second.second;
        
        if (filter.matches(event)) {
            callback(event);
        }
    }
}

void HealthMonitor::notifyStatusChange(const std::string& component,
                                       HealthStatus oldStatus,
                                       HealthStatus newStatus) {
    std::lock_guard<std::mutex> lock(m_subscribersMutex);
    
    for (const auto& callback : m_statusCallbacks) {
        callback(component, oldStatus, newStatus);
    }
}

HealthStatus HealthMonitor::getComponentStatus(const std::string& component) const {
    std::lock_guard<std::mutex> lock(m_healthMutex);
    auto it = m_componentHealth.find(component);
    if (it != m_componentHealth.end()) {
        return it->second.status;
    }
    return HealthStatus::UNKNOWN;
}

ComponentHealth HealthMonitor::getComponentHealth(const std::string& component) const {
    std::lock_guard<std::mutex> lock(m_healthMutex);
    auto it = m_componentHealth.find(component);
    if (it != m_componentHealth.end()) {
        return it->second;
    }
    return ComponentHealth{};
}

std::vector<ComponentHealth> HealthMonitor::getAllHealth() const {
    std::lock_guard<std::mutex> lock(m_healthMutex);
    std::vector<ComponentHealth> result;
    for (const auto& pair : m_componentHealth) {
        result.push_back(pair.second);
    }
    return result;
}

std::vector<std::string> HealthMonitor::getUnhealthyComponents() const {
    std::lock_guard<std::mutex> lock(m_healthMutex);
    std::vector<std::string> result;
    for (const auto& pair : m_componentHealth) {
        if (pair.second.status != HealthStatus::HEALTHY) {
            result.push_back(pair.first);
        }
    }
    return result;
}

HealthMonitor::Statistics HealthMonitor::getStatistics() const {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    return m_stats;
}

void HealthMonitor::resetStatistics() {
    std::lock_guard<std::mutex> lock(m_statsMutex);
    m_stats = Statistics{};
    m_stats.startTime = std::chrono::steady_clock::now();
}

void HealthMonitor::setGlobalProbeInterval(std::chrono::milliseconds interval) {
    m_globalInterval = interval;
}

void HealthMonitor::setFailureDetectionEnabled(bool enabled) {
    m_detectionEnabled.store(enabled);
}

// ============================================================================
// Scoped Health Reporter Implementation
// ============================================================================
ScopedHealthReporter::ScopedHealthReporter(const std::string& component,
                                           const std::string& operation)
    : m_component(component)
    , m_operation(operation)
    , m_startTime(std::chrono::steady_clock::now()) {
}

ScopedHealthReporter::~ScopedHealthReporter() {
    if (!m_completed) {
        markFailure("Operation aborted without completion");
    }
}

void ScopedHealthReporter::markSuccess() {
    m_completed = true;
    HealthMonitor::instance().reportHealthy(m_component, 
        m_operation + " completed successfully");
}

void ScopedHealthReporter::markFailure(const std::string& reason) {
    m_completed = true;
    FailureEvent event(FailureCategory::EXCEPTION_THROWN,
                       FailureSeverity::ERROR,
                       m_component,
                       m_operation + " failed: " + reason);
    HealthMonitor::instance().publishFailure(event);
}

void ScopedHealthReporter::markDegraded(const std::string& reason) {
    m_completed = true;
    HealthMonitor::instance().reportDegraded(m_component, reason);
}

} // namespace Reliability
} // namespace RawrXD