#include "sovereign/SovereignWatchdog.hpp"
#include "sovereign/Beaconism.hpp"
#include <intrin.h>
#include <cstring>

namespace Sovereign {

SovereignWatchdog& SovereignWatchdog::Instance() {
    static SovereignWatchdog instance;
    return instance;
}

void SovereignWatchdog::Initialize(uint32_t checkIntervalMs) {
    if (m_running) return;

    m_checkIntervalMs = checkIntervalMs;
    
    // Initialize metrics
    for (auto& metric : m_metrics) {
        metric.currentValue = 0;
        metric.threshold = UINT32_MAX;
        metric.severity = WatchdogSeverity::Info;
        metric.lastUpdate = 0;
        metric.active = false;
    }

    // Initialize subsystems
    for (auto& sub : m_subsystems) {
        sub.lastHeartbeat = 0;
        sub.active = false;
    }

    // Set default thresholds
    SetThreshold(0, 85, WatchdogSeverity::Warning);   // Memory usage %
    SetThreshold(1, 100, WatchdogSeverity::Critical); // Latency ms
    SetThreshold(2, 5000, WatchdogSeverity::Warning);   // Beacon queue depth

    m_alertCount = 0;
    m_enabled = true;
    m_running = true;

    // Start watchdog thread
    m_watchdogThread = std::thread(&SovereignWatchdog::WatchdogLoop, this);

    // Emit beacon
    BeaconismEmitter::Instance().Emit(BeaconID::RuntimeStart, 0xBADC0DE); // Watchdog init
}

void SovereignWatchdog::Shutdown() {
    m_running = false;
    if (m_watchdogThread.joinable()) {
        m_watchdogThread.join();
    }
}

void SovereignWatchdog::RegisterHandler(WatchdogHandler handler) {
    m_handler = std::move(handler);
}

void SovereignWatchdog::SetThreshold(uint32_t metricId, uint32_t threshold, WatchdogSeverity severity) {
    if (metricId >= MAX_METRICS) return;
    
    m_metrics[metricId].threshold = threshold;
    m_metrics[metricId].severity = severity;
    m_metrics[metricId].active = true;
}

void SovereignWatchdog::UpdateMetric(uint32_t metricId, uint32_t value) {
    if (metricId >= MAX_METRICS) return;
    
    m_metrics[metricId].currentValue = value;
    m_metrics[metricId].lastUpdate = GetTimestamp();
}

void SovereignWatchdog::Heartbeat(uint32_t subsystemId) {
    if (subsystemId >= MAX_SUBSYSTEMS) return;
    
    m_subsystems[subsystemId].lastHeartbeat = GetTimestamp();
    m_subsystems[subsystemId].active = true;
}

const WatchdogAlert* SovereignWatchdog::GetLastAlert() const {
    return m_alertCount > 0 ? &m_lastAlert : nullptr;
}

void SovereignWatchdog::WatchdogLoop() {
    while (m_running) {
        if (m_enabled) {
            CheckMetrics();
            CheckHeartbeats();
        }
        
        // Sleep with early exit check
        for (uint32_t i = 0; i < m_checkIntervalMs && m_running; i += 100) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void SovereignWatchdog::CheckMetrics() {
    uint64_t now = GetTimestamp();
    
    for (uint32_t i = 0; i < MAX_METRICS; i++) {
        auto& metric = m_metrics[i];
        if (!metric.active) continue;
        
        // Check if threshold exceeded
        if (metric.currentValue > metric.threshold) {
            WatchdogAlert alert{};
            alert.severity = metric.severity;
            alert.timestamp = now;
            alert.subsystemId = i;
            alert.metricValue = metric.currentValue;
            alert.threshold = metric.threshold;
            
            switch (i) {
                case 0: strcpy_s(alert.message, "Memory usage exceeded threshold"); break;
                case 1: strcpy_s(alert.message, "Latency exceeded threshold"); break;
                case 2: strcpy_s(alert.message, "Beacon queue depth exceeded threshold"); break;
                default: strcpy_s(alert.message, "Metric threshold exceeded"); break;
            }
            
            TriggerAlert(alert);
        }
    }
}

void SovereignWatchdog::CheckHeartbeats() {
    uint64_t now = GetTimestamp();
    
    for (uint32_t i = 0; i < MAX_SUBSYSTEMS; i++) {
        auto& sub = m_subsystems[i];
        if (!sub.active) continue;
        
        // Check for heartbeat timeout
        if (now - sub.lastHeartbeat > HEARTBEAT_TIMEOUT_CYCLES) {
            WatchdogAlert alert{};
            alert.severity = WatchdogSeverity::Critical;
            alert.timestamp = now;
            alert.subsystemId = i;
            alert.metricValue = static_cast<uint32_t>(now - sub.lastHeartbeat);
            alert.threshold = static_cast<uint32_t>(HEARTBEAT_TIMEOUT_CYCLES);
            
            strcpy_s(alert.message, "Subsystem heartbeat timeout");
            
            TriggerAlert(alert);
            
            // Mark as inactive to prevent repeated alerts
            sub.active = false;
        }
    }
}

void SovereignWatchdog::TriggerAlert(const WatchdogAlert& alert) {
    m_lastAlert = alert;
    m_alertCount++;
    
    // Call handler if registered
    if (m_handler) {
        m_handler(alert);
    }
    
    // Emit beacon based on severity
    BeaconID beaconId;
    switch (alert.severity) {
        case WatchdogSeverity::Warning:
            beaconId = BeaconID::REPAIR_VULKAN; // Reuse for warning
            break;
        case WatchdogSeverity::Critical:
        case WatchdogSeverity::Fatal:
            beaconId = BeaconID::REPAIR_KV; // Reuse for critical
            break;
        default:
            beaconId = BeaconID::BEACONISM_TEST;
    }
    
    BeaconismEmitter::Instance().Emit(beaconId, alert.subsystemId);
}

uint64_t SovereignWatchdog::GetTimestamp() {
    return __rdtsc();
}

} // namespace Sovereign
