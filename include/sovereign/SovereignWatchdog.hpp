#pragma once

#include <cstdint>
#include <atomic>
#include <thread>
#include <functional>
#include "Beaconism.hpp"

namespace Sovereign {

/**
 * @brief Watchdog severity levels
 */
enum class WatchdogSeverity : uint32_t {
    Info = 0,
    Warning = 1,
    Critical = 2,
    Fatal = 3
};

/**
 * @brief Watchdog alert structure
 */
struct WatchdogAlert {
    WatchdogSeverity severity;
    uint64_t timestamp;
    uint32_t subsystemId;
    uint32_t metricValue;
    uint32_t threshold;
    char message[256];
};

/**
 * @brief Watchdog handler function type
 */
using WatchdogHandler = std::function<void(const WatchdogAlert&)>;

/**
 * @brief Sovereign Runtime Watchdog
 * 
 * Monitors runtime health metrics and triggers alerts when thresholds
 * are exceeded. Runs in a dedicated thread with configurable check intervals.
 * 
 * Monitored metrics:
 * - Memory usage (heap, shared memory)
 * - Response latency (RDTSC-based)
 * - Beacon staleness (no updates within threshold)
 * - Subsystem heartbeats
 * - GPU/Vulkan health
 */
class SovereignWatchdog {
public:
    static SovereignWatchdog& Instance();

    /**
     * @brief Initialize the watchdog
     * @param checkIntervalMs Milliseconds between health checks
     */
    void Initialize(uint32_t checkIntervalMs = 1000);

    /**
     * @brief Shutdown the watchdog
     */
    void Shutdown();

    /**
     * @brief Register a handler for watchdog alerts
     */
    void RegisterHandler(WatchdogHandler handler);

    /**
     * @brief Set threshold for a metric
     * @param metricId Metric identifier (0-15)
     * @param threshold Threshold value
     * @param severity Severity when threshold exceeded
     */
    void SetThreshold(uint32_t metricId, uint32_t threshold, WatchdogSeverity severity);

    /**
     * @brief Update a metric value
     * @param metricId Metric identifier
     * @param value Current value
     */
    void UpdateMetric(uint32_t metricId, uint32_t value);

    /**
     * @brief Record a subsystem heartbeat
     * @param subsystemId Subsystem identifier
     */
    void Heartbeat(uint32_t subsystemId);

    /**
     * @brief Check if watchdog is running
     */
    bool IsRunning() const { return m_running; }

    /**
     * @brief Get last alert
     */
    const WatchdogAlert* GetLastAlert() const;

    /**
     * @brief Get alert count
     */
    uint32_t GetAlertCount() const { return m_alertCount; }

    /**
     * @brief Reset alert count
     */
    void ResetAlertCount() { m_alertCount = 0; }

    /**
     * @brief Enable/disable watchdog
     */
    void SetEnabled(bool enabled) { m_enabled = enabled; }

private:
    SovereignWatchdog() = default;
    ~SovereignWatchdog() { Shutdown(); }

    struct Metric {
        uint32_t currentValue;
        uint32_t threshold;
        WatchdogSeverity severity;
        uint64_t lastUpdate;
        bool active;
    };

    struct Subsystem {
        uint64_t lastHeartbeat;
        bool active;
    };

    static constexpr uint32_t MAX_METRICS = 16;
    static constexpr uint32_t MAX_SUBSYSTEMS = 32;
    static constexpr uint64_t HEARTBEAT_TIMEOUT_CYCLES = 10000000000ULL; // ~3s @ 3.3GHz

    std::atomic<bool> m_running{false};
    std::atomic<bool> m_enabled{true};
    std::atomic<uint32_t> m_alertCount{0};
    
    std::thread m_watchdogThread;
    uint32_t m_checkIntervalMs = 1000;
    
    Metric m_metrics[MAX_METRICS]{};
    Subsystem m_subsystems[MAX_SUBSYSTEMS]{};
    
    WatchdogHandler m_handler;
    WatchdogAlert m_lastAlert{};

    void WatchdogLoop();
    void CheckMetrics();
    void CheckHeartbeats();
    void TriggerAlert(const WatchdogAlert& alert);
    uint64_t GetTimestamp();
};

} // namespace Sovereign
