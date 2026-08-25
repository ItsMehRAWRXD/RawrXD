// ============================================================================
// PlasmaGovernor.hpp — Thermal-Aware Scheduler for R9700 (RDNA4)
// The plasma-facing components: monitors junction temp, throttles before meltdown
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <chrono>

namespace rawrxd {

// ============================================================================
// ThermalState — Real-time GPU thermal telemetry
// ============================================================================
struct ThermalState {
    float junction_temp_c = 0.0f;      // GPU die temperature (°C)
    float memory_temp_c = 0.0f;       // VRAM temperature (°C)
    float hotspot_temp_c = 0.0f;      // Hottest spot on die (°C)
    float power_watts = 0.0f;         // Current power draw
    float fan_rpm = 0.0f;             // Fan speed
    float throttle_percent = 0.0f;    // 0-100, how much GPU is throttling
    uint64_t timestamp_us = 0;        // Microsecond timestamp
};

// ============================================================================
// PlasmaGovernor — Thermal-aware inference scheduler
// Prevents the tokamak from melting by throttling token generation
// ============================================================================
class PlasmaGovernor {
public:
    // Thermal thresholds (conservative for R9700 RDNA4)
    static constexpr float TEMP_WARNING = 85.0f;   // Start throttling
    static constexpr float TEMP_CRITICAL = 95.0f;  // Aggressive throttling
    static constexpr float TEMP_EMERGENCY = 105.0f; // Emergency stop

    // Throttle curves
    static constexpr float THROTTLE_MIN = 0.0f;      // No throttling
    static constexpr float THROTTLE_MAX = 0.95f;   // 95% throttle (barely moving)

    PlasmaGovernor();
    ~PlasmaGovernor() = default;

    // ------------------------------------------------------------------------
    // Update thermal state (called from telemetry thread)
    // ------------------------------------------------------------------------
    void updateThermalState(const ThermalState& state);

    // ------------------------------------------------------------------------
    // Query current throttle level (0.0 = full speed, 1.0 = stopped)
    // ------------------------------------------------------------------------
    float currentThrottle() const;

    // ------------------------------------------------------------------------
    // Should we inject a cooling pause between tokens?
    // ------------------------------------------------------------------------
    bool needsCoolingPause() const;
    uint32_t coolingPauseMicros() const;

    // ------------------------------------------------------------------------
    // Should we evict cold weights to reduce VRAM thermal load?
    // ------------------------------------------------------------------------
    bool shouldEvictForThermal() const;
    float evictionPressure() const;  // 0.0-1.0, how aggressive to evict

    // ------------------------------------------------------------------------
    // Adaptive batch size: reduce tokens per batch as temperature rises
    // ------------------------------------------------------------------------
    size_t adaptiveBatchSize(size_t requested) const;

    // ------------------------------------------------------------------------
    // Telemetry
    // ------------------------------------------------------------------------
    ThermalState lastState() const;
    float averageTempOverWindow(size_t seconds) const;
    float peakTempRecorded() const { return peak_temp_.load(std::memory_order_relaxed); }

    // ------------------------------------------------------------------------
    // Emergency stop
    // ------------------------------------------------------------------------
    bool isEmergencyStopped() const { return emergency_stop_.load(std::memory_order_relaxed); }
    void resetEmergencyStop() { emergency_stop_.store(false, std::memory_order_relaxed); }

private:
    std::atomic<float> current_throttle_{0.0f};
    std::atomic<float> peak_temp_{0.0f};
    std::atomic<bool> emergency_stop_{false};
    std::atomic<uint64_t> last_update_us_{0};

    // Simple moving average window (circular buffer)
    static constexpr size_t TEMP_HISTORY_SIZE = 60;  // 60 seconds
    float temp_history_[TEMP_HISTORY_SIZE];
    size_t history_index_ = 0;
    size_t history_count_ = 0;

    float calculateThrottle(float temp) const;
};

} // namespace rawrxd
