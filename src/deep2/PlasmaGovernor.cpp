// ============================================================================
// PlasmaGovernor.cpp — Thermal-Aware Scheduler for R9700
// Prevents the tokamak from melting
// ============================================================================

#include "PlasmaGovernor.hpp"
#include <cmath>
#include <algorithm>

namespace rawrxd {

PlasmaGovernor::PlasmaGovernor() {
    std::fill(temp_history_, temp_history_ + TEMP_HISTORY_SIZE, 0.0f);
}

void PlasmaGovernor::updateThermalState(const ThermalState& state) {
    last_update_us_.store(state.timestamp_us, std::memory_order_relaxed);

    // Update peak
    float current_peak = peak_temp_.load(std::memory_order_relaxed);
    if (state.junction_temp_c > current_peak) {
        peak_temp_.store(state.junction_temp_c, std::memory_order_relaxed);
    }

    // Update history
    temp_history_[history_index_] = state.junction_temp_c;
    history_index_ = (history_index_ + 1) % TEMP_HISTORY_SIZE;
    if (history_count_ < TEMP_HISTORY_SIZE) ++history_count_;

    // Calculate throttle
    float throttle = calculateThrottle(state.junction_temp_c);
    current_throttle_.store(throttle, std::memory_order_relaxed);

    // Emergency stop check
    if (state.junction_temp_c >= TEMP_EMERGENCY) {
        emergency_stop_.store(true, std::memory_order_relaxed);
    }
}

float PlasmaGovernor::currentThrottle() const {
    return current_throttle_.load(std::memory_order_relaxed);
}

bool PlasmaGovernor::needsCoolingPause() const {
    return currentThrottle() > 0.5f;
}

uint32_t PlasmaGovernor::coolingPauseMicros() const {
    float throttle = currentThrottle();
    if (throttle <= 0.0f) return 0;
    // Linear ramp: 0% throttle = 0us, 95% throttle = 5000us (5ms)
    return static_cast<uint32_t>(throttle * 5000.0f);
}

bool PlasmaGovernor::shouldEvictForThermal() const {
    return currentThrottle() > 0.3f;
}

float PlasmaGovernor::evictionPressure() const {
    float throttle = currentThrottle();
    if (throttle <= 0.3f) return 0.0f;
    // Map 0.3-0.95 → 0.0-1.0
    return std::min(1.0f, (throttle - 0.3f) / 0.65f);
}

size_t PlasmaGovernor::adaptiveBatchSize(size_t requested) const {
    float throttle = currentThrottle();
    if (throttle <= 0.0f) return requested;

    // Reduce batch size as throttle increases
    // At 50% throttle: batch size halved
    // At 95% throttle: batch size = 1
    float factor = std::max(0.05f, 1.0f - (throttle * 1.1f));
    return std::max(size_t(1), static_cast<size_t>(requested * factor));
}

ThermalState PlasmaGovernor::lastState() const {
    // Reconstruct from atomic (lossy but sufficient for telemetry)
    ThermalState state;
    state.junction_temp_c = temp_history_[(history_index_ + TEMP_HISTORY_SIZE - 1) % TEMP_HISTORY_SIZE];
    return state;
}

float PlasmaGovernor::averageTempOverWindow(size_t seconds) const {
    size_t samples = std::min(seconds, history_count_);
    if (samples == 0) return 0.0f;

    float sum = 0.0f;
    for (size_t i = 0; i < samples; ++i) {
        size_t idx = (history_index_ + TEMP_HISTORY_SIZE - 1 - i) % TEMP_HISTORY_SIZE;
        sum += temp_history_[idx];
    }
    return sum / static_cast<float>(samples);
}

float PlasmaGovernor::calculateThrottle(float temp) const {
    if (temp < TEMP_WARNING) return THROTTLE_MIN;
    if (temp >= TEMP_CRITICAL) {
        // Exponential ramp to emergency
        float t = (temp - TEMP_CRITICAL) / (TEMP_EMERGENCY - TEMP_CRITICAL);
        return THROTTLE_MIN + (THROTTLE_MAX - THROTTLE_MIN) * (t * t);
    }
    // Linear between warning and critical
    float t = (temp - TEMP_WARNING) / (TEMP_CRITICAL - TEMP_WARNING);
    return THROTTLE_MIN + (THROTTLE_MAX - THROTTLE_MIN) * t * 0.5f;  // Only throttle 50% at critical
}

} // namespace rawrxd
