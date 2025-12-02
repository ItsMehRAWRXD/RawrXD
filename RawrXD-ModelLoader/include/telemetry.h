#pragma once
#include <string>
#include <cstdint>

namespace telemetry {

struct TelemetrySnapshot {
    double cpuTempC = -1.0;
    double gpuTempC = -1.0;
    double cpuUsagePercent = -1.0;
    double gpuUsagePercent = -1.0; // may not be available
    uint64_t timeMs = 0;
    bool cpuTempValid = false;
    bool gpuTempValid = false;
    std::string gpuVendor; // "NVIDIA", "AMD", or "" if unknown
};

// Initialize COM / PDH resources and detect GPU vendor.
bool Initialize();
// Poll current telemetry snapshot (thread-safe if single-thread usage).
bool Poll(TelemetrySnapshot &out);
// Shutdown and release resources.
void Shutdown();

} // namespace telemetry
