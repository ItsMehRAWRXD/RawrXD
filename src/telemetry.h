#pragma once
// Stub telemetry.h for CLI-only builds

#include <cstdint>
#include <string>

namespace telemetry {

struct TelemetrySnapshot {
    uint64_t timeMs = 0;
    bool cpuTempValid = false;
    double cpuTempC = 0.0;
    double cpuUsagePercent = 0.0;
    bool gpuTempValid = false;
    double gpuTempC = 0.0;
    double gpuUsagePercent = 0.0;
    std::string gpuVendor;
};

    inline bool Initialize() { return true; }
    inline bool InitializeHardware() { return true; }
    inline bool Poll(TelemetrySnapshot&) { return false; }
    inline void Shutdown() {}
}
