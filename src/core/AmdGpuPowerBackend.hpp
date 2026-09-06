// AmdGpuPowerBackend.hpp — real AMD GPU package power (ADL2/PDH only; no stubs)
#pragma once

#include <cstdint>

namespace rawrxd {

enum class GpuPowerSensorSource : std::uint8_t {
    None = 0,
    Adl2OverdriveN,
    PdhAmdGpuCounter,
};

struct GpuPowerSample {
    double watts = 0.0;
    GpuPowerSensorSource source = GpuPowerSensorSource::None;
    bool valid = false;
};

const char* GpuPowerSensorSourceName(GpuPowerSensorSource s) noexcept;

// Call once from UI/main thread before inference workers start.
void InitGpuPowerProbeMainThread() noexcept;
[[nodiscard]] bool GpuPowerProbeSuppressed() noexcept;
// When probe is suppressed (CPU E2E / dual-AMD quarantine), block atiadlxx loads.
void InstallAmdAdlLoadBlockIfSuppressed() noexcept;
[[nodiscard]] bool GpuPowerSensorReady() noexcept;

bool ProbeAmdGpuPowerBackend() noexcept;
GpuPowerSensorSource ActiveGpuPowerSensor() noexcept;
bool SampleAmdGpuPowerWatts(double& watts_out) noexcept;

} // namespace rawrxd
