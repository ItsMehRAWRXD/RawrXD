// GpuDecodeEfficiency.hpp — authoritative GPU decode tokens/watt (QPC + AMD sensors)
#pragma once

#include "AmdGpuPowerBackend.hpp"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace rawrxd {

struct GpuDecodeEfficiencyResult {
    bool     power_valid = false;
    double   decode_tps = 0.0;
    double   average_gpu_watts = 0.0;
    double   tokens_per_watt_gpu = 0.0;
    double   window_seconds = 0.0;
    uint64_t tokens_generated = 0;
    uint32_t power_sample_count = 0;
    uint64_t qpc_window_start = 0;
    uint64_t qpc_window_end = 0;
    GpuPowerSensorSource sensor_source = GpuPowerSensorSource::None;
};

bool AmdGpuPowerTelemetryAvailable() noexcept;

class GpuDecodeEfficiencySession final {
public:
    GpuDecodeEfficiencySession() noexcept;
    ~GpuDecodeEfficiencySession();

    GpuDecodeEfficiencySession(const GpuDecodeEfficiencySession&) = delete;
    GpuDecodeEfficiencySession& operator=(const GpuDecodeEfficiencySession&) = delete;

    void BeginDecodeWindow() noexcept;
    void SampleDuringDecode() noexcept;
    GpuDecodeEfficiencyResult Finalize(uint64_t tokens_generated) noexcept;
    [[nodiscard]] bool hasResult() const noexcept { return result_.has_value(); }
    [[nodiscard]] GpuDecodeEfficiencyResult result() const noexcept;

private:
    void AppendPowerSample(uint64_t qpc) noexcept;

    std::mutex samples_mu_;
    std::vector<std::pair<uint64_t, double>> samples_;
    uint64_t qpc_freq_ = 0;
    uint64_t window_start_qpc_ = 0;
    uint64_t window_end_qpc_ = 0;
    uint64_t last_sample_qpc_ = 0;
    bool sensor_available_ = false;
    GpuPowerSensorSource sensor_source_ = GpuPowerSensorSource::None;
    std::optional<GpuDecodeEfficiencyResult> result_;
};

class GpuDecodeEfficiencyAuthority final {
public:
    static GpuDecodeEfficiencyAuthority& Instance() noexcept;
    void BeginDecodeWindow() noexcept;
    void SampleDuringDecode() noexcept;
    GpuDecodeEfficiencyResult EndAndPublish(uint64_t tokens_generated) noexcept;
    [[nodiscard]] const GpuDecodeEfficiencyResult& Last() const noexcept;
    [[nodiscard]] bool PowerValidForPolicy() const noexcept;
    void WriteCertificationEvidence() const noexcept;

private:
    std::mutex mu_;
    GpuDecodeEfficiencySession session_;
    GpuDecodeEfficiencyResult last_{};
};

void PublishGpuDecodeEfficiency(const GpuDecodeEfficiencyResult& r) noexcept;
void ClearGpuDecodeEfficiencyMetrics() noexcept;
[[nodiscard]] bool GpuPowerValidForPolicy() noexcept;
[[nodiscard]] bool TryReadMeasuredGpuPowerWatts(double& watts_out) noexcept;

} // namespace rawrxd
