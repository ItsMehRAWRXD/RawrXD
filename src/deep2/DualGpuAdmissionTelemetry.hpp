// DualGpuAdmissionTelemetry.hpp — RAWRXD_DUAL_GPU_ADMISSION_TELEMETRY_001
//
// Fail-closed dual-GPU admission + aggregate-bandwidth telemetry for the
// locked performance profile. Header-only and dependency-free so it can be
// unit-tested without a GPU and wired into the Deep2 Kimi path by injection.
//
// Design law (fail closed):
//   * The locked profile is admitted ONLY when two DISTINCT, identity-verified,
//     healthy physical GPUs with MEASURED memory budgets are present.
//   * Single-GPU fallback is NEVER admitted under the lock (DGL-04).
//   * Aggregate PHYSICAL bandwidth is (B0+B1)/T_shared from real per-device
//     VRAM traffic. Theoretical peak is informational and never used as
//     evidence. If hardware traffic counters are unavailable the physical
//     result stays 0 and the caller must report logical bandwidth separately.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <mutex>
#include <cstdio>

namespace rawrxd {
namespace dualgpu {

// One physical device. `measuredCapBytes` is the measured free/available VRAM
// budget (never a theoretical total). `identityExact` is an exact LUID match.
struct DualGpuDevice {
    std::string stableId;           // "VENDOR:DEVICE:LUID" stable identity
    std::string name;
    uint64_t peakBandwidthGbps = 0; // theoretical, informational only
    uint64_t measuredCapBytes  = 0; // measured physical VRAM budget (DGL-05)
    bool identityExact = false;     // DGL-02 exact adapter identity
    bool healthy       = true;      // DGL-14 device-loss state
};

enum class AdmissionStatus : uint32_t {
    Admitted = 0,
    LockedRequiresTwoGpu        = 1,
    DuplicateOrUnverifiedIdentity = 2,
    MissingMeasuredBudget       = 3,
    UnhealthyDevice             = 4,
};

struct AdmissionResult {
    AdmissionStatus status = AdmissionStatus::LockedRequiresTwoGpu;
    bool     admitted = false;
    const char* reason = "locked_requires_two_gpu";
    uint32_t deviceCount = 0;
};

// DGL-01..05: fail-closed admission for the locked profile.
inline AdmissionResult AdmitLockedProfile(const std::vector<DualGpuDevice>& devs) {
    AdmissionResult r;
    r.deviceCount = static_cast<uint32_t>(devs.size());
    if (devs.size() < 2) {                       // DGL-03/DGL-04
        r.status = AdmissionStatus::LockedRequiresTwoGpu;
        r.reason = "locked_requires_two_gpu";
        return r;
    }
    for (size_t i = 0; i < devs.size(); ++i) {
        if (!devs[i].identityExact) {            // DGL-02
            r.status = AdmissionStatus::DuplicateOrUnverifiedIdentity;
            r.reason = "unverified_identity"; return r;
        }
        if (!devs[i].healthy) {                  // DGL-14
            r.status = AdmissionStatus::UnhealthyDevice;
            r.reason = "unhealthy_device"; return r;
        }
        if (!devs[i].measuredCapBytes) {         // DGL-05
            r.status = AdmissionStatus::MissingMeasuredBudget;
            r.reason = "missing_measured_budget"; return r;
        }
        for (size_t j = i + 1; j < devs.size(); ++j) {
            if (devs[i].stableId == devs[j].stableId) { // DGL-02 distinct
                r.status = AdmissionStatus::DuplicateOrUnverifiedIdentity;
                r.reason = "duplicate_stable_id"; return r;
            }
        }
    }
    r.admitted = true;
    r.status   = AdmissionStatus::Admitted;
    r.reason   = "dual_gpu_admitted";
    return r;
}

// DGL-07..12: per-device traffic + shared wall clock. VRAM, PCIe and storage
// are accounted separately so physical vs logical bandwidth never conflates.
struct DeviceTraffic {
    uint64_t vramReadBytes  = 0;
    uint64_t vramWriteBytes = 0;
    uint64_t pcieBytes      = 0;
    uint64_t storageBytes   = 0;
    uint64_t activeNs       = 0;
};

struct Telemetry {
    std::mutex   mu;
    DeviceTraffic dev[2];
    uint64_t sharedWallNs = 0;
    uint64_t overlapNs    = 0;

    void BeginWindow() {
        std::lock_guard<std::mutex> l(mu);
        sharedWallNs = 0; overlapNs = 0;
        for (auto& d : dev) d = DeviceTraffic{};
    }
    void EndWindow(uint64_t wallNs, uint64_t overlapNs_) {
        std::lock_guard<std::mutex> l(mu);
        sharedWallNs = wallNs; overlapNs = overlapNs_;
    }
    void AddVramRead (int i, uint64_t b) { std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].vramReadBytes  += b; }
    void AddVramWrite(int i, uint64_t b) { std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].vramWriteBytes += b; }
    void AddPcie     (int i, uint64_t b) { std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].pcieBytes      += b; }
    void AddStorage  (int i, uint64_t b) { std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].storageBytes   += b; }
    void AddActive   (int i, uint64_t ns){ std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].activeNs       += ns; }
};

// DGL-10: aggregate PHYSICAL bandwidth = (B0+B1)/T_shared. bytes/ns == GB/s.
// Returns 0 when no shared window or no physical traffic was measured — the
// caller must then report logical bandwidth separately and keep physical
// certification UNVERIFIED (never substitute theoretical peak).
inline double AggregatePhysicalBandwidthGbps(Telemetry& t) {
    std::lock_guard<std::mutex> l(t.mu);
    if (!t.sharedWallNs) return 0.0;
    const uint64_t b = t.dev[0].vramReadBytes + t.dev[0].vramWriteBytes +
                       t.dev[1].vramReadBytes + t.dev[1].vramWriteBytes;
    return static_cast<double>(b) / static_cast<double>(t.sharedWallNs);
}

// Logical (host-visible PCIe) bandwidth, reported SEPARATELY from physical.
inline double AggregateLogicalBandwidthGbps(Telemetry& t) {
    std::lock_guard<std::mutex> l(t.mu);
    if (!t.sharedWallNs) return 0.0;
    const uint64_t b = t.dev[0].pcieBytes + t.dev[1].pcieBytes;
    return static_cast<double>(b) / static_cast<double>(t.sharedWallNs);
}

// DGL-09: concurrent-execution overlap O = |I0 intersect I1| / T_shared.
inline double OverlapFraction(Telemetry& t) {
    std::lock_guard<std::mutex> l(t.mu);
    if (!t.sharedWallNs) return 0.0;
    return static_cast<double>(t.overlapNs) / static_cast<double>(t.sharedWallNs);
}

// True only when both devices recorded useful active time in the window.
inline bool BothDevicesContributed(Telemetry& t) {
    std::lock_guard<std::mutex> l(t.mu);
    return t.dev[0].activeNs != 0 && t.dev[1].activeNs != 0;
}

// DGL-11: active weight residency = resident requested bytes / total requested.
inline double ActiveWeightResidency(uint64_t residentReqBytes, uint64_t totalReqBytes) {
    return totalReqBytes ? static_cast<double>(residentReqBytes) /
                               static_cast<double>(totalReqBytes) : 0.0;
}

} // namespace dualgpu
} // namespace rawrxd