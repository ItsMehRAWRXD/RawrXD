// DualGpuAdmissionTelemetry.hpp — RAWRXD_DUAL_GPU_ADMISSION_TELEMETRY_001
//
// Fail-closed dual-GPU admission + aggregate-bandwidth telemetry for the
// locked performance profile. Header-only and dependency-free so it can be
// unit-tested without a GPU and wired into the Deep2 Kimi path by injection.
//
// Design law (fail closed):
//   * The locked profile is admitted ONLY when EXACTLY two DISTINCT,
//     identity-verified, healthy physical GPUs with MEASURED budgets are
//     present. More than two is rejected for a 2-lane lock (no silent
//     truncation to a fixed telemetry array).
//   * Single-GPU fallback is NEVER admitted under the lock (DGL-04).
//   * Aggregate PHYSICAL bandwidth is (B0+B1)/T_shared from per-device VRAM
//     traffic that is PROVENANCE-TAGGED as hardware-counter backed. Unverified
//     byte counts are tracked as logical only and never counted as physical.
//   * Overlap is derived from actual per-device active intervals intersected
//     over the shared wall window, not accepted from an unvalidated caller.
//   * Measurement functions are tri-state: they return false (UNMEASURED) when
//     no valid window / no counter-backed traffic exists, so a valid 0 and an
//     unavailable measurement are never conflated.
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <mutex>

namespace rawrxd {
namespace dualgpu {

// One physical device. `measuredCapBytes` is the measured free/available VRAM
// budget (never a theoretical total). `identityExact` is an exact LUID match.
struct DualGpuDevice {
    std::string stableId;           // "VENDOR:DEVICE:LUID" stable identity
    std::string name;
    uint32_t vendorId = 0;          // PCI vendor id (e.g. 0x1002 AMD)
    uint32_t deviceId = 0;          // PCI device id
    uint64_t peakBandwidthGbps = 0; // theoretical, informational only
    uint64_t measuredCapBytes  = 0; // measured physical VRAM budget (DGL-05)
    bool identityExact = false;     // DGL-02 exact adapter identity
    bool healthy       = true;      // DGL-14 device-loss state
};

// Expected hardware for the locked profile. When `enforce` is set, admission
// independently verifies the two devices are the expected adapters by vendor
// and/or case-insensitive name needle — identity is not merely caller-asserted.
struct ExpectedHardware {
    bool        enforce        = false;
    uint32_t    gpu0Vendor      = 0x1002; // AMD
    uint32_t    gpu1Vendor      = 0x1002; // AMD
    std::string gpu0NameNeedle  = "R9700";
    std::string gpu1NameNeedle  = "7800";
};

enum class AdmissionStatus : uint32_t {
    Admitted = 0,
    LockedRequiresTwoGpu          = 1,
    DuplicateOrUnverifiedIdentity = 2,
    MissingMeasuredBudget         = 3,
    UnhealthyDevice               = 4,
    UnexpectedHardware            = 5,
};

struct AdmissionResult {
    AdmissionStatus status = AdmissionStatus::LockedRequiresTwoGpu;
    bool     admitted = false;
    const char* reason = "locked_requires_two_gpu";
    uint32_t deviceCount = 0;
};

static inline bool ContainsCaseInsensitive(const std::string& h, const std::string& n) {
    if (n.empty()) return true;
    if (h.size() < n.size()) return false;
    for (size_t i = 0; i + n.size() <= h.size(); ++i) {
        size_t j = 0;
        for (; j < n.size(); ++j) {
            char a = h[i + j], b = n[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (j == n.size()) return true;
    }
    return false;
}

// DGL-01..05: fail-closed admission for the locked dual profile.
inline AdmissionResult AdmitLockedProfile(const std::vector<DualGpuDevice>& devs,
                                          const ExpectedHardware& expect = ExpectedHardware{}) {
    AdmissionResult r;
    r.deviceCount = static_cast<uint32_t>(devs.size());
    if (devs.size() != 2) {                        // DGL-03/DGL-04: exactly two
        r.status = AdmissionStatus::LockedRequiresTwoGpu;
        r.reason = "locked_requires_exactly_two_gpu";
        return r;
    }
    for (size_t i = 0; i < devs.size(); ++i) {
        if (!devs[i].identityExact) {              // DGL-02
            r.status = AdmissionStatus::DuplicateOrUnverifiedIdentity;
            r.reason = "unverified_identity"; return r;
        }
        if (!devs[i].healthy) {                    // DGL-14
            r.status = AdmissionStatus::UnhealthyDevice;
            r.reason = "unhealthy_device"; return r;
        }
        if (!devs[i].measuredCapBytes) {           // DGL-05
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
    if (expect.enforce) {                          // independent identity check
        const DualGpuDevice& g0 = devs[0];
        const DualGpuDevice& g1 = devs[1];
        const bool g0ok = (expect.gpu0Vendor == 0 || g0.vendorId == expect.gpu0Vendor) &&
                          ContainsCaseInsensitive(g0.name, expect.gpu0NameNeedle);
        const bool g1ok = (expect.gpu1Vendor == 0 || g1.vendorId == expect.gpu1Vendor) &&
                          ContainsCaseInsensitive(g1.name, expect.gpu1NameNeedle);
        if (!g0ok || !g1ok) {
            r.status = AdmissionStatus::UnexpectedHardware;
            r.reason = "unexpected_hardware"; return r;
        }
    }
    r.admitted = true;
    r.status   = AdmissionStatus::Admitted;
    r.reason   = "dual_gpu_admitted";
    return r;
}

// DGL-07..12: per-device traffic + shared wall clock. VRAM, PCIe and storage
// are accounted separately. Physical VRAM bytes are provenance-gated: only
// counter-backed bytes count as physical; the rest are logical/estimated.
struct DeviceTraffic {
    uint64_t vramReadBytes       = 0; // PHYSICAL (hardware-counter backed)
    uint64_t vramWriteBytes      = 0; // PHYSICAL (hardware-counter backed)
    uint64_t logicalReadBytes    = 0; // unverified / estimated (NOT physical)
    uint64_t pcieBytes           = 0;
    uint64_t storageBytes        = 0;
    uint64_t activeNs            = 0;
    bool     vramCounterBacked   = false;
    std::vector<std::pair<uint64_t, uint64_t>> activeIntervals; // [start,end) ns
};

struct Telemetry {
    std::mutex    mu;
    DeviceTraffic dev[2];
    uint64_t      sharedWallNs = 0;
    bool          windowValid  = false;

    void BeginWindow() {
        std::lock_guard<std::mutex> l(mu);
        sharedWallNs = 0; windowValid = false;
        for (auto& d : dev) d = DeviceTraffic{};
    }
    // DGL-08: end the shared wall window. Overlap is derived from intervals.
    void EndWindow(uint64_t wallNs) {
        std::lock_guard<std::mutex> l(mu);
        sharedWallNs = wallNs; windowValid = true;
    }
    // DGL-07: add VRAM traffic with explicit provenance. counterBacked=true
    // means the value came from a supported hardware performance counter.
    void AddVramRead (int i, uint64_t b, bool counterBacked) {
        std::lock_guard<std::mutex> l(mu);
        if (i < 0 || i >= 2) return;
        if (counterBacked) { dev[i].vramReadBytes += b; dev[i].vramCounterBacked = true; }
        else               { dev[i].logicalReadBytes += b; }
    }
    void AddVramWrite(int i, uint64_t b, bool counterBacked) {
        std::lock_guard<std::mutex> l(mu);
        if (i < 0 || i >= 2) return;
        if (counterBacked) { dev[i].vramWriteBytes += b; dev[i].vramCounterBacked = true; }
        else               { dev[i].logicalReadBytes += b; }
    }
    void AddPcie     (int i, uint64_t b) { std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].pcieBytes    += b; }
    void AddStorage  (int i, uint64_t b) { std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].storageBytes += b; }
    void AddActive   (int i, uint64_t ns){ std::lock_guard<std::mutex> l(mu); if (i>=0&&i<2) dev[i].activeNs     += ns; }
    // DGL-09: record a device active interval for overlap computation.
    void AddActiveInterval(int i, uint64_t startNs, uint64_t endNs) {
        std::lock_guard<std::mutex> l(mu);
        if (i>=0 && i<2 && endNs > startNs) dev[i].activeIntervals.emplace_back(startNs, endNs);
    }
};

static inline void MergeIntervals(std::vector<std::pair<uint64_t,uint64_t>>& v) {
    std::sort(v.begin(), v.end());
    std::vector<std::pair<uint64_t,uint64_t>> out;
    out.reserve(v.size());
    for (const auto& iv : v) {
        if (iv.second <= iv.first) continue;
        if (out.empty() || iv.first > out.back().second) out.push_back(iv);
        else if (iv.second > out.back().second) out.back().second = iv.second;
    }
    v.swap(out);
}
static inline uint64_t IntersectLen(std::vector<std::pair<uint64_t,uint64_t>> a,
                                    std::vector<std::pair<uint64_t,uint64_t>> b) {
    MergeIntervals(a); MergeIntervals(b);
    uint64_t total = 0; size_t i = 0, j = 0;
    while (i < a.size() && j < b.size()) {
        const uint64_t s = std::max(a[i].first, b[j].first);
        const uint64_t e = std::min(a[i].second, b[j].second);
        if (e > s) total += e - s;
        if (a[i].second < b[j].second) ++i; else ++j;
    }
    return total;
}

// DGL-10: aggregate PHYSICAL bandwidth = (B0+B1)/T_shared. bytes/ns == GB/s.
// Returns false (UNMEASURED) when there is no valid window or no counter-backed
// traffic; a valid 0 is only returned when a measured window genuinely had 0
// physical bytes. Never substitutes theoretical peak.
inline bool AggregatePhysicalBandwidthGbps(Telemetry& t, double& outGbps) {
    std::lock_guard<std::mutex> l(t.mu);
    outGbps = 0.0;
    if (!t.windowValid || !t.sharedWallNs) return false;
    if (!t.dev[0].vramCounterBacked && !t.dev[1].vramCounterBacked) return false;
    const uint64_t b = t.dev[0].vramReadBytes + t.dev[0].vramWriteBytes +
                       t.dev[1].vramReadBytes + t.dev[1].vramWriteBytes;
    outGbps = static_cast<double>(b) / static_cast<double>(t.sharedWallNs);
    return true;
}

// Logical (host-visible PCIe + unverified) bandwidth, reported SEPARATELY.
inline bool AggregateLogicalBandwidthGbps(Telemetry& t, double& outGbps) {
    std::lock_guard<std::mutex> l(t.mu);
    outGbps = 0.0;
    if (!t.windowValid || !t.sharedWallNs) return false;
    const uint64_t b = t.dev[0].pcieBytes + t.dev[1].pcieBytes +
                       t.dev[0].logicalReadBytes + t.dev[1].logicalReadBytes;
    outGbps = static_cast<double>(b) / static_cast<double>(t.sharedWallNs);
    return true;
}

// DGL-09: concurrent-execution overlap O = |I0 intersect I1| / T_shared,
// computed from actual active intervals and clamped to the shared window.
inline bool OverlapFraction(Telemetry& t, double& outFrac) {
    std::lock_guard<std::mutex> l(t.mu);
    outFrac = 0.0;
    if (!t.windowValid || !t.sharedWallNs) return false;
    uint64_t ov = IntersectLen(t.dev[0].activeIntervals, t.dev[1].activeIntervals);
    if (ov > t.sharedWallNs) ov = t.sharedWallNs; // clamp to window
    outFrac = static_cast<double>(ov) / static_cast<double>(t.sharedWallNs);
    return true;
}

// True only when both devices recorded useful active time in the window.
inline bool BothDevicesContributed(Telemetry& t) {
    std::lock_guard<std::mutex> l(t.mu);
    return t.dev[0].activeNs != 0 && t.dev[1].activeNs != 0;
}

// DGL-11: active weight residency = resident requested / total requested, in
// [0,1]. Resident is clamped to total so the ratio can never exceed 1.
inline double ActiveWeightResidency(uint64_t residentReqBytes, uint64_t totalReqBytes) {
    if (!totalReqBytes) return 0.0;
    if (residentReqBytes > totalReqBytes) residentReqBytes = totalReqBytes;
    return static_cast<double>(residentReqBytes) / static_cast<double>(totalReqBytes);
}

} // namespace dualgpu
} // namespace rawrxd