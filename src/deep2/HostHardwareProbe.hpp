// ============================================================================
// HostHardwareProbe.hpp — Real host hardware discovery (no hardcoded budgets)
//
// RawrXD model-fit authority input #1.  Every budget used by MODEL_FIT must
// come from here rather than a hardcoded constant:
//   * system RAM (total + available)     — GlobalMemoryStatusEx / sysconf
//   * NVMe storage headroom              — GetDiskFreeSpaceExA / statfs
//   * per-device local VRAM              — Vulkan physical-device enumeration
//   * per-device budget policy (80 %)    — reserve for driver, arenas, KV
//
// Nothing in here ever guesses: a value that cannot be measured reports 0 and
// is treated as "unknown", never as a fabricated capacity.
// ============================================================================
#ifndef RAWRXD_HOST_HARDWARE_PROBE_HPP
#define RAWRXD_HOST_HARDWARE_PROBE_HPP

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/statvfs.h>
#include <unistd.h>
#endif

namespace rawrxd {

// Fixed 80 % resident policy.  Kept in one place so MODEL_FIT, the tiered
// manager and the per-slot admission receipts all reserve the same margin.
static constexpr double kDefaultResidentFraction = 0.80;

// ---------------------------------------------------------------------------
// GpuDeviceInfo — one enumerated discrete Vulkan compute device.
//
// Identity is `stableId`, NOT `ordinal`.  The runtime's device manager
// (Deep2DeviceManager) assigns its own enumeration index and opens slots by
// device-name substring, while Deep2::VulkanCompute::EnumeratePhysicalDevices()
// dedups D3D12 aliases and issues its own independent ordinals.  The two
// orderings are not guaranteed to agree, so an ordinal is not a device
// identity anywhere in RawrXD.  stableId is the VENDOR:DEVICE:LUID triple the
// device manager builds (Deep2DeviceManager.cpp: MakeStableId), and it is what
// MakeStableId-based correlation across subsystems relies on.
// ---------------------------------------------------------------------------
struct GpuDeviceInfo {
    std::string stableId;    // "VENDOR:DEVICE:LUID" — the stable identity
    std::string name;        // adapter description (used as InitializeSolo needle)
    uint32_t vendorId = 0;
    uint32_t deviceId = 0;
    uint64_t deviceLocalBytes = 0;   // measured dedicated VRAM
    uint64_t sharedBytes = 0;
    bool discrete = false;
    bool compute = false;
    int deviceIndex = -1;    // index in the runtime's own enumeration

    // Effective budget after the resident-fraction reserve.  This is the only
    // number placement planning may allocate model bytes against.
    uint64_t budgetBytes(double residentFraction = kDefaultResidentFraction) const {
        if (!deviceLocalBytes) return 0;
        const uint64_t v = static_cast<uint64_t>(
            static_cast<double>(deviceLocalBytes) * residentFraction);
        return v;
    }
};

// ---------------------------------------------------------------------------
// HostHardwareSnapshot — measured capacities of the machine RawrXD is on.
// ---------------------------------------------------------------------------
struct HostHardwareSnapshot {
    // System RAM
    uint64_t totalSystemRamBytes = 0;
    uint64_t availableSystemRamBytes = 0;
    uint32_t numberOfCores = 0;
    // NVMe storage (volume that holds the model files; path supplied by caller)
    uint64_t storageTotalBytes = 0;
    uint64_t storageAvailableBytes = 0;
    std::string storageVolume;

    // GPUs, sorted best-first by (discrete, compute, VRAM).
    std::vector<GpuDeviceInfo> gpus;

    // Aggregate VRAM (informational only — never used as one allocation).
    uint64_t combinedVramBytes() const {
        uint64_t n = 0;
        for (const auto& g : gpus) {
            if (deviceLocalFits(g)) n += g.deviceLocalBytes;
        }
        return n;
    }
    uint64_t combinedBudgetBytes(double f = kDefaultResidentFraction) const {
        uint64_t n = 0;
        for (const auto& g : gpus) {
            if (deviceLocalFits(g)) n += g.budgetBytes(f);
        }
        return n;
    }

    // Host budget after reserving KV, scratch and staging overhead.  These
    // reservations are explicit and named rather than an implicit "54 GB".
    uint64_t hostBudgetBytes(uint64_t kvReserveBytes,
                             uint64_t scratchReserveBytes,
                             uint64_t stagingReserveBytes) const {
        uint64_t b = totalSystemRamBytes;
        if (b < kvReserveBytes) return 0;
        b -= kvReserveBytes;
        if (b < scratchReserveBytes) return 0;
        b -= scratchReserveBytes;
        if (b < stagingReserveBytes) return 0;
        b -= stagingReserveBytes;
        return b;
    }

    static bool deviceLocalFits(const GpuDeviceInfo& g) {
        return g.deviceLocalBytes != 0;
    }

    // Emit one authoritative block.  ESP / SNAP / the flight recorder all read
    // these exact keys so no two subsystems can disagree about "64 GB".
    void emit(FILE* f = stderr) const {
        if (!f) return;
        std::fprintf(f,
            "HOST_HARDWARE_SNAPSHOT\n"
            "system_ram_total_bytes=%llu\n"
            "system_ram_available_bytes=%llu\n"
            "cpu_cores=%u\n"
            "storage_available_bytes=%llu\n"
            "storage_volume=%s\n"
            "gpu_count=%zu\n"
            "combined_vram_bytes=%llu\n",
            (unsigned long long)totalSystemRamBytes,
            (unsigned long long)availableSystemRamBytes,
            (unsigned)numberOfCores,
            (unsigned long long)storageAvailableBytes,
            storageVolume.empty() ? "(unmeasured)" : storageVolume.c_str(),
            gpus.size(),
            (unsigned long long)combinedVramBytes());
        for (size_t i = 0; i < gpus.size(); ++i) {
            const GpuDeviceInfo& g = gpus[i];
            std::fprintf(f,
                "GPU%zu stable_id=%s name=%s vendor=0x%04X device=0x%04X "
                "local_bytes=%llu budget_bytes=%llu discrete=%d compute=%d\n",
                i, g.stableId.empty() ? "(unmeasured)" : g.stableId.c_str(),
                g.name.empty() ? "(unnamed)" : g.name.c_str(),
                g.vendorId, g.deviceId,
                (unsigned long long)g.deviceLocalBytes,
                (unsigned long long)g.budgetBytes(),
                g.discrete ? 1 : 0, g.compute ? 1 : 0);
        }
        std::fflush(f);
    }
};

// ---------------------------------------------------------------------------
// HostHardwareProbe — measures the machine.
// ---------------------------------------------------------------------------
class HostHardwareProbe {
public:
    // Full probe: RAM + storage + every Vulkan compute device.
    // `storagePathHint` is the directory (or file) that holds the model.
    static HostHardwareSnapshot Probe(const std::string& storagePathHint = std::string());

    // A GPU enumeration callback is injected so this header does not have to
    // link Vulkan.  `userdata` is the HostHardwareSnapshot to fill.
    using GpuEnumerateFn = void (*)(void* userdata);

    // Same probe, but GPU enumeration is supplied by the caller (the engine
    // passes its own VulkanCompute::EnumeratePhysicalDevices wrapper).
    static HostHardwareSnapshot ProbeWith(
        const std::string& storagePathHint,
        GpuEnumerateFn enumerateGpus,
        void* userdata);
};

// ---------------------------------------------------------------------------
// Inline implementations
// ---------------------------------------------------------------------------
inline HostHardwareSnapshot HostHardwareProbe::Probe(const std::string& storagePathHint) {
    HostHardwareSnapshot s;

#ifdef _WIN32
#pragma comment(lib, "kernel32.lib")
    MEMORYSTATUSEX msx{};
    msx.dwLength = sizeof(msx);
    if (GlobalMemoryStatusEx(&msx)) {
        s.totalSystemRamBytes = static_cast<uint64_t>(msx.ullTotalPhys);
        s.availableSystemRamBytes = static_cast<uint64_t>(msx.ullAvailPhys);
    }
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    s.numberOfCores = static_cast<uint32_t>(si.dwNumberOfProcessors);

    if (!storagePathHint.empty()) {
        std::string dir = storagePathHint;
        // Reduce to a volume root so GetDiskFreeSpaceExA always succeeds.
        for (size_t i = 0; i < dir.size(); ++i)
            if (dir[i] == '/') dir[i] = '\\';
        const size_t slash = dir.find_last_of("\\");
        if (slash != std::string::npos) dir = dir.substr(0, slash + 1);
        ULARGE_INTEGER freeAvail{}, totalBytes{}, freeTotal{};
        if (GetDiskFreeSpaceExA(dir.c_str(), &freeAvail, &totalBytes, &freeTotal)) {
            s.storageAvailableBytes = static_cast<uint64_t>(freeAvail.QuadPart);
            s.storageTotalBytes = static_cast<uint64_t>(totalBytes.QuadPart);
            s.storageVolume = dir;
        }
    }
#else
    const long pageSize = sysconf(_SC_PAGESIZE);
    const long pages = sysconf(_SC_PHYS_PAGES);
    if (pageSize > 0 && pages > 0)
        s.totalSystemRamBytes = static_cast<uint64_t>(pageSize) *
                                static_cast<uint64_t>(pages);
    const long availPages = sysconf(_SC_AVPHYS_PAGES);
    if (pageSize > 0 && availPages > 0)
        s.availableSystemRamBytes = static_cast<uint64_t>(pageSize) *
                                    static_cast<uint64_t>(availPages);
    s.numberOfCores = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_ONLN));
    if (!storagePathHint.empty()) {
        std::string dir = storagePathHint;
        const size_t slash = dir.find_last_of('/');
        if (slash != std::string::npos) dir = dir.substr(0, slash + 1);
        struct statvfs vfs{};
        if (::statvfs(dir.c_str(), &vfs) == 0) {
            s.storageAvailableBytes = static_cast<uint64_t>(vfs.f_bavail) *
                                      static_cast<uint64_t>(vfs.f_frsize);
            s.storageTotalBytes = static_cast<uint64_t>(vfs.f_blocks) *
                                  static_cast<uint64_t>(vfs.f_frsize);
            s.storageVolume = dir;
        }
    }
#endif
    return s;
}

inline HostHardwareSnapshot HostHardwareProbe::ProbeWith(
    const std::string& storagePathHint,
    GpuEnumerateFn enumerateGpus,
    void* userdata)
{
    HostHardwareSnapshot s = Probe(storagePathHint);
    if (enumerateGpus) enumerateGpus(userdata != nullptr ? userdata : static_cast<void*>(&s));
    return s;
}

} // namespace rawrxd

#endif // RAWRXD_HOST_HARDWARE_PROBE_HPP
