#pragma once
/* Capability facts → legality → measure. No vendor/tier/today paths. */
#include <cstdint>
#include <cstdio>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#endif

#define CAPABILITY_SOLVE_001 1
#define NO_TODAY_PATH 1
#define NO_TOMORROW_PATH 1
#define NO_DEVICE_PRESET 1
#define ROWS_NE_LOCAL 1

extern "C" {
struct RawrHostCaps {
    uint64_t AvailPhysical;
    uint64_t AvailCommit;
    uint64_t ProcessCommit;
    uint32_t LogicalProcessors;
    uint32_t _pad0;
};
struct RawrGpuCaps {
    uint64_t PhysicalDevice;
    uint64_t Device;
    uint64_t HeapSize;
    uint64_t HeapBudget;
    uint64_t HeapUsage;
    uint32_t BudgetKnown; // 1 only if VK_EXT_memory_budget filled
    uint32_t MaxSharedBytes;
    uint32_t MaxWGInvocations;
    uint32_t MaxWGX, MaxWGY, MaxWGZ;
    uint32_t DefaultSubgroup;
    uint32_t MinSubgroup;
    uint32_t MaxSubgroup;
    uint32_t TimestampValid;
};
struct RawrKernelShape {
    uint32_t LocalX, LocalY, LocalZ;
    uint32_t RowsPerWG;
    uint32_t SharedBytes;
    uint32_t PrefetchDepth;
    uint32_t WindowCount;
    uint64_t EstimatedLiveBytes;
    uint64_t MeasuredTicks;
};
int RawrShapeLegal(const RawrKernelShape* shape, const RawrGpuCaps* gpu);
}

namespace rawr::cap {

inline void SnapshotHost(RawrHostCaps& h) noexcept {
#ifdef _WIN32
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        h.AvailPhysical = ms.ullAvailPhys;
        h.AvailCommit = ms.ullAvailVirtual;
    }
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc)))
        h.ProcessCommit = pmc.PrivateUsage;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    h.LogicalProcessors = si.dwNumberOfProcessors;
#else
    (void)h;
#endif
}

/* LIVE_DEVICE_HEADROOM = BudgetKnown ? max(0,Budget-Usage) : UNKNOWN(0). */
inline uint64_t LiveDeviceHeadroom(const RawrGpuCaps& g) noexcept {
    if (!g.BudgetKnown) return 0;
    return (g.HeapBudget > g.HeapUsage) ? (g.HeapBudget - g.HeapUsage) : 0;
}

inline void EmitLoopLaw() noexcept {
    std::printf("EXEC_LOOP=DISCOVER_ABI>ENUMERATE>QUERY>SNAPSHOT>"
                "CANDIDATES>LEGAL>RESERVE>WARM>MEASURE>SELECT>"
                "EXECUTE>FEEDBACK>RE-SNAPSHOT\n");
    std::printf("ROWS_NE_LOCAL=1 BUDGET_FROM_EXT_MEMORY_BUDGET_ONLY=1\n");
    std::printf("HOST_RAM_IS_SNAPSHOT=1 NO_VENDOR_TABLE=1\n");
}

} // namespace rawr::cap
