// Deep2DeviceManager.hpp — topology-agnostic adapter inventory + policy
#pragma once
#include <cstdio>
#include <cstdint>

namespace Deep2 {

enum class GpuPolicy : uint8_t {
    Auto = 0,
    CpuOnly = 1,
    Single = 2,
    Multi = 3,
    UserList = 4,
};

enum class ExecMode : uint8_t {
    CpuNative = 0,
    SingleGpu = 1,
    MultiGpuShard = 2,
    Speculative = 3,
};

enum class DeviceDuty : uint8_t {
    Unused = 0,
    ComputePrimary = 1,
    ComputeSecondary = 2,
    Draft = 3,
    Display = 4,
    Excluded = 5,
};

struct DeviceIdentity {
    char name[128]{};
    char stableId[64]{};  // VENDOR:DEVICE:LUID
    uint64_t dedicatedVram = 0;
    uint64_t sharedVram = 0;
    uint64_t luid = 0;
    uint32_t vendorId = 0;
    uint32_t deviceId = 0;
    int index = -1;
    unsigned score = 0;
    bool integrated = false;
    bool healthy = true;
    DeviceDuty duty = DeviceDuty::Unused;
};

struct DevicePlan {
    unsigned detected = 0;
    unsigned opened = 0;
    int primaryIndex = -1;
    char primaryName[128]{};
    char primaryStableId[64]{};
    int openIndexes[8]{};
    unsigned openCount = 0;
    GpuPolicy policy = GpuPolicy::Auto;
    ExecMode mode = ExecMode::CpuNative;
    const char* backend = "CPU_NATIVE";
    const char* reason = "unset";
};

struct DeviceManagerSnapshot {
    DeviceIdentity devices[8]{};
    unsigned deviceCount = 0;
    DevicePlan plan{};
};

// Alias used by Deep2Engine enableVulkan path.
using Deep2DevicePlan = DeviceManagerSnapshot;
using Deep2AdapterInfo = DeviceIdentity;

extern "C" unsigned Deep2Device_ScoreAdapter(unsigned long long dedicated,
                                             unsigned long long shared,
                                             unsigned flags);
extern "C" int Deep2Device_PickBestIndex(const unsigned* scores,
                                         const unsigned long long* vram,
                                         unsigned count,
                                         unsigned minScore);

bool Deep2Device_Enumerate(DeviceManagerSnapshot& snap) noexcept;
bool Deep2Device_ApplyPolicy(DeviceManagerSnapshot& snap) noexcept;
const char* Deep2Device_VulkanNeedle(const DeviceManagerSnapshot& snap) noexcept;
void Deep2Device_EmitWitnesses(FILE* f, const DeviceManagerSnapshot& snap) noexcept;

// Gate aliases
inline bool DeviceManager_Enumerate(DeviceManagerSnapshot& s) noexcept {
    return Deep2Device_Enumerate(s);
}
inline DevicePlan DeviceManager_Plan(DeviceManagerSnapshot& s) noexcept {
    Deep2Device_ApplyPolicy(s);
    return s.plan;
}
inline void DeviceManager_EmitWitnesses(FILE* f, const DeviceManagerSnapshot& s) noexcept {
    Deep2Device_EmitWitnesses(f, s);
}

} // namespace Deep2
