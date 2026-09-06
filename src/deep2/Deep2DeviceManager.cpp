// Deep2DeviceManager.cpp — DXGI enumerate + capability policy (no card hard-codes)
#include "Deep2DeviceManager.hpp"
#include <cstring>
#include <cstdlib>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dxgi.h>
#pragma comment(lib, "dxgi.lib")
#endif

namespace Deep2 {
namespace {

bool HasI(const char* s, const char* n) noexcept {
    if (!s || !n || !*n) return false;
    for (; *s; ++s) {
        const char* a = s;
        const char* b = n;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
            if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
            if (ca != cb) break;
            ++a; ++b;
        }
        if (!*b) return true;
    }
    return false;
}

unsigned NameFlags(const char* n, uint64_t dedicated) noexcept {
    unsigned f = 0;
    if (HasI(n, "AI PRO") || HasI(n, "PRO")) f |= 1u;
    if (HasI(n, "XT") || HasI(n, "SUPER")) f |= 2u;
    if (dedicated < (1ull << 30) && (HasI(n, "Graphics") || HasI(n, "iGPU")))
        f |= 4u;
    return f;
}

void MakeStableId(DeviceIdentity& d) noexcept {
    std::snprintf(d.stableId, sizeof(d.stableId), "%04X:%04X:%016llX",
                  d.vendorId & 0xFFFFu, d.deviceId & 0xFFFFu,
                  (unsigned long long)d.luid);
}

const char* DutyName(DeviceDuty d) noexcept {
    switch (d) {
    case DeviceDuty::ComputePrimary: return "COMPUTE_PRIMARY";
    case DeviceDuty::ComputeSecondary: return "COMPUTE_SECONDARY";
    case DeviceDuty::Draft: return "DRAFT";
    case DeviceDuty::Display: return "DISPLAY";
    case DeviceDuty::Excluded: return "EXCLUDED";
    default: return "DETECTED/UNUSED";
    }
}

const char* VendorName(uint32_t id) noexcept {
    if (id == 0x1002) return "AMD";
    if (id == 0x10DE) return "NVIDIA";
    if (id == 0x8086) return "INTEL";
    return "OTHER";
}

GpuPolicy ParsePolicy() noexcept {
    const char* p = std::getenv("RAWRXD_GPU_POLICY");
    if (!p || !*p) p = std::getenv("DEEP2_GPU_POLICY");
    if (!p || !*p) return GpuPolicy::Auto;
    if (HasI(p, "CPU")) return GpuPolicy::CpuOnly;
    if (HasI(p, "SINGLE")) return GpuPolicy::Single;
    if (HasI(p, "MULTI")) return GpuPolicy::Multi;
    if (HasI(p, "LIST") || HasI(p, "USER")) return GpuPolicy::UserList;
    return GpuPolicy::Auto;
}

bool ParseDeviceList(int* out, unsigned& n, bool& cpuSentinel) noexcept {
    n = 0;
    cpuSentinel = false;
    const char* p = std::getenv("RAWRXD_GPU_DEVICES");
    if (!p || !*p) p = std::getenv("DEEP2_GPU_DEVICES");
    if (!p || !*p) return false;
    if (HasI(p, "CPU") || HasI(p, "NONE")) {
        cpuSentinel = true;
        return true;
    }
    if (HasI(p, "ALL")) {
        out[0] = -1;
        n = 1;
        return true;
    }
    const char* s = p;
    while (*s && n < 8) {
        while (*s == ' ' || *s == ',') ++s;
        if (!*s) break;
        int v = 0;
        bool any = false;
        while (*s >= '0' && *s <= '9') {
            any = true;
            v = v * 10 + (*s - '0');
            ++s;
        }
        if (any) out[n++] = v;
        while (*s && *s != ',') ++s;
    }
    return n > 0;
}

void SetPrimary(DevicePlan& plan, const DeviceIdentity& d) noexcept {
    plan.primaryIndex = d.index;
    std::snprintf(plan.primaryName, sizeof(plan.primaryName), "%s", d.name);
    std::snprintf(plan.primaryStableId, sizeof(plan.primaryStableId), "%s", d.stableId);
}

} // namespace

bool Deep2Device_Enumerate(DeviceManagerSnapshot& snap) noexcept {
    snap = DeviceManagerSnapshot{};
#ifdef _WIN32
    IDXGIFactory* factory = nullptr;
    if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory),
                                 reinterpret_cast<void**>(&factory))) || !factory)
        return false;
    IDXGIAdapter* adapter = nullptr;
    for (UINT i = 0; factory->EnumAdapters(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
        if (!adapter) continue;
        DXGI_ADAPTER_DESC d{};
        if (SUCCEEDED(adapter->GetDesc(&d)) && d.VendorId != 0x1414 &&
            snap.deviceCount < 8) {
            DeviceIdentity& id = snap.devices[snap.deviceCount];
            id.index = (int)snap.deviceCount;
            WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, id.name,
                                (int)sizeof(id.name), nullptr, nullptr);
            id.vendorId = d.VendorId;
            id.deviceId = d.DeviceId;
            id.luid = (uint64_t(d.AdapterLuid.HighPart) << 32) |
                      uint64_t(uint32_t(d.AdapterLuid.LowPart));
            id.dedicatedVram = (uint64_t)d.DedicatedVideoMemory;
            id.sharedVram = (uint64_t)d.SharedSystemMemory;
            id.integrated = id.dedicatedVram < (1ull << 30);
            id.score = Deep2Device_ScoreAdapter(id.dedicatedVram, id.sharedVram,
                                                NameFlags(id.name, id.dedicatedVram));
            id.healthy = true;
            id.duty = DeviceDuty::Unused;
            MakeStableId(id);
            ++snap.deviceCount;
        }
        adapter->Release();
        adapter = nullptr;
    }
    factory->Release();
    snap.plan.detected = snap.deviceCount;
    return snap.deviceCount > 0;
#else
    return false;
#endif
}

bool Deep2Device_ApplyPolicy(DeviceManagerSnapshot& snap) noexcept {
    DevicePlan& plan = snap.plan;
    plan = DevicePlan{};
    plan.detected = snap.deviceCount;
    plan.policy = ParsePolicy();
    plan.backend = "CPU_NATIVE";
    plan.mode = ExecMode::CpuNative;
    plan.reason = "no_usable_gpu";
    plan.primaryIndex = -1;

    if (plan.policy == GpuPolicy::CpuOnly || snap.deviceCount == 0) {
        plan.reason = "policy_cpu";
        return false;
    }

    int userList[8]{};
    unsigned userN = 0;
    bool cpuSentinel = false;
    const bool hasList = ParseDeviceList(userList, userN, cpuSentinel);
    if (cpuSentinel) {
        plan.reason = "user_devices_cpu";
        plan.policy = GpuPolicy::CpuOnly;
        return false;
    }

    const char* needle = std::getenv("DEEP2_GPU_SELECT");
    if (!needle || !*needle) needle = std::getenv("RAWRXD_GPU_SELECT");
    if (!needle || !*needle) needle = std::getenv("RAWRXD_GPU_NAME");

    if (needle && *needle) {
        for (unsigned i = 0; i < snap.deviceCount; ++i) {
            const DeviceIdentity& d = snap.devices[i];
            if (d.integrated) continue;
            if (!HasI(d.name, needle) && !HasI(d.stableId, needle)) continue;
            plan.openIndexes[0] = d.index;
            plan.openCount = 1;
            plan.opened = 1;
            SetPrimary(plan, d);
            plan.mode = ExecMode::SingleGpu;
            plan.backend = "GPU";
            plan.reason = "user_select_needle";
            snap.devices[i].duty = DeviceDuty::ComputePrimary;
            return true;
        }
    }

    if (hasList) {
        if (userN == 1 && userList[0] == -1) {
            for (unsigned i = 0; i < snap.deviceCount && plan.openCount < 8; ++i) {
                if (!snap.devices[i].integrated && snap.devices[i].score >= 10)
                    plan.openIndexes[plan.openCount++] = snap.devices[i].index;
            }
        } else {
            for (unsigned i = 0; i < userN && plan.openCount < 8; ++i) {
                const int idx = userList[i];
                if (idx >= 0 && idx < (int)snap.deviceCount)
                    plan.openIndexes[plan.openCount++] = idx;
            }
        }
        if (plan.openCount == 0) {
            plan.reason = "user_devices_empty";
            return false;
        }
        SetPrimary(plan, snap.devices[plan.openIndexes[0]]);
        plan.opened = plan.openCount;
        plan.mode = plan.opened > 1 ? ExecMode::MultiGpuShard : ExecMode::SingleGpu;
        plan.backend = plan.opened > 1 ? "MULTIGPU" : "GPU";
        plan.reason = "user_device_list";
        plan.policy = GpuPolicy::UserList;
        for (unsigned i = 0; i < plan.openCount; ++i) {
            const int di = plan.openIndexes[i];
            snap.devices[di].duty = (di == plan.primaryIndex)
                ? DeviceDuty::ComputePrimary : DeviceDuty::ComputeSecondary;
        }
        return true;
    }

    unsigned scores[8]{};
    unsigned long long vram[8]{};
    for (unsigned i = 0; i < snap.deviceCount; ++i) {
        scores[i] = snap.devices[i].score;
        vram[i] = snap.devices[i].dedicatedVram;
    }
    const int best = Deep2Device_PickBestIndex(scores, vram, snap.deviceCount, 10u);
    if (best < 0) {
        plan.reason = "no_discrete_gpu";
        return false;
    }
    plan.openIndexes[0] = best;
    plan.openCount = 1;
    plan.opened = 1;
    SetPrimary(plan, snap.devices[best]);
    plan.mode = ExecMode::SingleGpu;
    plan.backend = "GPU";
    plan.reason = (plan.policy == GpuPolicy::Multi) ? "auto_single_until_multi_ready"
                                                    : "auto_best_compute";
    snap.devices[best].duty = DeviceDuty::ComputePrimary;
    return true;
}

const char* Deep2Device_VulkanNeedle(const DeviceManagerSnapshot& snap) noexcept {
    if (snap.plan.primaryIndex < 0) return "";
    return snap.plan.primaryName;
}

void Deep2Device_EmitWitnesses(FILE* f, const DeviceManagerSnapshot& snap) noexcept {
    auto emit = [&](FILE* o) {
        if (!o) return;
        const DevicePlan& p = snap.plan;
        fprintf(o, "DEEP2_DEVICE_COUNT_DETECTED=%u\n", p.detected);
        fprintf(o, "DEEP2_DEVICE_COUNT_OPENED=%u\n", p.opened);
        fprintf(o, "DEEP2_COMPUTE_BACKEND=%s\n", p.backend);
        const char* execPath = "CPU_NATIVE";
        if (p.mode == ExecMode::SingleGpu) execPath = "SINGLE_GPU";
        else if (p.mode == ExecMode::MultiGpuShard) execPath = "MULTIGPU";
        else if (p.mode == ExecMode::Speculative) execPath = "SPECULATIVE";
        fprintf(o, "DEEP2_EXEC_PATH=%s\n", execPath);
        fprintf(o, "DEEP2_EXEC_MODE=%u\n", (unsigned)p.mode);
        fprintf(o, "DEEP2_GPU_POLICY=%u\n", (unsigned)p.policy);
        fprintf(o, "DEEP2_PLAN_REASON=%s\n", p.reason);
        if (p.primaryIndex >= 0) {
            fprintf(o, "DEEP2_PRIMARY_INDEX=%d\n", p.primaryIndex);
            fprintf(o, "DEEP2_PRIMARY_STABLE_ID=%s\n", p.primaryStableId);
            fprintf(o, "DEEP2_PRIMARY_NAME=%s\n", p.primaryName);
        }
        for (unsigned i = 0; i < snap.deviceCount; ++i) {
            const DeviceIdentity& d = snap.devices[i];
            DeviceDuty duty = d.duty;
            if (duty == DeviceDuty::Unused) {
                for (unsigned j = 0; j < p.openCount; ++j) {
                    if (p.openIndexes[j] != d.index) continue;
                    duty = (d.index == p.primaryIndex) ? DeviceDuty::ComputePrimary
                                                       : DeviceDuty::ComputeSecondary;
                    break;
                }
            }
            fprintf(o, "DEEP2_DEVICE_%u_NAME=%s\n", i, d.name);
            fprintf(o, "DEEP2_DEVICE_%u_VENDOR=%s\n", i, VendorName(d.vendorId));
            fprintf(o, "DEEP2_DEVICE_%u_STABLE_ID=%s\n", i, d.stableId);
            fprintf(o, "DEEP2_DEVICE_%u_VRAM_BYTES=%llu\n", i,
                    (unsigned long long)d.dedicatedVram);
            fprintf(o, "DEEP2_DEVICE_%u_SCORE=%u\n", i, d.score);
            fprintf(o, "DEEP2_DEVICE_%u_DUTY=%s\n", i, DutyName(duty));
        }
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2
