// Deep2DeviceManager.cpp � DXGI enumerate + capability policy (no card hard-codes)
#include "Deep2DeviceManager.hpp"
#include <cstring>
#include <cstdlib>
#include <algorithm>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <dxgi.h>
#include <cfgmgr32.h>
#include <setupapi.h>
#include <devguid.h>
#include <initguid.h>
#include <devpkey.h>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#ifndef CM_PROB_FAILED_ADD
#define CM_PROB_FAILED_ADD 31
#endif
#ifndef CR_ACCESS_DENIED
#define CR_ACCESS_DENIED ((CONFIGRET)0x33)
#endif
#pragma comment(lib, "advapi32.lib")
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
    if (HasI(p, "SINGLE") || HasI(p, "SOLO")) return GpuPolicy::Single;
    if (HasI(p, "DUAL_LANE") || HasI(p, "DUAL_SOVEREIGN") ||
        HasI(p, "SOVEREIGN_DUAL"))
        return GpuPolicy::DualLane;
    if (HasI(p, "HYBRID")) return GpuPolicy::Hybrid;
    if (HasI(p, "MULTI") || HasI(p, "ALL") || HasI(p, "DUAL"))
        return GpuPolicy::Multi;
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

bool Usable(const DeviceIdentity& d) noexcept {
    return d.healthy && d.problemCode == 0;
}

#ifdef _WIN32
bool DeviceResetOptIn() noexcept {
    const char* p = std::getenv("DEEP2_GPU_DEVICE_RESET");
    if (!p || !*p) p = std::getenv("RAWRXD_GPU_DEVICE_RESET");
    return p && (HasI(p, "1") || HasI(p, "ON") || HasI(p, "TRUE") || HasI(p, "YES"));
}

bool IsProcessElevated() noexcept {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD returned = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation,
                                        sizeof(elevation), &returned);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

bool MatchHwId(const wchar_t* hw, uint32_t vendorId, uint32_t deviceId) noexcept {
    if (!hw) return false;
    wchar_t needle[64];
    _snwprintf_s(needle, _TRUNCATE, L"VEN_%04X&DEV_%04X", vendorId & 0xFFFFu,
                 deviceId & 0xFFFFu);
    for (const wchar_t* p = hw; *p; ++p) {
        const wchar_t* a = p;
        const wchar_t* b = needle;
        while (*a && *b) {
            wchar_t ca = (*a >= L'a' && *a <= L'z') ? (wchar_t)(*a - 32) : *a;
            wchar_t cb = (*b >= L'a' && *b <= L'z') ? (wchar_t)(*b - 32) : *b;
            if (ca != cb) break;
            ++a;
            ++b;
        }
        if (!*b) return true;
    }
    return false;
}

bool QueryProblemForIds(uint32_t vendorId, uint32_t deviceId, ULONG* outCode,
                        char* instOut, size_t instChars) noexcept {
    if (outCode) *outCode = 0;
    if (instOut && instChars) instOut[0] = 0;
    // Prefer PRESENT; fall back to class-wide enum for FAILED_ADD nodes.
    const DWORD flagsTry[2] = {DIGCF_PRESENT, 0};
    for (int pass = 0; pass < 2; ++pass) {
        HDEVINFO di = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, nullptr,
                                           nullptr, flagsTry[pass]);
        if (di == INVALID_HANDLE_VALUE) continue;
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        for (DWORD i = 0; SetupDiEnumDeviceInfo(di, i, &info); ++i) {
            wchar_t hw[1024]{};
            if (!SetupDiGetDeviceRegistryPropertyW(di, &info, SPDRP_HARDWAREID,
                                                   nullptr, (PBYTE)hw,
                                                   sizeof(hw), nullptr))
                continue;
            if (!MatchHwId(hw, vendorId, deviceId)) continue;
            wchar_t iid[256]{};
            SetupDiGetDeviceInstanceIdW(di, &info, iid, 256, nullptr);
            ULONG status = 0, problem = 0;
            ULONG code = 0;
            if (CM_Get_DevNode_Status(&status, &problem, info.DevInst, 0) ==
                    CR_SUCCESS &&
                (status & DN_HAS_PROBLEM))
                code = problem;
            else {
                DEVPROPTYPE pt = 0;
                DWORD sz = sizeof(code);
                ULONG prop = 0;
                if (SetupDiGetDevicePropertyW(di, &info,
                                              &DEVPKEY_Device_ProblemCode, &pt,
                                              (PBYTE)&prop, sz, &sz, 0))
                    code = prop;
            }
            if (outCode) *outCode = code;
            if (instOut && instChars)
                WideCharToMultiByte(CP_UTF8, 0, iid, -1, instOut,
                                    (int)instChars, nullptr, nullptr);
            SetupDiDestroyDeviceInfoList(di);
            return true;
        }
        SetupDiDestroyDeviceInfoList(di);
    }
    return false;
}

bool AttemptDevNodeReset(const char* instanceIdUtf8, bool* accessDenied) noexcept {
    if (accessDenied) *accessDenied = false;
    if (!instanceIdUtf8 || !*instanceIdUtf8) return false;
    // CM_Disable_DevNode/CM_Enable_DevNode require elevation.  Refuse before
    // touching the device tree so a normal IDE launch never performs a futile
    // privileged call or reports a misleading reset attempt.
    if (!IsProcessElevated()) {
        if (accessDenied) *accessDenied = true;
        return false;
    }
    wchar_t iid[256]{};
    MultiByteToWideChar(CP_UTF8, 0, instanceIdUtf8, -1, iid, 256);
    DEVINST node = 0;
    CONFIGRET loc = CM_Locate_DevNodeW(&node, iid, CM_LOCATE_DEVNODE_NORMAL);
    if (loc != CR_SUCCESS)
        loc = CM_Locate_DevNodeW(&node, iid, CM_LOCATE_DEVNODE_PHANTOM);
    if (loc != CR_SUCCESS) return false;
    CONFIGRET cr = CM_Disable_DevNode(node, 0);
    if (cr == CR_ACCESS_DENIED) {
        if (accessDenied) *accessDenied = true;
        return false;
    }
    if (cr != CR_SUCCESS && cr != CR_NO_SUCH_DEVNODE) return false;
    Sleep(750);
    cr = CM_Enable_DevNode(node, 0);
    if (cr == CR_ACCESS_DENIED) {
        if (accessDenied) *accessDenied = true;
        return false;
    }
    return cr == CR_SUCCESS;
}

#ifdef _WIN32
// DXGI omits adapters in CM_PROB_FAILED_ADD; merge those PnP display GPUs in.
void MergeUnlistedPnPDisplays(DeviceManagerSnapshot& snap) noexcept {
    const DWORD flagsTry[2] = {DIGCF_PRESENT, 0};
    for (int pass = 0; pass < 2 && snap.deviceCount < 8; ++pass) {
        HDEVINFO di = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, nullptr,
                                           nullptr, flagsTry[pass]);
        if (di == INVALID_HANDLE_VALUE) continue;
        SP_DEVINFO_DATA info{};
        info.cbSize = sizeof(info);
        for (DWORD i = 0; SetupDiEnumDeviceInfo(di, i, &info) &&
             snap.deviceCount < 8; ++i) {
            wchar_t hw[1024]{};
            if (!SetupDiGetDeviceRegistryPropertyW(di, &info, SPDRP_HARDWAREID,
                                                   nullptr, (PBYTE)hw,
                                                   sizeof(hw), nullptr))
                continue;
            // Parse first PCI\VEN_xxxx&DEV_yyyy
            const wchar_t* p = hw;
            uint32_t ven = 0, dev = 0;
            bool parsed = false;
            while (*p) {
                if ((p[0] == L'V' || p[0] == L'v') &&
                    (p[1] == L'E' || p[1] == L'e') &&
                    (p[2] == L'N' || p[2] == L'n') && p[3] == L'_') {
                    wchar_t* end = nullptr;
                    ven = (uint32_t)wcstoul(p + 4, &end, 16);
                    if (end && wcsncmp(end, L"&DEV_", 5) == 0) {
                        dev = (uint32_t)wcstoul(end + 5, nullptr, 16);
                        parsed = true;
                    }
                    break;
                }
                ++p;
            }
            if (!parsed || ven == 0 || ven == 0x1414) continue;
            bool exists = false;
            for (unsigned j = 0; j < snap.deviceCount; ++j) {
                if (snap.devices[j].vendorId == ven &&
                    snap.devices[j].deviceId == dev) {
                    exists = true;
                    break;
                }
            }
            if (exists) continue;
            DeviceIdentity& id = snap.devices[snap.deviceCount];
            id = DeviceIdentity{};
            id.index = (int)snap.deviceCount;
            id.vendorId = ven;
            id.deviceId = dev;
            id.healthy = true;
            id.duty = DeviceDuty::Unused;
            wchar_t desc[128]{};
            if (!SetupDiGetDeviceRegistryPropertyW(di, &info, SPDRP_FRIENDLYNAME,
                                                   nullptr, (PBYTE)desc,
                                                   sizeof(desc), nullptr))
                SetupDiGetDeviceRegistryPropertyW(di, &info, SPDRP_DEVICEDESC,
                                                  nullptr, (PBYTE)desc,
                                                  sizeof(desc), nullptr);
            WideCharToMultiByte(CP_UTF8, 0, desc, -1, id.name,
                                (int)sizeof(id.name), nullptr, nullptr);
            if (!id.name[0])
                std::snprintf(id.name, sizeof(id.name), "PCI %04X:%04X",
                              ven & 0xFFFFu, dev & 0xFFFFu);
            wchar_t iid[256]{};
            SetupDiGetDeviceInstanceIdW(di, &info, iid, 256, nullptr);
            WideCharToMultiByte(CP_UTF8, 0, iid, -1, id.instanceId,
                                (int)sizeof(id.instanceId), nullptr, nullptr);
            MakeStableId(id);
            id.score = 0;
            id.integrated = false;
            ++snap.deviceCount;
        }
        SetupDiDestroyDeviceInfoList(di);
    }
}
#endif

#endif

} // namespace

void Deep2Device_RefreshPnPHealth(DeviceManagerSnapshot& snap) noexcept {
#ifdef _WIN32
    for (unsigned i = 0; i < snap.deviceCount; ++i) {
        DeviceIdentity& d = snap.devices[i];
        ULONG code = 0;
        if (!QueryProblemForIds(d.vendorId, d.deviceId, &code, d.instanceId,
                                sizeof(d.instanceId))) {
            continue; // leave healthy=true if PnP match unknown
        }
        d.problemCode = (uint32_t)code;
        if (code == 0) {
            d.healthy = true;
            continue;
        }
        // Any CM_PROB_* (incl. 31 FAILED_ADD): unhealthy. Device-node reset is
        // deliberately opt-in and requires an elevated process; a skipped or
        // denied reset never changes the unhealthy disposition.
        d.healthy = false;
        d.duty = DeviceDuty::Excluded;
        d.resetAttempted = false;
        d.resetOk = false;
        d.resetSkipped = false;
        d.resetRequiresElevation = false;
        if (!DeviceResetOptIn()) {
            d.resetSkipped = true;
        } else if (!IsProcessElevated()) {
            d.resetSkipped = true;
            d.resetRequiresElevation = true;
            d.accessDenied = true;
        } else {
            d.resetAttempted = true;
            d.resetOk = AttemptDevNodeReset(d.instanceId, &d.accessDenied);
            Sleep(500);
        }
        ULONG after = 0;
        QueryProblemForIds(d.vendorId, d.deviceId, &after, d.instanceId,
                           sizeof(d.instanceId));
        d.problemCode = (uint32_t)after;
        d.healthy = (after == 0);
        if (d.healthy)
            d.duty = DeviceDuty::Unused;
        std::fprintf(stderr,
                     "[Deep2Device] PnP name=%s PROBLEM_CODE=%u "
                     "RESET_ATTEMPTED=%d RESET_OK=%d RESET_SKIPPED=%d "
                     "RESET_REQUIRES_ELEVATION=%d ACCESS_DENIED=%d "
                     "HEALTHY=%d instance=%s\n",
                     d.name, d.problemCode, (int)d.resetAttempted,
                     (int)d.resetOk, (int)d.resetSkipped,
                     (int)d.resetRequiresElevation, (int)d.accessDenied,
                     (int)d.healthy,
                     d.instanceId);
        std::fflush(stderr);
    }
#else
    (void)snap;
#endif
}

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
            id.problemCode = 0;
            id.resetAttempted = false;
            id.resetOk = false;
            id.resetSkipped = false;
            id.resetRequiresElevation = false;
            id.duty = DeviceDuty::Unused;
            MakeStableId(id);
            bool dupPci = false;
            for (unsigned j = 0; j < snap.deviceCount; ++j) {
                if (snap.devices[j].vendorId != id.vendorId ||
                    snap.devices[j].deviceId != id.deviceId)
                    continue;
                if (id.dedicatedVram > snap.devices[j].dedicatedVram) {
                    const int keepIdx = snap.devices[j].index;
                    snap.devices[j] = id;
                    snap.devices[j].index = keepIdx;
                }
                dupPci = true;
                break;
            }
            if (!dupPci)
                ++snap.deviceCount;
        }
        adapter->Release();
        adapter = nullptr;
    }
    factory->Release();
    MergeUnlistedPnPDisplays(snap);
    snap.plan.detected = snap.deviceCount;
    Deep2Device_RefreshPnPHealth(snap);
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

    // DUAL_LANE before needle: two sovereign loaders; select is lane-hint only.
    if (plan.policy == GpuPolicy::DualLane) {
        int best[2] = {-1, -1};
        unsigned bestScore[2] = {0, 0};
        int needleIdx = -1;
        for (unsigned i = 0; i < snap.deviceCount; ++i) {
            const DeviceIdentity& d = snap.devices[i];
            if (!Usable(d) || d.integrated || d.score < 10) continue;
            if (needle && *needle &&
                (HasI(d.name, needle) || HasI(d.stableId, needle)))
                needleIdx = (int)i;
            if (best[0] < 0 || d.score > bestScore[0] ||
                (d.score == bestScore[0] &&
                 d.dedicatedVram > snap.devices[best[0]].dedicatedVram)) {
                best[1] = best[0];
                bestScore[1] = bestScore[0];
                best[0] = (int)i;
                bestScore[0] = d.score;
            } else if (best[1] < 0 || d.score > bestScore[1]) {
                best[1] = (int)i;
                bestScore[1] = d.score;
            }
        }
        if (needleIdx >= 0 && best[0] != needleIdx) {
            best[1] = best[0];
            bestScore[1] = bestScore[0];
            best[0] = needleIdx;
            bestScore[0] = snap.devices[needleIdx].score;
        }
        if (best[0] < 0 || best[1] < 0 || best[0] == best[1]) {
            plan.reason = "dual_lane_needs_two_discrete";
            return false;
        }
        plan.openIndexes[0] = snap.devices[best[0]].index;
        plan.openIndexes[1] = snap.devices[best[1]].index;
        plan.openCount = 2;
        plan.opened = 2;
        SetPrimary(plan, snap.devices[best[0]]);
        plan.mode = ExecMode::DualSovereign;
        plan.backend = "DUAL_SOVEREIGN";
        plan.reason = "dual_lane_sovereign_loaders";
        snap.devices[best[0]].duty = DeviceDuty::ComputePrimary;
        snap.devices[best[1]].duty = DeviceDuty::ComputeSecondary;
        return true;
    }

    if (needle && *needle) {
        for (unsigned i = 0; i < snap.deviceCount; ++i) {
            const DeviceIdentity& d = snap.devices[i];
            if (!Usable(d) || d.integrated) continue;
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
                if (Usable(snap.devices[i]) && !snap.devices[i].integrated &&
                    snap.devices[i].score >= 10)
                    plan.openIndexes[plan.openCount++] = snap.devices[i].index;
            }
        } else {
            for (unsigned i = 0; i < userN && plan.openCount < 8; ++i) {
                const int idx = userList[i];
                if (idx >= 0 && idx < (int)snap.deviceCount &&
                    Usable(snap.devices[idx]))
                    plan.openIndexes[plan.openCount++] = idx;
            }
        }
        if (plan.openCount == 0) {
            plan.reason = "user_devices_empty";
            return false;
        }
        SetPrimary(plan, snap.devices[plan.openIndexes[0]]);
        plan.opened = plan.openCount;
        if (plan.policy == GpuPolicy::Hybrid) {
            plan.mode = ExecMode::Hybrid;
            plan.backend = "HYBRID";
            plan.reason = "hybrid_device_list";
        } else {
            plan.mode = plan.opened > 1 ? ExecMode::MultiGpuShard : ExecMode::SingleGpu;
            plan.backend = plan.opened > 1 ? "MULTIGPU" : "GPU";
            plan.reason = "user_device_list";
            plan.policy = GpuPolicy::UserList;
        }
        for (unsigned i = 0; i < plan.openCount; ++i) {
            const int di = plan.openIndexes[i];
            snap.devices[di].duty = (di == plan.primaryIndex)
                ? DeviceDuty::ComputePrimary : DeviceDuty::ComputeSecondary;
        }
        return true;
    }

    // NOTE: MultiGpuShard shares residency � prefer DUAL_LANE for dual-model.
    // HYBRID / MULTI: DEEP2_GPU_DEVICE_CLASS=DISCRETE excludes iGPU.
    const char* dclass = std::getenv("DEEP2_GPU_DEVICE_CLASS");
    if (!dclass || !*dclass) dclass = std::getenv("RAWRXD_GPU_DEVICE_CLASS");
    const bool discreteOnly =
        !dclass || !*dclass || HasI(dclass, "DISCRETE") || HasI(dclass, "DGPU");

    if (plan.policy == GpuPolicy::Hybrid || plan.policy == GpuPolicy::Multi) {
        for (unsigned i = 0; i < snap.deviceCount && plan.openCount < 8; ++i) {
            DeviceIdentity& d = snap.devices[i];
            if (!Usable(d)) {
                d.duty = DeviceDuty::Excluded;
                continue;
            }
            if (discreteOnly && d.integrated) {
                d.duty = DeviceDuty::Excluded;
                continue;
            }
            if (d.score >= 10)
                plan.openIndexes[plan.openCount++] = d.index;
        }
        if (plan.openCount == 0) {
            plan.reason = discreteOnly ? "no_discrete_gpu" : "no_eligible_gpu";
            return false;
        }
        SetPrimary(plan, snap.devices[plan.openIndexes[0]]);
        plan.opened = plan.openCount;
        plan.mode = (plan.policy == GpuPolicy::Hybrid) ? ExecMode::Hybrid
                    : (plan.opened > 1 ? ExecMode::MultiGpuShard : ExecMode::SingleGpu);
        plan.backend = (plan.policy == GpuPolicy::Hybrid) ? "HYBRID"
                       : (plan.opened > 1 ? "MULTIGPU" : "GPU");
        plan.reason = (plan.policy == GpuPolicy::Hybrid)
                          ? "auto_hybrid_device_class"
                          : "auto_multi_device_class";
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
        if (!Usable(snap.devices[i])) {
            scores[i] = 0;
            vram[i] = 0;
            continue;
        }
        scores[i] = snap.devices[i].score;
        vram[i] = snap.devices[i].dedicatedVram;
    }

    // AUTOMATIC DUAL-GPU: when policy is Auto and two or more discrete GPUs
    // are available, engage DualLane without requiring any environment flag.
    // This makes dual-GPU work out of the box on systems like the R9700 + iGPU
    // or two discrete cards, maximizing throughput with zero user configuration.
    if (plan.policy == GpuPolicy::Auto) {
        unsigned discreteN = 0;
        int discreteIdx[2] = {-1, -1};
        unsigned long long discreteVram[2] = {0, 0};
        for (unsigned i = 0; i < snap.deviceCount && discreteN < 2; ++i) {
            const DeviceIdentity& d = snap.devices[i];
            if (!Usable(d) || d.integrated || d.score < 10 ||
                d.dedicatedVram < (1ull << 30))
                continue;
            discreteIdx[discreteN] = (int)i;
            discreteVram[discreteN] = d.dedicatedVram;
            ++discreteN;
        }
        if (discreteN >= 2) {
            // Sort by VRAM (descending) so primary gets the larger card.
            if (discreteVram[0] < discreteVram[1]) {
                std::swap(discreteIdx[0], discreteIdx[1]);
                std::swap(discreteVram[0], discreteVram[1]);
            }
            plan.openIndexes[0] = snap.devices[discreteIdx[0]].index;
            plan.openIndexes[1] = snap.devices[discreteIdx[1]].index;
            plan.openCount = 2;
            plan.opened = 2;
            SetPrimary(plan, snap.devices[discreteIdx[0]]);
            plan.mode = ExecMode::DualSovereign;
            plan.backend = "DUAL_SOVEREIGN";
            plan.policy = GpuPolicy::DualLane;
            plan.reason = "auto_dual_gpu_detected";
            snap.devices[discreteIdx[0]].duty = DeviceDuty::ComputePrimary;
            snap.devices[discreteIdx[1]].duty = DeviceDuty::ComputeSecondary;
            printf("[Deep2Engine] Auto dual-GPU: GPU0=%s (%llu MB) GPU1=%s (%llu MB)\n",
                   snap.devices[discreteIdx[0]].name,
                   discreteVram[0] / (1024ull * 1024ull),
                   snap.devices[discreteIdx[1]].name,
                   discreteVram[1] / (1024ull * 1024ull));
            return true;
        }
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
    plan.reason = "auto_best_compute";
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
        else if (p.mode == ExecMode::Hybrid) execPath = "HYBRID";
        else if (p.mode == ExecMode::Speculative) execPath = "SPECULATIVE";
        else if (p.mode == ExecMode::DualSovereign) execPath = "DUAL_SOVEREIGN";
        fprintf(o, "DEEP2_EXEC_PATH=%s\n", execPath);
        if (p.mode == ExecMode::DualSovereign) {
            fprintf(o, "SHARED_WEIGHT_ARENA=0\n");
            fprintf(o, "CROSS_GPU_WEIGHT_COPY=0\n");
            fprintf(o, "CROSS_LANE_SYNC=DEPENDENCIES_ONLY\n");
        }
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
            fprintf(o, "DEEP2_DEVICE_%u_PROBLEM_CODE=%u\n", i, d.problemCode);
            fprintf(o, "DEEP2_DEVICE_%u_HEALTHY=%d\n", i, (int)d.healthy);
            fprintf(o, "DEEP2_DEVICE_%u_RESET_ATTEMPTED=%d\n", i,
                    (int)d.resetAttempted);
            fprintf(o, "DEEP2_DEVICE_%u_RESET_OK=%d\n", i, (int)d.resetOk);
            fprintf(o, "DEEP2_DEVICE_%u_RESET_SKIPPED=%d\n", i,
                    (int)d.resetSkipped);
            fprintf(o, "DEEP2_DEVICE_%u_RESET_REQUIRES_ELEVATION=%d\n", i,
                    (int)d.resetRequiresElevation);
            fprintf(o, "DEEP2_DEVICE_%u_ACCESS_DENIED=%d\n", i, (int)d.accessDenied);
            if (d.instanceId[0])
                fprintf(o, "DEEP2_DEVICE_%u_INSTANCE_ID=%s\n", i, d.instanceId);
        }
    };
    emit(stdout);
    if (f && f != stdout) emit(f);
}

} // namespace Deep2
