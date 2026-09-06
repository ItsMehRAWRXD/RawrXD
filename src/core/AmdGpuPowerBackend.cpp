// AmdGpuPowerBackend.cpp — dynamic ADL2 OverdriveN + optional AMD PDH power
#include "AmdGpuPowerBackend.hpp"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#pragma comment(lib, "pdh.lib")
#endif

namespace rawrxd {
namespace {

std::mutex g_mu;
std::atomic<bool> g_probed{false};
std::atomic<GpuPowerSensorSource> g_source{GpuPowerSensorSource::None};
std::atomic<DWORD> g_probeThreadId{0};

static bool envFlagIsOn(const char* name) noexcept {
#ifdef _WIN32
    char v[8] = {};
    return GetEnvironmentVariableA(name, v, (DWORD)sizeof(v)) > 0 && v[0] != '0';
#else
    (void)name;
    return false;
#endif
}

static bool shouldSkipGpuPowerProbe() noexcept {
    return envFlagIsOn("RAWRXD_SKIP_GPU_POWER_PROBE") ||
           envFlagIsOn("RAWRXD_FORCE_CPU_INFERENCE") ||
           envFlagIsOn("RAWRXD_BRIDGE_CPU_ONLY");
}

static void H12AdlLog(const char* loc, const char* msg) noexcept {
    // #region agent log
    std::ofstream f("G:\\~dev\\debug-536900.log", std::ios::app);
    if (!f) return;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    f << "{\"sessionId\":\"536900\",\"timestamp\":" << ms
      << ",\"location\":\"" << loc << "\",\"message\":\"" << msg
      << "\",\"hypothesisId\":\"H12\",\"runId\":\"pre-fix\"}\n";
    // #endregion
}

#ifdef _WIN32
HMODULE g_adl = nullptr;
void* g_adlCtx = nullptr;
int g_adlAdapter = -1;

using ADL2_MAIN_CONTROL_CREATE = int(__cdecl*)(void*(__cdecl*)(int), int, void**, int);
using ADL2_MAIN_CONTROL_DESTROY = int(__cdecl*)(void*);
using ADL2_ADAPTER_NUMBEROFADAPTERS_GET = int(__cdecl*)(void*, int*);
using ADL2_ADAPTER_ADAPTERINFOX2_GET = int(__cdecl*)(void*, int, void*);
using ADL2_OVERDRIVE_CAPS = int(__cdecl*)(void*, int, int*);
using ADL2_OVERDRIVEN_PERFORMANCESTATUS_GET =
    int(__cdecl*)(void*, int, int, void*);

struct ADLAdapterInfoX2 {
    int iSize;
    int iAdapterIndex;
    char strUDID[256];
    int iBusNumber;
    int iDeviceNumber;
    int iFunctionNumber;
    int iVendorID;
    int iSystemID;
    int iRevID;
    int iSubSystemID;
    int iSubSystemVendorID;
    char strAdapterName[256];
    char strDisplayName[256];
    int iPresent;
    int iExist;
    char strDriverPath[256];
    int iOSDisplayIndex;
};

struct ADLODNPerformanceStatus {
    int iClock;
    int iClockMax;
    int iClockMin;
    int iTemperature;
    int iPower;
    int iReserved;
};

ADL2_MAIN_CONTROL_CREATE pCreate = nullptr;
ADL2_MAIN_CONTROL_DESTROY pDestroy = nullptr;
ADL2_ADAPTER_NUMBEROFADAPTERS_GET pNumAdapters = nullptr;
ADL2_ADAPTER_ADAPTERINFOX2_GET pAdapterInfoX2 = nullptr;
ADL2_OVERDRIVE_CAPS pOdCaps = nullptr;
ADL2_OVERDRIVEN_PERFORMANCESTATUS_GET pOdPerf = nullptr;

PDH_HQUERY g_pdhQ = nullptr;
PDH_HCOUNTER g_pdhCounter = nullptr;

static void* __cdecl AdlAlloc(int sz) { return malloc(static_cast<size_t>(sz)); }

static bool PdhAddAmd(PDH_HQUERY q, PDH_HCOUNTER* out) {
    const char* paths[] = {"\\AMD GPU(*)\\Power", nullptr};
    for (int i = 0; paths[i]; ++i) {
        if (PdhAddCounterA(q, paths[i], 0, out) == ERROR_SUCCESS)
            return true;
    }
    return false;
}

static bool ProbeAdl2() {
    if (shouldSkipGpuPowerProbe())
        return false;
    // #region agent log
    H12AdlLog("ProbeAdl2", "load_library_enter");
    // #endregion
    g_adl = LoadLibraryA("atiadlxx.dll");
    if (!g_adl) return false;
    pCreate = reinterpret_cast<ADL2_MAIN_CONTROL_CREATE>(
        GetProcAddress(g_adl, "ADL2_Main_Control_Create"));
    pDestroy = reinterpret_cast<ADL2_MAIN_CONTROL_DESTROY>(
        GetProcAddress(g_adl, "ADL2_Main_Control_Destroy"));
    pNumAdapters = reinterpret_cast<ADL2_ADAPTER_NUMBEROFADAPTERS_GET>(
        GetProcAddress(g_adl, "ADL2_Adapter_NumberOfAdapters_Get"));
    pAdapterInfoX2 = reinterpret_cast<ADL2_ADAPTER_ADAPTERINFOX2_GET>(
        GetProcAddress(g_adl, "ADL2_Adapter_AdapterInfoX2_Get"));
    pOdCaps = reinterpret_cast<ADL2_OVERDRIVE_CAPS>(
        GetProcAddress(g_adl, "ADL2_Overdrive_Caps"));
    pOdPerf = reinterpret_cast<ADL2_OVERDRIVEN_PERFORMANCESTATUS_GET>(
        GetProcAddress(g_adl, "ADL2_OverdriveN_PerformanceStatus_Get"));
    if (!pCreate || !pDestroy || !pNumAdapters || !pAdapterInfoX2 || !pOdPerf)
        return false;
    if (pCreate(AdlAlloc, 1, &g_adlCtx, 0) != 0 || !g_adlCtx)
        return false;
    int n = 0;
    if (pNumAdapters(g_adlCtx, &n) != 0 || n <= 0)
        return false;
    std::vector<ADLAdapterInfoX2> infos(static_cast<size_t>(n));
    for (auto& a : infos) a.iSize = sizeof(ADLAdapterInfoX2);
    if (pAdapterInfoX2(g_adlCtx, n, infos.data()) != 0)
        return false;
    for (const auto& a : infos) {
        if (a.iVendorID != 0x1002 || !a.iPresent) continue;
        int caps = 0;
        if (pOdCaps && pOdCaps(g_adlCtx, a.iAdapterIndex, &caps) != 0)
            continue;
        ADLODNPerformanceStatus st{};
        if (pOdPerf(g_adlCtx, a.iAdapterIndex, 0, &st) != 0)
            continue;
        if (st.iPower > 0) {
            g_adlAdapter = a.iAdapterIndex;
            return true;
        }
    }
    return false;
}

static bool ProbePdh() {
    if (PdhOpenQuery(nullptr, 0, &g_pdhQ) != ERROR_SUCCESS)
        return false;
    if (!PdhAddAmd(g_pdhQ, &g_pdhCounter)) {
        PdhCloseQuery(g_pdhQ);
        g_pdhQ = nullptr;
        return false;
    }
    PdhCollectQueryData(g_pdhQ);
    PdhCollectQueryData(g_pdhQ);
    PDH_FMT_COUNTERVALUE v{};
    if (PdhGetFormattedCounterValue(g_pdhCounter, PDH_FMT_DOUBLE, nullptr, &v) != ERROR_SUCCESS ||
        v.CStatus != PDH_CSTATUS_VALID_DATA || v.doubleValue <= 0.0) {
        PdhCloseQuery(g_pdhQ);
        g_pdhQ = nullptr;
        g_pdhCounter = nullptr;
        return false;
    }
    return true;
}

static bool SampleAdl2(double& w) {
    if (shouldSkipGpuPowerProbe())
        return false;
    // #region agent log
    H12AdlLog("SampleAdl2", "sample_enter");
    // #endregion
    if (!g_adlCtx || g_adlAdapter < 0 || !pOdPerf) return false;
    ADLODNPerformanceStatus st{};
    if (pOdPerf(g_adlCtx, g_adlAdapter, 0, &st) != 0)
        return false;
    if (st.iPower <= 0) return false;
    w = static_cast<double>(st.iPower);
    return true;
}

static bool SamplePdh(double& w) {
    if (!g_pdhQ || !g_pdhCounter) return false;
    PdhCollectQueryData(g_pdhQ);
    PDH_FMT_COUNTERVALUE v{};
    if (PdhGetFormattedCounterValue(g_pdhCounter, PDH_FMT_DOUBLE, nullptr, &v) != ERROR_SUCCESS)
        return false;
    if (v.CStatus != PDH_CSTATUS_VALID_DATA || v.doubleValue <= 0.0)
        return false;
    w = v.doubleValue;
    return true;
}
#endif

} // namespace

const char* GpuPowerSensorSourceName(GpuPowerSensorSource s) noexcept {
    switch (s) {
    case GpuPowerSensorSource::Adl2OverdriveN: return "ADL2_OverdriveN_PerformanceStatus";
    case GpuPowerSensorSource::PdhAmdGpuCounter: return "PDH_AMD_GPU_Power";
    default: return "none";
    }
}

bool GpuPowerProbeSuppressed() noexcept {
    return shouldSkipGpuPowerProbe();
}

#ifdef _WIN32
using LoadLibraryExW_fn = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
using LoadLibraryW_fn = HMODULE(WINAPI*)(LPCWSTR);
using LoadLibraryA_fn = HMODULE(WINAPI*)(LPCSTR);
static LoadLibraryExW_fn g_realLoadLibraryExW = nullptr;
static LoadLibraryW_fn g_realLoadLibraryW = nullptr;
static LoadLibraryA_fn g_realLoadLibraryA = nullptr;
static std::atomic<bool> g_adlBlockInstalled{false};

static bool adlNameBlockedW(const wchar_t* name) noexcept {
    if (!name || !name[0])
        return false;
    wchar_t low[MAX_PATH] = {};
    size_t i = 0;
    for (; name[i] && i + 1 < MAX_PATH; ++i) {
        const wchar_t c = name[i];
        low[i] = (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
    }
    low[i] = 0;
    return wcsstr(low, L"atiadlxx") != nullptr || wcsstr(low, L"atiadlxy") != nullptr ||
           wcsstr(low, L"amdocl") != nullptr || wcsstr(low, L"amd_ags") != nullptr;
}

static bool adlNameBlockedA(const char* name) noexcept {
    if (!name || !name[0])
        return false;
    char low[MAX_PATH] = {};
    size_t i = 0;
    for (; name[i] && i + 1 < MAX_PATH; ++i) {
        const unsigned char c = static_cast<unsigned char>(name[i]);
        low[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c);
    }
    low[i] = 0;
    return strstr(low, "atiadlxx") != nullptr || strstr(low, "atiadlxy") != nullptr ||
           strstr(low, "amdocl") != nullptr || strstr(low, "amd_ags") != nullptr;
}

static HMODULE WINAPI HookLoadLibraryExW(LPCWSTR n, HANDLE h, DWORD f) {
    if (shouldSkipGpuPowerProbe() && adlNameBlockedW(n)) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return nullptr;
    }
    return g_realLoadLibraryExW ? g_realLoadLibraryExW(n, h, f) : nullptr;
}

static HMODULE WINAPI HookLoadLibraryW(LPCWSTR n) {
    if (shouldSkipGpuPowerProbe() && adlNameBlockedW(n)) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return nullptr;
    }
    return g_realLoadLibraryW ? g_realLoadLibraryW(n) : nullptr;
}

static HMODULE WINAPI HookLoadLibraryA(LPCSTR n) {
    if (shouldSkipGpuPowerProbe() && adlNameBlockedA(n)) {
        SetLastError(ERROR_MOD_NOT_FOUND);
        return nullptr;
    }
    return g_realLoadLibraryA ? g_realLoadLibraryA(n) : nullptr;
}

static bool patchIatOne(HMODULE mod, const char* dll, const char* func, void* hook,
                        void** orig) noexcept {
    if (!mod || !dll || !func || !hook || !orig)
        return false;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    auto* nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(mod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress)
        return false;
    auto* imp = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        reinterpret_cast<BYTE*>(mod) + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        const char* name =
            reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(mod) + imp->Name);
        if (_stricmp(name, dll) != 0)
            continue;
        auto* thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(mod) + imp->FirstThunk);
        auto* origThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
            reinterpret_cast<BYTE*>(mod) +
            (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        for (; origThunk->u1.AddressOfData; ++thunk, ++origThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
                continue;
            auto* ibn = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                reinterpret_cast<BYTE*>(mod) + origThunk->u1.AddressOfData);
            if (strcmp(reinterpret_cast<const char*>(ibn->Name), func) != 0)
                continue;
            DWORD oldProt = 0;
            if (!VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt))
                return false;
            *orig = reinterpret_cast<void*>(thunk->u1.Function);
            thunk->u1.Function = reinterpret_cast<ULONG_PTR>(hook);
            VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProt, &oldProt);
            return true;
        }
    }
    return false;
}
#endif

#if defined(_WIN32) && defined(_MSC_VER)
static bool ProbeAdl2Seh() noexcept {
    __try {
        return ProbeAdl2();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
static bool SampleAdl2Seh(double& w) noexcept {
    __try {
        return SampleAdl2(w);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
static bool ProbePdhSeh() noexcept {
    __try {
        return ProbePdh();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}
#else
static bool ProbeAdl2Seh() noexcept { return ProbeAdl2(); }
static bool SampleAdl2Seh(double& w) noexcept { return SampleAdl2(w); }
static bool ProbePdhSeh() noexcept { return ProbePdh(); }
#endif

void InstallAmdAdlLoadBlockIfSuppressed() noexcept {
#ifdef _WIN32
    if (!shouldSkipGpuPowerProbe())
        return;
    bool expected = false;
    if (!g_adlBlockInstalled.compare_exchange_strong(expected, true))
        return;
    HMODULE self = GetModuleHandleW(nullptr);
    patchIatOne(self, "KERNEL32.dll", "LoadLibraryExW",
                reinterpret_cast<void*>(&HookLoadLibraryExW),
                reinterpret_cast<void**>(&g_realLoadLibraryExW));
    patchIatOne(self, "KERNEL32.dll", "LoadLibraryW",
                reinterpret_cast<void*>(&HookLoadLibraryW),
                reinterpret_cast<void**>(&g_realLoadLibraryW));
    patchIatOne(self, "KERNEL32.dll", "LoadLibraryA",
                reinterpret_cast<void*>(&HookLoadLibraryA),
                reinterpret_cast<void**>(&g_realLoadLibraryA));
    patchIatOne(self, "api-ms-win-core-libraryloader-l1-1-0.dll", "LoadLibraryExW",
                reinterpret_cast<void*>(&HookLoadLibraryExW),
                reinterpret_cast<void**>(&g_realLoadLibraryExW));
#endif
}

void InitGpuPowerProbeMainThread() noexcept {
#ifdef _WIN32
    g_probeThreadId.store(GetCurrentThreadId(), std::memory_order_release);
    // Incomplete skip previously returned without marking g_probed; IDT_GPU_TELEMETRY /
    // ActiveGpuPowerSensor then re-entered ADL and AV'd (target=0xA / -1).
    if (shouldSkipGpuPowerProbe()) {
        InstallAmdAdlLoadBlockIfSuppressed();
        std::lock_guard<std::mutex> lk(g_mu);
        g_source.store(GpuPowerSensorSource::None, std::memory_order_relaxed);
        g_probed.store(true, std::memory_order_release);
        return;
    }
#endif
    ProbeAmdGpuPowerBackend();
}

bool GpuPowerSensorReady() noexcept {
    return g_probed.load(std::memory_order_acquire) &&
           g_source.load(std::memory_order_relaxed) != GpuPowerSensorSource::None;
}

bool ProbeAmdGpuPowerBackend() noexcept {
    if (g_probed.load(std::memory_order_acquire))
        return g_source.load(std::memory_order_relaxed) != GpuPowerSensorSource::None;
#ifdef _WIN32
    if (shouldSkipGpuPowerProbe()) {
        std::lock_guard<std::mutex> lk(g_mu);
        if (!g_probed.load(std::memory_order_relaxed)) {
            g_source.store(GpuPowerSensorSource::None, std::memory_order_relaxed);
            g_probed.store(true, std::memory_order_release);
        }
        return false;
    }
    const DWORD probeTid = g_probeThreadId.load(std::memory_order_acquire);
    if (probeTid != 0 && GetCurrentThreadId() != probeTid)
        return false;
#endif
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_probed.load(std::memory_order_relaxed))
        return g_source.load(std::memory_order_relaxed) != GpuPowerSensorSource::None;
#ifdef _WIN32
    if (ProbeAdl2Seh())
        g_source.store(GpuPowerSensorSource::Adl2OverdriveN, std::memory_order_relaxed);
    else if (ProbePdhSeh())
        g_source.store(GpuPowerSensorSource::PdhAmdGpuCounter, std::memory_order_relaxed);
#endif
    g_probed.store(true, std::memory_order_release);
    return g_source.load(std::memory_order_relaxed) != GpuPowerSensorSource::None;
}

GpuPowerSensorSource ActiveGpuPowerSensor() noexcept {
    if (shouldSkipGpuPowerProbe())
        return GpuPowerSensorSource::None;
    ProbeAmdGpuPowerBackend();
    return g_source.load(std::memory_order_relaxed);
}

bool SampleAmdGpuPowerWatts(double& watts_out) noexcept {
    watts_out = 0.0;
    if (shouldSkipGpuPowerProbe())
        return false;
    if (!g_probed.load(std::memory_order_acquire)) return false;
    std::lock_guard<std::mutex> lk(g_mu);
#ifdef _WIN32
    const auto src = g_source.load(std::memory_order_relaxed);
    const DWORD probeTid = g_probeThreadId.load(std::memory_order_acquire);
    if (src == GpuPowerSensorSource::Adl2OverdriveN) {
        if (probeTid != 0 && GetCurrentThreadId() != probeTid)
            return false;
        return SampleAdl2Seh(watts_out);
    }
    if (src == GpuPowerSensorSource::PdhAmdGpuCounter)
        return SamplePdh(watts_out);
#endif
    return false;
}

} // namespace rawrxd
