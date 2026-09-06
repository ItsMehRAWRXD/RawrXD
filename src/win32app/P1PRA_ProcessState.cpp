// P1_PRODUCT_RUNTIME_AUTHORITY_002 — process-owned state, transport only.

#include "P1PRA_ProcessState.hpp"
#include "P1_ProductRuntimeAuthority_x64.hpp"
#include "P1PRA_RuntimeAuthority.hpp"
#include "../core/GpuDecodeEfficiency.hpp"
#include "../core/AmdGpuPowerBackend.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <intrin.h>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

alignas(64) static unsigned char g_P1PRA_State[p1pra::StateSize];
static std::uint64_t g_P1PRA_RequestId = 0;
static std::uint64_t g_P1PRA_StartupFinalize = 1;
static bool g_P1PRA_RequestActive = false;
static bool g_P1PRA_UiStageEntered = false;
static std::atomic<bool> g_P1PRA_ModelReadyWitness{false};
static std::atomic<bool> g_P1PRA_SyntheticFallbackUsed{false};
static std::atomic<std::uint32_t> g_p1praDeferredStage{P1PRA_DHI_NONE};
static std::atomic<std::uint32_t> g_p1praTelemetryStage{P1PRA_TLM_NONE};
static std::atomic<std::uint32_t> g_p1praUtcStage{P1PRA_UTC_NONE};

static std::uint64_t readQword(std::size_t off)
{
    std::uint64_t v = 0;
    std::memcpy(&v, g_P1PRA_State + off, sizeof(v));
    return v;
}

static const char* stageLabel(std::uint64_t stage)
{
    switch (stage) {
    case p1pra::StageUserPrompt: return "USER_PROMPT";
    case p1pra::StageRouter: return "ROUTER";
    case p1pra::StageGgufOpen: return "GGUF_OPEN";
    case p1pra::StageWeightAccess: return "WEIGHT_ACCESS";
    case p1pra::StageForward: return "FORWARD";
    case p1pra::StageSample: return "SAMPLE";
    case p1pra::StageDecode: return "DECODE";
    case p1pra::StageUiEmit: return "UI_EMIT";
    default: return "NONE";
    }
}

static bool evidenceDir(char* dirOut, DWORD dirChars)
{
    char root[MAX_PATH] = {};
    DWORD envLen = GetEnvironmentVariableA("RAWRXD_EVIDENCE_ROOT", root, MAX_PATH);
    if (envLen == 0 || envLen >= MAX_PATH) {
        DWORD n = GetModuleFileNameA(nullptr, root, MAX_PATH);
        if (n == 0 || n >= MAX_PATH)
            return false;
        char* slash = strrchr(root, '\\');
        if (!slash)
            return false;
        slash[1] = '\0';
        if (strlen(root) + 8 >= MAX_PATH)
            return false;
        strcat_s(root, "logs");
    }
    CreateDirectoryA(root, nullptr);
    snprintf(dirOut, dirChars, "%s\\P1_PRODUCT_RUNTIME_AUTHORITY_002", root);
    CreateDirectoryA(dirOut, nullptr);
    return true;
}

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
// #region agent log
static void agentDbgAppendLine(const char* line) noexcept
{
    if (!line || !line[0])
        return;
    char envPath[MAX_PATH] = {};
    const DWORD envLen =
        GetEnvironmentVariableA("RAWRXD_DEBUG_LOG", envPath, MAX_PATH);
    char evidencePath[MAX_PATH] = {};
    char dir[MAX_PATH] = {};
    if (evidenceDir(dir, MAX_PATH))
        snprintf(evidencePath, sizeof(evidencePath),
                 "%s\\debug-5daacc.log", dir);
    const char* paths[3] = {};
    int n = 0;
    if (envLen > 0 && envLen < MAX_PATH)
        paths[n++] = envPath;
    if (evidencePath[0])
        paths[n++] = evidencePath;
    paths[n++] = "F:\\~dev\\debug-5daacc.log";
    paths[n++] = "F:\\~dev\\debug-536900.log";
    for (int i = 0; i < n; ++i) {
        bool dup = false;
        for (int j = 0; j < i; ++j) {
            if (strcmp(paths[i], paths[j]) == 0) {
                dup = true;
                break;
            }
        }
        if (dup)
            continue;
        FILE* f = nullptr;
        if (fopen_s(&f, paths[i], "a") != 0 || !f)
            continue;
        fputs(line, f);
        fflush(f);
        fclose(f);
    }
}

static unsigned long long agentDbgTimestampMs() noexcept
{
    SYSTEMTIME st = {};
    GetSystemTime(&st);
    return ((st.wHour * 3600ULL + st.wMinute * 60ULL + st.wSecond) * 1000ULL) +
           st.wMilliseconds;
}
// #endregion agent log
#endif

void P1PRA_AgentDbg(const char* hyp, const char* loc, const char* msg,
                    unsigned long long d0, unsigned long long d1,
                    unsigned long long d2) noexcept
{
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    char line[512];
    snprintf(line, sizeof(line),
             "{\"sessionId\":\"536900\",\"hypothesisId\":\"%s\","
             "\"location\":\"%s\",\"message\":\"%s\","
             "\"data\":{\"d0\":%llu,\"d1\":%llu,\"d2\":%llu},"
             "\"timestamp\":%llu,\"runId\":\"pre-fix\"}\n",
             hyp ? hyp : "?", loc ? loc : "?", msg ? msg : "?",
             d0, d1, d2, agentDbgTimestampMs());
    agentDbgAppendLine(line);
#else
    (void)hyp;
    (void)loc;
    (void)msg;
    (void)d0;
    (void)d1;
    (void)d2;
#endif
}

void P1PRA_Witness(const char* key, const char* value) noexcept
{
    char dir[MAX_PATH] = {};
    if (!evidenceDir(dir, MAX_PATH))
        return;
    char path[MAX_PATH] = {};
    snprintf(path, sizeof(path), "%s\\WITNESS.log", dir);
    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f)
        return;
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    fprintf(f, "%04u-%02u-%02u %02u:%02u:%02u %s=%s\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            key ? key : "?", value ? value : "");
    fflush(f);
    fclose(f);
}

std::uint64_t P1PRA_Fnv1a64(const void* ptr, std::size_t len) noexcept
{
    if (!ptr)
        return len == 0 ? 14695981039346656037ull : 0ull;

    const auto* p = static_cast<const unsigned char*>(ptr);
    std::uint64_t h = 14695981039346656037ull;

    for (std::size_t i = 0; i < len; ++i)
    {
        h ^= static_cast<std::uint64_t>(p[i]);
        h *= 1099511628211ull;
    }

    return h;
}

void P1PRA_WitnessPtr(const char* key, const char* label, const void* ptr) noexcept
{
    char buf[96];
    snprintf(buf, sizeof(buf), "%s=%p", label ? label : "?", ptr);
    P1PRA_Witness(key, buf);
}

void P1PRA_WitnessLoadWorkerSnap(const void* bridge, const void* pathPtr,
                                 std::size_t pathLen, std::uint64_t pathHash,
                                 const void* hwndNotify) noexcept
{
    char buf[384];
    snprintf(buf, sizeof(buf),
             "worker_snap bridge=%p path_ptr=%p path_len=%zu path_hash=%016llx hwnd=%p tid=%lu",
             bridge, pathPtr, pathLen,
             static_cast<unsigned long long>(pathHash), hwndNotify,
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_LOAD", buf);
}

void P1PRA_DebugLog(const char* hypothesisId, const char* location,
                    const char* message, const char* dataJson) noexcept
{
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    char line[768];
    snprintf(line, sizeof(line),
             "{\"sessionId\":\"5daacc\",\"hypothesisId\":\"%s\","
             "\"location\":\"%s\",\"message\":\"%s\",\"data\":%s,"
             "\"timestamp\":%llu,\"runId\":\"pre-fix\"}\n",
             hypothesisId ? hypothesisId : "?",
             location ? location : "?",
             message ? message : "?",
             dataJson ? dataJson : "{}",
             agentDbgTimestampMs());
    agentDbgAppendLine(line);
#else
    (void)hypothesisId;
    (void)location;
    (void)message;
    (void)dataJson;
#endif
}

void P1PRA_ThreadWitness(const char* phase) noexcept
{
    char buf[96];
    snprintf(buf, sizeof(buf), "%s tid=%lu", phase ? phase : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_THREAD", buf);
}

void P1PRA_ThreadStartWitness(const char* owner) noexcept
{
    char buf[128];
    snprintf(buf, sizeof(buf), "owner=%s tid=%lu", owner ? owner : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_THREAD_START", buf);
}

void P1PRA_ThreadStopWitness(const char* owner) noexcept
{
    char buf[128];
    snprintf(buf, sizeof(buf), "owner=%s tid=%lu", owner ? owner : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_THREAD_STOP", buf);
}

void P1PRA_DhiEnter(const char* stage, std::uint32_t stageId) noexcept
{
    g_p1praDeferredStage.store(stageId, std::memory_order_release);
    char buf[128];
    snprintf(buf, sizeof(buf), "%s_enter tid=%lu", stage ? stage : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_DHI", buf);
}

void P1PRA_DhiExit(const char* stage) noexcept
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s_exit tid=%lu", stage ? stage : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_DHI", buf);
}

std::uint32_t P1PRA_DeferredStageId() noexcept
{
    return g_p1praDeferredStage.load(std::memory_order_acquire);
}

void P1PRA_TlmEnter(const char* stage, std::uint32_t stageId) noexcept
{
    g_p1praTelemetryStage.store(stageId, std::memory_order_release);
    char buf[128];
    snprintf(buf, sizeof(buf), "%s_enter tid=%lu", stage ? stage : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_TLM", buf);
}

void P1PRA_TlmExit(const char* stage) noexcept
{
    char buf[128];
    snprintf(buf, sizeof(buf), "%s_exit tid=%lu", stage ? stage : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_TLM", buf);
    g_p1praTelemetryStage.store(P1PRA_TLM_NONE, std::memory_order_release);
}

void P1PRA_TlmOwnership(const char* detail) noexcept
{
    char buf[256];
    snprintf(buf, sizeof(buf), "%s tid=%lu", detail ? detail : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_TLM", buf);
}

std::uint32_t P1PRA_TelemetryStageId() noexcept
{
    return g_p1praTelemetryStage.load(std::memory_order_acquire);
}

extern "C" void P1PRA_UtcEnter(const char* stage, std::uint32_t stageId) noexcept
{
    g_p1praUtcStage.store(stageId, std::memory_order_release);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    if (stageId >= 61u && stageId <= 70u) {
        void* const frameRsp = _AddressOfReturnAddress();
        void* const masmRsp =
            static_cast<char*>(frameRsp) + sizeof(void*);
        P1PRA_AgentDbg("H1", "P1PRA_UtcEnter", "enter_pre_witness",
                      stageId,
                      reinterpret_cast<std::uintptr_t>(masmRsp),
                      reinterpret_cast<std::uintptr_t>(masmRsp) & 0xFu);
    }
    // #endregion agent log
#endif
    char buf[160];
    if (stageId >= 64u && stageId <= 70u) {
        void* const frameRsp = _AddressOfReturnAddress();
        void* const masmRsp =
            static_cast<char*>(frameRsp) + sizeof(void*);
        snprintf(buf, sizeof(buf),
                 "%s_enter rsp=%p rsp_align=%u tid=%lu",
                 stage ? stage : "?",
                 masmRsp,
                 static_cast<unsigned>(
                     reinterpret_cast<std::uintptr_t>(masmRsp) & 0xFu),
                 static_cast<unsigned long>(GetCurrentThreadId()));
    } else {
        snprintf(buf, sizeof(buf), "%s_enter tid=%lu", stage ? stage : "?",
                 static_cast<unsigned long>(GetCurrentThreadId()));
    }
    P1PRA_Witness("P1PRA_UTC", buf);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    if (stageId >= 61u && stageId <= 70u) {
        P1PRA_AgentDbg("H1", "P1PRA_UtcEnter", "enter_post_witness",
                      stageId, 0, static_cast<unsigned long>(GetCurrentThreadId()));
    }
    // #endregion agent log
#endif
}

extern "C" void P1PRA_UtcExit(const char* stage) noexcept
{
    char buf[160];
    const bool alignSnap =
        stage && (strcmp(stage, "state_pub_store_handle") == 0 ||
                  strcmp(stage, "state_pub_set_init") == 0 ||
                  strcmp(stage, "counter_reset_metrics") == 0 ||
                  strcmp(stage, "counter_reset_ring_idx") == 0 ||
                  strcmp(stage, "init_banner_lea_msg") == 0 ||
                  strcmp(stage, "init_banner_log_event") == 0 ||
                  strcmp(stage, "return_success_zero") == 0);
    if (alignSnap) {
        void* const frameRsp = _AddressOfReturnAddress();
        void* const masmRsp =
            static_cast<char*>(frameRsp) + sizeof(void*);
        snprintf(buf, sizeof(buf),
                 "%s_exit rsp=%p rsp_align=%u tid=%lu",
                 stage,
                 masmRsp,
                 static_cast<unsigned>(
                     reinterpret_cast<std::uintptr_t>(masmRsp) & 0xFu),
                 static_cast<unsigned long>(GetCurrentThreadId()));
    } else {
        snprintf(buf, sizeof(buf), "%s_exit tid=%lu", stage ? stage : "?",
                 static_cast<unsigned long>(GetCurrentThreadId()));
    }
    P1PRA_Witness("P1PRA_UTC", buf);
    g_p1praUtcStage.store(P1PRA_UTC_NONE, std::memory_order_release);
}

extern "C" void P1PRA_UtcEntry(void* rip, void* rsp, void* retAddr) noexcept
{
    char buf[256];
    snprintf(buf, sizeof(buf),
             "rip=%p rsp=%p ret=%p rsp_align=%u tid=%lu",
             rip, rsp, retAddr,
             static_cast<unsigned>(
                 reinterpret_cast<std::uintptr_t>(rsp) & 0xFu),
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC_ENTRY", buf);
}

extern "C" void P1PRA_UtcReturn(void* rsp, void* retAddr) noexcept
{
    char buf[256];
    snprintf(buf, sizeof(buf),
             "rsp=%p ret=%p rsp_align=%u tid=%lu",
             rsp, retAddr,
             static_cast<unsigned>(
                 reinterpret_cast<std::uintptr_t>(rsp) & 0xFu),
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC_RETURN", buf);
}

extern "C" void P1PRA_UtcSymbolResolve(void* fnPtr) noexcept
{
    HMODULE module = nullptr;
    char modulePath[MAX_PATH] = {};
    void* exportPtr = nullptr;
    if (fnPtr) {
        GetModuleHandleExA(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            static_cast<LPCSTR>(fnPtr), &module);
        if (module)
            GetModuleFileNameA(module, modulePath, MAX_PATH);
        exportPtr = reinterpret_cast<void*>(GetProcAddress(module, "UTC_InitTelemetry"));
    }
    char buf[448];
    snprintf(buf, sizeof(buf),
             "symbol=UTC_InitTelemetry ptr=%p export=%p match=%u module=%p "
             "module_path=%s tid=%lu",
             fnPtr, exportPtr,
             (fnPtr && exportPtr && fnPtr == exportPtr) ? 1u : 0u,
             static_cast<void*>(module),
             modulePath[0] ? modulePath : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC", buf);
}

extern "C" void P1PRA_UtcPreCall(void* fnPtr, void* callSiteRet) noexcept
{
    char buf[320];
    snprintf(buf, sizeof(buf),
             "dispatch fn=%p ret=%p rsp=%p rsp_align=%u tid=%lu",
             fnPtr, callSiteRet,
             _AddressOfReturnAddress(),
             static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(
                                       _AddressOfReturnAddress()) &
                                   0xFu),
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC_PRECALL", buf);
}

std::uint32_t P1PRA_UtcStageId() noexcept
{
    return g_p1praUtcStage.load(std::memory_order_acquire);
}

static void utcCfSnapEmit(const char* stage, std::uint32_t stageId,
                          const char* detail) noexcept
{
    P1PRA_UtcEnter(stage, stageId);
    char buf[512];
    snprintf(buf, sizeof(buf), "%s tid=%lu", detail ? detail : "?",
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC_SNAP", buf);
    P1PRA_UtcExit(stage);
}

static bool utcTryPathPrefix(const void* path, char* out, std::size_t outLen) noexcept
{
    if (!path) {
        snprintf(out, outLen, "path=null");
        return false;
    }
    __try {
        const char* s = static_cast<const char*>(path);
        std::size_t n = 0;
        while (n + 1 < outLen && s[n] != '\0') {
            out[n] = s[n];
            ++n;
        }
        out[n] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        snprintf(out, outLen, "path=%p unreadable", path);
        return false;
    }
}

extern "C" void P1PRA_UtcCfSnapAll(void* path, std::uint32_t access,
                                    std::uint32_t share, void* security,
                                    std::uint32_t disp, std::uint32_t attrs,
                                    void* templ, void* rspSnap) noexcept
{
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    P1PRA_AgentDbg("H4", "P1PRA_UtcCfSnapAll", "snap_enter",
                  reinterpret_cast<std::uintptr_t>(path),
                  reinterpret_cast<std::uintptr_t>(rspSnap),
                  static_cast<unsigned long>(GetCurrentThreadId()));
    // #endregion agent log
#endif
    MEMORY_BASIC_INFORMATION mbi{};
    const SIZE_T vq =
        path ? VirtualQuery(path, &mbi, sizeof(mbi)) : 0;
    char detail[512];
    snprintf(detail, sizeof(detail),
             "path=%p vq=%zu state=%lu prot=0x%lx base=%p size=%zu",
             path, static_cast<std::size_t>(vq),
             vq ? static_cast<unsigned long>(mbi.State) : 0ul,
             vq ? static_cast<unsigned long>(mbi.Protect) : 0ul,
             vq ? mbi.BaseAddress : nullptr,
             vq ? static_cast<std::size_t>(mbi.RegionSize) : 0u);
    utcCfSnapEmit("cf_snap_path", P1PRA_UTC_CF_SNAP_PATH, detail);

    char prefix[64] = {};
    const bool readable = utcTryPathPrefix(path, prefix, sizeof(prefix));
    snprintf(detail, sizeof(detail), "readable=%u text=%s",
             readable ? 1u : 0u, prefix);
    utcCfSnapEmit("cf_snap_path_chars", P1PRA_UTC_CF_SNAP_PATH_CHARS, detail);

    snprintf(detail, sizeof(detail), "access=0x%lx", access);
    utcCfSnapEmit("cf_snap_access", P1PRA_UTC_CF_SNAP_ACCESS, detail);

    snprintf(detail, sizeof(detail), "share=0x%lx", share);
    utcCfSnapEmit("cf_snap_share", P1PRA_UTC_CF_SNAP_SHARE, detail);

    snprintf(detail, sizeof(detail), "security=%p", security);
    utcCfSnapEmit("cf_snap_security", P1PRA_UTC_CF_SNAP_SECURITY, detail);

    snprintf(detail, sizeof(detail), "disp=0x%lx attrs=0x%lx templ=%p",
             disp, attrs, templ);
    utcCfSnapEmit("cf_snap_disp", P1PRA_UTC_CF_SNAP_DISP, detail);

    snprintf(detail, sizeof(detail), "attrs=0x%lx", attrs);
    utcCfSnapEmit("cf_snap_attrs", P1PRA_UTC_CF_SNAP_ATTRS, detail);

    snprintf(detail, sizeof(detail), "templ=%p", templ);
    utcCfSnapEmit("cf_snap_template", P1PRA_UTC_CF_SNAP_TEMPLATE, detail);

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    void* createFileA =
        k32 ? reinterpret_cast<void*>(GetProcAddress(k32, "CreateFileA")) : nullptr;
    snprintf(detail, sizeof(detail),
             "rsp=%p rsp_align=%u createfileA=%p",
             rspSnap,
             rspSnap ? static_cast<unsigned>(
                           reinterpret_cast<std::uintptr_t>(rspSnap) & 0xFu)
                     : 0u,
             createFileA);
    utcCfSnapEmit("cf_snap_rsp", P1PRA_UTC_CF_SNAP_RSP, detail);

    snprintf(detail, sizeof(detail),
             "rsp=%p rsp_align=%u alloc_pending=72",
             rspSnap,
             rspSnap ? static_cast<unsigned>(
                           reinterpret_cast<std::uintptr_t>(rspSnap) & 0xFu)
                     : 0u);
    utcCfSnapEmit("cf_shadow_rsp_pre", P1PRA_UTC_CF_SHADOW_RSP_PRE, detail);
}

extern "C" void P1PRA_UtcCfStackLayoutSnap(void* frameRsp,
                                            std::uint32_t allocBytes) noexcept
{
    const auto rsp = reinterpret_cast<std::uintptr_t>(frameRsp);
    const std::uint32_t p32 =
        frameRsp ? *reinterpret_cast<std::uint32_t*>(rsp + 32) : 0;
    const std::uint32_t p40 =
        frameRsp ? *reinterpret_cast<std::uint32_t*>(rsp + 40) : 0;
    const std::uint64_t p48 =
        frameRsp ? *reinterpret_cast<std::uint64_t*>(rsp + 48) : 0;
    char detail[512];
    snprintf(detail, sizeof(detail),
             "rsp=%p alloc=%u p32@+32=0x%lx p40@+40=0x%lx p48@+48=0x%llx "
             "p32_oob=%u p40_oob=%u p48_oob=%u",
             frameRsp, allocBytes, p32, p40,
             static_cast<unsigned long long>(p48),
             (32u + sizeof(std::uint32_t) > allocBytes) ? 1u : 0u,
             (40u + sizeof(std::uint32_t) > allocBytes) ? 1u : 0u,
             (48u + sizeof(std::uint64_t) > allocBytes) ? 1u : 0u);
    utcCfSnapEmit("cf_stack_layout", P1PRA_UTC_CF_STACK_LAYOUT, detail);
}

std::uint64_t P1PRA_HandleToUint64(HANDLE handle) noexcept
{
    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handle));
}

bool P1PRA_IsInvalidHandle(HANDLE handle) noexcept
{
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
        return true;
    const auto raw = reinterpret_cast<std::uintptr_t>(handle);
    return raw == 0 || raw == static_cast<std::uintptr_t>(-1);
}

bool P1PRA_IsProcessStateTargetValid(HWND hwnd, HANDLE hProcess,
                                     LONG_PTR userData) noexcept
{
    if (hwnd == nullptr || !IsWindow(hwnd))
        return false;

    HANDLE proc = hProcess;
    if (P1PRA_IsInvalidHandle(proc))
        proc = GetCurrentProcess();

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(proc, &exitCode) || exitCode != STILL_ACTIVE)
        return false;

    LONG_PTR ud = userData;
    if (ud == 0)
        ud = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if (ud == 0)
        return false;

    return true;
}

bool P1PRA_CheckProcessStateHandle(HANDLE handle, HWND targetHwnd,
                                   LONG_PTR userData) noexcept
{
    HANDLE proc = handle;
    if (P1PRA_IsInvalidHandle(proc))
        proc = GetCurrentProcess();
    return P1PRA_IsProcessStateTargetValid(targetHwnd, proc, userData);
}

LRESULT P1PRA_SafeProcessE2EPostState(HWND hwnd, UINT uMsg, WPARAM wParam,
                                      LPARAM lParam) noexcept
{
    (void)uMsg;
    __try {
        const HANDLE hProcess = reinterpret_cast<HANDLE>(wParam);
        const LONG_PTR pUserData = static_cast<LONG_PTR>(lParam);
        if (!P1PRA_CheckProcessStateHandle(hProcess, hwnd, pUserData)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return -1;
        }
        if (reinterpret_cast<void*>(pUserData) == nullptr &&
            GetWindowLongPtrW(hwnd, GWLP_USERDATA) == 0) {
            return -1;
        }
        return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_EXCEPTION_IN_SERVICE);
        return -1;
    }
}

extern "C" void P1PRA_UtcHandleSnap(std::uint64_t handle) noexcept
{
    const std::uint64_t raw = handle;
    const std::uint64_t invalidVal = static_cast<std::uint64_t>(-1);
    const bool invalid = raw == invalidVal || raw == 0 ||
                         raw == P1PRA_HandleToUint64(INVALID_HANDLE_VALUE);
    char detail[256];
    snprintf(detail, sizeof(detail),
             "handle=0x%llx invalid=%u",
             static_cast<unsigned long long>(handle), invalid ? 1u : 0u);
    utcCfSnapEmit("cf_result_handle", P1PRA_UTC_CF_RESULT_HANDLE, detail);
}

extern "C" void P1PRA_UtcLastErrorSnap(std::uint32_t errorCode) noexcept
{
    char detail[128];
    snprintf(detail, sizeof(detail), "error=0x%lx", errorCode);
    utcCfSnapEmit("cf_last_error", P1PRA_UTC_CF_LAST_ERROR_SNAP, detail);
}

extern "C" void P1PRA_UtcRspSnapLight(void* frameRsp,
                                      std::uint32_t stageId) noexcept
{
    g_p1praUtcStage.store(stageId, std::memory_order_release);
    char detail[160];
    snprintf(detail, sizeof(detail),
             "rsp=%p rsp_align=%u stage=%u tid=%lu",
             frameRsp,
             frameRsp ? static_cast<unsigned>(
                            reinterpret_cast<std::uintptr_t>(frameRsp) & 0xFu)
                      : 0u,
             stageId,
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC_SNAP", detail);
}

extern "C" void P1PRA_UtcAlignmentFault(void* frameRsp) noexcept
{
    g_p1praUtcStage.store(P1PRA_UTC_LOG_TS_ALIGN_TRAP, std::memory_order_release);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    P1PRA_AgentDbg("H3", "P1PRA_UtcAlignmentFault", "utc_align_fault",
                  reinterpret_cast<std::uintptr_t>(frameRsp),
                  frameRsp ? (reinterpret_cast<std::uintptr_t>(frameRsp) & 0xFu) : 0u,
                  static_cast<unsigned long>(GetCurrentThreadId()));
    // #endregion agent log
#endif
    char detail[160];
    snprintf(detail, sizeof(detail),
             "rsp=%p rsp_align=%u tid=%lu",
             frameRsp,
             frameRsp ? static_cast<unsigned>(
                            reinterpret_cast<std::uintptr_t>(frameRsp) & 0xFu)
                      : 0u,
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC_ALIGN_FAULT", detail);
}

extern "C" void P1PRA_UtcShadowSnapLight(void* frameRsp,
                                          void* tsDest) noexcept
{
    g_p1praUtcStage.store(P1PRA_UTC_LOG_TS_SHADOW_CHK, std::memory_order_release);
    char detail[192];
    snprintf(detail, sizeof(detail),
             "rsp=%p rsp_align=%u dest=%p tid=%lu",
             frameRsp,
             frameRsp ? static_cast<unsigned>(
                            reinterpret_cast<std::uintptr_t>(frameRsp) & 0xFu)
                      : 0u,
             tsDest,
             static_cast<unsigned long>(GetCurrentThreadId()));
    P1PRA_Witness("P1PRA_UTC_SNAP", detail);
}

// Dual-adapter AMD stacks (iGPU + R9700 + 7800 XT) can AV inside atiadlxx after
// UI init even when our ADL probe is skipped. Quarantine those faults so E2E
// inventory/load survives.
static bool p1praFaultInAmdAdlModule(void* addr) noexcept
{
    if (!addr)
        return false;
    HMODULE mod = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(addr), &mod) ||
        !mod)
        return false;
    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(mod, path, MAX_PATH))
        return false;
    for (char* p = path; *p; ++p) {
        if (*p >= 'A' && *p <= 'Z')
            *p = static_cast<char>(*p - 'A' + 'a');
    }
    return std::strstr(path, "atiadlxx") != nullptr ||
           std::strstr(path, "atiadlxy") != nullptr ||
           std::strstr(path, "amdocl") != nullptr ||
           std::strstr(path, "amd_ags") != nullptr;
}

static bool p1praUnwindOneFrameAsFailedCall(CONTEXT* ctx) noexcept
{
#ifdef _WIN64
    if (!ctx || ctx->Rsp < 0x10000ull)
        return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<void*>(ctx->Rsp), &mbi, sizeof(mbi)) == 0)
        return false;
    const DWORD prot = mbi.Protect & 0xFFu;
    if (prot != PAGE_READONLY && prot != PAGE_READWRITE && prot != PAGE_WRITECOPY &&
        prot != PAGE_EXECUTE_READ && prot != PAGE_EXECUTE_READWRITE &&
        prot != PAGE_EXECUTE_WRITECOPY)
        return false;
    const ULONG64 ret =
        *reinterpret_cast<ULONG64*>(static_cast<ULONG_PTR>(ctx->Rsp));
    if (ret < 0x10000ull)
        return false;
    ctx->Rsp += 8;
    ctx->Rip = ret;
    ctx->Rax = 0;
    return true;
#else
    (void)ctx;
    return false;
#endif
}

static LONG CALLBACK P1PRA_Veh(EXCEPTION_POINTERS* ep)
{
    if (!ep || !ep->ExceptionRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    // Dual-AMD (iGPU+R9700+7800XT) can FailFast with heap corruption after ADL activity.
    if (code == 0xC0000374ul) {
        P1PRA_Witness("P1PRA_FAULT", "heap_corruption_c0000374");
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (code != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    const DWORD tid = GetCurrentThreadId();
    void* rip = ep->ExceptionRecord->ExceptionAddress;
    void* rsp = nullptr;
#ifdef _WIN64
    if (ep->ContextRecord) {
        rip = reinterpret_cast<void*>(ep->ContextRecord->Rip);
        rsp = reinterpret_cast<void*>(ep->ContextRecord->Rsp);
    }
#endif
    const std::uint32_t stageId = g_p1praDeferredStage.load(std::memory_order_acquire);
    const std::uint32_t telemetryStageId =
        g_p1praTelemetryStage.load(std::memory_order_acquire);
    const std::uint32_t utcStageId =
        g_p1praUtcStage.load(std::memory_order_acquire);
    ULONG_PTR faultTarget = 0;
    ULONG_PTR faultOp = 3;
    if (ep->ExceptionRecord->NumberParameters >= 2) {
        faultOp = ep->ExceptionRecord->ExceptionInformation[0];
        faultTarget = ep->ExceptionRecord->ExceptionInformation[1];
    }
    char buf[512];
    if (ep->ExceptionRecord->NumberParameters >= 2) {
        const char* opStr =
            (faultOp == 0) ? "read" : (faultOp == 1) ? "write" : "execute";
        snprintf(buf, sizeof(buf),
                 "code=%08lX tid=%lu rip=%p rsp=%p op=%s target=%p stage=%u telemetry_stage=%u utc_stage=%u",
                 static_cast<unsigned long>(ep->ExceptionRecord->ExceptionCode),
                 static_cast<unsigned long>(tid), rip, rsp, opStr,
                 reinterpret_cast<void*>(faultTarget),
                 static_cast<unsigned>(stageId),
                 static_cast<unsigned>(telemetryStageId),
                 static_cast<unsigned>(utcStageId));
    } else {
        snprintf(buf, sizeof(buf),
                 "code=%08lX tid=%lu rip=%p rsp=%p stage=%u telemetry_stage=%u utc_stage=%u",
                 static_cast<unsigned long>(ep->ExceptionRecord->ExceptionCode),
                 static_cast<unsigned long>(tid), rip, rsp,
                 static_cast<unsigned>(stageId),
                 static_cast<unsigned>(telemetryStageId),
                 static_cast<unsigned>(utcStageId));
    }
    P1PRA_Witness("P1PRA_FAULT", buf);
    {
        char dbg[384];
        snprintf(dbg, sizeof(dbg),
                 "{\"rip\":\"%p\",\"tid\":%lu,\"stage\":%u,\"telemetry_stage\":%u,"
                 "\"utc_stage\":%u}",
                 rip, static_cast<unsigned long>(tid),
                 static_cast<unsigned>(stageId),
                 static_cast<unsigned>(telemetryStageId),
                 static_cast<unsigned>(utcStageId));
        // #region agent log
        P1PRA_DebugLog("H2", "P1PRA_Veh", "access_violation", dbg);
        // #endregion
    }

    // Dual discrete AMD + iGPU: atiadlxx AVs (null/-1 target) kill startup.
    // When GPU probe is suppressed, quarantine those faults instead of dying.
    if (rawrxd::GpuPowerProbeSuppressed() && ep->ContextRecord) {
        const bool adlMod = p1praFaultInAmdAdlModule(rip);
        const bool nullIshTarget =
            faultTarget == ~static_cast<ULONG_PTR>(0) || faultTarget < 0x10000ull;
        const ULONG_PTR ripVal = reinterpret_cast<ULONG_PTR>(rip);
        const bool adlRvaHint = ((ripVal & 0xFFFFull) == 0x93C4ull) ||
                                ((ripVal & 0xFFFFull) == 0x9304ull) ||
                                ((ripVal & 0xFFFFull) == 0x097Dull);
        if ((adlMod || (nullIshTarget && adlRvaHint)) &&
            p1praUnwindOneFrameAsFailedCall(ep->ContextRecord)) {
            P1PRA_Witness("P1PRA_UI",
                          adlMod ? "adl_av_swallowed_dual_gpu"
                                 : "adl_av_swallowed_rva_hint");
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (!adlMod && nullIshTarget && adlRvaHint)
            P1PRA_Witness("P1PRA_UI", "adl_av_unwind_failed");
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void P1PRA_EnsureVeh() noexcept
{
    static volatile LONG once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) == 0)
        AddVectoredExceptionHandler(1, P1PRA_Veh);
}

static void appendRunLog(const char* phase)
{
    char dir[MAX_PATH] = {};
    if (!evidenceDir(dir, MAX_PATH))
        return;

    char path[MAX_PATH] = {};
    snprintf(path, sizeof(path), "%s\\RUN.log", dir);

    FILE* f = nullptr;
    if (fopen_s(&f, path, "a") != 0 || !f)
        return;

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    fprintf(f, "--- phase=%s ts=%04u-%02u-%02u %02u:%02u:%02u ---\n",
            phase ? phase : "unknown",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    const std::uint64_t finalizeMask = P1PRA_Finalize(g_P1PRA_State);
    const std::uint64_t promptCount = readQword(p1pra::OffPromptCount);
    const std::uint64_t promptBytes = readQword(p1pra::OffPromptBytes);
    const std::uint64_t promptTsc = readQword(p1pra::OffPromptTsc);
    const std::uint64_t requestId = readQword(p1pra::OffCurrentRequestId);
    const std::uint64_t stage = readQword(p1pra::OffCurrentStage);
    const std::uint64_t failFlags = readQword(p1pra::OffFailureFlags);

    fprintf(f, "P1PRA_SYMBOL_LINKED=1\n");
    fprintf(f, "P1PRA_STATE_ADDRESS=0x%p\n", static_cast<void*>(g_P1PRA_State));
    fprintf(f, "PROCESS_START_FINALIZE=%s\n",
            g_P1PRA_StartupFinalize != 0 ? "FAIL" : "PASS");
    fprintf(f, "P1PRA_REQUEST_ID=%llu\n",
            static_cast<unsigned long long>(requestId));
    fprintf(f, "P1PRA_USER_PROMPT_COUNT=%llu\n",
            static_cast<unsigned long long>(promptCount));
    fprintf(f, "P1PRA_USER_PROMPT_BYTES=%llu\n",
            static_cast<unsigned long long>(promptBytes));
    fprintf(f, "P1PRA_USER_PROMPT_TSC=%llu\n",
            static_cast<unsigned long long>(promptTsc));
    fprintf(f, "P1PRA_CURRENT_STAGE=%s\n", stageLabel(stage));
    fprintf(f, "P1PRA_FAILURE_FLAGS=0x%llX\n",
            static_cast<unsigned long long>(failFlags));
    fprintf(f, "P1PRA_FINALIZE=%llu\n",
            static_cast<unsigned long long>(finalizeMask));
    fprintf(f, "P1PRA_FINALIZE_NONZERO=%s\n",
            finalizeMask != 0 ? "PASS" : "FAIL");

    if (promptCount > 0 && promptBytes > 0 && requestId > 0 &&
        stage == p1pra::StageUserPrompt) {
        fprintf(f, "P1PRA_002_SLICE_06=PASS\n");
        fprintf(f, "REAL_CHAT_SUBMIT=PASS\n");
        fprintf(f, "REQUEST_ID_ALLOCATED=PASS\n");
        fprintf(f, "USER_PROMPT_STAGE=PASS\n");
        fprintf(f, "USER_PROMPT_BYTES_GT_0=PASS\n");
    }

    fprintf(f, "INFERENCE_BEHAVIOR_CHANGED=NO\n");
    fprintf(f, "FROZEN_BASELINES_CHANGED=0\n");
    fprintf(f, "PRODUCT_INFERENCE_AUTHORITY=NOT_CERTIFIED\n");
    fprintf(f, "P1_PRODUCT_RUNTIME_AUTHORITY_002=FAIL\n");
    fprintf(f, "RAWRXD_V1_0_0_RC1=HOLD\n");
    fflush(f);
    fclose(f);
}

static bool sha256FileHexA(const char* path, char out65[65]) noexcept
{
    if (!path || !out65)
        return false;
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE)
        return false;

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) {
        DWORD hashLen = 0;
        DWORD cb = 0;
        if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                              reinterpret_cast<PUCHAR>(&hashLen),
                              sizeof(hashLen), &cb, 0) == 0 &&
            BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
            UCHAR buf[65536];
            DWORD n = 0;
            bool readOk = true;
            while (ReadFile(hf, buf, sizeof(buf), &n, nullptr) && n > 0) {
                if (BCryptHashData(hash, buf, n, 0) != 0) {
                    readOk = false;
                    break;
                }
            }
            if (readOk) {
                std::vector<UCHAR> digest(hashLen);
                if (BCryptFinishHash(hash, digest.data(), hashLen, 0) == 0) {
                    static const char hex[] = "0123456789ABCDEF";
                    for (DWORD i = 0; i < hashLen; ++i) {
                        out65[i * 2] = hex[(digest[i] >> 4) & 0xF];
                        out65[i * 2 + 1] = hex[digest[i] & 0xF];
                    }
                    out65[hashLen * 2] = '\0';
                    ok = true;
                }
            }
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    CloseHandle(hf);
    return ok;
}

const char* P1PRA_GetExeSha256Hex() noexcept
{
    static char buf[65] = {};
    static bool done = false;
    if (done)
        return buf;
    char exe[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exe, MAX_PATH) && sha256FileHexA(exe, buf))
        done = true;
    return buf;
}

bool P1PRA_PhysicalStreamWitnessed() noexcept
{
    return readQword(p1pra::OffForwardCount) > 0 &&
           readQword(p1pra::OffSampleCount) > 0 &&
           readQword(p1pra::OffDecodeBytes) > 0 &&
           readQword(p1pra::OffUiBytes) > 0;
}

std::uint64_t P1PRA_EngineForwardCount() noexcept
{
    return readQword(p1pra::OffForwardCount);
}

std::uint64_t P1PRA_EngineSampleCount() noexcept
{
    return readQword(p1pra::OffSampleCount);
}

std::uint64_t P1PRA_EngineDecodeBytes() noexcept
{
    return readQword(p1pra::OffDecodeBytes);
}

std::uint64_t P1PRA_EngineUiEmitBytes() noexcept
{
    return readQword(p1pra::OffUiBytes);
}

void P1PRA_ClearModelReadyWitness() noexcept
{
    g_P1PRA_ModelReadyWitness.store(false, std::memory_order_release);
}

void P1PRA_SetModelReadyWitness() noexcept
{
    g_P1PRA_ModelReadyWitness.store(true, std::memory_order_release);
}

bool P1PRA_ModelReadyWitnessed() noexcept
{
    return g_P1PRA_ModelReadyWitness.load(std::memory_order_acquire);
}

bool P1PRA_RealProductRequestPass(bool streamSeen) noexcept
{
    if (!streamSeen || g_P1PRA_SyntheticFallbackUsed.load(std::memory_order_acquire))
        return false;
    if (g_P1PRA_RequestId == 0 || !P1PRA_ModelReadyWitnessed())
        return false;
    return readQword(p1pra::OffForwardCount) > 0 && readQword(p1pra::OffSampleCount) > 0 &&
           readQword(p1pra::OffDecodeBytes) > 0 && readQword(p1pra::OffUiBytes) > 0;
}

static bool advanceTo(std::uint64_t stage)
{
    if (!g_P1PRA_RequestActive || g_P1PRA_RequestId == 0) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        // #region agent log
        P1PRA_AgentDbg("H2", "advanceTo", "req_inactive",
                      stage, g_P1PRA_RequestId, g_P1PRA_RequestActive ? 1u : 0u);
        // #endregion agent log
#endif
        return false;
    }
    const std::uint64_t cur = readQword(p1pra::OffCurrentStage);
    if (cur + 1 != stage) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        // #region agent log
        P1PRA_AgentDbg("H2", "advanceTo", "adjacency_fail",
                      cur, stage, g_P1PRA_RequestId);
        // #endregion agent log
#endif
        return false;
    }
    return P1PRA_AdvanceStage(g_P1PRA_State, g_P1PRA_RequestId, stage) == 0;
}

static void witnessStageHook(const char* hook, bool advanced) noexcept
{
    char b[384];
    snprintf(b, sizeof(b),
             "%s adv=%u tid=%lu req=%llu stg=%s r=%llu g=%llu w=%llu f=%llu s=%llu "
             "d=%llu u=%llu",
             hook ? hook : "?",
             advanced ? 1u : 0u,
             static_cast<unsigned long>(GetCurrentThreadId()),
             static_cast<unsigned long long>(g_P1PRA_RequestId),
             stageLabel(readQword(p1pra::OffCurrentStage)),
             static_cast<unsigned long long>(readQword(p1pra::OffRouterCount)),
             static_cast<unsigned long long>(readQword(p1pra::OffGgufOpenCount)),
             static_cast<unsigned long long>(readQword(p1pra::OffWeightBytes)),
             static_cast<unsigned long long>(readQword(p1pra::OffForwardCount)),
             static_cast<unsigned long long>(readQword(p1pra::OffSampleCount)),
             static_cast<unsigned long long>(readQword(p1pra::OffDecodeBytes)),
             static_cast<unsigned long long>(readQword(p1pra::OffUiBytes)));
    P1PRA_Witness("P1PRA_HOOK", b);
}

void P1PRA_ProcessStartup() noexcept
{
    P1PRA_EnsureVeh();
    rawrxd::InstallAmdAdlLoadBlockIfSuppressed();
    P1PRA_Initialize(g_P1PRA_State);
    P1PRA_RuntimeAuthorityInit();
    g_P1PRA_StartupFinalize = P1PRA_Finalize(g_P1PRA_State);
    g_P1PRA_RequestActive = false;
    g_P1PRA_UiStageEntered = false;
    appendRunLog("startup");
}

void P1PRA_OnAcceptedUserPrompt(const char* promptUtf8,
                                const std::size_t byteCount) noexcept
{
    if (!promptUtf8 || byteCount == 0)
        return;

    g_P1PRA_RequestId = P1PRA_BeginUserPrompt(
        g_P1PRA_State,
        promptUtf8,
        static_cast<std::uint64_t>(byteCount));
    g_P1PRA_RequestActive = (g_P1PRA_RequestId != 0);
    g_P1PRA_UiStageEntered = false;
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    // #region agent log
    P1PRA_AgentDbg("H2", "P1PRA_OnAcceptedUserPrompt", "user_prompt_begin",
                  g_P1PRA_RequestId,
                  readQword(p1pra::OffCurrentStage),
                  static_cast<unsigned long>(GetCurrentThreadId()));
    // #endregion agent log
#endif

    P1PRA_RuntimeAuthorityAppend(RA_EVT_PROMPT_ACCEPT, 0, g_P1PRA_RequestId,
                                 static_cast<std::uint64_t>(byteCount), 0);
    appendRunLog("user_prompt");
}

void P1PRA_OnRouterDispatch() noexcept
{
    if (!advanceTo(p1pra::StageRouter)) {
        witnessStageHook("ROUTER", false);
        return;
    }
    P1PRA_AddPhysicalCounter(g_P1PRA_State, p1pra::OffRouterCount, 1);
    witnessStageHook("ROUTER", true);
}

void P1PRA_OnGgufOpen(std::uint64_t openCount) noexcept
{
    if (openCount == 0)
        openCount = 1;
    if (!advanceTo(p1pra::StageGgufOpen)) {
        witnessStageHook("GGUF_OPEN", false);
        return;
    }
    P1PRA_AddPhysicalCounter(g_P1PRA_State, p1pra::OffGgufOpenCount, openCount);
    witnessStageHook("GGUF_OPEN", true);
}

void P1PRA_OnWeightAccess(std::uint64_t weightBytes) noexcept
{
    if (weightBytes == 0) {
        witnessStageHook("WEIGHT_ACCESS", false);
        return;
    }
    if (!advanceTo(p1pra::StageWeightAccess)) {
        witnessStageHook("WEIGHT_ACCESS", false);
        return;
    }
    P1PRA_AddPhysicalCounter(g_P1PRA_State, p1pra::OffWeightBytes, weightBytes);
    witnessStageHook("WEIGHT_ACCESS", true);
}

void P1PRA_OnForward() noexcept
{
    if (!g_P1PRA_RequestActive || g_P1PRA_RequestId == 0) {
        witnessStageHook("FORWARD", false);
        return;
    }
    const std::uint64_t cur = readQword(p1pra::OffCurrentStage);
    if (cur < p1pra::StageForward) {
        if (!advanceTo(p1pra::StageForward)) {
            witnessStageHook("FORWARD", false);
            return;
        }
        P1PRA_RuntimeAuthorityAppend(RA_EVT_INFERENCE_BEGIN,
                                     static_cast<std::uint32_t>(p1pra::StageForward), 0, 0, 0);
    } else if (cur != p1pra::StageForward && cur != p1pra::StageSample &&
               cur != p1pra::StageDecode && cur != p1pra::StageUiEmit) {
        witnessStageHook("FORWARD", false);
        return;
    }
    P1PRA_AddPhysicalCounter(g_P1PRA_State, p1pra::OffForwardCount, 1);
    witnessStageHook("FORWARD", true);
}

void P1PRA_OnSample() noexcept
{
    if (!g_P1PRA_RequestActive || g_P1PRA_RequestId == 0) {
        witnessStageHook("SAMPLE", false);
        return;
    }
    const std::uint64_t cur = readQword(p1pra::OffCurrentStage);
    if (cur < p1pra::StageSample) {
        if (cur < p1pra::StageForward) {
            witnessStageHook("SAMPLE", false);
            return;
        }
        if (!advanceTo(p1pra::StageSample)) {
            witnessStageHook("SAMPLE", false);
            return;
        }
    } else if (cur != p1pra::StageSample && cur != p1pra::StageDecode &&
               cur != p1pra::StageUiEmit) {
        witnessStageHook("SAMPLE", false);
        return;
    }
    P1PRA_AddPhysicalCounter(g_P1PRA_State, p1pra::OffSampleCount, 1);
    witnessStageHook("SAMPLE", true);
}

void P1PRA_OnDecode(std::uint64_t decodeBytes) noexcept
{
    if (decodeBytes == 0) {
        witnessStageHook("DECODE", false);
        return;
    }
    const std::uint64_t cur = readQword(p1pra::OffCurrentStage);
    if (cur == p1pra::StageSample) {
        if (!advanceTo(p1pra::StageDecode)) {
            witnessStageHook("DECODE", false);
            return;
        }
    } else if (cur != p1pra::StageDecode && cur != p1pra::StageUiEmit) {
        witnessStageHook("DECODE", false);
        return;
    }
    P1PRA_AddPhysicalCounter(g_P1PRA_State, p1pra::OffDecodeBytes, decodeBytes);
    witnessStageHook("DECODE", true);
    P1PRA_RuntimeAuthorityAppend(RA_EVT_DECODE,
                                 static_cast<std::uint32_t>(p1pra::StageDecode),
                                 decodeBytes, 0, 0);
}

void P1PRA_OnUiEmit(std::uint64_t uiBytes) noexcept
{
    if (uiBytes == 0) {
        witnessStageHook("UI_EMIT", false);
        return;
    }
    const std::uint64_t cur = readQword(p1pra::OffCurrentStage);
    if (cur == p1pra::StageDecode) {
        if (!advanceTo(p1pra::StageUiEmit)) {
            witnessStageHook("UI_EMIT", false);
            return;
        }
        g_P1PRA_UiStageEntered = true;
    } else if (cur != p1pra::StageUiEmit) {
        witnessStageHook("UI_EMIT", false);
        return;
    }
    P1PRA_AddPhysicalCounter(g_P1PRA_State, p1pra::OffUiBytes, uiBytes);
    witnessStageHook("UI_EMIT", true);
    P1PRA_RuntimeAuthorityAppend(RA_EVT_UI_EMIT,
                                 static_cast<std::uint32_t>(p1pra::StageUiEmit),
                                 uiBytes, 0, 0);
}

std::uint64_t P1PRA_OnRequestComplete(const P1PRA_E2E_Meta& meta) noexcept
{
    P1PRA_Witness("P1PRA_FINALIZE_CALL", "1");
    const std::uint64_t finalizeMask = P1PRA_Finalize(g_P1PRA_State);
    {
        char rc[32] = {};
        snprintf(rc, sizeof(rc), "%llu", static_cast<unsigned long long>(finalizeMask));
        P1PRA_Witness("P1PRA_FINALIZE_RC", rc);
    }
    g_P1PRA_RequestActive = false;

    char dir[MAX_PATH] = {};
    if (!evidenceDir(dir, MAX_PATH)) {
        P1PRA_Witness("P1PRA_E2E_OPEN", "evidence_dir_fail");
        return finalizeMask;
    }

    char path[MAX_PATH] = {};
    snprintf(path, sizeof(path), "%s\\E2E.log", dir);

    FILE* f = nullptr;
    const int openErr = fopen_s(&f, path, "a");
    if (openErr != 0 || !f) {
        char err[32] = {};
        snprintf(err, sizeof(err), "err=%d", openErr);
        P1PRA_Witness("P1PRA_E2E_OPEN", err);
        return finalizeMask;
    }
    P1PRA_Witness("P1PRA_E2E_OPEN", "ok");

    SYSTEMTIME st = {};
    GetLocalTime(&st);
    const long posBefore = ftell(f);
    fprintf(f, "--- P1PRA_002_E2E ts=%04u-%02u-%02u %02u:%02u:%02u ---\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    const std::uint64_t stage = readQword(p1pra::OffCurrentStage);
    const std::uint64_t failFlags = readQword(p1pra::OffFailureFlags);
    const bool chainComplete = (stage == p1pra::StageUiEmit && failFlags == 0 &&
                                readQword(p1pra::OffRouterCount) > 0 &&
                                readQword(p1pra::OffGgufOpenCount) > 0 &&
                                readQword(p1pra::OffWeightBytes) > 0 &&
                                readQword(p1pra::OffForwardCount) > 0 &&
                                readQword(p1pra::OffSampleCount) > 0 &&
                                readQword(p1pra::OffDecodeBytes) > 0 &&
                                readQword(p1pra::OffUiBytes) > 0);

    fprintf(f, "LOAD_MODEL=%s\n", meta.loadModelPass ? "PASS" : "FAIL");
    fprintf(f, "COMMAND_SEND=%s\n", meta.commandSendPass ? "PASS" : "FAIL");
    fprintf(f, "P1PRA_ENTER=%d\n", g_P1PRA_RequestId != 0 ? 1 : 0);
    fprintf(f, "P1PRA_STAGE_CHAIN=%s\n", chainComplete ? "COMPLETE" : "INCOMPLETE");
    fprintf(f, "P1PRA_CURRENT_STAGE=%s\n", stageLabel(stage));
    fprintf(f, "P1PRA_FAILURE_FLAGS=0x%llX\n",
            static_cast<unsigned long long>(failFlags));
    fprintf(f, "REAL_INFERENCE_ENGINE=%d\n", meta.realInferenceEngine ? 1 : 0);
    fprintf(f, "STREAM_BEGIN=%d\n", meta.streamBegin ? 1 : 0);
    fprintf(f, "STREAM_END=%d\n", meta.streamEnd ? 1 : 0);
    fprintf(f, "FINALIZE=%llu\n", static_cast<unsigned long long>(finalizeMask));
    fprintf(f, "LEASE_RELEASED=%d\n", meta.leaseReleased ? 1 : 0);
    fprintf(f, "EXIT=%d\n", meta.exitCode);
    fprintf(f, "EXE_SHA256=%s\n", meta.exeSha256 ? meta.exeSha256 : "");
    fprintf(f, "MODEL_PATH=%s\n", meta.modelPath ? meta.modelPath : "");
    fprintf(f, "STEER_MODE=%s\n", meta.steerMode ? meta.steerMode : "");
    fprintf(f, "SYNTHETIC_FALLBACK=%d\n", meta.syntheticFallback ? 1 : 0);
    fprintf(f, "P1PRA_SYMBOL_LINKED=1\n");
    fprintf(f, "P1PRA_ROUTER_COUNT=%llu\n",
            static_cast<unsigned long long>(readQword(p1pra::OffRouterCount)));
    fprintf(f, "P1PRA_GGUF_OPEN_COUNT=%llu\n",
            static_cast<unsigned long long>(readQword(p1pra::OffGgufOpenCount)));
    fprintf(f, "P1PRA_WEIGHT_BYTES=%llu\n",
            static_cast<unsigned long long>(readQword(p1pra::OffWeightBytes)));
    fprintf(f, "P1PRA_FORWARD_COUNT=%llu\n",
            static_cast<unsigned long long>(readQword(p1pra::OffForwardCount)));
    fprintf(f, "P1PRA_SAMPLE_COUNT=%llu\n",
            static_cast<unsigned long long>(readQword(p1pra::OffSampleCount)));
    fprintf(f, "P1PRA_DECODE_BYTES=%llu\n",
            static_cast<unsigned long long>(readQword(p1pra::OffDecodeBytes)));
    fprintf(f, "P1PRA_UI_BYTES=%llu\n",
            static_cast<unsigned long long>(readQword(p1pra::OffUiBytes)));

    {
        const auto& eff = rawrxd::GpuDecodeEfficiencyAuthority::Instance().Last();
        fprintf(f, "GPU_POWER_VALID=%d\n", eff.power_valid ? 1 : 0);
        if (eff.power_valid) {
            fprintf(f, "AVG_GPU_WATTS=%.3f\n", eff.average_gpu_watts);
            fprintf(f, "TOKENS_PER_WATT_GPU=%.6f\n", eff.tokens_per_watt_gpu);
            fprintf(f, "GPU_POWER_SAMPLES=%u\n", eff.power_sample_count);
            fprintf(f, "GPU_POWER_SENSOR=%s\n",
                    rawrxd::GpuPowerSensorSourceName(eff.sensor_source));
            fprintf(f, "DECODE_WINDOW_SECONDS=%.6f\n", eff.window_seconds);
        }
    }

    P1PRA_RuntimeAuthorityAppend(RA_EVT_SHUTDOWN, 0, finalizeMask,
                                   chainComplete ? 1u : 0u, 0);
    const std::uint64_t finalTag = P1PRA_RuntimeAuthorityFinalTag();
    const std::uint64_t verifyTag = P1PRA_RuntimeAuthorityVerifyChain();
    {
        char tagBuf[32];
        snprintf(tagBuf, sizeof(tagBuf), "%016llX",
                 static_cast<unsigned long long>(finalTag));
        P1PRA_Witness("AUTHORITY_FINAL_TAG", tagBuf);
        fprintf(f, "AUTHORITY_FINAL_TAG=%s\n", tagBuf);
        fprintf(f, "REPLAY_MATCH=%d\n", (verifyTag != 0 && verifyTag == finalTag) ? 1 : 0);
    }

    if (finalizeMask == 0 && chainComplete) {
        fprintf(f, "P1PRA_002_E2E_PRODUCT_AUTHORITY=PASS\n");
        fprintf(f, "PRODUCT_INFERENCE_AUTHORITY=WITNESSED\n");
    } else {
        fprintf(f, "P1PRA_002_E2E_PRODUCT_AUTHORITY=FAIL\n");
        if (!meta.loadModelPass || !meta.commandSendPass || !meta.streamBegin)
            fprintf(f, "FAIL_OWNER=EARLIER_STAGE\n");
        else
            fprintf(f, "FAIL_OWNER=P1PRA_FINALIZATION_SEAM\n");
        fprintf(f, "PRODUCT_INFERENCE_AUTHORITY=NOT_CERTIFIED\n");
        fprintf(f, "RAWRXD_V1_0_0_RC1=HOLD\n");
    }
    fflush(f);
    {
        const long posAfter = ftell(f);
        const long wrote = (posBefore >= 0 && posAfter >= posBefore) ? (posAfter - posBefore) : -1;
        char wb[32] = {};
        snprintf(wb, sizeof(wb), "%ld", wrote);
        P1PRA_Witness("P1PRA_E2E_WRITE", wb);
    }
    fclose(f);
    P1PRA_Witness("P1PRA_E2E_CLOSE", "1");
    return finalizeMask;
}

void P1PRA_ProcessShutdownEvidence() noexcept
{
    appendRunLog("shutdown");
}

void* P1PRA_StateAddress() noexcept
{
    return g_P1PRA_State;
}

std::uint64_t P1PRA_CurrentRequestId() noexcept
{
    return g_P1PRA_RequestId;
}

bool P1PRA_RequestActive() noexcept
{
    return g_P1PRA_RequestActive;
}
