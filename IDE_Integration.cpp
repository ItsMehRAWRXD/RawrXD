// ==============================================================================
// IDE_Integration.cpp — Minimal WinMain + Thread Spawn
// Loads Sovereign_SDK.dll, initializes all subsystems, spawns sim + render threads
// ==============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "Sovereign_LoadResult.h"
#include "Sovereign_Network.h"

static constexpr uint64_t MAX_ENTITIES = 256;

// Host-visible deterministic state lanes used by desync recovery snapshotting.
static uint64_t g_EntityX[MAX_ENTITIES] = {};
static uint64_t g_EntityY[MAX_ENTITIES] = {};
static uint64_t g_EntityVX[MAX_ENTITIES] = {};
static uint64_t g_EntityVY[MAX_ENTITIES] = {};
static uint64_t g_EntityFlags[MAX_ENTITIES] = {};

static volatile uint64_t g_LocalTick = 0;
static uint8_t g_PacketBuf[24] = {};

struct TickHashState {
    uint64_t tick;
    uint64_t entity_count;
    uint64_t lane_x0;
    uint64_t lane_y0;
    uint64_t lane_vx0;
    uint64_t lane_vy0;
    uint64_t lane_flags0;
};

// ==============================================================================
// SDK Function Pointer Types
// ==============================================================================
typedef int  (*Sunshine_Init_t)(HWND hwnd, uint32_t width, uint32_t height);
typedef uint64_t (*Sunshine_Present_t)(uint64_t targetTick);
typedef void (*Sunshine_SetVSync_t)(int enable);
typedef void (*Sunshine_Shutdown_t)(void);
typedef uint64_t (*Sunshine_GetCurrentTick_t)(void);
typedef void (*Sunshine_SetCurrentTick_t)(uint64_t tick);

typedef int  (*GhostHUD_Init_t)(HWND hwnd);
typedef void (*GhostHUD_Shutdown_t)(void);
typedef void (*GhostHUD_Update_t)(void);
typedef void (*GhostHUD_Render_t)(HDC hdc, int x, int y);
typedef void (*GhostHUD_SetLockstepTelemetry_t)(uint64_t localCRC, uint64_t peerCRC, uint32_t desyncCount, int32_t tickDelta);

typedef HANDLE (*Sovereign_StartLoad_t)(HWND hwnd, const char* path, uint64_t expectedSize);
typedef int  (*Sovereign_IsLoading_t)(void);
typedef int  (*Sovereign_IsModelReady_t)(void);
typedef int  (*Sovereign_GetLastLoadResult_t)(void);
typedef uint32_t (*Sovereign_GetLastLoadWin32Error_t)(void);
typedef int  (*GhostBuffer_ReadEvent_t)(void* out);

typedef void (*Simulation_Thread_Entry_t)(void);
typedef void (*Simulation_Stop_t)(void);
typedef uint64_t (*Simulation_GetCurrentTick_t)(void);
typedef int (*Simulation_SetExitAckEvent_t)(HANDLE hExitAckEvent);
typedef uint32_t (*GetSimulationStatus_t)(void);

typedef void (*CRC64_InitTable_t)(void);
typedef uint64_t (*CRC64_HashState_t)(const void* data, uint64_t size);

typedef int (*Bridge_InitInput_t)(HWND hwnd);
typedef int (*Bridge_ProcessRawInput_t)(LPARAM hRawInput);
typedef int (*ClearTape_t)(void);

typedef int (*DesyncRecovery_Configure_t)(uint64_t entityCount,
                                          uint64_t* entityX,
                                          uint64_t* entityY,
                                          uint64_t* entityVX,
                                          uint64_t* entityVY,
                                          uint64_t* entityFlags);
typedef int (*SaveState_t)(void);
typedef int (*RestoreState_t)(void);

typedef int (*LockstepNet_Init_t)(uint16_t localPort, uint32_t remoteIPv4NetworkOrder, uint16_t remotePort);
typedef int (*LockstepNet_Shutdown_t)(void);
typedef int (*LockstepNet_PollRecv_t)(void);
typedef int (*LockstepNet_SendTickCRC_t)(uint32_t tick, uint64_t crc64);
typedef void (*Net_PreparePacket_t)(void* packetBuf, uint64_t tick, uint64_t crc64, uint32_t inputDigest);
typedef int (*Net_VerifySync_t)(void);
typedef uint64_t (*Net_AdoptRemoteTick_t)(void);
typedef uint64_t (*Net_GetLocalTick_t)(void);
typedef uint64_t (*Net_GetLatestRemoteTick_t)(void);
typedef uint64_t (*Net_GetLocalCRC_t)(void);
typedef uint64_t (*Net_GetPeerCRC_t)(void);

// ==============================================================================
// SDK Gateway
// ==============================================================================
struct SovereignGateway {
    HMODULE hSDK;

    // Sunshine
    Sunshine_Init_t           Sunshine_Init;
    Sunshine_Present_t        Sunshine_Present;
    Sunshine_SetVSync_t       Sunshine_SetVSync;
    Sunshine_Shutdown_t       Sunshine_Shutdown;
    Sunshine_GetCurrentTick_t Sunshine_GetCurrentTick;
    Sunshine_SetCurrentTick_t Sunshine_SetCurrentTick;

    // GhostHUD
    GhostHUD_Init_t           GhostHUD_Init;
    GhostHUD_Shutdown_t       GhostHUD_Shutdown;
    GhostHUD_Update_t         GhostHUD_Update;
    GhostHUD_Render_t         GhostHUD_Render;
    GhostHUD_SetLockstepTelemetry_t GhostHUD_SetLockstepTelemetry;

    // Loader
    Sovereign_StartLoad_t     Sovereign_StartLoad;
    Sovereign_IsLoading_t     Sovereign_IsLoading;
    Sovereign_IsModelReady_t  Sovereign_IsModelReady;
    Sovereign_GetLastLoadResult_t Sovereign_GetLastLoadResult;
    Sovereign_GetLastLoadWin32Error_t Sovereign_GetLastLoadWin32Error;
    GhostBuffer_ReadEvent_t   GhostBuffer_ReadEvent;

    // Simulation
    Simulation_Thread_Entry_t Simulation_Thread_Entry;
    Simulation_Stop_t         Simulation_Stop;
    Simulation_GetCurrentTick_t Simulation_GetCurrentTick;
    Simulation_SetExitAckEvent_t Simulation_SetExitAckEvent;
    GetSimulationStatus_t     GetSimulationStatus;

    // Determinism + input
    CRC64_InitTable_t         CRC64_InitTable;
    CRC64_HashState_t         CRC64_HashState;
    Bridge_InitInput_t        Bridge_InitInput;
    Bridge_ProcessRawInput_t  Bridge_ProcessRawInput;
    ClearTape_t               ClearTape;

    // Desync recovery
    DesyncRecovery_Configure_t DesyncRecovery_Configure;
    SaveState_t               SaveState;
    RestoreState_t            RestoreState;

    // Lockstep network
    LockstepNet_Init_t        LockstepNet_Init;
    LockstepNet_Shutdown_t    LockstepNet_Shutdown;
    LockstepNet_PollRecv_t    LockstepNet_PollRecv;
    LockstepNet_SendTickCRC_t LockstepNet_SendTickCRC;
    Net_PreparePacket_t       Net_PreparePacket;
    Net_VerifySync_t          Net_VerifySync;
    Net_AdoptRemoteTick_t     Net_AdoptRemoteTick;
    Net_GetLocalTick_t        Net_GetLocalTick;
    Net_GetLatestRemoteTick_t Net_GetLatestRemoteTick;
    Net_GetLocalCRC_t         Net_GetLocalCRC;
    Net_GetPeerCRC_t          Net_GetPeerCRC;

    bool Init() {
        char exePath[MAX_PATH] = {};
        char sdkPath[MAX_PATH] = {};

        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        char* lastSlash = strrchr(exePath, '\\');
        if (lastSlash) {
            *lastSlash = '\0';
            wsprintfA(sdkPath, "%s\\Sovereign_SDK.dll", exePath);
            hSDK = LoadLibraryA(sdkPath);
        }

        if (!hSDK) {
            hSDK = LoadLibraryA("Sovereign_SDK.dll");
        }

        if (!hSDK) {
            printf("[Gateway] Failed to load Sovereign_SDK.dll (err=%lu)\n", GetLastError());
            return false;
        }

        #define RESOLVE(name) \
            name = (name##_t)GetProcAddress(hSDK, #name); \
            if (!name) { printf("[Gateway] Missing export: %s\n", #name); }

        RESOLVE(Sunshine_Init);
        RESOLVE(Sunshine_Present);
        RESOLVE(Sunshine_SetVSync);
        RESOLVE(Sunshine_Shutdown);
        RESOLVE(Sunshine_GetCurrentTick);
        RESOLVE(Sunshine_SetCurrentTick);

        RESOLVE(GhostHUD_Init);
        RESOLVE(GhostHUD_Shutdown);
        RESOLVE(GhostHUD_Update);
        RESOLVE(GhostHUD_Render);
        RESOLVE(GhostHUD_SetLockstepTelemetry);

        RESOLVE(Sovereign_StartLoad);
        RESOLVE(Sovereign_IsLoading);
        RESOLVE(Sovereign_IsModelReady);
        RESOLVE(Sovereign_GetLastLoadResult);
        RESOLVE(Sovereign_GetLastLoadWin32Error);
        RESOLVE(GhostBuffer_ReadEvent);

        RESOLVE(Simulation_Thread_Entry);
        RESOLVE(Simulation_Stop);
        RESOLVE(Simulation_GetCurrentTick);
        RESOLVE(Simulation_SetExitAckEvent);
        RESOLVE(GetSimulationStatus);

        RESOLVE(CRC64_InitTable);
        RESOLVE(CRC64_HashState);
        RESOLVE(Bridge_InitInput);
        RESOLVE(Bridge_ProcessRawInput);
        RESOLVE(ClearTape);

        RESOLVE(DesyncRecovery_Configure);
        RESOLVE(SaveState);
        RESOLVE(RestoreState);

        RESOLVE(LockstepNet_Init);
        RESOLVE(LockstepNet_Shutdown);
        RESOLVE(LockstepNet_PollRecv);
        RESOLVE(LockstepNet_SendTickCRC);
        RESOLVE(Net_PreparePacket);
        RESOLVE(Net_VerifySync);
        RESOLVE(Net_AdoptRemoteTick);
        RESOLVE(Net_GetLocalTick);
        RESOLVE(Net_GetLatestRemoteTick);
        RESOLVE(Net_GetLocalCRC);
        RESOLVE(Net_GetPeerCRC);

        #undef RESOLVE
        return true;
    }

    void Shutdown() {
        if (hSDK) {
            FreeLibrary(hSDK);
            hSDK = nullptr;
        }
    }
};

static SovereignGateway g_Gateway;
static volatile int g_Running = 1;
static volatile uint32_t g_DesyncCount = 0;
static bool g_SdkUnloadAllowed = true;
static HANDLE g_hSimThread = nullptr;
static HANDLE g_hRenderThread = nullptr;
static HANDLE g_hHUDThread = nullptr;
static HANDLE g_hLockstepThread = nullptr;
static HANDLE g_hSimExitAck = nullptr;
static HANDLE g_hLockstepExitAck = nullptr;

static constexpr DWORD kShutdownTimeoutMs = 3000;

enum class TeardownResult : uint32_t {
    Success = 0,
    AckTimeout = 1,
    InternalError = 2,
};

struct NetworkStressConfig {
    float dropRate;
    float jitterRate;
    float corruptRate;
    int jitterHoldMaxTicks;
    bool enabled;
};

struct NetworkStressState {
    int jitterHoldTicks;
    uint32_t dropsInjected;
    uint32_t jitterInjected;
    uint32_t corruptInjected;
};

static NetworkStressConfig g_StressConfig = {0.0f, 0.0f, 0.0f, 2, false};
static NetworkStressState g_StressState = {0, 0, 0, 0};
static uint16_t g_LocalPort = 7777;
static uint16_t g_RemotePort = 7778;

static FILE* g_TelemetryFile = nullptr;
static uint64_t g_LastTelemetryTick = 0;
static const uint64_t g_TelemetryFlushIntervalTicks = 600;
static char g_TelemetryPath[MAX_PATH] = {};
static uint64_t QpcNow();
static uint64_t QpcDeltaToUs(uint64_t startQpc, uint64_t endQpc);
static void TraceHeadless(const char* tag);
static DWORD WINAPI LockstepThread(LPVOID);
static DWORD WINAPI RenderThread(LPVOID);
static DWORD WINAPI HUDThread(LPVOID);
static bool StartGuiWorkers();
static uint64_t g_QpcFrequency = 0;
static volatile LONG64 g_LastSimLoopUs = 0;
static volatile LONG64 g_LastFramePresentUs = 0;
static volatile LONG g_bModelLoaded = 0;
static bool g_GuiWorkersStarted = false;

enum class LoadState : LONG {
    Idle = 0,
    Loading = 1,
    Ready = 2,
    Faulted = 3,
};

struct LoadManager {
    LoadState state;
    bool loadRequested;
    DWORD timeoutMs;
    DWORD startTickMs;
    uint64_t startQpc;
    uint32_t lastEventSequence;
    bool eventSequenceSeen;
    bool eventOrderingViolation;
    bool sawLoadStart;
    bool sawLoadComplete;
    bool sawLoadFailed;
    char modelPath[MAX_PATH];
};

static LoadManager g_LoadManager = {LoadState::Idle, false, 30000, 0, 0, 0, false, false, false, false, false, {0}};

struct GhostRecord {
    uint64_t timestamp;
    uint64_t payload;
    uint32_t thread_id;
    uint8_t event_type;
    uint8_t pad[3];
    uint32_t sequence;
};

enum : uint8_t {
    GHOST_LOAD_START = 0x01,
    GHOST_LOAD_PROGRESS = 0x02,
    GHOST_LOAD_COMPLETE = 0x03,
    GHOST_LOAD_FAILED = 0x04,
};

static const char* LoadResultTag(LoadResult result) {
    switch (result) {
        case LoadResult::Success:
            return "load_success";
        case LoadResult::Pending:
            return "load_pending";
        case LoadResult::Error_FileNotFound:
            return "load_error_file_not_found";
        case LoadResult::Error_InsufficientVRAM:
            return "load_error_insufficient_vram";
        case LoadResult::Error_CorruptData:
            return "load_error_corrupt_data";
        case LoadResult::Error_HardwareTimeout:
            return "load_error_hardware_timeout";
        case LoadResult::Error_OpenFailed:
            return "load_error_open_failed";
        case LoadResult::Error_FileSizeReadFailed:
            return "load_error_file_size_read_failed";
        case LoadResult::Error_FileMappingFailed:
            return "load_error_file_mapping_failed";
        case LoadResult::Error_MapViewFailed:
            return "load_error_map_view_failed";
        default:
            return "load_error_unknown";
    }
}

static LoadResult GetLastLoadResultOrUnknown() {
    if (!g_Gateway.Sovereign_GetLastLoadResult) {
        return LoadResult::Error_Unknown;
    }

    int result = static_cast<int>(LoadResult::Error_Unknown);
    __try {
        result = g_Gateway.Sovereign_GetLastLoadResult();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return LoadResult::Error_Unknown;
    }
    return static_cast<LoadResult>(result);
}

static uint32_t GetLastLoadWin32ErrorOrZero() {
    if (!g_Gateway.Sovereign_GetLastLoadWin32Error) {
        return 0;
    }

    uint32_t errorCode = 0;
    __try {
        errorCode = g_Gateway.Sovereign_GetLastLoadWin32Error();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return errorCode;
}

static void LoadManager_Reset() {
    g_LoadManager.state = LoadState::Idle;
    g_LoadManager.loadRequested = false;
    g_LoadManager.timeoutMs = 30000;
    g_LoadManager.startTickMs = 0;
    g_LoadManager.startQpc = 0;
    g_LoadManager.lastEventSequence = 0;
    g_LoadManager.eventSequenceSeen = false;
    g_LoadManager.eventOrderingViolation = false;
    g_LoadManager.sawLoadStart = false;
    g_LoadManager.sawLoadComplete = false;
    g_LoadManager.sawLoadFailed = false;
    g_LoadManager.modelPath[0] = '\0';
    InterlockedExchange(&g_bModelLoaded, 0);
    SovereignNetwork::SetLoadState(SovereignNetwork::LoaderApiState::Idle, "none", 0);
}

static void LoadManager_DrainEvents(bool headlessMode) {
    if (!g_Gateway.GhostBuffer_ReadEvent) {
        return;
    }

    GhostRecord rec = {};
    while (true) {
        int hasEvent = 0;
        __try {
            hasEvent = g_Gateway.GhostBuffer_ReadEvent(&rec);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_LoadManager.sawLoadFailed = true;
            if (headlessMode) {
                TraceHeadless("headless_load_event_read_av");
            } else {
                printf("[Load] GhostBuffer_ReadEvent AV\n");
            }
            break;
        }

        if (!hasEvent) {
            break;
        }

        if (g_LoadManager.eventSequenceSeen && rec.sequence <= g_LoadManager.lastEventSequence) {
            g_LoadManager.eventOrderingViolation = true;
            if (headlessMode) {
                TraceHeadless("headless_load_event_order_violation");
            } else {
                printf("[Load] Event order violation: prev=%u current=%u\n",
                       static_cast<unsigned>(g_LoadManager.lastEventSequence),
                       static_cast<unsigned>(rec.sequence));
            }
        }

        g_LoadManager.lastEventSequence = rec.sequence;
        g_LoadManager.eventSequenceSeen = true;

        if (rec.event_type == GHOST_LOAD_START) {
            g_LoadManager.sawLoadStart = true;
        } else if (rec.event_type == GHOST_LOAD_COMPLETE) {
            g_LoadManager.sawLoadComplete = true;
            if (headlessMode) {
                TraceHeadless("headless_load_event_complete");
            }
        } else if (rec.event_type == GHOST_LOAD_FAILED) {
            g_LoadManager.sawLoadFailed = true;
            if (headlessMode) {
                TraceHeadless("headless_load_event_failed");
            }
        }
    }
}

static void TrimCopy(char* dst, size_t dstCount, const char* src, size_t srcLen) {
    if (!dst || dstCount == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src || srcLen == 0) {
        return;
    }

    while (srcLen > 0 && (*src == ' ' || *src == '\t' || *src == '"')) {
        ++src;
        --srcLen;
    }
    while (srcLen > 0) {
        const char tail = src[srcLen - 1];
        if (tail == ' ' || tail == '\t' || tail == '"') {
            --srcLen;
            continue;
        }
        break;
    }

    if (srcLen == 0) {
        return;
    }

    const size_t copyLen = (srcLen < (dstCount - 1)) ? srcLen : (dstCount - 1);
    memcpy(dst, src, copyLen);
    dst[copyLen] = '\0';
}

static void ConfigureModelPathFromCommandLine(const char* cmdLine) {
    LoadManager_Reset();
    if (!cmdLine || !cmdLine[0]) {
        return;
    }

    const char* modelArg = strstr(cmdLine, "--model=");
    if (modelArg) {
        modelArg += 8;
        const char* end = modelArg;
        bool inQuotes = false;
        while (*end) {
            if (*end == '"') {
                inQuotes = !inQuotes;
            } else if (!inQuotes && (*end == ' ' || *end == '\t')) {
                break;
            }
            ++end;
        }
        TrimCopy(g_LoadManager.modelPath, MAX_PATH, modelArg, static_cast<size_t>(end - modelArg));
    } else if (strstr(cmdLine, "--") == nullptr) {
        TrimCopy(g_LoadManager.modelPath, MAX_PATH, cmdLine, strlen(cmdLine));
    }

    g_LoadManager.loadRequested = (g_LoadManager.modelPath[0] != '\0');
    SovereignNetwork::SetActiveModel(g_LoadManager.modelPath[0] ? g_LoadManager.modelPath : "none");
}

static void ReportLoadStateTransition(LoadState state, bool headlessMode, const char* detail = nullptr) {
    const LoadResult lastLoadResult = (state == LoadState::Faulted) ? GetLastLoadResultOrUnknown() : LoadResult::Success;
    const uint32_t lastWin32Error = (state == LoadState::Faulted) ? GetLastLoadWin32ErrorOrZero() : 0;

    switch (state) {
        case LoadState::Ready:
            SovereignNetwork::SetLoadState(SovereignNetwork::LoaderApiState::Ready, "none", 0);
            break;
        case LoadState::Faulted: {
            const char* netTag = (detail && strstr(detail, "headless_") == detail) ? detail : LoadResultTag(lastLoadResult);
            SovereignNetwork::SetLoadState(SovereignNetwork::LoaderApiState::Fault, netTag, static_cast<int>(lastWin32Error));
            break;
        }
        case LoadState::Idle:
            SovereignNetwork::SetLoadState(SovereignNetwork::LoaderApiState::Idle, "none", 0);
            break;
        case LoadState::Loading:
            SovereignNetwork::SetLoadState(SovereignNetwork::LoaderApiState::Loading, "none", 0);
            break;
    }

    if (headlessMode) {
        const char* tag = nullptr;
        switch (state) {
            case LoadState::Idle: tag = "headless_load_idle"; break;
            case LoadState::Loading: tag = "headless_load_started"; break;
            case LoadState::Ready: tag = "headless_load_ready"; break;
            case LoadState::Faulted: tag = detail ? detail : "headless_load_faulted"; break;
        }
        if (tag) {
            TraceHeadless(tag);
        }
        if (state == LoadState::Faulted) {
            char resultTag[96] = {};
            wsprintfA(resultTag, "headless_%s", LoadResultTag(lastLoadResult));
            TraceHeadless(resultTag);
            if (lastWin32Error != 0) {
                char win32Tag[96] = {};
                wsprintfA(win32Tag, "headless_load_win32_error_%lu", static_cast<unsigned long>(lastWin32Error));
                TraceHeadless(win32Tag);
            }
        }
        return;
    }

    switch (state) {
        case LoadState::Idle:
            printf("[Load] Idle\n");
            break;
        case LoadState::Loading:
            printf("[Load] Started: %s\n", g_LoadManager.modelPath[0] ? g_LoadManager.modelPath : "<unspecified>");
            break;
        case LoadState::Ready:
            printf("[Load] Ready\n");
            break;
        case LoadState::Faulted:
             printf("[Load] Faulted%s%s (result=%d:%s win32=%lu)\n",
                   detail ? ": " : "",
                   detail ? detail : "",
                   static_cast<int>(lastLoadResult),
                 LoadResultTag(lastLoadResult),
                 static_cast<unsigned long>(lastWin32Error));
            break;
    }
}

static bool LoadManager_Begin(bool headlessMode) {
    if (!g_LoadManager.loadRequested) {
        g_LoadManager.state = LoadState::Idle;
        InterlockedExchange(&g_bModelLoaded, 1);
        return true;
    }

    if (!g_Gateway.Sovereign_StartLoad || (!g_Gateway.Sovereign_IsLoading && !g_Gateway.Sovereign_IsModelReady)) {
        g_LoadManager.state = LoadState::Faulted;
        ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_load_exports_missing" : "missing load exports");
        return false;
    }

    const char* targetPath = g_LoadManager.modelPath;
    printf("[Load] Preflight path_ptr=%p path='%s'\n", (const void*)targetPath, targetPath ? targetPath : "<null>");
    fflush(stdout);

    const DWORD attrs = GetFileAttributesA(targetPath);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        g_LoadManager.state = LoadState::Faulted;
        ReportLoadStateTransition(
            LoadState::Faulted,
            headlessMode,
            headlessMode ? "headless_load_path_invalid" : "model path missing or invalid");
        return false;
    }

    WIN32_FILE_ATTRIBUTE_DATA fileData = {};
    uint64_t modelSizeBytes = 0;
    if (GetFileAttributesExA(targetPath, GetFileExInfoStandard, &fileData)) {
        modelSizeBytes = (static_cast<uint64_t>(fileData.nFileSizeHigh) << 32ULL) |
                         static_cast<uint64_t>(fileData.nFileSizeLow);
    }

    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        SYSTEM_INFO si = {};
        GetSystemInfo(&si);
        printf("[Load] VM preflight: model=%llu bytes availPhys=%llu availPageFile=%llu availVirtual=%llu pageSize=%lu allocGran=%lu\n",
               static_cast<unsigned long long>(modelSizeBytes),
               static_cast<unsigned long long>(mem.ullAvailPhys),
               static_cast<unsigned long long>(mem.ullAvailPageFile),
               static_cast<unsigned long long>(mem.ullAvailVirtual),
               static_cast<unsigned long>(si.dwPageSize),
               static_cast<unsigned long>(si.dwAllocationGranularity));
    } else {
        printf("[Load] VM preflight unavailable (err=%lu)\n", GetLastError());
    }
    fflush(stdout);

    InterlockedExchange(&g_bModelLoaded, 0);
    HANDLE loadHandle = nullptr;
    __try {
        loadHandle = g_Gateway.Sovereign_StartLoad(nullptr, g_LoadManager.modelPath, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        g_LoadManager.state = LoadState::Faulted;
        ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_load_start_av" : "start load AV");
        return false;
    }

    if (!loadHandle) {
        g_LoadManager.state = LoadState::Faulted;
        ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_load_start_failed" : "start load failed");
        return false;
    }

    g_LoadManager.state = LoadState::Loading;
    g_LoadManager.startTickMs = GetTickCount();
    g_LoadManager.startQpc = QpcNow();
    ReportLoadStateTransition(LoadState::Loading, headlessMode);
    return true;
}

static LoadState LoadManager_Poll(bool headlessMode) {
    if (!g_LoadManager.loadRequested) {
        InterlockedExchange(&g_bModelLoaded, 1);
        return LoadState::Idle;
    }
    if (g_LoadManager.state != LoadState::Loading) {
        return g_LoadManager.state;
    }

    LoadManager_DrainEvents(headlessMode);

    if (g_LoadManager.sawLoadFailed) {
        g_LoadManager.state = LoadState::Faulted;
        ReportLoadStateTransition(LoadState::Faulted, headlessMode,
                                  headlessMode ? "headless_load_failed_event" : "load failed event");
        return g_LoadManager.state;
    }

    const DWORD elapsedMs = GetTickCount() - g_LoadManager.startTickMs;
    if (elapsedMs >= g_LoadManager.timeoutMs) {
        g_LoadManager.state = LoadState::Faulted;
        ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_load_timeout" : "load timeout");
        return g_LoadManager.state;
    }

    int readyRc = 0;
    if (g_Gateway.Sovereign_IsModelReady) {
        __try {
            readyRc = g_Gateway.Sovereign_IsModelReady();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_LoadManager.state = LoadState::Faulted;
            ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_load_ready_av" : "IsModelReady AV");
            return g_LoadManager.state;
        }
        if (readyRc != 0) {
            g_LoadManager.state = LoadState::Ready;
            InterlockedExchange(&g_bModelLoaded, 1);
            const uint64_t loadEndQpc = QpcNow();
            printf("[Load] Ready in %llu us\n",
                   static_cast<unsigned long long>(QpcDeltaToUs(g_LoadManager.startQpc, loadEndQpc)));
            ReportLoadStateTransition(LoadState::Ready, headlessMode);
            return g_LoadManager.state;
        }
    } else if (g_LoadManager.sawLoadComplete) {
        g_LoadManager.state = LoadState::Ready;
        InterlockedExchange(&g_bModelLoaded, 1);
        ReportLoadStateTransition(LoadState::Ready, headlessMode);
        return g_LoadManager.state;
    }

    if (g_Gateway.Sovereign_IsLoading) {
        int loadingRc = 0;
        __try {
            loadingRc = g_Gateway.Sovereign_IsLoading();
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            g_LoadManager.state = LoadState::Faulted;
            ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_isloading_av" : "IsLoading AV");
            return g_LoadManager.state;
        }
        if (loadingRc < 0) {
            g_LoadManager.state = LoadState::Faulted;
            ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_load_failed_sdk" : "IsLoading reported failure");
            return g_LoadManager.state;
        }
        if (loadingRc == 0 && readyRc == 0) {
            g_LoadManager.state = LoadState::Faulted;
            ReportLoadStateTransition(LoadState::Faulted, headlessMode, headlessMode ? "headless_load_stopped_not_ready" : "load stopped before ready");
            return g_LoadManager.state;
        }
    }

    return g_LoadManager.state;
}

static bool WaitForLoadReadyHeadless() {
    TraceHeadless("headless_wait_loadready_enter");

    if (!g_LoadManager.loadRequested) {
        InterlockedExchange(&g_bModelLoaded, 1);
        TraceHeadless("headless_wait_loadready_no_model");
        return true;
    }

    while (g_Running) {
        const LoadState state = LoadManager_Poll(true);
        if (state == LoadState::Ready) {
            TraceHeadless("headless_wait_loadready_ready_return");
            return true;
        }
        if (state == LoadState::Faulted) {
            TraceHeadless("headless_wait_loadready_fault_return");
            return false;
        }
        Sleep(10);
    }

    TraceHeadless("headless_wait_loadready_running_cleared");
    return false;
}

static bool StartGuiWorkers() {
    if (g_GuiWorkersStarted) {
        return true;
    }

    if (InterlockedCompareExchange(&g_bModelLoaded, 0, 0) == 0) {
        printf("[Load] Safety gate blocked worker startup until model is ready\n");
        return false;
    }

    g_hSimThread = CreateThread(nullptr, 0,
        (LPTHREAD_START_ROUTINE)g_Gateway.Simulation_Thread_Entry,
        nullptr, 0, nullptr);
    if (g_hSimThread) {
        SetThreadPriority(g_hSimThread, THREAD_PRIORITY_HIGHEST);
        printf("[WM_CREATE] Simulation thread spawned\n");
    }

    g_hRenderThread = CreateThread(nullptr, 0, RenderThread, nullptr,
        THREAD_PRIORITY_TIME_CRITICAL, nullptr);
    if (g_hRenderThread) {
        printf("[WM_CREATE] Render thread spawned\n");
    }

    g_hHUDThread = CreateThread(nullptr, 0, HUDThread, nullptr, 0, nullptr);
    if (g_hHUDThread) {
        printf("[WM_CREATE] HUD thread spawned\n");
    }

    g_hLockstepThread = CreateThread(nullptr, 0, LockstepThread, nullptr, 0, nullptr);
    if (g_hLockstepThread) {
        SetThreadPriority(g_hLockstepThread, THREAD_PRIORITY_ABOVE_NORMAL);
        printf("[WM_CREATE] Lockstep thread spawned\n");
    }

    g_GuiWorkersStarted = (g_hSimThread && g_hRenderThread && g_hHUDThread && g_hLockstepThread);
    if (!g_GuiWorkersStarted) {
        printf("[WM_CREATE] Worker startup failed under load gate\n");
    }
    return g_GuiWorkersStarted;
}

static uint64_t QpcNow() {
    LARGE_INTEGER counter = {};
    QueryPerformanceCounter(&counter);
    return static_cast<uint64_t>(counter.QuadPart);
}

static uint64_t QpcDeltaToUs(uint64_t startQpc, uint64_t endQpc) {
    if (g_QpcFrequency == 0 || endQpc <= startQpc) {
        return 0;
    }
    const uint64_t deltaQpc = endQpc - startQpc;
    return ((deltaQpc * 1000000ULL) + (g_QpcFrequency - 1ULL)) / g_QpcFrequency;
}

static void TraceHeadless(const char* tag) {
    char exePath[MAX_PATH] = {};
    char logPath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    char* lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        wsprintfA(logPath, "%s\\headless_trace.log", exePath);
    } else {
        wsprintfA(logPath, "headless_trace.log");
    }

    FILE* f = fopen(logPath, "a");
    if (!f) {
        return;
    }
    fprintf(f, "%llu,pid=%lu,port=%u,%s\n",
            static_cast<unsigned long long>(GetTickCount64()),
            static_cast<unsigned long>(GetCurrentProcessId()),
            static_cast<unsigned>(g_LocalPort),
            tag ? tag : "?");
    fclose(f);
}

static TeardownResult WaitForExitAcks(HANDLE hSimExitAck, HANDLE hLockstepExitAck, bool headlessMode) {
    HANDLE waitHandles[2] = {};
    DWORD handleCount = 0;

    if (hSimExitAck) {
        waitHandles[handleCount++] = hSimExitAck;
    }
    if (hLockstepExitAck) {
        waitHandles[handleCount++] = hLockstepExitAck;
    }

    if (handleCount == 0) {
        return TeardownResult::Success;
    }

    const DWORD wr = WaitForMultipleObjects(handleCount, waitHandles, TRUE, kShutdownTimeoutMs);
    if (wr == WAIT_OBJECT_0) {
        if (headlessMode) {
            TraceHeadless("headless_exitack_all_ok");
        }
        return TeardownResult::Success;
    }

    if (wr == WAIT_TIMEOUT) {
        uint32_t simStatus = 0xFFFFFFFFu;
        if (g_Gateway.GetSimulationStatus) {
            simStatus = g_Gateway.GetSimulationStatus();
        }
        if (headlessMode) {
            TraceHeadless("headless_exitack_timeout");
            char statusTag[80] = {};
            if (simStatus != 0xFFFFFFFFu) {
                wsprintfA(statusTag, "headless_sim_status_%u", static_cast<unsigned>(simStatus));
            } else {
                wsprintfA(statusTag, "headless_sim_status_unavailable");
            }
            TraceHeadless(statusTag);
            if (hSimExitAck) {
                TraceHeadless(WaitForSingleObject(hSimExitAck, 0) == WAIT_OBJECT_0 ? "headless_sim_exitack_ok" : "headless_sim_exitack_timeout");
            }
            if (hLockstepExitAck) {
                TraceHeadless(WaitForSingleObject(hLockstepExitAck, 0) == WAIT_OBJECT_0 ? "headless_lockstep_exitack_ok" : "headless_lockstep_exitack_timeout");
            }
        } else {
            if (simStatus != 0xFFFFFFFFu) {
                printf("[Shutdown] Simulation status=%u\n", static_cast<unsigned>(simStatus));
            } else {
                printf("[Shutdown] Simulation status unavailable\n");
            }
            if (hSimExitAck && WaitForSingleObject(hSimExitAck, 0) != WAIT_OBJECT_0) {
                printf("[Shutdown] Simulation exit-ack timeout\n");
            }
            if (hLockstepExitAck && WaitForSingleObject(hLockstepExitAck, 0) != WAIT_OBJECT_0) {
                printf("[Shutdown] Lockstep exit-ack timeout\n");
            }
        }
        return TeardownResult::AckTimeout;
    }

    if (headlessMode) {
        TraceHeadless("headless_exitack_wait_failed");
    } else {
        printf("[Shutdown] Exit-ack wait failed (err=%lu)\n", GetLastError());
    }
    return TeardownResult::InternalError;
}

static float ClampRate(float v) {
    if (v < 0.0f) return 0.0f;
    if (v > 1.0f) return 1.0f;
    return v;
}

static bool Roll(float rate) {
    if (rate <= 0.0f) return false;
    const float r = static_cast<float>(rand()) / static_cast<float>(RAND_MAX);
    return r < rate;
}

static void PrintStressConfig() {
    printf("[Stress] %s drop=%.2f jitter=%.2f corrupt=%.2f jitterHoldMax=%d (drops=%u jitter=%u corrupt=%u)\n",
           g_StressConfig.enabled ? "ON" : "OFF",
           g_StressConfig.dropRate,
           g_StressConfig.jitterRate,
           g_StressConfig.corruptRate,
           g_StressConfig.jitterHoldMaxTicks,
           g_StressState.dropsInjected,
           g_StressState.jitterInjected,
           g_StressState.corruptInjected);
}

static bool Telemetry_Init() {
    if (g_TelemetryFile) {
        return true;
    }

    char exePath[MAX_PATH] = {};
    char csvPath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    char* lastSlash = strrchr(exePath, '\\');
    if (lastSlash) {
        *lastSlash = '\0';
        wsprintfA(csvPath, "%s\\soak_log_%u_%lu.csv", exePath, g_LocalPort, GetCurrentProcessId());
    } else {
        wsprintfA(csvPath, "soak_log_%u_%lu.csv", g_LocalPort, GetCurrentProcessId());
    }

    g_TelemetryFile = fopen(csvPath, "w");
    if (!g_TelemetryFile) {
        printf("[Telemetry] Failed to create soak_log.csv\n");
        return false;
    }

    lstrcpynA(g_TelemetryPath, csvPath, MAX_PATH);

    fprintf(g_TelemetryFile,
            "WallMs,Tick,LocalCRC,PeerCRC,DesyncCount,TickDelta,JitterHoldTicks,DropRate,JitterRate,CorruptRate,DropsInjected,JitterInjected,CorruptInjected,SimLoopUs,FramePresentUs,TPS\n");
    fflush(g_TelemetryFile);
    printf("[Telemetry] Logging to %s\n", g_TelemetryPath);
    return true;
}

static void Telemetry_Flush(uint64_t tick, uint64_t localCRC, uint64_t peerCRC, int32_t tickDelta) {
    if (!g_TelemetryFile) {
        return;
    }

    static uint64_t prevTick = 0;
    static uint64_t prevQpc = 0;
    const uint64_t nowQpc = QpcNow();
    double tps = 0.0;
    if (prevQpc != 0 && nowQpc > prevQpc && g_QpcFrequency != 0) {
        const uint64_t tickDeltaLocal = (tick >= prevTick) ? (tick - prevTick) : 0;
        const uint64_t qpcDelta = nowQpc - prevQpc;
        tps = (static_cast<double>(tickDeltaLocal) * static_cast<double>(g_QpcFrequency)) / static_cast<double>(qpcDelta);
    }
    prevTick = tick;
    prevQpc = nowQpc;

    const LONG64 simLoopUs = InterlockedCompareExchange64(&g_LastSimLoopUs, 0, 0);
    const LONG64 framePresentUs = InterlockedCompareExchange64(&g_LastFramePresentUs, 0, 0);

    fprintf(g_TelemetryFile,
            "%llu,%llu,%016llX,%016llX,%u,%d,%d,%.4f,%.4f,%.4f,%u,%u,%u,%lld,%lld,%.2f\n",
            static_cast<unsigned long long>(GetTickCount64()),
            static_cast<unsigned long long>(tick),
            static_cast<unsigned long long>(localCRC),
            static_cast<unsigned long long>(peerCRC),
            static_cast<unsigned>(g_DesyncCount),
            static_cast<int>(tickDelta),
            g_StressState.jitterHoldTicks,
            g_StressConfig.dropRate,
            g_StressConfig.jitterRate,
            g_StressConfig.corruptRate,
            g_StressState.dropsInjected,
            g_StressState.jitterInjected,
            g_StressState.corruptInjected,
            static_cast<long long>(simLoopUs),
            static_cast<long long>(framePresentUs),
            tps);

    if ((tick - g_LastTelemetryTick) >= g_TelemetryFlushIntervalTicks) {
        fflush(g_TelemetryFile);
        g_LastTelemetryTick = tick;
    }
}

static void Telemetry_Shutdown() {
    if (!g_TelemetryFile) {
        return;
    }
    fflush(g_TelemetryFile);
    fclose(g_TelemetryFile);
    g_TelemetryFile = nullptr;
    printf("[Telemetry] closed %s\n", g_TelemetryPath);
}

static int RunHeadlessSoak(int durationSeconds) {
    if (durationSeconds <= 0) {
        durationSeconds = 60;
    }

    g_Running = 1;

    printf("[Headless] Starting soak for %d seconds\n", durationSeconds);
    TraceHeadless("headless_start");

    if (!WaitForLoadReadyHeadless()) {
        TraceHeadless("headless_load_blocked_startup");
        printf("[Headless] Model load faulted before startup\n");
        return 1;
    }

    TraceHeadless("headless_pre_first_flush");
    __try {
        Telemetry_Flush(0, 0, 0, 0);
        TraceHeadless("headless_first_flush_ok");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TraceHeadless("headless_first_flush_av");
    }

    if (g_Gateway.CRC64_InitTable) {
        TraceHeadless("headless_pre_crc_init");
        __try {
            g_Gateway.CRC64_InitTable();
            TraceHeadless("headless_crc_init_ok");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TraceHeadless("headless_crc_init_av");
        }
    }
    if (g_Gateway.ClearTape) {
        TraceHeadless("headless_pre_cleartape");
        __try {
            g_Gateway.ClearTape();
            TraceHeadless("headless_cleartape_ok");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TraceHeadless("headless_cleartape_av");
        }
    }
    if (g_Gateway.DesyncRecovery_Configure) {
        TraceHeadless("headless_pre_recovery_config");
        __try {
            g_Gateway.DesyncRecovery_Configure(
                MAX_ENTITIES,
                g_EntityX,
                g_EntityY,
                g_EntityVX,
                g_EntityVY,
                g_EntityFlags);
            TraceHeadless("headless_recovery_config_ok");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TraceHeadless("headless_recovery_config_av");
        }
    }
    bool netReady = false;
    if (g_Gateway.LockstepNet_Init) {
        TraceHeadless("headless_pre_net_init");
        const uint32_t loopbackNetworkOrder = 0x0100007F; // 127.0.0.1
        int netOk = 0;
        __try {
            netOk = g_Gateway.LockstepNet_Init(g_LocalPort, loopbackNetworkOrder, g_RemotePort);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TraceHeadless("headless_net_init_av");
            netOk = 0;
        }
        printf("[Headless] LockstepNet_Init %s\n", netOk ? "OK" : "FAILED");
        TraceHeadless(netOk ? "net_init_ok" : "net_init_failed");
        netReady = (netOk != 0);
    }

    HANDLE hSim = nullptr;
    HANDLE hLockstep = nullptr;
    HANDLE hSimExitAck = nullptr;
    HANDLE hLockstepExitAck = nullptr;
    if (netReady && g_Gateway.Simulation_Thread_Entry) {
        if (g_Gateway.Simulation_SetExitAckEvent) {
            hSimExitAck = CreateEventA(nullptr, TRUE, FALSE, nullptr);
            if (!hSimExitAck) {
                TraceHeadless("headless_sim_exitack_create_failed");
                netReady = false;
            } else {
                ResetEvent(hSimExitAck);
                if (!g_Gateway.Simulation_SetExitAckEvent(hSimExitAck)) {
                    TraceHeadless("headless_sim_exitack_register_failed");
                    CloseHandle(hSimExitAck);
                    hSimExitAck = nullptr;
                    netReady = false;
                }
            }
        } else {
            TraceHeadless("headless_sim_exitack_export_missing");
        }
    }

    if (netReady) {
        hLockstepExitAck = CreateEventA(nullptr, TRUE, FALSE, nullptr);
        if (!hLockstepExitAck) {
            TraceHeadless("headless_lockstep_exitack_create_failed");
            netReady = false;
        } else {
            ResetEvent(hLockstepExitAck);
        }
    }

    if (netReady && g_Gateway.Simulation_Thread_Entry) {
        g_hLockstepExitAck = hLockstepExitAck;
        hSim = CreateThread(nullptr, 0,
                           (LPTHREAD_START_ROUTINE)g_Gateway.Simulation_Thread_Entry,
                           nullptr, 0, nullptr);
        hLockstep = CreateThread(nullptr, 0, LockstepThread, nullptr, 0, nullptr);
    } else {
        TraceHeadless("headless_threads_skipped_net_not_ready");
    }

    if (netReady && (!hSim || !hLockstep)) {
        if (hSim) CloseHandle(hSim);
        if (hLockstep) CloseHandle(hLockstep);
        if (g_Gateway.Simulation_SetExitAckEvent) {
            g_Gateway.Simulation_SetExitAckEvent(nullptr);
        }
        if (hSimExitAck) CloseHandle(hSimExitAck);
        if (hLockstepExitAck) CloseHandle(hLockstepExitAck);
        g_hLockstepExitAck = nullptr;
        printf("[Headless] Failed to create worker threads\n");
        TraceHeadless("thread_create_failed");
        return 1;
    }
    if (hSim && hLockstep) {
        TraceHeadless("threads_started");
    }

    if (hSim) {
        SetThreadPriority(hSim, THREAD_PRIORITY_HIGHEST);
    }
    if (hLockstep) {
        SetThreadPriority(hLockstep, THREAD_PRIORITY_ABOVE_NORMAL);
    }

    const uint64_t waitMs = static_cast<uint64_t>(durationSeconds) * 1000ULL;
    const uint64_t startMs = GetTickCount64();
    uint64_t nextSampleMs = startMs;
    while (g_Running && (GetTickCount64() - startMs) < waitMs) {
        unsigned long long reqId = 0;
        char reqPrompt[2048] = {};
        char reqCap[64] = {};
        while (SovereignNetwork::ConsumeInferenceRequest(&reqId, reqPrompt, sizeof(reqPrompt), reqCap, sizeof(reqCap))) {
            TraceHeadless("headless_infer_stub_executed");
            SovereignNetwork::CompleteInference(reqId);
        }

        if (SovereignNetwork::ConsumeUnloadRequested()) {
            TraceHeadless("headless_unload_requested");
            break;
        }

        const uint64_t nowMs = GetTickCount64();
        if (nowMs >= nextSampleMs) {
            uint64_t localTick = g_LocalTick;
            uint64_t remoteTick = g_LocalTick;
            uint64_t localCRC = 0;
            uint64_t peerCRC = 0;
            if (netReady) {
                __try {
                    if (g_Gateway.Net_GetLocalTick) localTick = g_Gateway.Net_GetLocalTick();
                    if (g_Gateway.Net_GetLatestRemoteTick) remoteTick = g_Gateway.Net_GetLatestRemoteTick();
                    if (g_Gateway.Net_GetLocalCRC) localCRC = g_Gateway.Net_GetLocalCRC();
                    if (g_Gateway.Net_GetPeerCRC) peerCRC = g_Gateway.Net_GetPeerCRC();
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    TraceHeadless("headless_getters_av");
                }
            }
            const int32_t tickDelta = static_cast<int32_t>(localTick - remoteTick);
            Telemetry_Flush(localTick, localCRC, peerCRC, tickDelta);
            nextSampleMs = nowMs + 100;
        }
        Sleep(10);
    }

    g_Running = 0;
    TraceHeadless("headless_stopping");
    __try {
        g_Gateway.Simulation_Stop();
        TraceHeadless("headless_sim_stop_ok");
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        TraceHeadless("headless_sim_stop_av");
    }

    bool joinedWorkers = true;
    const TeardownResult ackResult = WaitForExitAcks(hSimExitAck, hLockstepExitAck, true);
    if (ackResult != TeardownResult::Success) {
        joinedWorkers = false;
    }

    if (hLockstep) {
        const DWORD wr = WaitForSingleObject(hLockstep, kShutdownTimeoutMs);
        if (wr != WAIT_OBJECT_0) {
            joinedWorkers = false;
            TraceHeadless("headless_lockstep_join_timeout");
        }
        CloseHandle(hLockstep);
    }
    if (hSim) {
        const DWORD wr = WaitForSingleObject(hSim, kShutdownTimeoutMs);
        if (wr != WAIT_OBJECT_0) {
            joinedWorkers = false;
            TraceHeadless("headless_sim_join_timeout");
        }
        CloseHandle(hSim);
    }

    if (g_Gateway.Simulation_SetExitAckEvent) {
        g_Gateway.Simulation_SetExitAckEvent(nullptr);
    }
    if (hSimExitAck) {
        CloseHandle(hSimExitAck);
        hSimExitAck = nullptr;
    }
    if (hLockstepExitAck) {
        CloseHandle(hLockstepExitAck);
        hLockstepExitAck = nullptr;
    }
    g_hLockstepExitAck = nullptr;

    if (!joinedWorkers) {
        g_SdkUnloadAllowed = false;
        TraceHeadless("headless_unload_blocked_live_threads");
        if (ackResult == TeardownResult::AckTimeout) {
            TraceHeadless("headless_teardown_ack_timeout");
        } else if (ackResult == TeardownResult::InternalError) {
            TraceHeadless("headless_teardown_internal_error");
        }
    }

    if (joinedWorkers && netReady && g_Gateway.LockstepNet_Shutdown) {
        __try {
            g_Gateway.LockstepNet_Shutdown();
            TraceHeadless("headless_net_shutdown_ok");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            TraceHeadless("headless_net_shutdown_av");
        }
    }

    printf("[Headless] Soak complete\n");
    TraceHeadless("headless_complete");
    return 0;
}

static DWORD WINAPI LockstepThread(LPVOID) {
    printf("[Lockstep] Thread started\n");

    while (g_Running) {
        const uint64_t simLoopStartQpc = QpcNow();

        if (g_Gateway.SaveState) {
            g_Gateway.SaveState();
        }

        const uint64_t tick = g_Gateway.Simulation_GetCurrentTick ? g_Gateway.Simulation_GetCurrentTick() : g_LocalTick;
        g_LocalTick = tick;

        TickHashState hs = {};
        hs.tick = tick;
        hs.entity_count = MAX_ENTITIES;
        hs.lane_x0 = g_EntityX[0];
        hs.lane_y0 = g_EntityY[0];
        hs.lane_vx0 = g_EntityVX[0];
        hs.lane_vy0 = g_EntityVY[0];
        hs.lane_flags0 = g_EntityFlags[0];

        const uint64_t currentCRC = g_Gateway.CRC64_HashState ? g_Gateway.CRC64_HashState(&hs, sizeof(hs)) : 0;
        const uint32_t inputDigest = static_cast<uint32_t>(tick & 0xFFFFFFFFu);

        uint64_t txCRC = currentCRC;
        if (g_StressConfig.enabled && Roll(g_StressConfig.corruptRate)) {
            txCRC ^= (1ULL << (tick & 63));
            ++g_StressState.corruptInjected;
        }

        if (g_Gateway.Net_PreparePacket) {
            g_Gateway.Net_PreparePacket(g_PacketBuf, tick, txCRC, inputDigest);
        }

        if (g_Gateway.LockstepNet_SendTickCRC) {
            g_Gateway.LockstepNet_SendTickCRC(static_cast<uint32_t>(tick & 0xFFFFFFFFu), txCRC);
        }

        bool skipPoll = false;
        if (g_StressConfig.enabled) {
            if (g_StressState.jitterHoldTicks > 0) {
                --g_StressState.jitterHoldTicks;
                skipPoll = true;
            } else if (Roll(g_StressConfig.jitterRate)) {
                const int jitterSpan = (g_StressConfig.jitterHoldMaxTicks > 0) ? g_StressConfig.jitterHoldMaxTicks : 1;
                g_StressState.jitterHoldTicks = 1 + (rand() % jitterSpan);
                ++g_StressState.jitterInjected;
                skipPoll = true;
            } else if (Roll(g_StressConfig.dropRate)) {
                ++g_StressState.dropsInjected;
                skipPoll = true;
            }
        }

        if (!skipPoll && g_Gateway.LockstepNet_PollRecv) {
            g_Gateway.LockstepNet_PollRecv();
        }

        const uint64_t localTickTelemetry = g_Gateway.Net_GetLocalTick ? g_Gateway.Net_GetLocalTick() : g_LocalTick;
        const uint64_t remoteTickTelemetry = g_Gateway.Net_GetLatestRemoteTick ? g_Gateway.Net_GetLatestRemoteTick() : g_LocalTick;
        const int32_t tickDelta = static_cast<int32_t>(localTickTelemetry - remoteTickTelemetry);
        const uint64_t localCRC = g_Gateway.Net_GetLocalCRC ? g_Gateway.Net_GetLocalCRC() : currentCRC;
        const uint64_t peerCRC = g_Gateway.Net_GetPeerCRC ? g_Gateway.Net_GetPeerCRC() : 0;

        if (g_Gateway.Net_VerifySync && g_Gateway.Net_VerifySync() != 0) {
            ++g_DesyncCount;
            printf("[Lockstep] DESYNC detected at tick %llu -> restoring snapshot\n", static_cast<unsigned long long>(tick));

            if (g_Gateway.GhostHUD_SetLockstepTelemetry) {
                g_Gateway.GhostHUD_SetLockstepTelemetry(localCRC, peerCRC, g_DesyncCount, tickDelta);
            }
            Telemetry_Flush(localTickTelemetry, localCRC, peerCRC, tickDelta);

            if (g_Gateway.RestoreState) {
                g_Gateway.RestoreState();
            }

            if (g_Gateway.Net_AdoptRemoteTick) {
                const uint64_t adoptedTick = g_Gateway.Net_AdoptRemoteTick();
                g_LocalTick = adoptedTick;
                if (g_Gateway.Sunshine_SetCurrentTick) {
                    g_Gateway.Sunshine_SetCurrentTick(adoptedTick);
                }
                printf("[Lockstep] Adopted remote tick %llu; replay hook pending SimTick export\n",
                       static_cast<unsigned long long>(adoptedTick));
            }

            Sleep(1);
            continue;
        }

        if (g_Gateway.GhostHUD_SetLockstepTelemetry) {
            g_Gateway.GhostHUD_SetLockstepTelemetry(localCRC, peerCRC, g_DesyncCount, tickDelta);
        }

        const uint64_t simLoopEndQpc = QpcNow();
        InterlockedExchange64(&g_LastSimLoopUs, static_cast<LONG64>(QpcDeltaToUs(simLoopStartQpc, simLoopEndQpc)));

        Telemetry_Flush(localTickTelemetry, localCRC, peerCRC, tickDelta);

        Sleep(1);
    }

    printf("[Lockstep] Thread exiting\n");
    if (g_hLockstepExitAck) {
        SetEvent(g_hLockstepExitAck);
    }
    return 0;
}

// ==============================================================================
// Render Thread — 144Hz lockstep compositor
// ==============================================================================
static DWORD WINAPI RenderThread(LPVOID) {
    printf("[Render] Thread started\n");

    uint64_t desiredTick = 0;
    while (g_Running) {
        // Present waits internally for simulation tick via Sunshine_SetCurrentTick
        const uint64_t frameStartQpc = QpcNow();
        uint64_t tick = g_Gateway.Sunshine_Present(desiredTick);
        const uint64_t frameEndQpc = QpcNow();
        InterlockedExchange64(&g_LastFramePresentUs, static_cast<LONG64>(QpcDeltaToUs(frameStartQpc, frameEndQpc)));
        if (tick == 0) {
            // Desync or not ready — brief yield
            Sleep(1);
            continue;
        }
        desiredTick = tick + 1;
    }

    printf("[Render] Thread exiting\n");
    return 0;
}

// ==============================================================================
// HUD Thread — 60Hz telemetry overlay
// ==============================================================================
static DWORD WINAPI HUDThread(LPVOID) {
    printf("[HUD] Thread started\n");

    while (g_Running) {
        g_Gateway.GhostHUD_Update();
        Sleep(16);  // ~60Hz
    }

    printf("[HUD] Thread exiting\n");
    return 0;
}

// ==============================================================================
// Window Procedure
// ==============================================================================
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            RECT rc;
            GetClientRect(hwnd, &rc);
            uint32_t w = rc.right - rc.left;
            uint32_t h = rc.bottom - rc.top;

            // Init Sunshine Compositor
            if (g_Gateway.Sunshine_Init(hwnd, w, h)) {
                printf("[WM_CREATE] Sunshine_Init OK (%dx%d)\n", w, h);
            } else {
                printf("[WM_CREATE] Sunshine_Init FAILED\n");
            }

            // Init GhostHUD
            if (g_Gateway.GhostHUD_Init(hwnd)) {
                printf("[WM_CREATE] GhostHUD_Init OK\n");
            }

            if (g_Gateway.CRC64_InitTable) {
                g_Gateway.CRC64_InitTable();
                printf("[WM_CREATE] CRC64_InitTable OK\n");
            }

            if (g_Gateway.ClearTape) {
                g_Gateway.ClearTape();
                printf("[WM_CREATE] ClearTape OK\n");
            }

            if (g_Gateway.DesyncRecovery_Configure) {
                const int cfgOk = g_Gateway.DesyncRecovery_Configure(
                    MAX_ENTITIES,
                    g_EntityX,
                    g_EntityY,
                    g_EntityVX,
                    g_EntityVY,
                    g_EntityFlags);
                printf("[WM_CREATE] DesyncRecovery_Configure %s\n", cfgOk ? "OK" : "FAILED");
            }

            if (g_Gateway.Bridge_InitInput) {
                const int bridgeOk = g_Gateway.Bridge_InitInput(hwnd);
                printf("[WM_CREATE] Bridge_InitInput %s\n", bridgeOk ? "OK" : "FAILED");
            }

            if (g_Gateway.LockstepNet_Init) {
                const uint32_t loopbackNetworkOrder = 0x0100007F; // 127.0.0.1
                const int netOk = g_Gateway.LockstepNet_Init(g_LocalPort, loopbackNetworkOrder, g_RemotePort);
                printf("[WM_CREATE] LockstepNet_Init %s\n", netOk ? "OK" : "FAILED");
            }

            if (g_Gateway.Simulation_SetExitAckEvent) {
                g_hSimExitAck = CreateEventA(nullptr, TRUE, FALSE, nullptr);
                if (g_hSimExitAck) {
                    ResetEvent(g_hSimExitAck);
                    if (!g_Gateway.Simulation_SetExitAckEvent(g_hSimExitAck)) {
                        printf("[WM_CREATE] Simulation_SetExitAckEvent FAILED\n");
                        CloseHandle(g_hSimExitAck);
                        g_hSimExitAck = nullptr;
                    } else {
                        printf("[WM_CREATE] Simulation exit-ack armed\n");
                    }
                } else {
                    printf("[WM_CREATE] CreateEvent(sim-exit-ack) FAILED\n");
                }
            }

            g_hLockstepExitAck = CreateEventA(nullptr, TRUE, FALSE, nullptr);
            if (g_hLockstepExitAck) {
                ResetEvent(g_hLockstepExitAck);
                printf("[WM_CREATE] Lockstep exit-ack armed\n");
            } else {
                printf("[WM_CREATE] CreateEvent(lockstep-exit-ack) FAILED\n");
            }

            if (g_LoadManager.loadRequested) {
                LoadManager_Begin(false);
            } else {
                InterlockedExchange(&g_bModelLoaded, 1);
            }

            SetTimer(hwnd, 1, 16, nullptr);

            return 0;
        }

        case WM_TIMER: {
            if (wParam != 1) {
                break;
            }

            if (g_GuiWorkersStarted) {
                KillTimer(hwnd, 1);
                return 0;
            }

            const LoadState state = LoadManager_Poll(false);
            if (!g_LoadManager.loadRequested || state == LoadState::Ready || state == LoadState::Idle) {
                if (StartGuiWorkers()) {
                    KillTimer(hwnd, 1);
                }
                return 0;
            }

            if (state == LoadState::Faulted) {
                KillTimer(hwnd, 1);
                MessageBoxA(hwnd, "Model load faulted before simulation start", "Load Error", MB_OK | MB_ICONERROR);
                DestroyWindow(hwnd);
                return 0;
            }

            return 0;
        }

        case WM_INPUT: {
            if (g_Gateway.Bridge_ProcessRawInput) {
                g_Gateway.Bridge_ProcessRawInput(static_cast<LPARAM>(lParam));
            }
            return 0;
        }

        case WM_KEYDOWN: {
            switch (wParam) {
                case VK_F6:
                    g_StressConfig.enabled = !g_StressConfig.enabled;
                    PrintStressConfig();
                    return 0;
                case VK_F7:
                    g_StressConfig.dropRate = ClampRate(g_StressConfig.dropRate - 0.01f);
                    PrintStressConfig();
                    return 0;
                case VK_F8:
                    g_StressConfig.dropRate = ClampRate(g_StressConfig.dropRate + 0.01f);
                    PrintStressConfig();
                    return 0;
                case VK_F9:
                    g_StressConfig.jitterRate = ClampRate(g_StressConfig.jitterRate - 0.01f);
                    PrintStressConfig();
                    return 0;
                case VK_F10:
                    g_StressConfig.jitterRate = ClampRate(g_StressConfig.jitterRate + 0.01f);
                    PrintStressConfig();
                    return 0;
                case VK_F11:
                    g_StressConfig.corruptRate = ClampRate(g_StressConfig.corruptRate - 0.01f);
                    PrintStressConfig();
                    return 0;
                case VK_F12:
                    g_StressConfig.corruptRate = ClampRate(g_StressConfig.corruptRate + 0.01f);
                    PrintStressConfig();
                    return 0;
                default:
                    break;
            }
            break;
        }

        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            // GhostHUD renders overlay
            g_Gateway.GhostHUD_Render(hdc, 8, 8);
            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_SIZE: {
            // Re-init Sunshine on resize (or handle dynamically)
            return 0;
        }

        case WM_DESTROY: {
            g_Running = 0;
            g_Gateway.Simulation_Stop();

            bool joinedWorkers = true;

            const TeardownResult ackResult = WaitForExitAcks(g_hSimExitAck, g_hLockstepExitAck, false);
            if (ackResult != TeardownResult::Success) {
                joinedWorkers = false;
            }

            if (g_hLockstepThread) {
                const DWORD wr = WaitForSingleObject(g_hLockstepThread, kShutdownTimeoutMs);
                if (wr != WAIT_OBJECT_0) {
                    joinedWorkers = false;
                }
                CloseHandle(g_hLockstepThread);
                g_hLockstepThread = nullptr;
            }

            if (g_hSimThread) {
                const DWORD wr = WaitForSingleObject(g_hSimThread, kShutdownTimeoutMs);
                if (wr != WAIT_OBJECT_0) {
                    joinedWorkers = false;
                }
                CloseHandle(g_hSimThread);
                g_hSimThread = nullptr;
            }

            if (g_Gateway.Simulation_SetExitAckEvent) {
                g_Gateway.Simulation_SetExitAckEvent(nullptr);
            }
            if (g_hSimExitAck) {
                CloseHandle(g_hSimExitAck);
                g_hSimExitAck = nullptr;
            }
            if (g_hLockstepExitAck) {
                CloseHandle(g_hLockstepExitAck);
                g_hLockstepExitAck = nullptr;
            }

            if (!joinedWorkers) {
                g_SdkUnloadAllowed = false;
                if (ackResult == TeardownResult::AckTimeout) {
                    printf("[Shutdown] Teardown reason: ACK_TIMEOUT\n");
                } else if (ackResult == TeardownResult::InternalError) {
                    printf("[Shutdown] Teardown reason: INTERNAL_ERROR\n");
                }
            }

            if (joinedWorkers && g_Gateway.LockstepNet_Shutdown) {
                g_Gateway.LockstepNet_Shutdown();
            }

            if (g_hHUDThread) {
                WaitForSingleObject(g_hHUDThread, 3000);
                CloseHandle(g_hHUDThread);
                g_hHUDThread = nullptr;
            }

            if (g_hRenderThread) {
                WaitForSingleObject(g_hRenderThread, 3000);
                CloseHandle(g_hRenderThread);
                g_hRenderThread = nullptr;
            }

            g_Gateway.Sunshine_Shutdown();
            g_Gateway.GhostHUD_Shutdown();
            PostQuitMessage(0);
            return 0;
        }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

// ==============================================================================
// WinMain
// ==============================================================================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR lpCmdLine, int nCmdShow) {
    srand(static_cast<unsigned int>(time(nullptr)));
    LARGE_INTEGER qpcFreq = {};
    if (QueryPerformanceFrequency(&qpcFreq) && qpcFreq.QuadPart > 0) {
        g_QpcFrequency = static_cast<uint64_t>(qpcFreq.QuadPart);
    }
    bool headlessSoak = false;
    int headlessSeconds = 0;
    const char* cmd = (lpCmdLine && lpCmdLine[0]) ? lpCmdLine : GetCommandLineA();

    if (cmd && cmd[0]) {
        if (strstr(cmd, "--peer-b") != nullptr) {
            g_LocalPort = 7778;
            g_RemotePort = 7777;
        }

        const char* localPortArg = strstr(cmd, "--local-port=");
        if (localPortArg) {
            const int p = atoi(localPortArg + 13);
            if (p > 0 && p <= 65535) g_LocalPort = static_cast<uint16_t>(p);
        }

        const char* remotePortArg = strstr(cmd, "--remote-port=");
        if (remotePortArg) {
            const int p = atoi(remotePortArg + 14);
            if (p > 0 && p <= 65535) g_RemotePort = static_cast<uint16_t>(p);
        }

        if (strstr(cmd, "--stress-on") != nullptr) {
            g_StressConfig.enabled = true;
        }

        const char* dropArg = strstr(cmd, "--drop=");
        if (dropArg) g_StressConfig.dropRate = ClampRate(static_cast<float>(atof(dropArg + 7)));

        const char* jitterArg = strstr(cmd, "--jitter=");
        if (jitterArg) g_StressConfig.jitterRate = ClampRate(static_cast<float>(atof(jitterArg + 9)));

        const char* corruptArg = strstr(cmd, "--corrupt=");
        if (corruptArg) g_StressConfig.corruptRate = ClampRate(static_cast<float>(atof(corruptArg + 10)));

        if (strstr(cmd, "--headless-soak") != nullptr) {
            headlessSoak = true;
            headlessSeconds = 60;
            const char* soakEq = strstr(cmd, "--headless-soak=");
            if (soakEq) {
                const int v = atoi(soakEq + 16);
                if (v > 0) headlessSeconds = v;
            }
        }
    }
    ConfigureModelPathFromCommandLine(cmd);
    SovereignNetwork::SetActiveModel(g_LoadManager.modelPath[0] ? g_LoadManager.modelPath : "none");
    SovereignNetwork::SetLoadState(SovereignNetwork::LoaderApiState::Idle, "none", 0);
    if (!SovereignNetwork::StartNetworkThread()) {
        printf("[Network] Failed to start listener on 127.0.0.1:11435\n");
    } else {
        printf("[Network] Listener active on 127.0.0.1:11435\n");
    }
    TraceHeadless("winmain_parsed_args");

    printf("[IDE] Sovereign SDK Integration Stub\n");
    printf("[IDE] Loading SDK...\n");
    printf("[IDE] Loopback ports: local=%u remote=%u\n", g_LocalPort, g_RemotePort);
    printf("[IDE] Stress controls: F6 toggle, F8/F7 drop +/-, F10/F9 jitter +/-, F12/F11 corrupt +/-\n");
    PrintStressConfig();

    Telemetry_Init();

    if (!g_Gateway.Init()) {
        TraceHeadless("gateway_init_failed");
        SovereignNetwork::StopNetworkThread();
        MessageBoxA(nullptr, "Failed to load Sovereign_SDK.dll", "Error", MB_OK);
        return 1;
    }
    TraceHeadless("gateway_init_ok");
    printf("[IDE] SDK loaded. extended lockstep/recovery exports resolved.\n");

    if (headlessSoak && g_LoadManager.loadRequested && !LoadManager_Begin(true)) {
        Telemetry_Shutdown();
        SovereignNetwork::StopNetworkThread();
        if (g_SdkUnloadAllowed) {
            g_Gateway.Shutdown();
        }
        return 1;
    }

    if (headlessSoak) {
        TraceHeadless("enter_headless_mode");
        const int rc = RunHeadlessSoak(headlessSeconds);
        Telemetry_Shutdown();
        if (g_SdkUnloadAllowed) {
            __try {
                g_Gateway.Shutdown();
                TraceHeadless("headless_gateway_shutdown_ok");
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                TraceHeadless("headless_gateway_shutdown_av");
            }
        } else {
            TraceHeadless("headless_gateway_shutdown_skipped_live_threads");
        }
        TraceHeadless("headless_shutdown_complete");
        printf("[IDE] Headless shutdown complete.\n");
        SovereignNetwork::StopNetworkThread();
        return rc;
    }

    // Register window class
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.lpszClassName = "SovereignIDE";
    wc.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    RegisterClassA(&wc);

    // Create window
    HWND hwnd = CreateWindowExA(
        0, "SovereignIDE", "Sovereign IDE — Lockstep Compositor",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 1280, 720,
        nullptr, nullptr, hInst, nullptr);

    if (!hwnd) {
        printf("[IDE] CreateWindowEx failed\n");
        SovereignNetwork::StopNetworkThread();
        return 1;
    }
    SovereignNetwork::SetControlWindow(hwnd);

    if (!g_LoadManager.loadRequested) {
        InterlockedExchange(&g_bModelLoaded, 1);
    } else {
        printf("[IDE] Loading model: %s\n", g_LoadManager.modelPath);
    }

    // Message loop
    MSG msg;
    while (GetMessageA(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);

        unsigned long long reqId = 0;
        char reqPrompt[2048] = {};
        char reqCap[64] = {};
        while (SovereignNetwork::ConsumeInferenceRequest(&reqId, reqPrompt, sizeof(reqPrompt), reqCap, sizeof(reqCap))) {
            SovereignNetwork::CompleteInference(reqId);
        }

        if (SovereignNetwork::ConsumeUnloadRequested()) {
            PostMessageA(hwnd, WM_CLOSE, 0, 0);
        }
    }

    Telemetry_Shutdown();
    SovereignNetwork::StopNetworkThread();
    if (g_SdkUnloadAllowed) {
        g_Gateway.Shutdown();
    }
    printf("[IDE] Shutdown complete.\n");
    return 0;
}
