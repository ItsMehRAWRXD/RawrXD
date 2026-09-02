#pragma once
// P1_PRODUCT_RUNTIME_AUTHORITY_002 — process-owned transport only.

#include <cstddef>
#include <cstdint>

void P1PRA_ProcessStartup() noexcept;
void P1PRA_OnAcceptedUserPrompt(const char* promptUtf8, std::size_t byteCount) noexcept;
void P1PRA_ProcessShutdownEvidence() noexcept;

void* P1PRA_StateAddress() noexcept;
std::uint64_t P1PRA_CurrentRequestId() noexcept;

// Stage chain (strict +1). Call only on real product path.
void P1PRA_OnRouterDispatch() noexcept;
void P1PRA_OnGgufOpen(std::uint64_t openCount = 1) noexcept;
void P1PRA_OnWeightAccess(std::uint64_t weightBytes) noexcept;
void P1PRA_OnForward() noexcept;
void P1PRA_OnSample() noexcept;
void P1PRA_OnDecode(std::uint64_t decodeBytes) noexcept;
void P1PRA_OnUiEmit(std::uint64_t uiBytes) noexcept;

struct P1PRA_E2E_Meta {
    const char* modelPath = "";
    const char* steerMode = "";
    const char* exeSha256 = "";
    int loadModelPass = 0;
    int commandSendPass = 0;
    int realInferenceEngine = 0;
    int streamBegin = 0;
    int streamEnd = 0;
    int syntheticFallback = 0;
    int leaseReleased = 0;
    int exitCode = 1;
};

// Calls P1PRA_Finalize and appends E2E.log (contract fields).
std::uint64_t P1PRA_OnRequestComplete(const P1PRA_E2E_Meta& meta) noexcept;

// SHA-256 hex of current process image (cached). Empty on failure.
const char* P1PRA_GetExeSha256Hex() noexcept;

// True when MASM physical counters show FORWARD+SAMPLE+DECODE+UI all > 0.
bool P1PRA_PhysicalStreamWitnessed() noexcept;

// MASM-backed physical counters (engine + UI layers).
std::uint64_t P1PRA_EngineForwardCount() noexcept;
std::uint64_t P1PRA_EngineSampleCount() noexcept;
std::uint64_t P1PRA_EngineDecodeBytes() noexcept;
std::uint64_t P1PRA_EngineUiEmitBytes() noexcept;

// Set when load worker publishes model_ready; cleared on each new load dispatch.
void P1PRA_ClearModelReadyWitness() noexcept;
void P1PRA_SetModelReadyWitness() noexcept;
bool P1PRA_ModelReadyWitnessed() noexcept;

// Certification pass: fresh request + engine counters + UI stream + model ready.
bool P1PRA_RealProductRequestPass(bool streamSeen) noexcept;

// Debug session NDJSON (hypothesisId, location, message, dataJson object literal).
void P1PRA_DebugLog(const char* hypothesisId, const char* location,
                    const char* message, const char* dataJson) noexcept;

// Append one witness line to P1_PRODUCT_RUNTIME_AUTHORITY_002/WITNESS.log
void P1PRA_Witness(const char* key, const char* value) noexcept;

// P1PRA_LOAD worker bisect helpers (raw pointer snapshots only).
std::uint64_t P1PRA_Fnv1a64(const void* data, std::size_t byteCount) noexcept;
void P1PRA_WitnessPtr(const char* key, const char* label, const void* ptr) noexcept;
void P1PRA_WitnessLoadWorkerSnap(const void* bridge, const void* pathPtr,
                                 std::size_t pathLen, std::uint64_t pathHash,
                                 const void* hwndNotify) noexcept;

// P1PRA_THREAD=<phase> tid=<GetCurrentThreadId()>
void P1PRA_ThreadWitness(const char* phase) noexcept;

// P1PRA_THREAD_START/STOP owner=<label> tid=<GetCurrentThreadId()>
void P1PRA_ThreadStartWitness(const char* owner) noexcept;
void P1PRA_ThreadStopWitness(const char* owner) noexcept;

// deferredHeavyInitBody stage bisect: P1PRA_DHI=<stage>_enter|exit tid=<tid>
void P1PRA_DhiEnter(const char* stage, std::uint32_t stageId) noexcept;
void P1PRA_DhiExit(const char* stage) noexcept;
std::uint32_t P1PRA_DeferredStageId() noexcept;

// Stable ids for VEH stage=<id> (matches deferredHeavyInitBody top-level calls).
enum P1PRA_DhiStageId : std::uint32_t {
    P1PRA_DHI_NONE = 0,
    P1PRA_DHI_LOGGER_INIT = 1,
    P1PRA_DHI_STREAMING_GGUF_LOADER = 2,
    P1PRA_DHI_ENTERPRISE_LICENSE = 3,
    P1PRA_DHI_CPU_INFERENCE_ENGINE = 4,
    P1PRA_DHI_TRANSPARENT_RENDERER = 5,
    P1PRA_DHI_POWERSHELL_STATE = 6,
    P1PRA_DHI_CODE_SNIPPETS = 7,
    P1PRA_DHI_NATIVE_AGENT = 8,
    P1PRA_DHI_EXTENSION_LOADER = 9,
    P1PRA_DHI_AGENTIC_BRIDGE = 10,
    P1PRA_DHI_AI_PANELS = 11,
    P1PRA_DHI_GHOST_TEXT = 12,
    P1PRA_DHI_FAILURE_DETECTOR = 13,
    P1PRA_DHI_AGENT_PANEL = 14,
    P1PRA_DHI_LOAD_APPLY_SETTINGS = 15,
    P1PRA_DHI_AGENT_HISTORY = 16,
    P1PRA_DHI_FAILURE_INTELLIGENCE = 17,
    P1PRA_DHI_MODEL_RESOLVER = 18,
    P1PRA_DHI_GPU_BACKEND_BRIDGE = 19,
    P1PRA_DHI_PHASE10 = 20,
    P1PRA_DHI_MULTI_RESPONSE = 21,
    P1PRA_DHI_LSP_SERVER = 22,
    P1PRA_DHI_HOTPATCH_UI = 23,
    P1PRA_DHI_PHASE11 = 24,
    P1PRA_DHI_PHASE12 = 25,
    P1PRA_DHI_DECOMPILER_VIEW = 26,
    P1PRA_DHI_VOICE_CHAT = 27,
    P1PRA_DHI_VOICE_AUTOMATION = 28,
    P1PRA_DHI_TIER3_POLISH = 29,
    P1PRA_DHI_TIER1_COSMETICS = 30,
    P1PRA_DHI_QUICK_WIN_SYSTEMS = 31,
    P1PRA_DHI_CHAIN_OF_THOUGHT = 32,
    P1PRA_DHI_TELEMETRY = 33,
    P1PRA_DHI_FLIGHT_RECORDER = 34,
    P1PRA_DHI_INIT_MCP = 35,
    P1PRA_DHI_INIT_VSCODE_EXTENSION_API = 36,
    P1PRA_DHI_INIT_PLUGIN_SYSTEM = 37,
    P1PRA_DHI_START_LOCAL_SERVER = 38,
    P1PRA_DHI_INIT_ALL_FEATURE_MODULES = 39,
    P1PRA_DHI_INIT_TIER5_COSMETICS = 40,
    P1PRA_DHI_DEFERRED_HEAVY_INIT_COMPLETE = 41,
    P1PRA_DHI_AI_BACKEND = 42,
};

// initTelemetry() bisect: P1PRA_TLM=<stage>_enter|exit tid=<tid>
void P1PRA_TlmEnter(const char* stage, std::uint32_t stageId) noexcept;
void P1PRA_TlmExit(const char* stage) noexcept;
void P1PRA_TlmOwnership(const char* detail) noexcept;
std::uint32_t P1PRA_TelemetryStageId() noexcept;

enum P1PRA_TlmStageId : std::uint32_t {
    P1PRA_TLM_NONE = 0,
    P1PRA_TLM_PROLOGUE = 1,
    P1PRA_TLM_MUTEX_LOCK = 2,
    P1PRA_TLM_SESSION_INIT = 3,
    P1PRA_TLM_ENV_OPT_IN = 4,
    P1PRA_TLM_PREFS_OPT_IN = 5,
    P1PRA_TLM_MARK_INITIALIZED = 6,
    P1PRA_TLM_MASM_KERNEL_INIT = 7,
    P1PRA_TLM_COMPLETE_LOG = 8,
};

// UTC_InitTelemetry MASM bisect: P1PRA_UTC=<stage>_enter|exit tid=<tid>
extern "C" void P1PRA_UtcEnter(const char* stage, std::uint32_t stageId) noexcept;
extern "C" void P1PRA_UtcExit(const char* stage) noexcept;
extern "C" void P1PRA_UtcEntry(void* rip, void* rsp, void* retAddr) noexcept;
extern "C" void P1PRA_UtcReturn(void* rsp, void* retAddr) noexcept;
extern "C" void P1PRA_UtcSymbolResolve(void* fnPtr) noexcept;
extern "C" void P1PRA_UtcPreCall(void* fnPtr, void* callSiteRet) noexcept;
extern "C" void P1PRA_UtcCfSnapAll(void* path, std::uint32_t access, std::uint32_t share,
                                    void* security, std::uint32_t disp, std::uint32_t attrs,
                                    void* templ, void* rspSnap) noexcept;
extern "C" void P1PRA_UtcCfStackLayoutSnap(void* frameRsp,
                                            std::uint32_t allocBytes) noexcept;
extern "C" void P1PRA_UtcHandleSnap(std::uint64_t handle) noexcept;
extern "C" void P1PRA_UtcLastErrorSnap(std::uint32_t errorCode) noexcept;
extern "C" void P1PRA_UtcRspSnapLight(void* frameRsp,
                                      std::uint32_t stageId) noexcept;
extern "C" void P1PRA_UtcAlignmentFault(void* frameRsp) noexcept;
extern "C" void P1PRA_UtcShadowSnapLight(void* frameRsp,
                                          void* tsDest) noexcept;
std::uint32_t P1PRA_UtcStageId() noexcept;

enum P1PRA_UtcStageId : std::uint32_t {
    P1PRA_UTC_NONE = 0,
    P1PRA_UTC_PATH_RESOLVE = 1,
    P1PRA_UTC_CREATE_FILE = 2,
    P1PRA_UTC_STATE_PUBLICATION = 3,
    P1PRA_UTC_COUNTER_RING_RESET = 4,
    P1PRA_UTC_INIT_BANNER_LOG = 5,
    P1PRA_UTC_RETURN_SUCCESS = 6,
    P1PRA_UTC_RETURN_ERROR = 7,
    P1PRA_UTC_LOG_SLOT_RESERVE = 8,
    P1PRA_UTC_LOG_TIMESTAMP = 9,
    P1PRA_UTC_LOG_MESSAGE_COPY = 10,
    P1PRA_UTC_LOG_NEWLINE = 11,
    P1PRA_UTC_CF_SHADOW = 12,
    P1PRA_UTC_CF_ARG_PATH = 13,
    P1PRA_UTC_CF_ARG_ACCESS = 14,
    P1PRA_UTC_CF_ARG_SHARE = 15,
    P1PRA_UTC_CF_ARG_SECURITY = 16,
    P1PRA_UTC_CF_STACK_PARAMS = 17,
    P1PRA_UTC_CF_CALL = 18,
    P1PRA_UTC_CF_POSTCALL = 19,
    P1PRA_UTC_EXPORT_SHUTDOWN = 20,
    P1PRA_UTC_EXPORT_FLUSH = 21,
    P1PRA_UTC_EXPORT_GET_METRIC_BASE = 22,
    P1PRA_UTC_EXPORT_GET_BUFFER_STATS = 23,
    P1PRA_UTC_EXPORT_LOG_EVENT = 24,
    P1PRA_UTC_EXPORT_INC = 25,
    P1PRA_UTC_EXPORT_DEC = 26,
    P1PRA_UTC_EXPORT_READ = 27,
    P1PRA_UTC_EXPORT_RESET = 28,
    P1PRA_UTC_TS_GET_FILETIME = 29,
    P1PRA_UTC_TS_SYSTEMTIME = 30,
    P1PRA_UTC_TS_FORMAT = 31,
    P1PRA_UTC_CF_SNAP_PATH = 32,
    P1PRA_UTC_CF_SNAP_PATH_CHARS = 33,
    P1PRA_UTC_CF_SNAP_ACCESS = 34,
    P1PRA_UTC_CF_SNAP_SHARE = 35,
    P1PRA_UTC_CF_SNAP_SECURITY = 36,
    P1PRA_UTC_CF_SNAP_DISP = 37,
    P1PRA_UTC_CF_SNAP_ATTRS = 38,
    P1PRA_UTC_CF_SNAP_TEMPLATE = 39,
    P1PRA_UTC_CF_SNAP_RSP = 40,
    P1PRA_UTC_FLUSH_INIT_GATE = 41,
    P1PRA_UTC_FLUSH_LOOP_COMPARE = 42,
    P1PRA_UTC_FLUSH_STRLEN_SLOT = 43,
    P1PRA_UTC_FLUSH_WRITE_FILE = 44,
    P1PRA_UTC_FLUSH_ADVANCE_TAIL = 45,
    P1PRA_UTC_FLUSH_OS_BUFFERS = 46,
    P1PRA_UTC_CF_STACK_LAYOUT = 47,
    P1PRA_UTC_CF_RESULT_HANDLE = 48,
    P1PRA_UTC_CF_HANDLE_COMPARE = 49,
    P1PRA_UTC_CF_HANDLE_SUCCESS = 50,
    P1PRA_UTC_CF_LAST_ERROR_SNAP = 51,
    P1PRA_UTC_SHUTDOWN_FLUSH_CALL = 52,
    P1PRA_UTC_SHUTDOWN_HANDLE_LOAD = 53,
    P1PRA_UTC_SHUTDOWN_HANDLE_GATE = 54,
    P1PRA_UTC_SHUTDOWN_CLOSE_CALL = 55,
    P1PRA_UTC_SHUTDOWN_STATE_CLEAR = 56,
    P1PRA_UTC_LOG_SLOT_ADDR_CALC = 57,
    P1PRA_UTC_LOG_COPY_BOUNDS = 58,
    P1PRA_UTC_LOG_COPY_LOOP_ENTER = 59,
    P1PRA_UTC_LOG_COPY_LOOP_DONE = 60,
    P1PRA_UTC_LOG_TS_INTERNAL_CALL = 61,
    P1PRA_UTC_CF_SHADOW_RSP_PRE = 62,
    P1PRA_UTC_CF_SHADOW_SUB56 = 63,
    P1PRA_UTC_STATE_PUB_STORE_HANDLE = 64,
    P1PRA_UTC_STATE_PUB_SET_INIT = 65,
    P1PRA_UTC_COUNTER_RESET_METRICS = 66,
    P1PRA_UTC_COUNTER_RESET_RING_IDX = 67,
    P1PRA_UTC_INIT_BANNER_LEA_MSG = 68,
    P1PRA_UTC_INIT_BANNER_LOG_EVENT = 69,
    P1PRA_UTC_RETURN_SUCCESS_ZERO = 70,
    P1PRA_UTC_RETURN_ERROR_ENTER = 71,
    P1PRA_UTC_KERNEL_RETURN = 72,
    P1PRA_UTC_FLUSH_COUNTER_INC = 73,
    P1PRA_UTC_FLUSH_WRITE_SHADOW = 74,
    P1PRA_UTC_TS_ASCII2_HOUR = 75,
    P1PRA_UTC_TS_ASCII2_MINUTE = 76,
    P1PRA_UTC_LOG_TS_RSP_PRE = 77,
    P1PRA_UTC_LOG_TS_ARGS = 78,
    P1PRA_UTC_LOG_TS_POST = 79,
    P1PRA_UTC_TS_GET_SYSTEM_TIME = 80,
    P1PRA_UTC_TS_TIME_TO_FIELDS = 81,
    P1PRA_UTC_TS_ASCII2_YEAR = 82,
    P1PRA_UTC_TS_ASCII2_MONTH = 83,
    P1PRA_UTC_TS_ASCII2_DAY = 84,
    P1PRA_UTC_TS_ASCII2_SEC = 85,
    P1PRA_UTC_TS_ASCII2_MSEC = 86,
    P1PRA_UTC_LOG_SLOT_ADDR_CALC87 = 87,
    P1PRA_UTC_LOG_COPY_TS_STRING = 88,
    P1PRA_UTC_LOG_COPY_PAYLOAD_LOOP = 89,
    P1PRA_UTC_LOG_APPEND_NEWLINE = 90,
    P1PRA_UTC_LOG_COMMIT_SLOT = 91,
    P1PRA_UTC_LOG_TS_ALIGN_TRAP = 92,
    P1PRA_UTC_LOG_TS_RSP_SNAP_LIGHT = 93,
    P1PRA_UTC_LOG_TS_SHADOW_CHK = 94,
};

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

std::uint64_t P1PRA_HandleToUint64(HANDLE handle) noexcept;
bool P1PRA_IsInvalidHandle(HANDLE handle) noexcept;
bool P1PRA_IsProcessStateTargetValid(HWND hwnd, HANDLE hProcess,
                                     LONG_PTR userData) noexcept;
bool P1PRA_CheckProcessStateHandle(HANDLE handle, HWND targetHwnd,
                                   LONG_PTR userData) noexcept;
LRESULT P1PRA_SafeProcessE2EPostState(HWND hwnd, UINT uMsg, WPARAM wParam,
                                      LPARAM lParam) noexcept;
#endif

// True while a request has begun and not yet completed.
bool P1PRA_RequestActive() noexcept;

// Debug-mode NDJSON (session 5daacc); no-op outside P1PRA builds.
void P1PRA_AgentDbg(const char* hypothesisId, const char* location,
                    const char* message, unsigned long long d0,
                    unsigned long long d1, unsigned long long d2) noexcept;
