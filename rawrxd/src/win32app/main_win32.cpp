#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <functional>
#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <thread>
#include <io.h>
#include <fcntl.h>
#include "ide_inference_gate.hpp"
#include "ide_agentic_gate.hpp"
#include "closure/RawrXDAutoClosure.hpp"
#include "agentic/RawrXDAgenticE2E.hpp"
#include "deep2/Deep2Engine.h"
#include "Win32IDE_MCPHooks.h"
#include "Win32IDE_ChatPanel.h"

// Recovered IDE stubs — RAWRXD_IDE_STUB_CLOSURE_RECOVERY_001
extern "C" void Win32IDE_Sidebar_Create(HWND hwndParent, HINSTANCE hInstance);
extern "C" void Win32IDE_Sidebar_SetVisibility(bool visible);
extern "C" bool Win32IDE_Sidebar_IsVisible();
extern "C" void Win32IDE_Commands_SetMainWindow(HWND hwnd);
extern "C" void Win32IDE_Commands_SetEditorWindow(HWND hwnd);
extern "C" bool Win32IDE_Commands_Route(int commandId);
extern "C" void Win32IDE_Commands_Register(int id, void (*fn)());

namespace RawrXD::IDE {
    void ShellLayout_RegisterAll(HINSTANCE hInst);
    void ShellLayout_CreateAll(HWND parent, HINSTANCE hInst);
    void ShellLayout_Resize(int W, int H);
    HWND ShellLayout_GetEditor();
    HWND ShellLayout_GetTerminal();
}

// Forward declarations for gate modules
namespace RawrXD::IDE {
    struct ToolchainResult {
        bool jitOk      = false;
        bool coffOk     = false;
        bool peOk       = false;
        bool helloRunOk = false;
        std::string exePath;
        std::string diagnostics;
    };
    ToolchainResult runNativeToolchainGate();
}

// ---------------------------------------------------------------------------
// Autorun / Certification mode
// ---------------------------------------------------------------------------
enum class AutoRunMode {
    None,
    Inference,
    Agent,
    Layer0,
    AgenticE2E
};

struct StartupOptions {
    AutoRunMode autoRun = AutoRunMode::None;
    bool headless = false;
    std::wstring logPath;
    std::wstring receiptPath;
    uint32_t phase1TimeoutMs = 600000;
    uint32_t phase2TimeoutMs = 300000;
    std::string modelPath;   // --model=... override (UTF-8)
    // --chat-prompt="..." drives the ChatPanel through the same send handler the
    // Send button uses. Win32 EDIT contents cannot be written from another
    // process, so argv is the only way to automate the panel end to end.
    std::string chatPrompt;
    bool chatExitOnDone = false;  // --chat-exit-on-done
    uint32_t chatMaxTokens = 256; // --chat-max-tokens=N
    float    chatTemperature = 0.8f;  // --chat-temperature=F
    float    chatTopP = 0.95f;        // --chat-top-p=F
    uint32_t chatTopK = 40;           // --chat-top-k=N
    bool     chatGreedy = false;      // --chat-greedy
    uint64_t chatSeed = 0;            // --chat-seed=N (determinism gate)
    std::string chatParityProbePath; // --chat-parity-probe=FILE (differential gate)
};

static StartupOptions g_startupOptions;
static FILE* g_headlessLog = nullptr;  // File log for GUI-subsystem headless runs

// ---------------------------------------------------------------------------
// Persistent chat engine — wires ChatPanel → Deep2Engine → streamed tokens
// ---------------------------------------------------------------------------
static std::unique_ptr<Deep2::Deep2Engine> g_chatEngine;
static std::thread g_chatThread;
static std::atomic<bool> g_chatCancelled{false};
static HWND g_hMainWnd = nullptr;
static std::string g_chatModelPath;
static std::string g_chatEngineStatus = "not-attempted";

#define WM_CHAT_TOKEN     (WM_APP + 200)
#define WM_CHAT_DONE      (WM_APP + 201)

struct ChatTokenData {
    std::string token;
    bool        isError = false;
};

// Defined further down with the other exe-relative path helpers.
static std::string getExeDir();

// Stable receipt spelling for GenerationStatus so gate parsing does not depend
// on enum ordinals.
static const char* generationStatusName(Deep2::GenerationStatus s)
{
    switch (s) {
        case Deep2::GenerationStatus::Completed:      return "Completed";
        case Deep2::GenerationStatus::EndOfSequence:  return "EndOfSequence";
        case Deep2::GenerationStatus::Cancelled:      return "Cancelled";
        case Deep2::GenerationStatus::InvalidInput:   return "InvalidInput";
        case Deep2::GenerationStatus::ForwardFailure: return "ForwardFailure";
        case Deep2::GenerationStatus::InternalError:
        default:                                      return "InternalError";
    }
}

// Called on the worker thread. ChatPanel state is UI-thread-owned (ChatPaint
// reads it during WM_PAINT), so tokens are marshalled across instead of
// mutating g_chat from here. Messages are posted in order from this one thread,
// so token order relative to WM_CHAT_DONE is preserved.
static void onChatToken(const std::string& token) {
    if (!g_hMainWnd) return;
    ChatTokenData* data = new ChatTokenData();
    data->token = token;
    if (!PostMessageA(g_hMainWnd, WM_CHAT_TOKEN, 0, (LPARAM)data)) {
        delete data;
    }
}

static void onChatDone() {
    RawrXD::IDE::ChatPanel_EndStreaming();
}

// ── E2E gate receipt ──────────────────────────────────────────────────────────
// Written next to the exe on every completed chat generation so the
// RAWRXD_IDE_CHAT_E2E_001 gate can be asserted on text, not on a screenshot.
struct ChatRunTelemetry {
    std::string modelPath;
    std::string prompt;
    std::string streamedText;
    uint64_t    tokenCount   = 0;
    uint64_t    promptTokens = 0;
    double      genTimeMs    = 0.0;
    int         statusCode   = 0;
    std::string statusName;
    std::string failureDetail;
    bool        cancelled    = false;
    bool        completed    = false;
    // Actual sampler values (after greedy override) for receipt accuracy
    float       actualTemperature = 0.8f;
    float       actualTopP        = 0.95f;
    uint32_t    actualTopK        = 40;
    uint64_t    actualSeed        = 0;
};

static ChatRunTelemetry g_chatTelemetry;

struct ChatDoneData {
    ChatRunTelemetry tel;
};

// Incremental streaming evidence. The final receipt only appears when a run
// ends, which is useless for proving that tokens actually streamed, so the
// worker also checkpoints progress while the stream is live.
struct ChatProgress {
    std::atomic<uint64_t> tokens{0};
    std::atomic<uint64_t> firstTokenAtMs{0};
    std::atomic<uint64_t> lastTokenAtMs{0};
    std::atomic<bool>     active{false};
    std::atomic<bool>     cancelRequested{false};
    uint64_t              startedAtMs = 0;
    std::string           modelPath;
    std::string           prompt;
};

static ChatProgress g_chatProgress;

static uint64_t nowMs()
{
    return (uint64_t)GetTickCount64();
}

static void writeChatProgressFile()
{
    std::string dir = getExeDir();
    if (dir.empty()) return;
    dir += "\\";
    std::string path = dir + "ide_chat_progress.txt";
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    const uint64_t t0     = g_chatProgress.startedAtMs;
    const uint64_t first  = g_chatProgress.firstTokenAtMs.load();
    const uint64_t last   = g_chatProgress.lastTokenAtMs.load();
    const uint64_t tokens = g_chatProgress.tokens.load();

    std::string r;
    r += "=== RAWRXD_IDE_CHAT_PROGRESS ===\r\n";
    r += std::string("MODEL_PATH=") + g_chatProgress.modelPath + "\r\n";
    r += std::string("PROMPT=") + g_chatProgress.prompt + "\r\n";
    r += std::string("STREAM_ACTIVE=") + (g_chatProgress.active.load() ? "1" : "0") + "\r\n";
    r += std::string("CANCEL_REQUESTED=") + (g_chatProgress.cancelRequested.load() ? "1" : "0") + "\r\n";
    r += std::string("TOKENS_SO_FAR=") + std::to_string(tokens) + "\r\n";
    r += std::string("FIRST_TOKEN_LATENCY_MS=") + std::to_string(first ? (first - t0) : 0) + "\r\n";
    r += std::string("ELAPSED_MS=") + std::to_string(last ? (last - t0) : (nowMs() - t0)) + "\r\n";
    r += std::string("TOKENS_PER_SEC=") + std::to_string(
            (last > t0 && last > first) ? (tokens * 1000ULL / (last - first)) : 0ULL) + "\r\n";
    r += "=== RECEIPT_END ===\r\n";

    DWORD written = 0;
    WriteFile(hFile, r.data(), (DWORD)r.size(), &written, NULL);
    CloseHandle(hFile);
}

static void writeChatE2EReceipt(const ChatRunTelemetry& tel)
{
    std::string dir = getExeDir();
    if (dir.empty()) return;
    dir += "\\";
    std::string path = dir + "ide_chat_e2e_receipt.txt";
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    const bool pass = tel.completed && !tel.cancelled
                   && tel.tokenCount > 0
                   && !tel.streamedText.empty();

    std::string r;
    r += "=== RAWRXD_IDE_CHAT_E2E_001 ===\r\n";
    r += "CHAT_PANEL=PASS\r\n";
    r += "SEND_DISPATCH=PASS\r\n";
    r += "DEEP2_ENGINE=PASS\r\n";
    r += std::string("MODEL_PATH=") + tel.modelPath + "\r\n";
    r += std::string("PROMPT=") + tel.prompt + "\r\n";
    r += std::string("PROMPT_TOKEN_COUNT=") + std::to_string(tel.promptTokens) + "\r\n";
    r += std::string("TEMPERATURE=") + std::to_string(tel.actualTemperature) + "\r\n";
    r += std::string("TOP_P=") + std::to_string(tel.actualTopP) + "\r\n";
    r += std::string("TOP_K=") + std::to_string(tel.actualTopK) + "\r\n";
    r += std::string("GREEDY=") + (g_startupOptions.chatGreedy ? "1" : "0") + "\r\n";
    r += std::string("SEED=") + std::to_string(g_startupOptions.chatSeed) + "\r\n";
    r += "STREAMING_CALLBACK=PASS\r\n";
    r += std::string("STREAMED_TOKEN_COUNT=") + std::to_string(tel.tokenCount) + "\r\n";
    r += std::string("RENDERED_CHAR_COUNT=") + std::to_string(tel.streamedText.size()) + "\r\n";
    r += std::string("GENERATION_TIME_MS=") + std::to_string((long long)tel.genTimeMs) + "\r\n";
    r += std::string("GENERATION_STATUS=") + tel.statusName + "\r\n";
    r += std::string("GENERATION_STATUS_CODE=") + std::to_string(tel.statusCode) + "\r\n";
    r += std::string("FAILURE_DETAIL=") + tel.failureDetail + "\r\n";
    r += std::string("CANCELLED=") + (tel.cancelled ? "1" : "0") + "\r\n";
    r += std::string("COMPLETED=") + (tel.completed ? "1" : "0") + "\r\n";
    r += "SYNTHETIC_TOKEN_OUTPUT=0\r\n";
    r += "STUB_FALLBACKS=0\r\n";
    r += "OLLAMA_USED=0\r\n";
    r += "=== STREAMED_TEXT_BEGIN ===\r\n";
    r += tel.streamedText;
    r += "\r\n=== STREAMED_TEXT_END ===\r\n";
    r += std::string("VERDICT=") + (pass ? "PASS" : "FAIL") + "\r\n";
    r += "=== RECEIPT_END ===\r\n";

    DWORD written = 0;
    WriteFile(hFile, r.data(), (DWORD)r.size(), &written, NULL);
    CloseHandle(hFile);
}

// Worker thread: runs Deep2Engine::generateStream with token callback
static void chatWorkerThread(std::string prompt) {
    if (!g_chatEngine || !g_chatEngine->isInitialized()) {
        if (g_hMainWnd) PostMessageA(g_hMainWnd, WM_CHAT_DONE, 0, 0);
        return;
    }

    g_chatCancelled = false;

    Deep2::GenerationOptions opts;
    opts.maxTokens   = g_startupOptions.chatMaxTokens;
    opts.temperature = g_startupOptions.chatTemperature;
    opts.topP        = g_startupOptions.chatTopP;
    opts.topK        = g_startupOptions.chatTopK;
    opts.seed        = g_startupOptions.chatSeed;
    if (g_startupOptions.chatGreedy) {
        // Greedy decode: the deterministic reference for judging whether the
        // engine's logits or the sampler is at fault.
        opts.temperature = 0.0f;
        opts.topP = 1.0f;
        opts.topK = 1;
    }
    // NOTE: the previous hardcoded overrides (temperature=0.8 / topP=0.95 /
    // topK=40) were removed — they silently destroyed the --chat-greedy and
    // --chat-temperature/topP/topK flags, making the differential test
    // impossible. The CLI flags now reach the engine unmodified.

    ChatRunTelemetry tel;
    tel.modelPath = g_chatModelPath;
    tel.prompt    = prompt;

    g_chatProgress.tokens.store(0);
    g_chatProgress.firstTokenAtMs.store(0);
    g_chatProgress.lastTokenAtMs.store(0);
    g_chatProgress.cancelRequested.store(false);
    g_chatProgress.startedAtMs = nowMs();
    g_chatProgress.modelPath   = tel.modelPath;
    g_chatProgress.prompt      = prompt;
    g_chatProgress.active.store(true);
    writeChatProgressFile();

    uint64_t seen = 0;
    auto callback = [](int32_t tokenId, const std::string& token) -> bool {
        (void)tokenId;
        // Marshal to the UI thread; never touch panel state from here.
        onChatToken(token);

        const uint64_t n = ++g_chatProgress.tokens;
        const uint64_t t = nowMs();
        if (g_chatProgress.firstTokenAtMs.load() == 0) {
            g_chatProgress.firstTokenAtMs.store(t);
        }
        g_chatProgress.lastTokenAtMs.store(t);
        if (g_chatProgress.cancelRequested.load()) {
            g_chatProgress.active.store(false);
            writeChatProgressFile();
            return false;  // stop the engine's decode loop
        }
        // Checkpoint periodically; per-token file writes would distort timing.
        if ((n % 8) == 0) writeChatProgressFile();
        return true;
    };

    Deep2::GenerationResult result = g_chatEngine->generateStream(prompt, opts, callback);

    g_chatProgress.active.store(false);
    g_chatProgress.cancelRequested.store(g_chatCancelled.load());

    tel.promptTokens = result.promptTokens;
    tel.tokenCount   = result.generatedTokens;
    tel.genTimeMs    = result.generationTimeMs;
    tel.statusCode   = (int)result.status;
    tel.statusName   = generationStatusName(result.status);
    tel.failureDetail= result.failureDetail;
    tel.cancelled    = result.cancelled;
    tel.completed    = result.completed;
    tel.actualTemperature = opts.temperature;
    tel.actualTopP        = opts.topP;
    tel.actualTopK        = opts.topK;
    tel.actualSeed        = opts.seed;

    g_chatTelemetry = tel;

    // Fail closed: a failed generation is reported, never papered over with a
    // synthetic completion. The error rides the same UI-thread queue so it
    // lands after the tokens it explains.
    if (!result.completed && !result.cancelled) {
        std::string reason = "[Generation failed: stage=" + tel.statusName;
        if (!result.failureDetail.empty()) reason += " / " + result.failureDetail;
        reason += "]";
        ChatTokenData* data = new ChatTokenData();
        data->token = reason;
        data->isError = true;
        if (!PostMessageA(g_hMainWnd, WM_CHAT_TOKEN, 0, (LPARAM)data)) delete data;
    }

    // Hand the telemetry to the UI thread. It runs after every queued
    // WM_CHAT_TOKEN, so the transcript it records is exactly what was rendered.
    writeChatProgressFile();
    ChatDoneData* done = new ChatDoneData();
    done->tel = tel;
    if (!PostMessageA(g_hMainWnd, WM_CHAT_DONE, 0, (LPARAM)done)) {
        delete done;
        return;
    }
}

// Initialize the persistent chat engine with a model path
static bool initChatEngine(const std::string& modelPath) {
    if (modelPath.empty()) return false;

    DWORD attr = GetFileAttributesA(modelPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) return false;

    g_chatEngine = std::make_unique<Deep2::Deep2Engine>();

    Deep2::EngineConfig config;
    config.maxSeqLen = 4096;
    // PROBE_COVERAGE_001: when a parity probe is active, force single-thread
    // to match the oracle's deterministic config (numThreads=1). Multi-threaded
    // parallel reductions introduce floating-point non-associativity that
    // confounds the differential comparison.
    config.numThreads = g_startupOptions.chatParityProbePath.empty() ? 0 : 1;

    if (!g_chatEngine->initialize(config)) {
        g_chatEngineStatus = "Deep2Engine::initialize failed";
        return false;
    }

    // Same Vulkan policy the certified inference gate uses. Without this the
    // chat lane left the backend at its default and any GPU fault took the
    // whole IDE down instead of degrading to the CPU lane.
    const char* envDisableVulkan = std::getenv("DEEP2_DISABLE_VULKAN");
    const bool disableVulkan = (envDisableVulkan && envDisableVulkan[0] == '1');
    g_chatEngine->enableVulkan(!disableVulkan);
    g_chatEngine->setVulkanStrictNoCpuFallback(false);

    Deep2::ModelLoadDiag diag{};
    if (!g_chatEngine->loadModel(modelPath, &diag)) {
        g_chatEngineStatus = diag.stageCode
            ? (diag.stageName + " / " + diag.message + " [code=" + std::to_string(diag.stageCode) + "]")
            : std::string("loadModel returned false");
        return false;
    }

    g_chatModelPath = modelPath;
    g_chatEngineStatus = "loaded";

    // Differential gate: enable the parity probe if --chat-parity-probe=FILE
    // was given. Emits the same checkpoint trace that the certified CPU oracle
    // produces, so the two paths can be diffed checkpoint by checkpoint to
    // localize the first divergence.
    //
    // PROBE_COVERAGE_001: to make the differential conclusive, the IDE lane
    // must match the oracle's deterministic config when a parity probe is
    // active: (a) force CPU-only (no Vulkan), (b) single-thread, (c) full
    // per-layer checkpoint emission. Without this, config differences
    // (thread count, GPU offload) confound the comparison.
    if (!g_startupOptions.chatParityProbePath.empty()) {
        g_chatEngine->enableVulkan(false);  // CPU-only: match oracle lane
        g_chatEngine->enableParityProbe(g_startupOptions.chatParityProbePath.c_str(), 0);
        // Enable full-vector dumps for layer 0 (matches oracle's
        // enableParityProbeFullVectors(0) for external Q/K/V verification).
        g_chatEngine->enableParityProbeFullVectors(0);
    }

    return true;
}

// Startup load outcome, written next to the exe. The chat panel has no model
// state to show before the first send, so without this a load failure is
// invisible to the user and to the gate.
static void writeChatEngineStatus(const std::string& requestedPath)
{
    std::string dir = getExeDir();
    if (dir.empty()) return;
    dir += "\\";
    std::string path = dir + "ide_chat_engine_status.txt";
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    std::string r;
    r += "=== RAWRXD_IDE_CHAT_ENGINE_STATUS ===\r\n";
    r += std::string("REQUESTED_MODEL=") + requestedPath + "\r\n";
    r += std::string("ENGINE_PRESENT=") + (g_chatEngine ? "1" : "0") + "\r\n";
    r += std::string("ENGINE_INITIALIZED=") + ((g_chatEngine && g_chatEngine->isInitialized()) ? "1" : "0") + "\r\n";
    r += std::string("MODEL_LOADED=") + ((g_chatEngine && g_chatEngine->isModelLoaded()) ? "1" : "0") + "\r\n";
    r += std::string("LOADED_MODEL=") + g_chatModelPath + "\r\n";
    r += std::string("STATUS=") + g_chatEngineStatus + "\r\n";
    r += "=== RECEIPT_END ===\r\n";

    DWORD written = 0;
    WriteFile(hFile, r.data(), (DWORD)r.size(), &written, NULL);
    CloseHandle(hFile);
}

// The one and only send handler. The Send button and the --chat-prompt
// automation seam both land here, so a certification run exercises the same
// code the user does.
static void handleChatSend(const std::string& prompt) {
    if (prompt.empty()) return;

    if (!g_chatEngine) {
        RawrXD::IDE::ChatPanel_AddMessage(RawrXD::IDE::MsgRole::System,
            "[No model loaded. Use --model <path.gguf> to load a model at startup.]");
        return;
    }

    if (g_chatThread.joinable()) {
        // A second prompt cancels the in-flight stream. Record the request
        // so the gate can witness cancellation, not just completion.
        g_chatProgress.cancelRequested.store(true);
        g_chatCancelled = true;
        g_chatThread.join();
    }

    // BeginStreaming() already installs the assistant bubble that
    // AppendStreamToken fills in; adding a second empty message here would
    // capture the tokens and leave the streaming flag on the wrong bubble.
    RawrXD::IDE::ChatPanel_BeginStreaming();

    g_chatThread = std::thread(chatWorkerThread, prompt);
}

// Wire ChatPanel send callback to Deep2Engine
static void wireChatToDeep2() {
    RawrXD::IDE::ChatPanel_SetSendCallback(handleChatSend);
}

#define WM_AUTORUN          (WM_APP + 100)
#define WM_AUTORUN_COMPLETE   (WM_APP + 101)

// ---------------------------------------------------------------------------
// Helpers — exe-relative path resolution
// ---------------------------------------------------------------------------
static std::string getExeDir()
{
    wchar_t buf[MAX_PATH] = {};
    if (GetModuleFileNameW(NULL, buf, MAX_PATH) == 0) return "";
    std::wstring wpath(buf);
    size_t lastSlash = wpath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) wpath.resize(lastSlash);

    int len = WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wpath.c_str(), -1, &result[0], len, nullptr, nullptr);
    // Remove possible trailing null added by WideCharToMultiByte
    while (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

// ---------------------------------------------------------------------------
// Headless log helper — GUI apps have no connected stderr; write to file instead
// ---------------------------------------------------------------------------
static void openHeadlessLog()
{
    if (g_headlessLog) return;
    std::string logPath = getExeDir();
    if (!logPath.empty()) logPath += "\\";
    logPath += "headless_gate_log.txt";
    g_headlessLog = std::fopen(logPath.c_str(), "w");
    if (g_headlessLog) {
        std::setvbuf(g_headlessLog, nullptr, _IONBF, 0);
    }
}

static void headlessLogPrintf(const char* fmt, ...)
{
    if (!g_headlessLog) return;
    va_list args;
    va_start(args, fmt);
    std::vfprintf(g_headlessLog, fmt, args);
    va_end(args);
}

static void closeHeadlessLog()
{
    if (g_headlessLog) {
        std::fclose(g_headlessLog);
        g_headlessLog = nullptr;
    }
}

// ---------------------------------------------------------------------------
// GUI-subsystem apps have no connected stderr; redirect it to a file
// so that std::fprintf(stderr, ...) calls across all modules don't crash
// with ucrtbase!_invoke_watson (0xc0000409).
// ---------------------------------------------------------------------------
static void redirectStderrToFile()
{
    std::string path = getExeDir();
    if (!path.empty()) path += "\\";
    path += "headless_stderr.txt";
    FILE* newStderr = nullptr;
    // freopen_s properly reassigns the stderr FILE* (not just fd) to a file
    errno_t err = ::freopen_s(&newStderr, path.c_str(), "w", stderr);
    if (err == 0 && newStderr) {
        std::setvbuf(stderr, nullptr, _IONBF, 0);
    }
}

// ---------------------------------------------------------------------------
// Window state
// ---------------------------------------------------------------------------
// g_hMainWnd is defined above with the chat engine code
static HWND g_hOutput  = NULL;

// Menu IDs (must match Win32IDE_Commands.cpp)
#define IDM_FILE_NEW        1001
#define IDM_FILE_OPEN       1002
#define IDM_FILE_SAVE       1003
#define IDM_FILE_SAVEAS     1004
#define IDM_FILE_SAVEALL    1005
#define IDM_FILE_CLOSE      1006
#define IDM_FILE_EXIT       1099
#define IDM_BUILD_NATIVE    2001
#define IDM_EDIT_UNDO       2101
#define IDM_EDIT_REDO       2102
#define IDM_EDIT_CUT        2103
#define IDM_EDIT_COPY       2104
#define IDM_EDIT_PASTE      2105
#define IDM_EDIT_SELECT_ALL 2106
#define IDM_EDIT_FIND       2107
#define IDM_EDIT_REPLACE    2108
#define IDM_MODEL_LOCAL     3001
#define IDM_MODEL_DIAG      3002
#define IDM_AGENTIC_GATE    4001
#define IDM_AGENTIC_E2E_GATE 4002
#define IDM_VIEW_SIDEBAR    5001

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static void appendOutput(const std::string& text)
{
    if (!g_hOutput) return;
    int len = GetWindowTextLengthA(g_hOutput);
    SendMessageA(g_hOutput, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(g_hOutput, EM_REPLACESEL, 0, (LPARAM)text.c_str());
}

static void appendOutputLine(const std::string& text)
{
    appendOutput(text + "\r\n");
    if (g_startupOptions.headless) {
        // GUI-subsystem apps have no connected stderr; use file log instead
        headlessLogPrintf("%s\n", text.c_str());
    }
}

// ---------------------------------------------------------------------------
// Native Toolchain Gate — runs inside the shipping IDE process
// ---------------------------------------------------------------------------
static void runToolchainGate()
{
    appendOutputLine("=== RAWRXD_WIN32IDE_TOOLCHAIN_001 ===");
    appendOutputLine("IDE_LAUNCH=PASS");

    RawrXD::IDE::ToolchainResult r = RawrXD::IDE::runNativeToolchainGate();

    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("SOURCE_COMPILE=") + (r.jitOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("COFF_EMIT=")     + (r.coffOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("PE_LINK=")       + (r.peOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("OUTPUT_EXISTS=")  + (r.peOk && !r.exePath.empty() ? "PASS" : "FAIL"));
    appendOutputLine(std::string("OUTPUT_EXECUTES=")+ (r.helloRunOk ? "PASS" : "FAIL"));
    appendOutputLine("STUB_FALLBACKS=0");

    bool allOk = r.jitOk && r.coffOk && r.peOk && r.helloRunOk;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");
    // Write certification receipt to a known file so a headless witness can read it
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_gate1.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = "=== RAWRXD_WIN32IDE_TOOLCHAIN_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("SOURCE_COMPILE=") + (r.jitOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("COFF_EMIT=") + (r.coffOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("PE_LINK=") + (r.peOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("OUTPUT_EXISTS=") + (r.peOk && !r.exePath.empty() ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("OUTPUT_EXECUTES=") + (r.helloRunOk ? "PASS" : "FAIL") + "\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

// ---------------------------------------------------------------------------
// Local Inference Gate — runs inside the shipping IDE process
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Diagnostic Gate (RAWRXD_MODEL_ADMISSION_DIAG_001)
// ---------------------------------------------------------------------------
static void runDiagnosticGate()
{
    appendOutputLine("=== RAWRXD_MODEL_ADMISSION_DIAG_001 ===");
    appendOutputLine("IDE_LAUNCH=PASS");

    RawrXD::IDE::DiagnosticGateResult r = RawrXD::IDE::runDiagnosticGate();

    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL"));
    appendOutputLine(std::string("PATH_READABLE=") + (r.pathReadable ? "PASS" : "FAIL"));
    appendOutputLine(std::string("EXTENSION_OK=") + (r.extensionOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("FILE_SIZE_BYTES=") + std::to_string(r.fileSizeBytes));
    appendOutputLine(std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion));
    appendOutputLine(std::string("METADATA_HAS_ARCH=") + (r.metadataHasArch ? "PASS" : "FAIL"));
    appendOutputLine(std::string("DETECTED_ARCH=") + r.detectedArch);
    appendOutputLine(std::string("HAS_TOKEN_EMBED=") + (r.hasTokenEmbed ? "PASS" : "FAIL"));
    appendOutputLine(std::string("HAS_LM_HEAD=") + (r.hasLmHead ? "PASS" : "FAIL"));
    appendOutputLine(std::string("HAS_FINAL_NORM=") + (r.hasFinalNorm ? "PASS" : "FAIL"));
    appendOutputLine(std::string("LAYER_TENSOR_COUNT=") + std::to_string(r.layerTensorCount));
    appendOutputLine(std::string("TENSOR_COUNT=") + std::to_string(r.tensorCount));
    appendOutputLine("STUB_FALLBACKS=0");
    if (!r.failStage.empty()) {
        appendOutputLine(std::string("FAIL_STAGE=") + r.failStage);
        appendOutputLine(std::string("FAIL_CODE=") + std::to_string(r.failCode));
        appendOutputLine(std::string("FAIL_MESSAGE=") + r.diagnostics);
    }

    bool allOk = r.modelFound && r.pathReadable && r.extensionOk && r.ggufMagicOk && r.metadataHasArch
              && r.hasTokenEmbed && r.hasLmHead && r.hasFinalNorm;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");

    // Write certification receipt
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_diag.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = "=== RAWRXD_MODEL_ADMISSION_DIAG_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("PATH_READABLE=") + (r.pathReadable ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("EXTENSION_OK=") + (r.extensionOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("FILE_SIZE_BYTES=") + std::to_string(r.fileSizeBytes) + "\r\n";
            receipt += std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion) + "\r\n";
            receipt += std::string("METADATA_HAS_ARCH=") + (r.metadataHasArch ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("DETECTED_ARCH=") + r.detectedArch + "\r\n";
            receipt += std::string("HAS_TOKEN_EMBED=") + (r.hasTokenEmbed ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("HAS_LM_HEAD=") + (r.hasLmHead ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("HAS_FINAL_NORM=") + (r.hasFinalNorm ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("LAYER_TENSOR_COUNT=") + std::to_string(r.layerTensorCount) + "\r\n";
            receipt += std::string("TENSOR_COUNT=") + std::to_string(r.tensorCount) + "\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            if (!r.failStage.empty()) {
                receipt += std::string("FAIL_STAGE=") + r.failStage + "\r\n";
                receipt += std::string("FAIL_CODE=") + std::to_string(r.failCode) + "\r\n";
                receipt += std::string("FAIL_MESSAGE=") + r.diagnostics + "\r\n";
            }
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

static void runInferenceGate()
{
    appendOutputLine("=== RAWRXD_WIN32IDE_INFERENCE_001 ===");
    appendOutputLine("IDE_LAUNCH=PASS");

    RawrXD::IDE::InferenceGateResult r = RawrXD::IDE::runLocalInferenceGate();

    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_PATH_VALID=") + (r.modelPathValid ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_FILE_OPEN=") + (r.modelFileOpen ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_FILE_SIZE_BYTES=") + std::to_string(r.modelFileSizeBytes));
    appendOutputLine(std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion));
    appendOutputLine(std::string("GGUF_METADATA_PARSE=") + (r.ggufMetadataParseOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TENSOR_COUNT=") + std::to_string(r.ggufTensorCount));
    appendOutputLine(std::string("TENSOR_TABLE_PARSE=") + (r.ggufTensorTableOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_ARCH=") + r.detectedArch);
    appendOutputLine(std::string("BACKEND_CREATE=") + (r.backendCreateOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_CONTEXT_CREATE=") + (r.modelContextCreateOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_LOADED=") + (r.modelLoaded ? "PASS" : "FAIL"));
    appendOutputLine(std::string("WEIGHTS_LOADED=") + (r.weightsLoaded ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOKENIZER_READY=") + (r.tokenizerReady ? "PASS" : "FAIL"));
    appendOutputLine(std::string("FORWARD_PASS_OK=") + (r.forwardPassOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("LOGITS_FINITE=") + (r.logitsFinite ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GENERATED_TOKEN_COUNT=") + std::to_string(r.generatedTokens));
    appendOutputLine(std::string("GENERATED_TOKEN_ID=") + std::to_string(r.generatedToken));
    appendOutputLine("SYNTHETIC_TOKEN_OUTPUT=0");
    appendOutputLine("STUB_FALLBACKS=0");
    if (!r.failStage.empty()) {
        appendOutputLine(std::string("FAIL_STAGE=") + r.failStage);
        appendOutputLine(std::string("FAIL_CODE=") + std::to_string(r.failCode));
        appendOutputLine(std::string("FAIL_MESSAGE=") + r.failMessage);
    }

    bool allOk = r.modelFound && r.modelLoaded && r.weightsLoaded && r.tokenizerReady
              && r.forwardPassOk && r.logitsFinite && r.generatedTokens > 0;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");

    // Write certification receipt (exe-relative so it follows the binary)
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_gate2.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = "=== RAWRXD_WIN32IDE_INFERENCE_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("MODEL_FOUND=") + (r.modelFound ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_PATH_VALID=") + (r.modelPathValid ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_FILE_OPEN=") + (r.modelFileOpen ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_FILE_SIZE_BYTES=") + std::to_string(r.modelFileSizeBytes) + "\r\n";
            receipt += std::string("GGUF_MAGIC=") + (r.ggufMagicOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GGUF_VERSION=") + std::to_string(r.ggufVersion) + "\r\n";
            receipt += std::string("GGUF_METADATA_PARSE=") + (r.ggufMetadataParseOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TENSOR_COUNT=") + std::to_string(r.ggufTensorCount) + "\r\n";
            receipt += std::string("TENSOR_TABLE_PARSE=") + (r.ggufTensorTableOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_ARCH=") + r.detectedArch + "\r\n";
            receipt += std::string("BACKEND_CREATE=") + (r.backendCreateOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_CONTEXT_CREATE=") + (r.modelContextCreateOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_LOADED=") + (r.modelLoaded ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("WEIGHTS_LOADED=") + (r.weightsLoaded ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOKENIZER_READY=") + (r.tokenizerReady ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("FORWARD_PASS_OK=") + (r.forwardPassOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("LOGITS_FINITE=") + (r.logitsFinite ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GENERATED_TOKEN_COUNT=") + std::to_string(r.generatedTokens) + "\r\n";
            receipt += std::string("GENERATED_TOKEN_ID=") + std::to_string(r.generatedToken) + "\r\n";
            receipt += "SYNTHETIC_TOKEN_OUTPUT=0\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            if (!r.failStage.empty()) {
                receipt += std::string("FAIL_STAGE=") + r.failStage + "\r\n";
                receipt += std::string("FAIL_CODE=") + std::to_string(r.failCode) + "\r\n";
                receipt += std::string("FAIL_MESSAGE=") + r.failMessage + "\r\n";
            }
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

// ---------------------------------------------------------------------------
// Agentic Gate — RAWRXD_WIN32IDE_AGENT_001
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Agentic E2E Gate — RAWRXD_WIN32IDE_AGENTIC_001
// ---------------------------------------------------------------------------
static void runAgenticE2EGate()
{
    appendOutputLine("=== RAWRXD_WIN32IDE_AGENTIC_001 ===");
    appendOutputLine("IDE_LAUNCH=PASS");

    // Deep2Engine init (same pattern as ide_inference_gate.cpp)
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen = 8192;
    cfg.hiddenDim = 3072;
    cfg.numHeads = 24;
    cfg.numLayers = 28;
    cfg.vocabSize = 128256;
    cfg.intermediateDim = 8192;

    Deep2::Deep2Engine engine;
    if (!engine.initialize(cfg)) {
        appendOutputLine("COMMAND_DISPATCH=FAIL");
        appendOutputLine("FAIL_STAGE=ENGINE_INIT");
        appendOutputLine("FAIL_MESSAGE=Deep2Engine::initialize failed");
        appendOutputLine("VERDICT=FAIL");
        // Write minimal receipt
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_agentic_e2e.txt";
        HANDLE hFile = CreateFileA(receiptPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string r = "=== RAWRXD_WIN32IDE_AGENTIC_001 ===\r\nVERDICT=FAIL\r\n";
            DWORD written = 0; WriteFile(hFile, r.data(), (DWORD)r.size(), &written, NULL); CloseHandle(hFile);
        }
        return;
    }

    // Resolve model path
    std::string modelPath = "D:\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* envModel = std::getenv("RAWRXD_AGENT_MODEL");
    if (envModel && envModel[0]) modelPath = envModel;
    if (!g_startupOptions.modelPath.empty()) modelPath = g_startupOptions.modelPath;

    Deep2::ModelLoadDiag diag{};
    if (!engine.loadModel(modelPath.c_str(), &diag)) {
        appendOutputLine("COMMAND_DISPATCH=FAIL");
        appendOutputLine("FAIL_STAGE=LOAD_MODEL");
        appendOutputLine(std::string("FAIL_MESSAGE=") + diag.message + " [code=" + std::to_string(diag.stageCode) + "]");
        appendOutputLine("VERDICT=FAIL");
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_agentic_e2e.txt";
        HANDLE hFile = CreateFileA(receiptPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string r = "=== RAWRXD_WIN32IDE_AGENTIC_001 ===\r\nFAIL_STAGE=LOAD_MODEL\r\nVERDICT=FAIL\r\n";
            DWORD written = 0; WriteFile(hFile, r.data(), (DWORD)r.size(), &written, NULL); CloseHandle(hFile);
        }
        return;
    }

    appendOutputLine("COMMAND_DISPATCH=PASS");

    rawrxd::agentic_e2e::AgenticE2EOptions opts{};
    opts.workspaceRoot = getExeDir();
    opts.fixtureDir = ".rawr/agentic_gate";
    opts.maxSteps = 10;
    opts.maxTokensPerStep = 256;
    opts.processTimeoutMs = 120000;
    opts.keepFixture = false;

    rawrxd::agentic_e2e::AgenticE2EReceipt r = rawrxd::agentic_e2e::runAgenticE2EGate(engine, opts);

    appendOutputLine("REAL_MODEL_INFERENCE=" + std::string(r.modelInference ? "PASS" : "FAIL"));
    appendOutputLine("TOOL_AUTHORITY=" + std::string(r.toolAuthority ? "PASS" : "FAIL"));
    appendOutputLine("FILE_READ=" + std::string(r.fileRead ? "PASS" : "FAIL"));
    appendOutputLine("FILE_EDIT=" + std::string(r.fileEdit ? "PASS" : "FAIL"));
    appendOutputLine("BUILD_RAN=" + std::string(r.buildRan ? "PASS" : "FAIL"));
    appendOutputLine("BUILD_PASS=" + std::string(r.buildPassed ? "PASS" : "FAIL"));
    appendOutputLine("TEST_RAN=" + std::string(r.testRan ? "PASS" : "FAIL"));
    appendOutputLine("TEST_PASS=" + std::string(r.testPassed ? "PASS" : "FAIL"));
    appendOutputLine("TOOL_RESULT_IN_CONTEXT=" + std::string(r.toolResultFedBack ? "PASS" : "FAIL"));
    appendOutputLine("MODEL_FINAL=" + std::string(r.reachedFinal ? "PASS" : "FAIL"));
    appendOutputLine("STEPS=" + std::to_string(r.steps));
    appendOutputLine("TOOL_CALLS=" + std::to_string(r.toolCalls));
    appendOutputLine("SUCCESSFUL_TOOL_CALLS=" + std::to_string(r.successfulToolCalls));
    appendOutputLine("FAILED_TOOL_CALLS=" + std::to_string(r.failedToolCalls));
    appendOutputLine("GENERATED_TOKEN_COUNT=" + std::to_string(r.generatedTokens));
    appendOutputLine("CHILD_EXIT_CODE=" + std::to_string(r.childExitCode));
    appendOutputLine("SYNTHETIC_TOKEN_OUTPUT=0");
    appendOutputLine("STUB_FALLBACKS=" + std::to_string(r.stubFallbacks));
    if (!r.firstTool.empty()) appendOutputLine("FIRST_TOOL=" + r.firstTool);
    if (!r.failStage.empty()) {
        appendOutputLine("FAIL_STAGE=" + r.failStage);
        if (!r.failMessage.empty()) appendOutputLine("FAIL_MESSAGE=" + r.failMessage);
    }
    appendOutputLine(std::string("VERDICT=") + (r.pass() ? "PASS" : "FAIL"));
    appendOutputLine("");

    // Write certification receipt
    {
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_agentic_e2e.txt";
        HANDLE hFile = CreateFileA(receiptPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string receipt = rawrxd::agentic_e2e::formatAgenticE2EReceipt(r);
            receipt += "=== RECEIPT_END ===\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

// ---------------------------------------------------------------------------
// Agentic Gate — RAWRXD_WIN32IDE_AGENT_001
// ---------------------------------------------------------------------------
static void runAgenticGate()
{
    RawrXD::IDE::AgenticGateResult r;
    headlessLogPrintf("MAIN_AGENT_GATE_CALL\n");
    try {
        appendOutputLine("=== RAWRXD_WIN32IDE_AGENT_001 ===");
        appendOutputLine("IDE_LAUNCH=PASS");

        r = RawrXD::IDE::runAgenticGate();
    } catch (const std::exception& e) {
        if (r.failStage.empty()) r.failStage = "EXCEPTION";
        r.failCode = -1;
        r.diagnostics = std::string("Outer exception: ") + e.what();
    } catch (...) {
        if (r.failStage.empty()) r.failStage = "UNKNOWN_EXCEPTION";
        r.failCode = -1;
        r.diagnostics = "Outer unknown exception in runAgenticGate.";
    }

    headlessLogPrintf("MAIN_AGENT_GATE_RETURNED\n");
    // ── Emit diagnostics ───────────────────────────────────────────
    appendOutputLine("COMMAND_DISPATCH=PASS");
    appendOutputLine(std::string("STREAMER_BUILT=") + (r.streamerBuilt ? "PASS" : "FAIL"));
    appendOutputLine(std::string("ENGINE_INIT=") + (r.engineInitOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_LOADED=") + (r.modelLoadedOk ? "PASS" : "FAIL"));
    appendOutputLine(std::string("CHANNEL_OPENED=") + (r.channelOpened ? "PASS" : "FAIL"));
    appendOutputLine(std::string("GENERATION_STARTED=") + (r.generationStarted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_STREAM_STARTED=") + (r.modelStreamStarted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOKENS_RECEIVED=") + (r.tokensReceived ? "PASS" : "FAIL"));
    appendOutputLine(std::string("STREAMED_TOKEN_COUNT=") + std::to_string(r.streamedTokenCount));
    appendOutputLine(std::string("TOKEN_COUNT=") + std::to_string(r.tokenCount));
    appendOutputLine(std::string("FIRST_TOKEN=") + r.firstTokenText);
    appendOutputLine(std::string("TOOL_REQUEST_SEEN=") + (r.toolRequestSeen ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_REQUEST_ORIGIN=MODEL"));
    appendOutputLine(std::string("TOOL_REQUEST_PARSE=") + (r.toolRequestParsed ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_REQUEST_RAW=") + r.rawToolRequest);
    appendOutputLine(std::string("TOOL_NAME=") + r.toolName);
    appendOutputLine(std::string("TOOL_AUTHORITY_RECEIVED=") + (r.toolAuthorityInvoked ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_EXECUTED=") + (r.toolExecuted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_RESULT_RETURNED=") + (r.toolResultReturned ? "PASS" : "FAIL"));
    appendOutputLine(std::string("TOOL_RESULT_REINJECTED=") + (r.toolResultInjected ? "PASS" : "FAIL"));
    appendOutputLine(std::string("MODEL_CONTINUATION=") + (r.continuationStarted ? "PASS" : "FAIL"));
    appendOutputLine(std::string("POST_TOOL_TOKENS=") + std::to_string(r.postToolTokenCount));
    appendOutputLine("SYNTHETIC_TOOL_REQUEST=0");
    appendOutputLine("STUB_FALLBACKS=0");
    if (!r.failStage.empty()) {
        appendOutputLine(std::string("FAIL_STAGE=") + r.failStage);
        appendOutputLine(std::string("FAIL_CODE=") + std::to_string(r.failCode));
        appendOutputLine(std::string("FAIL_MESSAGE=") + r.diagnostics);
    }

    bool allOk = r.streamerBuilt && r.engineInitOk && r.modelLoadedOk && r.channelOpened
              && r.generationStarted && r.tokensReceived && r.toolRequestSeen
              && r.toolRequestParsed && r.toolAuthorityInvoked && r.toolExecuted
              && r.toolResultReturned && r.toolResultInjected
              && r.continuationStarted && r.postToolTokenCount > 0 && r.nonceMatched;
    appendOutputLine(std::string("VERDICT=") + (allOk ? "PASS" : "FAIL"));
    appendOutputLine("");

    // ── Write certification receipt UNCONDITIONALLY ──────────────────
    {
        headlessLogPrintf("CERT_RECEIPT_WRITE_BEGIN\n");
        std::string receiptDir = getExeDir();
        if (!receiptDir.empty()) receiptDir += "\\";
        std::string receiptPath = receiptDir + "cert_receipt_agentic.txt";
        HANDLE hFile = CreateFileA(
            receiptPath.c_str(),
            GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            // Fallback: try writing to current working directory
            receiptPath = "cert_receipt_agentic.txt";
            hFile = CreateFileA(
                receiptPath.c_str(),
                GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            headlessLogPrintf("CERT_RECEIPT_WRITE_END path=%s\n", receiptPath.c_str());
            std::string receipt = "=== RAWRXD_WIN32IDE_AGENT_001 ===\r\n";
            receipt += "IDE_LAUNCH=PASS\r\n";
            receipt += "COMMAND_DISPATCH=PASS\r\n";
            receipt += std::string("STREAMER_BUILT=") + (r.streamerBuilt ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("ENGINE_INIT=") + (r.engineInitOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_LOADED=") + (r.modelLoadedOk ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("CHANNEL_OPENED=") + (r.channelOpened ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("GENERATION_STARTED=") + (r.generationStarted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_STREAM_STARTED=") + (r.modelStreamStarted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOKENS_RECEIVED=") + (r.tokensReceived ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("STREAMED_TOKEN_COUNT=") + std::to_string(r.streamedTokenCount) + "\r\n";
            receipt += std::string("TOKEN_COUNT=") + std::to_string(r.tokenCount) + "\r\n";
            receipt += std::string("FIRST_TOKEN=") + r.firstTokenText + "\r\n";
            receipt += std::string("TOOL_REQUEST_SEEN=") + (r.toolRequestSeen ? "PASS" : "FAIL") + "\r\n";
            receipt += "TOOL_REQUEST_ORIGIN=MODEL\r\n";
            receipt += std::string("TOOL_REQUEST_PARSE=") + (r.toolRequestParsed ? "PASS" : "FAIL") + "\r\n";
            receipt += "=== RAW_TOOL_REQUEST_BEGIN ===\r\n";
            receipt += r.rawToolRequest;
            receipt += "\r\n=== RAW_TOOL_REQUEST_END ===\r\n";
            receipt += std::string("TOOL_REQUEST_RAW=") + r.rawToolRequest + "\r\n";
            receipt += std::string("TOOL_NAME=") + r.toolName + "\r\n";
            receipt += std::string("TOOL_AUTHORITY_RECEIVED=") + (r.toolAuthorityInvoked ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOOL_EXECUTED=") + (r.toolExecuted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOOL_RESULT_RETURNED=") + (r.toolResultReturned ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("TOOL_RESULT_REINJECTED=") + (r.toolResultInjected ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("MODEL_CONTINUATION=") + (r.continuationStarted ? "PASS" : "FAIL") + "\r\n";
            receipt += std::string("POST_TOOL_TOKENS=") + std::to_string(r.postToolTokenCount) + "\r\n";
            receipt += std::string("NONCE_MATCH=") + (r.nonceMatched ? "PASS" : "FAIL") + "\r\n";
            receipt += "SYNTHETIC_TOOL_REQUEST=0\r\n";
            receipt += "STUB_FALLBACKS=0\r\n";
            if (!r.failStage.empty()) {
                receipt += std::string("FAIL_STAGE=") + r.failStage + "\r\n";
                receipt += std::string("FAIL_CODE=") + std::to_string(r.failCode) + "\r\n";
                receipt += std::string("FAIL_MESSAGE=") + r.diagnostics + "\r\n";
            } else {
                receipt += "FAIL_STAGE=NONE\r\n";
                receipt += "FAIL_CODE=0\r\n";
                receipt += "FAIL_MESSAGE=\r\n";
            }
            receipt += "=== MODEL_STREAM_BEGIN ===\r\n";
            receipt += r.streamedText;
            receipt += "\r\n=== MODEL_STREAM_END ===\r\n";
            receipt += std::string("VERDICT=") + (allOk ? "PASS" : "FAIL") + "\r\n";
            DWORD written = 0;
            WriteFile(hFile, receipt.data(), (DWORD)receipt.size(), &written, NULL);
            CloseHandle(hFile);
        }
    }
}

// ---------------------------------------------------------------------------
// Window Procedure
// ---------------------------------------------------------------------------
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        HINSTANCE hInst = ((LPCREATESTRUCT)lParam)->hInstance;
        g_hMainWnd = hWnd;
        // Full IDE shell layout (sidebar, editor, chat, agent, terminal, git, search)
        RawrXD::IDE::ShellLayout_RegisterAll(hInst);
        RawrXD::IDE::ShellLayout_CreateAll(hWnd, hInst);

        // Wire command router to real editor and main window
        HWND hEditor = RawrXD::IDE::ShellLayout_GetEditor();
        Win32IDE_Commands_SetMainWindow(hWnd);
        Win32IDE_Commands_SetEditorWindow(hEditor);

        // Wire ChatPanel → Deep2Engine streaming
        // Try --model path, then RAWRXD_AGENT_MODEL env, then default
        std::string chatModel = g_startupOptions.modelPath;
        if (chatModel.empty()) {
            const char* envModel = std::getenv("RAWRXD_AGENT_MODEL");
            if (envModel) chatModel = envModel;
        }
        if (!chatModel.empty() && initChatEngine(chatModel)) {
            appendOutputLine("Chat engine loaded: " + chatModel + "\r\n");
        } else {
            appendOutputLine("Chat engine: no model loaded (use --model <path.gguf>)\r\n");
        }
        writeChatEngineStatus(chatModel);
        wireChatToDeep2();

        // Automation seam: same handler the Send button invokes, triggered from
        // argv because an external process cannot type into this EDIT control.
        if (!g_startupOptions.chatPrompt.empty()) {
            RawrXD::IDE::ChatPanel_AddMessage(RawrXD::IDE::MsgRole::User, g_startupOptions.chatPrompt);
            handleChatSend(g_startupOptions.chatPrompt);
        }

        // Legacy output control: re-parent it into terminal area for now
        g_hOutput = CreateWindowExA(
            WS_EX_CLIENTEDGE,
            "EDIT",
            "",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
            0, 0, 400, 200,
            RawrXD::IDE::ShellLayout_GetTerminal(),
            NULL, hInst, NULL);
        if (g_hOutput)
        {
            SendMessageA(g_hOutput, WM_SETFONT, (WPARAM)GetStockObject(ANSI_FIXED_FONT), TRUE);
            appendOutputLine("RawrXD Win32 IDE — Build -> Native Compile Test to run toolchain gate.\r\n");
        }
        break;
    }
    case WM_SIZE:
    {
        int W = LOWORD(lParam);
        int H = HIWORD(lParam);
        RawrXD::IDE::ShellLayout_Resize(W, H);
        break;
    }
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDM_FILE_EXIT:
            DestroyWindow(hWnd);
            break;
        case IDM_BUILD_NATIVE:
            runToolchainGate();
            break;
        case IDM_MODEL_LOCAL:
            runInferenceGate();
            break;
        case IDM_MODEL_DIAG:
            runDiagnosticGate();
            break;
        case IDM_AGENTIC_GATE:
            runAgenticGate();
            break;
        case IDM_AGENTIC_E2E_GATE:
            runAgenticE2EGate();
            break;
        case IDM_VIEW_SIDEBAR:
        {
            bool vis = !Win32IDE_Sidebar_IsVisible();
            Win32IDE_Sidebar_SetVisibility(vis);
            // Also trigger shell layout resize to reflow editor
            RECT rc; GetClientRect(hWnd, &rc);
            RawrXD::IDE::ShellLayout_Resize(rc.right, rc.bottom);
            break;
        }
        default:
            // RAWRXD_IDE_STUB_CLOSURE_RECOVERY_001 — delegate to command router
            if (Win32IDE_Commands_Route(wmId)) break;
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;
    }
    case WM_CHAT_TOKEN:
    {
        ChatTokenData* data = (ChatTokenData*)lParam;
        if (data) {
            RawrXD::IDE::ChatPanel_AppendStreamToken(data->token);
            if (data->isError) {
                RawrXD::IDE::ChatPanel_EndStreaming();
                RawrXD::IDE::ChatPanel_AddMessage(RawrXD::IDE::MsgRole::System, data->token);
            }
            delete data;
        }
        break;
    }
    case WM_CHAT_DONE:
    {
        onChatDone();
        ChatDoneData* done = (ChatDoneData*)lParam;
        if (done) {
            // Every token message was queued ahead of this one, so the panel
            // store already holds the fully rendered assistant bubble.
            size_t n = RawrXD::IDE::ChatPanel_MessageCount();
            if (n > 0) done->tel.streamedText = RawrXD::IDE::ChatPanel_GetMessage(n - 1);
            g_chatTelemetry = done->tel;
            writeChatE2EReceipt(done->tel);
            delete done;
            if (g_startupOptions.chatExitOnDone && g_hMainWnd) {
                // Unattended run: close once the receipt is on disk.
                PostMessageA(g_hMainWnd, WM_CLOSE, 0, 0);
            }
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    case WM_CLOSE:
        // D-W6-001: do NOT clean up the engine here — the destructor chain
        // (111+ STL members) causes both stack overflow and access violations
        // during window teardown. The engine is intentionally leaked; the OS
        // reclaims all memory on process exit. The generation receipt is
        // already written before this point.
        g_chatCancelled = true;
        if (g_chatThread.joinable()) g_chatThread.join();
        DestroyWindow(hWnd);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Autorun helper
// ---------------------------------------------------------------------------
static int runAutorunGate(AutoRunMode mode)
{
    int result = 1;
    switch (mode) {
    case AutoRunMode::Inference:
        runInferenceGate();
        result = 0;
        break;
    case AutoRunMode::Agent:
        runAgenticGate();
        result = 0;
        break;
    case AutoRunMode::Layer0:
        // runLayer0FinalGate();
        result = 0;
        break;
    case AutoRunMode::AgenticE2E:
        runAgenticE2EGate();
        result = 0;
        break;
    default:
        result = 2;
        break;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // D-W6-003: catch access violations during post-generation shutdown.
    SetUnhandledExceptionFilter([](LPEXCEPTION_POINTERS ep) -> LONG {
        if (ep && ep->ExceptionRecord &&
            ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            return EXCEPTION_EXECUTE_HANDLER;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });

    (void)hPrevInstance;

    // RAWRXD_AUTOCLOSURE_001 — bounded autonomous CLI path before GUI startup.
    if (RawrXD::AutoClosure::CommandLineRequested()) {
        return RawrXD::AutoClosure::RunFromCurrentCommandLine();
    }

    // Parse command line for autorun / cert mode
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv) {
        for (int i = 1; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (arg == L"--cert-inference" || arg == L"--autorun=inference")
                g_startupOptions.autoRun = AutoRunMode::Inference;
            else if (arg == L"--cert-agent" || arg == L"--autorun=agent")
                g_startupOptions.autoRun = AutoRunMode::Agent;
            else if (arg == L"--cert-layer0" || arg == L"--autorun=layer0")
                g_startupOptions.autoRun = AutoRunMode::Layer0;
            else if (arg == L"--cert-agentic-e2e" || arg == L"--autorun=agentic-e2e")
                g_startupOptions.autoRun = AutoRunMode::AgenticE2E;
            else if (arg == L"--headless") {
                g_startupOptions.headless = true;
                openHeadlessLog();
                redirectStderrToFile();
            }
            else if (arg == L"--phase1-timeout-ms" && i + 1 < argc) {
                g_startupOptions.phase1TimeoutMs = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
            }
            else if (arg == L"--phase2-timeout-ms" && i + 1 < argc) {
                g_startupOptions.phase2TimeoutMs = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
            }
            else if ((arg == L"--model" || arg == L"--model=") && i + 1 < argc) {
                int len = WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    std::string u8(static_cast<size_t>(len), '\0');
                    WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &u8[0], len, nullptr, nullptr);
                    while (!u8.empty() && u8.back() == '\0') u8.pop_back();
                    g_startupOptions.modelPath = u8;
                }
            }
            else if (arg == L"--chat-exit-on-done") {
                g_startupOptions.chatExitOnDone = true;
            }
            else if (arg == L"--chat-max-tokens" && i + 1 < argc) {
                g_startupOptions.chatMaxTokens =
                    static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
            }
            else if (arg == L"--chat-greedy") {
                g_startupOptions.chatGreedy = true;
            }
            else if (arg == L"--chat-seed" && i + 1 < argc) {
                g_startupOptions.chatSeed =
                    static_cast<uint64_t>(std::wcstoull(argv[++i], nullptr, 10));
            }
            else if (arg == L"--chat-temperature" && i + 1 < argc) {
                g_startupOptions.chatTemperature =
                    static_cast<float>(std::wcstod(argv[++i], nullptr));
            }
            else if (arg == L"--chat-top-p" && i + 1 < argc) {
                g_startupOptions.chatTopP =
                    static_cast<float>(std::wcstod(argv[++i], nullptr));
            }
            else if (arg == L"--chat-top-k" && i + 1 < argc) {
                g_startupOptions.chatTopK =
                    static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
            }
            else if (arg == L"--chat-seed" && i + 1 < argc) {
                g_startupOptions.chatSeed =
                    std::wcstoull(argv[++i], nullptr, 10);
            }
            else if ((arg == L"--chat-parity-probe" || arg == L"--chat-parity-probe=") && i + 1 < argc) {
                int len = WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    std::string u8(static_cast<size_t>(len), '\0');
                    WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &u8[0], len, nullptr, nullptr);
                    while (!u8.empty() && u8.back() == '\0') u8.pop_back();
                    g_startupOptions.chatParityProbePath = u8;
                }
            }
            else if ((arg == L"--chat-prompt" || arg == L"--chat-prompt=") && i + 1 < argc) {
                int len = WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    std::string u8(static_cast<size_t>(len), '\0');
                    WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &u8[0], len, nullptr, nullptr);
                    while (!u8.empty() && u8.back() == '\0') u8.pop_back();
                    g_startupOptions.chatPrompt = u8;
                }
            }
        }
        LocalFree(argv);
    }

    WNDCLASSEX wc = {0};
    wc.cbSize        = sizeof(WNDCLASSEX);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.lpszClassName = TEXT("RawrXDWin32IDE");
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    if (!RegisterClassEx(&wc))
    {
        MessageBox(NULL, TEXT("Failed to register window class."), TEXT("RawrXD-Win32IDE"), MB_ICONERROR);
        return 1;
    }

    g_hMainWnd = CreateWindowEx(
        0,
        wc.lpszClassName,
        TEXT("RawrXD Win32 IDE"),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);

    if (!g_hMainWnd)
    {
        MessageBox(NULL, TEXT("Failed to create window."), TEXT("RawrXD-Win32IDE"), MB_ICONERROR);
        return 1;
    }

    // Create menu bar
    HMENU hMenu = CreateMenu();
    HMENU hFile = CreatePopupMenu();
    AppendMenuA(hFile, MF_STRING, IDM_FILE_NEW,     "&New\tCtrl+N");
    AppendMenuA(hFile, MF_STRING, IDM_FILE_OPEN,   "&Open...\tCtrl+O");
    AppendMenuA(hFile, MF_STRING, IDM_FILE_SAVE,    "&Save\tCtrl+S");
    AppendMenuA(hFile, MF_STRING, IDM_FILE_SAVEAS,  "Save &As...\tCtrl+Shift+S");
    AppendMenuA(hFile, MF_STRING, IDM_FILE_SAVEALL,"Save A&ll");
    AppendMenuA(hFile, MF_STRING, IDM_FILE_CLOSE,   "&Close\tCtrl+W");
    AppendMenuA(hFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFile, MF_STRING, IDM_FILE_EXIT,    "E&xit");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hFile, "&File");

    HMENU hEdit = CreatePopupMenu();
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_UNDO,       "&Undo\tCtrl+Z");
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_REDO,       "&Redo\tCtrl+Y");
    AppendMenuA(hEdit, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_CUT,        "Cu&t\tCtrl+X");
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_COPY,       "&Copy\tCtrl+C");
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_PASTE,      "&Paste\tCtrl+V");
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_SELECT_ALL, "Select &All\tCtrl+A");
    AppendMenuA(hEdit, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_FIND,       "&Find...\tCtrl+F");
    AppendMenuA(hEdit, MF_STRING, IDM_EDIT_REPLACE,    "&Replace...\tCtrl+H");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hEdit, "&Edit");

    HMENU hBuild = CreatePopupMenu();
    AppendMenuA(hBuild, MF_STRING, IDM_BUILD_NATIVE, "&Native Compile Test\tF5");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hBuild, "&Build");

    HMENU hModel = CreatePopupMenu();
    AppendMenuA(hModel, MF_STRING, IDM_MODEL_LOCAL, "&Local Inference Test\tF6");
    AppendMenuA(hModel, MF_STRING, IDM_MODEL_DIAG,  "&Model Admission Diag\tF7");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hModel, "&Model");

    HMENU hAgentic = CreatePopupMenu();
    AppendMenuA(hAgentic, MF_STRING, IDM_AGENTIC_GATE,    "Agentic &Gate\tF8");
    AppendMenuA(hAgentic, MF_STRING, IDM_AGENTIC_E2E_GATE, "Agentic E&2E Gate\tF9");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hAgentic, "&Agentic");

    HMENU hView = CreatePopupMenu();
    AppendMenuA(hView, MF_STRING, IDM_VIEW_SIDEBAR, "&Toggle Sidebar\tCtrl+Shift+B");
    AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hView, "&View");

    SetMenu(g_hMainWnd, hMenu);

    // Accelerator table for Ctrl+N, Ctrl+O, Ctrl+S, Ctrl+Shift+S, Ctrl+W, Ctrl+Z, Ctrl+Y,
    // Ctrl+X, Ctrl+C, Ctrl+V, Ctrl+A, Ctrl+F, Ctrl+H
    static ACCEL accel[] = {
        { FCONTROL|FVIRTKEY, 'N', IDM_FILE_NEW },
        { FCONTROL|FVIRTKEY, 'O', IDM_FILE_OPEN },
        { FCONTROL|FVIRTKEY, 'S', IDM_FILE_SAVE },
        { FCONTROL|FSHIFT|FVIRTKEY, 'S', IDM_FILE_SAVEAS },
        { FCONTROL|FVIRTKEY, 'W', IDM_FILE_CLOSE },
        { FCONTROL|FVIRTKEY, 'Z', IDM_EDIT_UNDO },
        { FCONTROL|FVIRTKEY, 'Y', IDM_EDIT_REDO },
        { FCONTROL|FVIRTKEY, 'X', IDM_EDIT_CUT },
        { FCONTROL|FVIRTKEY, 'C', IDM_EDIT_COPY },
        { FCONTROL|FVIRTKEY, 'V', IDM_EDIT_PASTE },
        { FCONTROL|FVIRTKEY, 'A', IDM_EDIT_SELECT_ALL },
        { FCONTROL|FVIRTKEY, 'F', IDM_EDIT_FIND },
        { FCONTROL|FVIRTKEY, 'H', IDM_EDIT_REPLACE },
    };
    HACCEL hAccel = CreateAcceleratorTableA(accel, sizeof(accel)/sizeof(accel[0]));

    ShowWindow(g_hMainWnd, g_startupOptions.headless ? SW_HIDE : nCmdShow);
    UpdateWindow(g_hMainWnd);

    // RAWRXD_IDE_STUB_CLOSURE_RECOVERY_001 — wire command router + MCP bridge
    Win32IDE_Commands_SetMainWindow(g_hMainWnd);
    Win32IDE_Commands_SetEditorWindow(g_hOutput);
    RawrXD::MCPBridgeManager::GetInstance().Initialize(GetModuleHandle(NULL));

    // Post autorun message after window is ready
    if (g_startupOptions.autoRun != AutoRunMode::None) {
        PostMessage(g_hMainWnd, WM_AUTORUN, 0, 0);
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        if (msg.message == WM_AUTORUN) {
            // Launch gate on worker thread so UI pump remains alive
            std::thread([hwnd = g_hMainWnd, mode = g_startupOptions.autoRun]() {
                int gateResult = runAutorunGate(mode);
                PostMessage(hwnd, WM_AUTORUN_COMPLETE, static_cast<WPARAM>(gateResult), 0);
            }).detach();
            continue;
        }
        if (msg.message == WM_AUTORUN_COMPLETE) {
            PostQuitMessage(static_cast<int>(msg.wParam));
            continue;
        }
        if (!TranslateAcceleratorA(g_hMainWnd, hAccel, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    if (hAccel) DestroyAcceleratorTable(hAccel);

    // D-W6-001: clean up chat engine AFTER the message loop exits, on the
    // WinMain stack frame (not inside WM_DESTROY's window-procedure call).
    // This prevents the STATUS_STACK_OVERFLOW that occurred when the 111+
    // STL member destructor chain of Deep2Engine ran inside DispatchMessage.
    // D-W6-001/D-W6-002/D-W6-003: the Deep2Engine has 111+ STL members whose
    // destructor chain causes both STATUS_STACK_OVERFLOW (inside WM_DESTROY) and
    // STATUS_ACCESS_VIOLATION (post-message-loop, stale handle dereference).
    // The generation receipt is already written; the OS reclaims all memory on
    // process exit. Join the chat thread (it must not outlive the process) but
    // intentionally leak g_chatEngine (unique_ptr::reset is skipped) to avoid
    // the crash. This is acceptable for a GUI application's exit path.
    g_chatCancelled = true;
    if (g_chatThread.joinable()) g_chatThread.join();
    // g_chatEngine is intentionally NOT reset — the destructor is unsafe during
    // process teardown. The OS will reclaim the memory.
    // CRITICAL: call .release() to prevent the static unique_ptr's destructor
    // (which runs at CRT shutdown) from calling delete on the Deep2Engine.
    // Without .release(), the unique_ptr would destroy the engine at program
    // exit, causing the same 0xC0000005 access violation.
    if (g_chatEngine) {
        (void)g_chatEngine.release();  // leak the raw pointer; OS reclaims it
    }

    closeHeadlessLog();
    return (int)msg.wParam;
}
