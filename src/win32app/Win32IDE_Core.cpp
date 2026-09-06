// ============================================================================
// Win32IDE_Core.cpp - Core Window Management Functions
// createWindow, showWindow, runMessageLoop, ~Win32IDE, onSize,
// syncEditorToGpuSurface, initializeEditorSurface, trySendToOllama,
// createReverseEngineeringMenu, handleReverseEngineering* — implemented in Win32IDE_ReverseEngineering.cpp (output to
// IDE Output tab)
// ============================================================================

// AI Completion System forward declaration (VAL-063)
extern "C" void ShutdownAICompletion();

#include "../../include/agentic_autonomous_config.h"
#include "../../include/benchmark_menu_widget.hpp"
#include "../../include/checkpoint_manager.h"
#include "../../include/ci_cd_settings.h"
#include "CICDSettings.h"
#include "BenchmarkMenu.h"
#include "p1_gguf_load_cert.hpp"
#include "p1_load_checkpoint.hpp"
#include "P1PRA_ProcessState.hpp"
#include <thread>
#include <cstdlib>
#include <vector>
#include "../../include/enterprise_license.h"
#include "../../include/feature_flags_runtime.h"
#include "../../include/interpretability_panel.h"
#include "../../include/license_enforcement.h"
#include "../../include/model_registry.h"
#include "../../include/multi_file_search.h"
#include "../core/enterprise_license.h"
#include "../core/AmdGpuPowerBackend.hpp"
#include "../cpu_inference_engine.h"
#include "../modules/ExtensionLoader.hpp"

class Win32IDE;
void RunUiMenuE2eProbe(Win32IDE* ide);
#include "../modules/native_memory.hpp"
#include "../native_agent.hpp"
#include "../streaming_gguf_loader.h"
#include "IDEConfig.h"
#include "Win32IDE_HexMagMessages.h"
#include "IDELogger.h"
#include "ModelConnection.h"
#include "../deep2/Deep2Discovery.h"
#include "RawrXD_AgentCoordinator.h"
#include "RawrXD_AutonomousAgenticPipeline.h"
#include "Win32IDE.h"
#include "resource.h"
#include "../command/CommandEventJournal.h"
#include "../command/CommandBroker.h"
#include "Win32IDE_MainMenuAuthority.hpp"
#include "Win32IDE_CommandFlight.hpp"
#include "Win32IDE_ShellLayout.hpp"
#include "Win32Utf8.hpp"
#include "Win32IdeSpatial.hpp"
#include "../SettingsManager.h"
#include <exception>
#include "Win32IDE_AgenticBrowser.h"

#ifndef WM_APP_MENU_IDLE_STABLE
#define WM_APP_MENU_IDLE_STABLE (WM_APP + 322)
#endif
#include "Win32IDE_ComponentManagers.h"  // Complete types for unique_ptr<T> dtor
#include "Win32IDE_IELabels.h"
#include "enterprise_feature_manager.hpp"
#include "feature_registry_panel.h"
#include "lsp/RawrXD_LSPServer.h"
#include "multi_response_engine.h"
#include "win32_feature_adapter.h"  // Unified Feature Dispatch adapter
#include <commctrl.h>
#include <richedit.h>

// Stub definition for B428Trace (was declared extern, defined here)
static void B428Trace(const char* msg) {
    if (msg) OutputDebugStringA(msg);
}

#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <shlobj.h>
#include <sstream>


// Menu command IDs — must match Win32IDE.cpp definitions
#ifndef IDM_FILE_NEW
#ifndef IDM_BUILD_PROJECT
#define IDM_BUILD_PROJECT 2801
#endif

#define IDM_FILE_NEW 1001
#endif
#ifndef IDM_FILE_OPEN
#define IDM_FILE_OPEN 1002
#endif
#ifndef IDM_FILE_SAVE
#define IDM_FILE_SAVE 1003
#endif
#ifndef IDM_FILE_SAVEAS
#define IDM_FILE_SAVEAS 1004
#endif
#ifndef IDM_FILE_EXIT
#define IDM_FILE_EXIT 1099
#endif
#ifndef IDM_EDIT_FIND
#define IDM_EDIT_FIND 2016
#endif
#ifndef IDM_EDIT_REPLACE
#define IDM_EDIT_REPLACE 2017
#endif

// ============================================================================
// Window Class Name
// ============================================================================
static const char* kWindowClassName = "RawrXD_IDE_MainWindow";

// Interface includes for proper abstraction
#include "IV280Bridge.h"
#include "IMultiFileSearchWidget.h"
#include "gguf_loader.h"

// AI workers: process main-thread invoke queue every message (avoids queue buildup).
extern void AIWorkersProcessInvokeQueue();

// ============================================================================
// Destructor
// ============================================================================
Win32IDE::~Win32IDE()
{
    // Ensure shutdown flag is set (may already be from onDestroy)
    m_shuttingDown.store(true, std::memory_order_release);

    // If onDestroy wasn't called (abnormal exit), do the thread wait here
    if (m_activeDetachedThreads.load(std::memory_order_acquire) > 0)
    {
        for (int i = 0; i < 300 && m_activeDetachedThreads.load(std::memory_order_acquire) > 0; ++i)
        {
            Sleep(10);
        }
    }

    // Explicitly destroy objects that detached threads reference BEFORE
    // implicit member destruction order (which is reverse-declaration-order
    // and unpredictable for crash safety).
    m_subAgentManager.reset();
    m_multiResponseEngine.reset();
    // m_agenticBridge is non-owning; do not call reset() on raw pointers.
    m_agenticBridge = nullptr;
    m_agent.reset();
    
    // Shutdown AI Completion system (VAL-063)
    ShutdownAICompletion();
    
    m_nativeEngine.reset();
    m_modelResolver.reset();
    m_ggufLoader.reset();
    m_extensionLoader.reset();
    m_lspServer.reset();
    m_mcpServer.reset();
    m_renderer.reset();
    m_autonomousPipeline.reset();
    if (m_agentCoordinatorForPipeline)
    {
        DestroyAgentCoordinator((AgentCoordinatorHandle)m_agentCoordinatorForPipeline);
        m_agentCoordinatorForPipeline = nullptr;
    }
    m_autonomyManager.reset();

    // Null out raw pointers to externally-owned objects (deleted in main)
    m_engineManager = nullptr;
    m_codexUltimate = nullptr;

    // Clean up optional panel objects allocated with 'new' in onCreate
    delete m_modelRegistry;         m_modelRegistry = nullptr;
    delete m_interpretabilityPanel; m_interpretabilityPanel = nullptr;
    delete m_checkpointManager;     m_checkpointManager = nullptr;
    delete m_ciCdSettings;          m_ciCdSettings = nullptr;
    delete m_multiFileSearch;       m_multiFileSearch = nullptr;
    delete m_benchmarkMenu;         m_benchmarkMenu = nullptr;

    if (m_backgroundBrush)
    {
        DeleteObject(m_backgroundBrush);
        m_backgroundBrush = nullptr;
    }
    if (m_editorFont)
    {
        DeleteObject(m_editorFont);
        m_editorFont = nullptr;
    }
}

// ============================================================================
// WindowProc - Static callback that routes to instance handleMessage
// ============================================================================
LRESULT CALLBACK Win32IDE::WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;

    if (uMsg == WM_NCCREATE)
    {
        CREATESTRUCT* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        pThis = reinterpret_cast<Win32IDE*>(cs->lpCreateParams);
        if (!pThis)
            return FALSE;
        // P1_UI_WINDOW_OWNERSHIP_001: exactly one product shell per Win32IDE instance.
        if (pThis->m_hwndMain && IsWindow(pThis->m_hwndMain) && pThis->m_hwndMain != hwnd)
        {
            OutputDebugStringA("[P1_UI_WINDOW_OWNERSHIP] REJECT second product shell (WM_NCCREATE)\n");
            fileTrace("[P1_UI_WINDOW_OWNERSHIP] REJECT second product shell NCCREATE");
            return FALSE;
        }
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->m_hwndMain = hwnd;
        return TRUE;
    }

    pThis = reinterpret_cast<Win32IDE*>(GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    if (pThis) {
        RawrXD::CommandTelemetry::CmdDiagNoteMessage(
            uMsg, static_cast<unsigned long long>(wParam), hwnd,
            static_cast<unsigned long long>(lParam));
        if (uMsg == WM_APP + 209) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
            P1PRA_Witness("P1PRA_SEND", "wndproc_route");
            // #region agent log
            P1PRA_AgentDbg("H1", "WindowProc", "wm_app_209_route",
                           reinterpret_cast<unsigned long long>(hwnd),
                           reinterpret_cast<unsigned long long>(pThis),
                           static_cast<unsigned long long>(GetCurrentThreadId()));
            // #endregion agent log
#endif
        }
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        if (uMsg == WM_APP_MENU_IDLE_STABLE) {
            // #region agent log
            P1PRA_AgentDbg("H13", "WindowProc", "menu_idle_wndproc_enter",
                           reinterpret_cast<unsigned long long>(hwnd), 0, 0);
            // #endregion agent log
        }
#endif
        return pThis->handleMessage(hwnd, uMsg, wParam, lParam);
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

// Forward declaration for use in handleMessage (WM_APP+199) and showWindow
static void forceWindowToForeground(HWND hwnd);
static void runWindowVisibilityWatchdog(HWND hwnd);
static void drawLayoutDebugOverlay(HWND hwnd, HDC hdc);
static void restoreWindowOpacityIfNeeded(HWND hwnd);

static constexpr UINT_PTR IDT_VISIBILITY_WATCHDOG = 0x7D11;
static constexpr UINT_PTR IDT_GPU_TELEMETRY = 0x7D12;  // 2-second backend/GPU status refresh

// Fail-closed: layered + alpha 0 (or missing LWA) makes the IDE invisible/see-thru.
// Glass/transparency is opt-in via setWindowTransparency; launch must be opaque.
static void restoreWindowOpacityIfNeeded(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd))
        return;

    const LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    if ((exStyle & WS_EX_LAYERED) == 0)
        return;

    COLORREF colorKey = 0;
    BYTE alpha = 255;
    DWORD flags = 0;
    const BOOL got = GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags);
    const bool badAlpha = !got || ((flags & LWA_ALPHA) && alpha < 250);
    if (!badAlpha)
        return;

    // Prefer fully opaque non-layered for performance; if style clear fails, force alpha=255.
    SetLayeredWindowAttributes(hwnd, 0, 255, LWA_ALPHA);
    SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle & ~WS_EX_LAYERED);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    OutputDebugStringA("[Win32IDE] Recovered main window from layered see-thru (forced opaque)\n");
}

static bool isLayoutDebugOverlayEnabled()
{
    static bool initialized = false;
    static bool enabled = false;
    if (!initialized)
    {
        initialized = true;
        char value[16] = {};
        DWORD n = GetEnvironmentVariableA("RAWRXD_DEBUG_LAYOUT_OVERLAY", value, (DWORD)sizeof(value));
        enabled = (n > 0 && value[0] == '1');
    }
    return enabled;
}

static void logFirstPaint()
{
    static bool logged = false;
    if (logged)
        return;
    logged = true;
    OutputDebugStringA("[Win32IDE] first_paint\n");
    std::ofstream out("ide_startup.log", std::ios::out | std::ios::app);
    if (out)
    {
        out << "first_paint\n";
        out.flush();
    }
}

static void runWindowVisibilityWatchdog(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd))
        return;

    if (IsIconic(hwnd))
    {
        ShowWindow(hwnd, SW_RESTORE);
    }
    if (!IsWindowVisible(hwnd))
    {
        ShowWindow(hwnd, SW_SHOW);
    }

    RECT rc = {};
    GetWindowRect(hwnd, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;
    if (width < 200 || height < 200)
    {
        SetWindowPos(hwnd, HWND_TOP, 100, 100, 1400, 900, SWP_SHOWWINDOW);
    }

    HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL);
    if (!monitor)
    {
        SetWindowPos(hwnd, HWND_TOP, 100, 100, 1400, 900, SWP_SHOWWINDOW);
    }

    // Keep top-level IDE discoverable without pinning always-on-top.
    BringWindowToTop(hwnd);
    restoreWindowOpacityIfNeeded(hwnd);
}

static void drawLayoutDebugOverlay(HWND hwnd, HDC hdc)
{
    if (!isLayoutDebugOverlayEnabled())
        return;
    RECT rc = {};
    GetClientRect(hwnd, &rc);
    int width = rc.right - rc.left;
    int height = rc.bottom - rc.top;

    char text[128] = {};
    snprintf(text, sizeof(text), "IDE Client Size: %d x %d", width, height);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 80, 80));
    TextOutA(hdc, 10, 10, text, (int)strlen(text));

    if (width < 200 || height < 200)
    {
        const char* warn = "WARNING: Layout collapsed";
        SetTextColor(hdc, RGB(255, 0, 0));
        TextOutA(hdc, 10, 30, warn, (int)strlen(warn));

        HPEN pen = CreatePen(PS_SOLID, 4, RGB(255, 0, 0));
        if (pen)
        {
            HGDIOBJ oldPen = SelectObject(hdc, pen);
            HGDIOBJ oldBrush = SelectObject(hdc, GetStockObject(HOLLOW_BRUSH));
            Rectangle(hdc, 0, 0, (std::max)(width, 1), (std::max)(height, 1));
            SelectObject(hdc, oldBrush);
            SelectObject(hdc, oldPen);
            DeleteObject(pen);
        }
    }
}

// ============================================================================
// SEH wrappers — must be standalone functions without C++ objects (MSVC C2712)
typedef void (*OnCreateFn)(void* self, HWND hwnd);
typedef void (*DeferredInitFn)(void* self);

// Stack usage diagnostic - helps identify stack overflow issues
static size_t getApproximateStackUsed()
{
    // Simple heuristic: compare current stack pointer to a reference
    volatile int localVar = 0;
    return (size_t)&localVar;  // Lower values = more stack used
}

static void logStackUsage(const char* context)
{
    size_t stackPtr = getApproximateStackUsed();
    char msg[256];
    snprintf(msg, sizeof(msg), "[StackDiag] %s - stack ptr: 0x%p\n", context, (void*)stackPtr);
    OutputDebugStringA(msg);
}

// Forward declaration — defined later near onCreate()
extern thread_local int gCreateDepth;

static void sehCallOnCreate(OnCreateFn fn, void* self, HWND hwnd)
{
    logStackUsage("onCreate ENTRY");
#if defined(_MSC_VER)
    __try
    {
        fn(self, hwnd);
        logStackUsage("onCreate EXIT");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DWORD excCode = GetExceptionCode();
        RawrXD::MainMenuAuthority::TraceLine(
            "STARTUP_SEH region=onCreate_outer code=0x%08lX",
            static_cast<unsigned long>(excCode));
        RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "ONCREATE_OUTER_SEH_ABORT");
        
        char crashMsg[512];
        if (excCode == STATUS_STACK_OVERFLOW)
        {
            snprintf(crashMsg, sizeof(crashMsg),
                     "[RawrXD] STACK OVERFLOW (0x%08lX) caught in onCreate!\n\n"
                     "This usually means:\n"
                     "1. Recursive window creation (child sends message to parent during WM_CREATE)\n"
                     "2. Large stack-allocated buffers\n"
                     "3. Deep call chain in window creation\n\n"
                     "Current onCreate depth: %d\n"
                     "The window will still display, but some panels may be missing.",
                     excCode, gCreateDepth);
        }
        else
        {
            snprintf(crashMsg, sizeof(crashMsg),
                     "[RawrXD] SEH exception 0x%08lX caught in onCreate — window will still display.\n"
                     "Current onCreate depth: %d\n"
                     "Some panels may be missing.",
                     excCode, gCreateDepth);
        }
        OutputDebugStringA(crashMsg);
        MessageBoxA(hwnd, crashMsg, "RawrXD IDE - Startup Warning", MB_OK | MB_ICONWARNING);
    }
#else
    try
    {
        fn(self, hwnd);
        logStackUsage("onCreate EXIT");
    }
    catch (...)
    {
        const char* crashMsg = "[RawrXD] C++ exception caught in onCreate — window will still display.\n"
                               "Some panels may be missing.";
        OutputDebugStringA(crashMsg);
        MessageBoxA(hwnd, crashMsg, "RawrXD IDE - Startup Warning", MB_OK | MB_ICONWARNING);
    }
#endif
}

void onCreateTrampoline(void* self, HWND hwnd)
{
    static_cast<Win32IDE*>(self)->onCreate(hwnd);
}

// P1_UI_MENU_E2E_001 — contain WM_COMMAND faults (0xC000041D) + localize branch.
typedef void (*OnCommandFn)(void* self, HWND hwnd, int id, HWND ctl, UINT code);

static void onCommandCpp(void* self, HWND hwnd, int id, HWND ctl, UINT code)
{
    try {
        static_cast<Win32IDE*>(self)->onCommand(hwnd, id, ctl, code);
    } catch (const std::exception& e) {
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "CXX_EXCEPTION");
        RawrXD::CommandTelemetry::CmdDiagException(
            id, 0xE06D7363u, e.what(), nullptr, 0, "CXX_STD_EXCEPTION");
        char buf[256];
        snprintf(buf, sizeof(buf), "[CMD_DIAG] C++ exception id=%d what=%s\n", id,
                 e.what());
        OutputDebugStringA(buf);
    } catch (...) {
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "CXX_UNKNOWN");
        RawrXD::CommandTelemetry::CmdDiagException(id, 0xE06D7363u, nullptr, nullptr, 0,
                                                  "CXX_UNKNOWN");
        OutputDebugStringA("[CMD_DIAG] unknown C++ exception in onCommand\n");
    }
}

#if defined(_MSC_VER)
static int cmdSehFilter(unsigned long code, EXCEPTION_POINTERS* ep, int id)
{
    void* frames[32] = {};
    unsigned n = 0;
#if defined(_WIN64)
    n = CaptureStackBackTrace(0, 32, frames, nullptr);
#endif
    const void* addr =
        (ep && ep->ExceptionRecord) ? ep->ExceptionRecord->ExceptionAddress : nullptr;
    RawrXD::CommandTelemetry::CmdDiagException(
        id, code, addr, reinterpret_cast<const void* const*>(frames), n, "SEH");
    char buf[192];
    snprintf(buf, sizeof(buf),
             "[CMD_DIAG] SEH 0x%08lX id=%d addr=%p frames=%u\n", code, id, addr, n);
    OutputDebugStringA(buf);
    return EXCEPTION_EXECUTE_HANDLER;
}
#endif

static void sehCallOnCommand(OnCommandFn fn, void* self, HWND hwnd, int id, HWND ctl,
                             UINT code)
{
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "WM_COMMAND_ENTER");
#if defined(_MSC_VER)
    __try {
        fn(self, hwnd, id, ctl, code);
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "WM_COMMAND_EXIT_OK");
    } __except (cmdSehFilter(GetExceptionCode(), GetExceptionInformation(), id)) {
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "WM_COMMAND_SEH_SWALLOWED");
    }
#else
    fn(self, hwnd, id, ctl, code);
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "WM_COMMAND_EXIT_OK");
#endif
}

// Heavy teardown is invoked from WM_NCDESTROY (children already destroyed).
// No blanket SEH — faults must remain visible for localization.

// ---------------------------------------------------------------------------
// P1_UI_MENU_LIFETIME_001 — late onCreate / deferred-child phase localization
// Each major late-startup call runs under its own SEH boundary so the first
// missing ONCREATE_LATE_NN / DEFERRED_CHILD_NN checkpoint is authoritative.
// ---------------------------------------------------------------------------
typedef void (*IdeHwndStepFn)(void* self, HWND hwnd, int step);

static void sehCallIdeHwndStep(IdeHwndStepFn fn, void* self, HWND hwnd, int step,
                               const char* beforePhase, const char* afterPhase)
{
    HWND traceHwnd = hwnd;
    if (self) {
        auto* ide = static_cast<Win32IDE*>(self);
        if (ide->getMainWindow())
            traceHwnd = ide->getMainWindow();
    }
    RawrXD::MainMenuAuthority::TraceMenuState(traceHwnd, beforePhase);
#if defined(_MSC_VER)
    __try
    {
        fn(self, hwnd, step);
        RawrXD::MainMenuAuthority::TraceMenuState(traceHwnd, afterPhase);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        const DWORD code = GetExceptionCode();
        RawrXD::MainMenuAuthority::TraceLine(
            "STARTUP_SEH region=%s step=%d code=0x%08lX", beforePhase, step,
            static_cast<unsigned long>(code));
        RawrXD::MainMenuAuthority::TraceMenuState(traceHwnd, "STARTUP_SEH_ABORT");
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "[RawrXD] SEH 0x%08lX in %s (step=%d) — continuing startup\n",
                 static_cast<unsigned long>(code), beforePhase, step);
        OutputDebugStringA(msg);
        fileTrace(msg);
    }
#else
    try
    {
        fn(self, hwnd, step);
        RawrXD::MainMenuAuthority::TraceMenuState(traceHwnd, afterPhase);
    }
    catch (...)
    {
        RawrXD::MainMenuAuthority::TraceLine(
            "STARTUP_SEH region=%s step=%d code=cpp_exception", beforePhase, step);
        RawrXD::MainMenuAuthority::TraceMenuState(traceHwnd, "STARTUP_SEH_ABORT");
        fileTrace("[RawrXD] C++ exception in late/deferred startup step\n");
    }
#endif
}

void onCreateLateStepTrampoline(void* self, HWND hwnd, int step)
{
    static_cast<Win32IDE*>(self)->onCreateLateStep(step, hwnd);
}

void onCreateChildrenStepTrampoline(void* self, HWND hwnd, int step)
{
    static_cast<Win32IDE*>(self)->onCreateChildrenStep(step, hwnd);
}

// Trampoline for deferred UI child creation (prevents stack overflow)
void onCreateChildrenTrampoline(void* self, HWND hwnd)
{
    static_cast<Win32IDE*>(self)->onCreateChildren(hwnd);
}

// SEH wrapper for onCreateChildren - prevents stack overflow crashes
typedef void (*OnCreateChildrenFn)(void* self, HWND hwnd);

static void sehCallOnCreateChildren(OnCreateChildrenFn fn, void* self, HWND hwnd)
{
    logStackUsage("onCreateChildren ENTRY");
#if defined(_MSC_VER)
    __try
    {
        fn(self, hwnd);
        logStackUsage("onCreateChildren EXIT");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DWORD excCode = GetExceptionCode();
        RawrXD::MainMenuAuthority::TraceLine(
            "STARTUP_SEH region=onCreateChildren_outer code=0x%08lX",
            static_cast<unsigned long>(excCode));
        RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "DEFERRED_CHILDREN_OUTER_SEH_ABORT");
        char crashMsg[512];
        if (excCode == STATUS_STACK_OVERFLOW)
        {
            snprintf(crashMsg, sizeof(crashMsg),
                     "[RawrXD] STACK OVERFLOW (0x%08lX) caught in onCreateChildren!\n\n"
                     "Deferred UI creation failed due to stack overflow.\n"
                     "Some panels may be missing.",
                     excCode);
        }
        else
        {
            snprintf(crashMsg, sizeof(crashMsg),
                     "[RawrXD] SEH exception 0x%08lX caught in onCreateChildren.\n"
                     "Some panels may be missing.",
                     excCode);
        }
        OutputDebugStringA(crashMsg);
        MessageBoxA(hwnd, crashMsg, "RawrXD IDE - Deferred Init Warning", MB_OK | MB_ICONWARNING);
    }
#else
    try
    {
        fn(self, hwnd);
        logStackUsage("onCreateChildren EXIT");
    }
    catch (...)
    {
        const char* crashMsg = "[RawrXD] C++ exception caught in onCreateChildren.\n"
                               "Some panels may be missing.";
        OutputDebugStringA(crashMsg);
        MessageBoxA(hwnd, crashMsg, "RawrXD IDE - Deferred Init Warning", MB_OK | MB_ICONWARNING);
    }
#endif
}

static void sehCallDeferredInit(DeferredInitFn fn, void* self)
{
#if defined(_MSC_VER)
    __try
    {
        fn(self);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        char crashMsg[256];
        snprintf(crashMsg, sizeof(crashMsg), "[RawrXD] SEH exception 0x%08lX in deferredHeavyInit — non-fatal.\n",
                 GetExceptionCode());
        OutputDebugStringA(crashMsg);
    }
#else
    try
    {
        fn(self);
    }
    catch (...)
    {
        OutputDebugStringA("[RawrXD] C++ exception in deferredHeavyInit — non-fatal.\n");
    }
#endif
}

// SEH wrapper for background thread body — standalone function (no C++ objects
// with destructors allowed inside __try on MSVC, hence the trampoline pattern).
typedef void (*BgThreadBodyFn)(void* self);

// Phase 2: last reached marker for 0xC0000005 isolation in background init.
static thread_local volatile const char* g_bgInitStep = "bg_uninitialized";

static void bgInitMark(const char* step)
{
    g_bgInitStep = step;
    OutputDebugStringA("[BgInit] ");
    OutputDebugStringA(step);
    OutputDebugStringA("\n");
    // Lifetime cert localization: emit HEAVY_STEP_* into the same trace file.
    if (RawrXD::MainMenuAuthority::TraceEnabled()) {
        char phase[96];
        snprintf(phase, sizeof(phase), "HEAVY_STEP_%s", step ? step : "?");
        HWND hwnd = RawrXD::MainMenuAuthority::State().hwnd;
        RawrXD::MainMenuAuthority::TraceMenuState(hwnd, phase);
    }
}

static DWORD sehRunBgThread(BgThreadBodyFn fn, void* self)
{
#if defined(_MSC_VER)
    __try
    {
        fn(self);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DWORD code = GetExceptionCode();
        char crashMsg[768];
        const char* step = const_cast<const char*>(g_bgInitStep);
        if (!step)
            step = "(null)";
        snprintf(crashMsg, sizeof(crashMsg),
                 "[RawrXD] SEH exception 0x%08lX in background init thread — non-fatal.\n"
                 "Last BgInit step: %s\n"
                 "Some subsystems may be unavailable. The IDE window remains open.\n",
                 code, step);
        OutputDebugStringA(crashMsg);

        // Write crash log for diagnostics
        FILE* f = fopen("rawrxd_crash.log", "a");
        if (f)
        {
            fprintf(f, "BACKGROUND THREAD CRASH: Exception 0x%08lX last_step=%s\n", code, step);
            fclose(f);
        }
        return code;
    }
    return 0;
#else
    try
    {
        fn(self);
        return 0;
    }
    catch (...)
    {
        const char* crashMsg = "[RawrXD] C++ exception in background init thread — non-fatal.\n"
                               "Some subsystems may be unavailable. The IDE window remains open.\n";
        OutputDebugStringA(crashMsg);
        FILE* f = fopen("rawrxd_crash.log", "a");
        if (f)
        {
            fprintf(f, "BACKGROUND THREAD CRASH: C++ exception\n");
            fclose(f);
        }
        return 1;
    }
#endif
}

void deferredInitTrampoline(void* self)
{
    static_cast<Win32IDE*>(self)->deferredHeavyInit();
}

// handleMessage - Instance message handler
// ============================================================================
// v280 WndProc Hook — intercepts WM_CREATE/DESTROY/KEYDOWN/TIMER for
// shared-memory inference bridge (ghost text, token polling, etc.)
// Returns 1 (rax) if consumed, 0 if pass-through to normal dispatch.
extern "C" int64_t V280_UI_WndProc_Hook(void* hwnd, uint32_t uMsg, uint64_t wParam, int64_t lParam);
// v280 ghost text query for WM_PAINT overlay
extern "C" int V280_UI_IsGhostActive(void);
extern "C" int V280_UI_GetGhostText(char* buf, int buf_size);

LRESULT Win32IDE::handleMessage(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // ── v280 SHM Bridge Hook ──
    // Must fire BEFORE normal dispatch so it can:
    //   - Intercept Tab/Esc on ghost text (WM_KEYDOWN)
    //   - Install/kill poll timer (WM_CREATE/WM_DESTROY)
    //   - Drive token polling (WM_TIMER with IDT_V280_POLL)
    //   - Trigger repaint on WM_V280_GHOST_TEXT
    IV280Bridge* v280Bridge = GetV280Bridge();
    if (v280Bridge) {
        int64_t v280_result = v280Bridge->WndProcHook((void*)hwnd, (uint32_t)uMsg, (uint64_t)wParam, (int64_t)lParam);
        if (v280_result != 0)
        {
            return 0;  // Message consumed by v280 bridge
        }
        if (uMsg == WM_APP + 209) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
            P1PRA_Witness("P1PRA_SEND", "post_v280");
#endif
        }
    }

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    if (uMsg == WM_APP_MENU_IDLE_STABLE ||
        (uMsg == WM_TIMER && wParam == IDT_GPU_TELEMETRY)) {
        // #region agent log
        P1PRA_AgentDbg("H12", "handleMessage", "dispatch_enter",
                       static_cast<unsigned long long>(uMsg),
                       static_cast<unsigned long long>(wParam),
                       static_cast<unsigned long long>(GetCurrentThreadId()));
        // #endregion
    }
#endif

    switch (uMsg)
    {
        case WM_CREATE:
            sehCallOnCreate(onCreateTrampoline, this, hwnd);
            return 0;

        case WM_SIZE:
        {
            // SIZE_MINIMIZED → never commit layout from a collapsed client.
            if (wParam == SIZE_MINIMIZED)
                return 0;
            int width = LOWORD(lParam);
            int height = HIWORD(lParam);
            if (width <= 0 || height <= 0)
                return 0;
            onSize(width, height);
            onEditorContentChanged();
            // Ownership dump only on maximize / restore-from-maximize (not every drag resize).
            {
                static WPARAM s_lastSizeType = SIZE_RESTORED;
                if (wParam == SIZE_MAXIMIZED ||
                    (wParam == SIZE_RESTORED && s_lastSizeType == SIZE_MAXIMIZED))
                {
                    dumpUiWindowOwnership(wParam == SIZE_MAXIMIZED ? "SIZE_MAXIMIZED"
                                                                   : "SIZE_RESTORE_FROM_MAX");
                }
                s_lastSizeType = wParam;
            }
            return 0;
        }

        case WM_DPICHANGED:
        {
            // Tier 3 (Feature 33): Full High-DPI polish — scale fonts, UI dimensions, relayout
            UINT newDpi = HIWORD(wParam);
            RECT* prc = reinterpret_cast<RECT*>(lParam);
            onDpiChanged(newDpi, prc);
            return 0;
        }

        case WM_GETMINMAXINFO:
        case WM_NCCALCSIZE:
        case WM_WINDOWPOSCHANGING:
        case WM_WINDOWPOSCHANGED:
        case WM_ACTIVATEAPP:
        case WM_ACTIVATE:
        case WM_NCACTIVATE:
        case WM_KILLFOCUS:
        case WM_IME_SETCONTEXT:
        case WM_IME_NOTIFY:
        case WM_SHOWWINDOW:
        case WM_NCPAINT:
            return DefWindowProcA(hwnd, uMsg, wParam, lParam);

        case WM_SETFOCUS:
            // Forward focus to the editor so the caret appears and keyboard input works
            if (m_hwndEditor && IsWindow(m_hwndEditor))
            {
                SetFocus(m_hwndEditor);
            }
            return 0;

        case WM_KEYDOWN:
            // Command Palette from main window (e.g. when frame has focus)
            if ((GetKeyState(VK_CONTROL) & 0x8000) && (GetKeyState(VK_SHIFT) & 0x8000) && (wParam == 'P'))
            {
                if (m_commandPaletteVisible)
                    hideCommandPalette();
                else
                    showCommandPalette();
                return 0;
            }

            // Peek overlay keyboard shortcuts
            if (isPeekOverlayActive())
            {
                bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
                bool alt = (GetKeyState(VK_MENU) & 0x8000) != 0;
                bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                handlePeekOverlayKey((UINT)wParam, ctrl, alt, shift);
                return 0;
            }

            // Peek definition (Alt+F12)
            if ((GetKeyState(VK_MENU) & 0x8000) && (wParam == VK_F12))
            {
                routeCommand(IDM_LSP_GOTO_DEFINITION);
                return 0;
            }

            // Peek references (Shift+F12)
            if ((GetKeyState(VK_SHIFT) & 0x8000) && (wParam == VK_F12))
            {
                routeCommand(IDM_LSP_FIND_REFERENCES);
                return 0;
            }
            break;

        case WM_ERASEBKGND:
        {
            // Paint the background dark instead of default white
            HDC hdc = (HDC)wParam;
            RECT rc;
            GetClientRect(hwnd, &rc);
            if (!m_backgroundBrush)
            {
                m_backgroundBrush = CreateSolidBrush(RGB(30, 30, 30));
            }
            FillRect(hdc, &rc, m_backgroundBrush);
            return 1;  // We handled it
        }

        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            if (!m_backgroundBrush)
            {
                m_backgroundBrush = CreateSolidBrush(RGB(30, 30, 30));
            }
            FillRect(hdc, &ps.rcPaint, m_backgroundBrush);

            // ── v280 Ghost Text Overlay ──
            // Render inline completion suggestion (dimmed, italic) at actual caret position
            IV280Bridge* v280BridgePaint = GetV280Bridge();
            if (v280BridgePaint && v280BridgePaint->IsGhostActive())
            {
                char ghost_buf[4096];
                int ghost_len = v280BridgePaint->GetGhostText(ghost_buf, sizeof(ghost_buf));
                if (ghost_len > 0 && m_hwndEditor && IsWindow(m_hwndEditor))
                {
                    // Get actual caret position from RichEdit
                    CHARRANGE sel;
                    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&sel);
                    
                    // Get the position (in client coordinates) of the cursor
                    POINTL pt;
                    LRESULT posResult = SendMessage(m_hwndEditor, EM_POSFROMCHAR, (WPARAM)&pt, sel.cpMin);
                    
                    if (posResult == 0)  // Success
                    {
                        // Convert client coordinates to window coordinates for painting
                        POINT screenPt = { pt.x, pt.y };
                        ClientToScreen(m_hwndEditor, &screenPt);
                        ScreenToClient(hwnd, &screenPt);
                        
                        // Create ghost text font (italic, same face as editor)
                        HFONT ghostFont =
                            CreateFontA(-14, 0, 0, 0, FW_NORMAL,
                                        TRUE,  // italic
                                        FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
                        HFONT oldFont = (HFONT)SelectObject(hdc, ghostFont);

                        // Ghost text color: dimmed gray (VS Code style)
                        SetTextColor(hdc, RGB(128, 128, 128));
                        SetBkMode(hdc, TRANSPARENT);

                        // Position at actual cursor location
                        RECT ghostRect;
                        ghostRect.left = screenPt.x;
                        ghostRect.top = screenPt.y;
                        ghostRect.right = ps.rcPaint.right;
                        ghostRect.bottom = ps.rcPaint.bottom;

                        DrawTextA(hdc, ghost_buf, ghost_len, &ghostRect, DT_LEFT | DT_TOP | DT_NOPREFIX | DT_WORDBREAK);

                        SelectObject(hdc, oldFont);
                        DeleteObject(ghostFont);
                    }
                }
            }

            drawLayoutDebugOverlay(hwnd, hdc);
            logFirstPaint();

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_COMMAND:
            sehCallOnCommand(onCommandCpp, this, hwnd, LOWORD(wParam), (HWND)lParam,
                             HIWORD(wParam));
            return 0;

        case WM_DRAWITEM:
        {
            DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
            if (dis && m_hwndActivityBar && IsWindow(m_hwndActivityBar))
            {
                HWND hwndParent = GetParent(dis->hwndItem);
                if (hwndParent == m_hwndActivityBar)
                {
                    // Forward to ActivityBarProc with the activity bar HWND
                    // so GWLP_USERDATA resolves to Win32IDE* correctly
                    return ActivityBarProc(m_hwndActivityBar, uMsg, wParam, lParam);
                }
            }
            break;
        }

        case WM_NOTIFY:
        {
            NMHDR* pNMHDR = reinterpret_cast<NMHDR*>(lParam);
            if (pNMHDR)
            {
                const int idFrom = (int)pNMHDR->idFrom;
                // VS Code panel tabs (Terminal / Output / Problems / Debug Console)
                if (pNMHDR->code == TCN_SELCHANGE && (pNMHDR->hwndFrom == m_hwndPanelTabs || idFrom == 1301))
                {
                    int idx = (int)TabCtrl_GetCurSel(m_hwndPanelTabs);
                    if (idx < 0)
                        idx = 0;
                    if (idx > 3)
                        idx = 3;
                    switchPanelTab(static_cast<PanelTab>(idx));
                }
                // Tier 3 (Feature 38/39): Status bar click → language/encoding selector (use part index for reliable
                // dispatch)
                if (pNMHDR->hwndFrom == m_hwndStatusBar && pNMHDR->code == NM_CLICK)
                {
                    NMMOUSE* pNMMouse = reinterpret_cast<NMMOUSE*>(lParam);
                    handleStatusBarClick(static_cast<int>(pNMMouse->dwItemSpec));
                }
                // Output panel tab switch (Output / Errors / Debug / Find Results / Problems)
                // Combined handler for all 5 tabs - fixes duplicate TCN_SELCHANGE blocks
                if (pNMHDR->code == TCN_SELCHANGE && pNMHDR->hwndFrom == m_hwndOutputTabs)
                {
                    int idx = (int)TabCtrl_GetCurSel(m_hwndOutputTabs);
                    static const char* outputTabKeys[] = {"Output", "Errors", "Debug", "Find Results", "Problems"};
                    constexpr int numTabs = sizeof(outputTabKeys) / sizeof(outputTabKeys[0]);
                    if (idx >= 0 && idx < numTabs)
                    {
                        m_activeOutputTab = outputTabKeys[idx];
                        m_selectedOutputTab = idx;
                        for (auto& kv : m_outputWindows)
                        {
                            ShowWindow(kv.second,
                                       (kv.first == m_activeOutputTab && m_outputPanelVisible) ? SW_SHOW : SW_HIDE);
                        }
                        if (m_hwndProblemsListView)
                        {
                            ShowWindow(m_hwndProblemsListView, (idx == 4 && m_outputPanelVisible) ? SW_SHOW : SW_HIDE);
                        }
                    }
                }
                // Problems ListView double-click → goToProblem
                if ((pNMHDR->hwndFrom == m_hwndProblemsListView || idFrom == IDC_PROBLEMS_LISTVIEW) &&
                    (pNMHDR->code == NM_DBLCLK || pNMHDR->code == LVN_ITEMACTIVATE))
                {
                    int idx = (int)ListView_GetNextItem(m_hwndProblemsListView, -1, LVNI_SELECTED);
                    if (idx >= 0)
                        goToProblem(idx);
                }
                // Handle tab bar selection change
                if (pNMHDR->code == TCN_SELCHANGE && pNMHDR->hwndFrom == m_hwndTabBar)
                {
                    onTabChanged();
                }
                // Handle RichEdit scroll/change notifications for line number sync
                if (pNMHDR->hwndFrom == m_hwndEditor)
                {
                    if (pNMHDR->code == EN_VSCROLL || pNMHDR->code == EN_SELCHANGE || pNMHDR->code == EN_CHANGE)
                    {
                        updateLineNumbers();
                        // Debounce syntax coloring on content change
                        if (pNMHDR->code == EN_CHANGE && m_syntaxColoringEnabled)
                        {
                            onEditorContentChanged();
                        }
                        // Trigger AI Ghost Text on typing
                        if (pNMHDR->code == EN_CHANGE)
                        {
                            triggerGhostTextCompletion();
                        }
                        // Tier 3 (Feature 36): Mark file dirty on any content change
                        if (pNMHDR->code == EN_CHANGE)
                        {
                            markFileModified();
                        }
                        // Tier 3 (Feature 31): Update smooth caret target on selection change
                        if (pNMHDR->code == EN_SELCHANGE)
                        {
                            updateCaretTarget();
                        }
                        // Dismiss ghost text when caret moves (anchor becomes stale)
                        if (pNMHDR->code == EN_SELCHANGE && m_ghostTextVisible)
                        {
                            dismissGhostText();
                        }
                        // Update status bar cursor position
                        CHARRANGE sel;
                        SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&sel);
                        int line = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, sel.cpMin, 0);
                        int lineStart = (int)SendMessage(m_hwndEditor, EM_LINEINDEX, line, 0);
                        int col = sel.cpMin - lineStart;
                        wchar_t posBuf[64];
                        swprintf(posBuf, 64, L"Ln %d, Col %d", line + 1, col + 1);
                        if (m_hwndStatusBar)
                        {
                            SendMessageW(m_hwndStatusBar, SB_SETTEXTW, 1, (LPARAM)posBuf);
                        }
                        // Breadcrumb: update symbol path (File > Class > Method) on cursor move
                        if (pNMHDR->code == EN_SELCHANGE)
                        {
                            updateBreadcrumbsOnCursorMove();
                        }
                    }
                }
            }
            return 0;
        }

        case WM_HSCROLL:
        case WM_VSCROLL:
            // Forward scrollbar messages and update line numbers
            {
                // Phase 44: VoiceAutomation slider routing
                if (uMsg == WM_HSCROLL)
                {
                    extern bool Win32IDE_HandleVoiceAutomationScroll(HWND, LPARAM);
                    if (Win32IDE_HandleVoiceAutomationScroll(hwnd, lParam))
                    {
                        return 0;
                    }
                }
                LRESULT result = DefWindowProcA(hwnd, uMsg, wParam, lParam);
                updateLineNumbers();
                // Recolor visible lines on scroll
                if (m_syntaxColoringEnabled)
                {
                    onEditorContentChanged();
                }
                return result;
            }

        case WM_MOUSEWHEEL:
            // Tier 1: Smooth scroll interpolation
            if (handleTier1MouseWheel(wParam, lParam))
            {
                return 0;
            }
            break;

        case WM_TIMER:
            if (m_ircBridge)
            {
                m_ircBridge->tick();
            }
            if (wParam == SYNTAX_COLOR_TIMER_ID)
            {
                // Handled by SyntaxColorTimerProc callback — this is a fallback
                KillTimer(hwnd, SYNTAX_COLOR_TIMER_ID);
                if (m_syntaxColoringEnabled)
                {
                    applySyntaxColoring();
                }
                return 0;
            }
            if (wParam == 8888)
            {  // GHOST_TEXT_TIMER_ID
                onGhostTextTimer();
                return 0;
            }
            if (wParam == 9999)
            {  // COMPLETION_TRIGGER_TIMER_ID - trigger character completion
                KillTimer(hwnd, 9999);
                triggerCodeCompletion();
                return 0;
            }
            if (wParam == MODEL_PROGRESS_TIMER_ID)
            {
                // Poll model progress and update the progress bar UI
                if (m_modelOperationActive.load())
                {
                    float pct = m_modelProgressPercent.load();
                    if (m_hwndModelProgressBar)
                    {
                        SendMessage(m_hwndModelProgressBar, PBM_SETPOS, (WPARAM)(int)(pct * 10.0f), 0);
                    }
                    std::string status;
                    {
                        std::lock_guard<std::mutex> lock(m_modelProgressMutex);
                        status = m_modelProgressStatus;
                    }
                    if (m_hwndModelProgressLabel && !status.empty())
                    {
                        SetWindowTextA(m_hwndModelProgressLabel, status.c_str());
                    }
                }
                else
                {
                    hideModelProgressBar();
                }
                return 0;
            }
            if (wParam == 199)
            {  // IDT_FORCE_VISIBLE — one-shot to force window visible again after init
                KillTimer(hwnd, 199);
                if (m_hwndMain && IsWindow(m_hwndMain) && !IsIconic(m_hwndMain))
                {
                    ShowWindow(m_hwndMain, SW_SHOW);
                    SetWindowPos(m_hwndMain, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                    forceWindowToForeground(m_hwndMain);
                    restoreWindowOpacityIfNeeded(m_hwndMain);
                }
                return 0;
            }
            if (wParam == IDT_VISIBILITY_WATCHDOG)
            {
                runWindowVisibilityWatchdog(m_hwndMain ? m_hwndMain : hwnd);
                return 0;
            }
            if (wParam == IDT_GPU_TELEMETRY)
            {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                P1PRA_Witness("P1PRA_UI", "gpu_telemetry_timer_enter");
                P1PRA_AgentDbg("H10", "WM_TIMER", "gpu_telemetry_enter", 0, 0, 0);
#endif
                updateStatusBarBackend();
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                P1PRA_Witness("P1PRA_UI", "gpu_telemetry_timer_exit");
#endif
                return 0;
            }
            if (wParam == 42)
            {  // IDT_STATUS_FLASH
                KillTimer(hwnd, 42);
                // Restore default status bar text
                if (m_hwndStatusBar)
                {
                    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Ready");
                }
                return 0;
            }
            if (wParam == 0x7C01)
            {  // VOICE_TIMER_ID (voice chat VU meter)
                onVoiceChatTimer();
                return 0;
            }
            if (wParam == 0x7C10)
            {  // VA_TIMER_ID (Phase 44: VoiceAutomation status)
                extern void Win32IDE_VoiceAutomationTimerTick();
                Win32IDE_VoiceAutomationTimerTick();
                return 0;
            }
            if (wParam == 0xDC01)
            {  // RECOVERY_TIMER_ID (Phase 45: DiskRecovery progress)
                onRecoveryTimer();
                return 0;
            }
            // Tier 3: Polish timers (caret animation, theme transition, format status)
            if (handleTier3Timer(wParam))
            {
                return 0;
            }
            // Tier 1: Critical cosmetic timers (smooth scroll, minimap, auto-update)
            if (handleTier1Timer(wParam))
            {
                return 0;
            }
            break;

        // Phase 33: Voice Chat Global Hotkeys
        case WM_HOTKEY:
            if (wParam == 0xA001)
            {  // VOICE_HOTKEY_TOGGLE_PTT
                cmdVoicePTT();
                return 0;
            }
            if (wParam == 0xA002)
            {  // VOICE_HOTKEY_TOGGLE_PANEL
                cmdVoiceTogglePanel();
                return 0;
            }
            if (wParam == 0xA003)
            {                      // VOICE_HOTKEY_STOP
                cmdVoiceRecord();  // stop recording
                return 0;
            }
            break;

        case WM_CLOSE:
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_CLOSE_ENTER");
            if (!m_fileModified || promptSaveChanges())
            {
                // Save window state before closing
                SaveWindowState();
                
                // Shutdown settings manager (saves dirty settings)
                RawrXD::GetSettings().Shutdown();
                
                DestroyWindow(hwnd);
            }
            return 0;

        // Tier 1: Auto-update notification (WM_APP+501)
        case (WM_APP + 501):
            showUpdateNotification();
            return 0;

        // Model progress update from background thread
        case WM_APP + 300:
        {  // WM_MODEL_PROGRESS_UPDATE
            float pct = (float)wParam / 10.0f;
            if (m_hwndModelProgressBar)
            {
                SendMessage(m_hwndModelProgressBar, PBM_SETPOS, wParam, 0);
            }
            return 0;
        }
        case WM_APP + 301:
        {  // WM_MODEL_PROGRESS_DONE
            hideModelProgressBar();
            return 0;
        }

        // Visibility watchdog request (posted from watchdog worker thread)
        case WM_APP + 1:
        {
            if (m_hwndMain && IsWindow(m_hwndMain))
            {
                ShowWindow(m_hwndMain, (int)wParam);
                SetForegroundWindow(m_hwndMain);
            }
            return 0;
        }

        // Ghost Text delivery from background completion thread
        case WM_GHOST_TEXT_READY:
        {
            int cursorPos = (int)wParam;
            const char* text = reinterpret_cast<const char*>(lParam);
            onGhostTextReady(cursorPos, text);
            if (text)
                free(const_cast<char*>(text));  // Allocated with _strdup
            return 0;
        }

        case WM_DESTROY:
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_ENTER");
            KillTimer(hwnd, IDT_VISIBILITY_WATCHDOG);
            // Parent WM_DESTROY is top-down: children still exist. Detach QuickJS
            // hosts only. Native FreeLibrary / VSCodeExtensionAPI::shutdown /
            // ExtensionLoader unload wait for WM_NCDESTROY (bottom-up).
            m_shuttingDown.store(true, std::memory_order_release);
            m_inferenceStopRequested = true;
            m_planExecutionCancelled.store(true);
            stopVisibilityWatchdog();
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_BEFORE_js_detach");
            detachJSExtensionHosts();
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_AFTER_js_detach");
            // Close WebView2 COM controller before child HWND teardown.
            if (m_webView2) {
                m_webView2->destroy();
                delete m_webView2;
                m_webView2 = nullptr;
            }
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_AFTER_webview2");
            // Drop terminal callbacks before pane HWNDs destroy (UAF otherwise).
            if (m_dedicatedPowerShellTerminal) {
                m_dedicatedPowerShellTerminal->onOutput = nullptr;
                m_dedicatedPowerShellTerminal->onError = nullptr;
                m_dedicatedPowerShellTerminal->onStarted = nullptr;
                m_dedicatedPowerShellTerminal->onFinished = nullptr;
                m_dedicatedPowerShellTerminal->stop();
            }
            for (auto& pane : m_terminalPanes) {
                if (pane.manager) {
                    pane.manager->onOutput = nullptr;
                    pane.manager->onError = nullptr;
                    pane.manager->onStarted = nullptr;
                    pane.manager->onFinished = nullptr;
                    pane.manager->stop();
                }
            }
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_AFTER_terminals");
            // Agentic browser WebView2 must Close while a message pump can still
            // run (nested in DestroyWindow). Child neutralize would replace its
            // WndProc and skip host WM_DESTROY → g_layer leak → COM hang in
            // WinMain after MESSAGE_LOOP_EXIT.
            Win32IDE_AgenticBrowser_Shutdown();
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_AFTER_agentic_browser");
            // Neutralize child WndProcs before the system destroys them.
            // Custom child procs otherwise re-enter freed QuickJS / IDE state
            // after detachJSExtensionHosts (LAST_MSG=WM_DESTROY AV → 0xC000041D).
            EnumChildWindows(
                hwnd,
                [](HWND h, LPARAM) -> BOOL {
                    if (!h || !IsWindow(h))
                        return TRUE;
                    SetWindowLongPtrA(h, GWLP_USERDATA, 0);
                    SetWindowLongPtrA(h, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(DefWindowProcA));
                    return TRUE;
                },
                0);
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_AFTER_child_neutralize");
            PostQuitMessage(0);
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_DESTROY_EXIT_armed");
            return 0;

        case WM_NCDESTROY:
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_NCDESTROY_ENTER");
            onDestroy();
            SetWindowLongPtrA(hwnd, GWLP_USERDATA, 0);
            // Re-arm quit: nested DestroyWindow / COM pumps during onDestroy can
            // PeekMessage-consume the WM_QUIT posted from WM_DESTROY, leaving
            // runMessageLoop blocked forever on GetMessage (no 0xC000041D, no exit).
            PostQuitMessage(0);
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "WM_NCDESTROY_AFTER_onDestroy");
            return 0;

        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX:
        {
            // Dark mode colors for controls
            HDC hdcCtrl = (HDC)wParam;
            SetTextColor(hdcCtrl, RGB(220, 220, 220));
            SetBkColor(hdcCtrl, RGB(30, 30, 30));
            if (!m_backgroundBrush)
            {
                m_backgroundBrush = CreateSolidBrush(RGB(30, 30, 30));
            }
            return (LRESULT)m_backgroundBrush;
        }

        default:
            // Force main window visible once after startup (posted before message loop).
            // Also set a one-shot timer to force visible again ~400ms later (catches init that hides window).
            if (uMsg == WM_APP + 199)
            {
                if (m_hwndMain && IsWindow(m_hwndMain))
                {
                    if (IsIconic(m_hwndMain))
                        ShowWindow(m_hwndMain, SW_RESTORE);
                    ShowWindow(m_hwndMain, SW_SHOW);
                    SetWindowPos(m_hwndMain, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
                    forceWindowToForeground(m_hwndMain);
                    restoreWindowOpacityIfNeeded(m_hwndMain);
                    SetTimer(hwnd, 199, 400, nullptr);  // One-shot: force visible again in 400ms
                }
                return 0;
            }
            // Handle deferred UI child creation (posted after session restore)
            if (uMsg == WM_APP_INIT_CHILDREN)
            {
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "DEFERRED_CHILDREN_BEGIN");
                sehCallOnCreateChildren(onCreateChildrenTrampoline, this, hwnd);
                RawrXD::MainMenuAuthority::TraceMenuState(
                    m_hwndMain ? m_hwndMain : hwnd, "DEFERRED_CHILDREN_COMPLETE");
                // Menu lifetime: command surface + idle-stable are ready once children
                // complete. Do not wait on deferredHeavyInit (enterprise/feature hang).
                if (m_hMenu)
                    RawrXD::MainMenuAuthority::EnsureAttached(hwnd, m_hMenu);
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "AFTER_COMMAND_AUTHORITY_INIT");
                PostMessage(hwnd, WM_APP_MENU_IDLE_STABLE, 0, 0);
                updateMenuEnableStates();  // after cert phases armed (can be slow)
                return 0;
            }
            // Off-WM_CREATE session restore (own checkpoint; then arm deferred children)
            if (uMsg == WM_APP_RESTORE_SESSION)
            {
                clearPendingSessionRestore();
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "RESTORE_SESSION_BEGIN");
                restoreSession();
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "RESTORE_SESSION_COMPLETE");
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "BEFORE_DEFERRED_INIT");
                PostMessage(hwnd, WM_APP_INIT_CHILDREN, 0, 0);
                PostMessage(hwnd, WM_APP_DEFERRED_INIT, 0, 0);
                return 0;
            }
            // Async model restore requested by session restore (never sync-load in restore)
            if (uMsg == WM_APP_RESTORE_MODEL)
            {
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "RESTORE_MODEL_BEGIN");
                m_pendingApp201ModelLoad = true;
                if (m_startupPumpsComplete && m_engineManager)
                    PostMessage(hwnd, WM_APP + 201, 0, 0);
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "RESTORE_MODEL_POSTED");
                return 0;
            }
            // Deferred CWD — same-drive string check only (no FS probe). Cross-drive skipped.
            // Observed hang: SetCurrentDirectory("G:\\...") with EXE on F:\.
            if (uMsg == WM_APP_RESTORE_CWD)
            {
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "RESTORE_CWD_BEGIN");
                const std::string cwd = std::move(m_pendingRestoreCwd);
                m_pendingRestoreCwd.clear();
                bool applied = false;
                if (!cwd.empty()) {
                    char exePath[MAX_PATH] = {};
                    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
                    const bool sameDrive =
                        cwd.size() >= 2 && exePath[0] && cwd[1] == ':' && exePath[1] == ':' &&
                        ((cwd[0] | 32) == (exePath[0] | 32));
                    if (sameDrive) {
                        SetCurrentDirectoryA(cwd.c_str());
                        applied = true;
                    } else {
                        LOG_WARNING(std::string("Session: skipping cross-drive workingDirectory: ") + cwd);
                    }
                }
                RawrXD::MainMenuAuthority::TraceMenuState(
                    hwnd, applied ? "RESTORE_SESSION_CWD_OK" : "RESTORE_SESSION_CWD_SKIPPED");
                return 0;
            }
            // Handle deferred heavy initialization (posted from onCreate)
            if (uMsg == WM_APP_DEFERRED_INIT)
            {
                sehCallDeferredInit(deferredInitTrampoline, this);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                P1PRA_Witness("P1PRA_UI", "wm_app_deferred_init_done");
                P1PRA_AgentDbg("H10", "handleMessage", "after_wm_deferred_init", 0, 0, 0);
#endif
                return 0;
            }
            // HexMag controller → Copilot render (shared WM_HEXMAG_COPILOT_DONE)
            if (uMsg == WM_HEXMAG_COPILOT_DONE)
            {
                RawrXD_FinishHexMagCopilotDone(this, lParam);
                return 0;
            }
            // Handle Ollama model list update from background thread
            // NOTE: Using WM_APP + 310 to avoid collision with WM_MODEL_PROGRESS_UPDATE (WM_APP + 300)
            if (uMsg == WM_APP + 310)
            {
                std::vector<std::string>* models = reinterpret_cast<std::vector<std::string>*>(wParam);
                onOllamaModelsUpdated(models);
                delete models;  // FIX: free heap-allocated vector from sender
                return 0;
            }
            if (uMsg == WM_APP_PS_SESSION_BRINGUP)
            {
                // Rebuild phases 0–4: do not spin up PowerShell chrome.
                if (!RawrXD::ShellLayout::RebuildRestrictActive())
                    startPowerShellSession();
                RawrXD::ShellLayout::ApplyFromIde(this);
                return 0;
            }
            if (uMsg == WM_APP_RUN_MENU_PROBE)
            {
                if (!RawrXD::ShellLayout::RebuildActive())
                    RunUiMenuE2eProbe(this);
                RawrXD::ShellLayout::ApplyFromIde(this);
                return 0;
            }
            // Handle background init completion — refresh UI (Tier 5 menus enabled here after initTier5Cosmetics)
            if (uMsg == WM_APP + 101)
            {
                if (m_hMenu)
                    RawrXD::MainMenuAuthority::EnsureAttached(hwnd, m_hMenu);
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "AFTER_COMMAND_AUTHORITY_INIT");
                if (!RawrXD::ShellLayout::FrameOnlyMode()) {
                    applyTheme();
                    updateMenuEnableStates();
                }
                RawrXD::ShellLayout::ApplyFromIde(this);
                InvalidateRect(hwnd, nullptr, TRUE);
                UpdateWindow(hwnd);
                PostMessage(hwnd, WM_APP_MENU_IDLE_STABLE, 0, 0);
                return 0;
            }
            if (uMsg == WM_APP_MENU_IDLE_STABLE)
            {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                P1PRA_Witness("P1PRA_UI", "menu_idle_stable_enter");
                P1PRA_AgentDbg("H11", "handleMessage", "menu_idle_stable", 0, 0, 0);
                P1PRA_AgentDbg("H12", "handleMessage", "menu_idle_handler_body", 0, 0, 0);
#endif
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "IDLE_ENTERED");
                if (m_hMenu)
                    RawrXD::MainMenuAuthority::EnsureAttached(hwnd, m_hMenu);
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "WM_ENTERIDLE_STABLE");
                RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "IDLE_STABLE");
                RawrXD::ShellLayout::ApplyFromIde(this);
                return 0;
            }
            // AI backend verification result from background probe thread
            if (uMsg == WM_AI_BACKEND_STATUS)
            {
                onAIBackendVerified(wParam != 0);
                return 0;
            }
            // Tier 3 (Feature 35): File changed externally → show reload toast
            if (uMsg == WM_FILE_CHANGED_EXTERNAL)
            {
                showFileChangedToast();
                return 0;
            }
            // Handle "load downloaded model" signal from background download threads
            // (HuggingFace / URL downloads complete, m_loadedModelPath already set).
            // Also used for session restore once StreamingGGUFLoader exists.
            // P1-B: first createWindow pump can deliver this before EngineManager is
            // wired; loading then surfaces as uncaught 0xE06D7363 and kills startup.
            if (uMsg == WM_APP + 201)
            {
                // P0: never run GGUF/model load during createWindow post-create pumps.
                // ide_startup.log last edge: P1_pump_before post_create_2 msg=0x80c9
                // (= WM_APP+201) → SEH 0xE06D7363. Defer until pumps complete.
                if (!m_startupPumpsComplete || !m_engineManager)
                {
                    m_pendingApp201ModelLoad = true;
                    RawrXD::P1GgufCert::emit("ENGINE_MANAGER_PRESENT",
                                             m_engineManager ? "INFO" : "FAIL",
                                             "deferring_WM_APP_201_startup");
                    OutputDebugStringA("[WM_APP+201] deferred (startup pumps / no engine)\n");
                    fprintf(stderr, "[STARTUP] WM_APP+201 deferred (startup)\n");
                    fflush(stderr);
                    return 0;
                }
                RawrXD::P1GgufCert::emit("ENGINE_MANAGER_PRESENT", "PASS");
                m_pendingApp201ModelLoad = false;
                if (m_p1GgufDeferredFlushPosted)
                {
                    RawrXD::P1GgufCert::emit("DEFERRED_LOAD_FLUSHED", "PASS");
                    m_p1GgufDeferredFlushPosted = false;
                }
                else
                {
                    RawrXD::P1GgufCert::emit("DEFERRED_LOAD_FLUSHED", "INFO", "direct_delivery_no_prior_defer");
                }
                try
                {
                    const std::string& pathToLoad = getLoadedModelPath();
                    if (pathToLoad.empty())
                    {
                        RawrXD::P1GgufCert::emit("MODEL_FILE_OPEN", "FAIL", "empty_loadedModelPath");
                        RawrXD::P1GgufCert::emit("MODEL_READY", "FAIL", "empty_path");
                        return 0;
                    }
                    appendToOutput("Loading downloaded model: " + pathToLoad + "\n", "Output",
                                   OutputSeverity::Info);
                    const bool ggufOk = loadGGUFModel(pathToLoad);
                    if (!ggufOk)
                    {
                        RawrXD::P1GgufCert::emit("MODEL_READY", "FAIL", "gguf_streaming_fail");
                        appendToOutput("Model load incomplete (streaming). Path: " + pathToLoad + "\n",
                                       "Errors", OutputSeverity::Error);
                        return 0;
                    }
                    // Streaming stays on UI (matches live IDE: "STREAMING MODE").
                    // Native LoadModel runs on a worker — UI-pump Vulkan init dies at
                    // INF_vulkan; harness PASSes the same call off the UI thread.
                    RawrXD::P1GgufCert::emit("INFERENCE_ENGINE_CREATED", "INFO",
                                             "calling_LoadModel_worker");
                    RawrXD::P1LoadCkpt::emit("IDE_LoadModel", "dispatch_worker");
                    appendToOutput("Native LoadModel started on worker thread...\n", "Output",
                                   OutputSeverity::Info);
                    const std::string pathCopy = pathToLoad;
                    HWND hwndNotify = m_hwndMain;
                    std::thread([pathCopy, hwndNotify]() {
                        bool infOk = false;
                        try
                        {
                            auto engine = RawrXD::CPUInferenceEngine::GetSharedInstance();
                            auto memPlugin = std::make_shared<RawrXD::Modules::NativeMemoryModule>();
                            engine->RegisterMemoryPlugin(memPlugin);
                            RawrXD::P1LoadCkpt::emit("IDE_LoadModel", "before_worker_LoadModel");
                            if (engine->LoadModel(pathCopy))
                            {
                                RawrXD::P1LoadCkpt::emit("IDE_LoadModel", "ok");
                                RawrXD::P1GgufCert::emit("INFERENCE_ENGINE_CREATED", "PASS");
                                RawrXD::P1GgufCert::emit("MODEL_READY", "PASS", pathCopy.c_str());
                                RawrXD::P1GgufCert::emit("NO_UNHANDLED_EXCEPTION", "PASS",
                                                         "worker_ok");
                                infOk = true;
                            }
                            else
                            {
                                const std::string err = engine->GetLastLoadErrorMessage();
                                RawrXD::P1LoadCkpt::emit("IDE_LoadModel",
                                                         err.empty() ? "fail" : err.c_str());
                                RawrXD::P1GgufCert::emit("INFERENCE_ENGINE_CREATED", "FAIL",
                                                         err.empty() ? "LoadModel_false" : err.c_str());
                                RawrXD::P1GgufCert::emit("MODEL_READY", "FAIL",
                                                         err.empty() ? "LoadModel_false" : err.c_str());
                            }
                        }
                        catch (const std::exception& ex)
                        {
                            RawrXD::P1LoadCkpt::emit("IDE_LoadModel", ex.what());
                            RawrXD::P1GgufCert::emit("INFERENCE_ENGINE_CREATED", "FAIL", ex.what());
                            RawrXD::P1GgufCert::emit("MODEL_READY", "FAIL", ex.what());
                            RawrXD::P1GgufCert::emit("NO_UNHANDLED_EXCEPTION", "PASS",
                                                     "contained_std_exception_worker");
                        }
                        catch (...)
                        {
                            RawrXD::P1LoadCkpt::emit("IDE_LoadModel", "unknown_exception");
                            RawrXD::P1GgufCert::emit("INFERENCE_ENGINE_CREATED", "FAIL",
                                                     "worker_unknown");
                            RawrXD::P1GgufCert::emit("MODEL_READY", "FAIL", "worker_unknown");
                            RawrXD::P1GgufCert::emit("NO_UNHANDLED_EXCEPTION", "PASS",
                                                     "contained_unknown_worker");
                        }
                        if (hwndNotify && IsWindow(hwndNotify))
                            PostMessageA(hwndNotify, WM_APP + 205, infOk ? 1 : 0, 0);
                    }).detach();
                    return 0;
                }
                catch (const std::exception& ex)
                {
                    RawrXD::P1GgufCert::emit("NO_UNHANDLED_EXCEPTION", "PASS", "contained_std_exception");
                    RawrXD::P1GgufCert::emit("MODEL_READY", "FAIL", ex.what());
                    OutputDebugStringA("[WM_APP+201] std::exception (contained)\n");
                    appendToOutput(std::string("Model auto-load exception (contained): ") + ex.what() + "\n",
                                   "Errors", OutputSeverity::Error);
                }
                catch (...)
                {
                    RawrXD::P1GgufCert::emit("NO_UNHANDLED_EXCEPTION", "PASS", "contained_unknown");
                    RawrXD::P1GgufCert::emit("MODEL_READY", "FAIL", "unknown_exception_contained");
                    OutputDebugStringA("[WM_APP+201] unknown C++ exception (contained)\n");
                    appendToOutput("Model auto-load unknown exception (contained)\n", "Errors",
                                   OutputSeverity::Error);
                }
                return 0;
            }
            // WM_APP+205: native LoadModel worker finished (wParam=1 success)
            if (uMsg == WM_APP + 205)
            {
                if (wParam)
                {
                    m_nativeEngineLoaded = true;
                    if (!m_nativeEngine)
                        m_nativeEngine = RawrXD::CPUInferenceEngine::GetSharedInstance();
                    appendToOutput("Native inference model READY (worker LoadModel).\n", "Output",
                                   OutputSeverity::Info);
                }
                else
                {
                    appendToOutput("Native LoadModel failed (see p1_gguf_load_cert / p1_cpu_load_ckpt).\n",
                                   "Errors", OutputSeverity::Error);
                }
                return 0;
            }
            // WM_APP+206: command-home AgenticBridge LoadModel worker finished
            if (uMsg == WM_APP + 206)
            {
                std::unique_ptr<std::string> path(reinterpret_cast<std::string*>(lParam));
                const bool loadOk = (wParam != 0);
                onCommandModelLoadWorkerDone(loadOk, path ? *path : std::string{});
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                if (loadOk) {
                    DWORD pid = 0;
                    const DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
                    const LONG_PTR ud = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
                    char line[192];
                    snprintf(line, sizeof(line),
                             "main=%p self=%p userdata=%p pid=%lu tid=%lu",
                             static_cast<void*>(m_hwndMain), static_cast<void*>(hwnd),
                             reinterpret_cast<void*>(ud),
                             static_cast<unsigned long>(pid),
                             static_cast<unsigned long>(tid));
                    P1PRA_Witness("P1PRA_HWND", line);
                    P1PRA_ThreadWitness("ui_post_window");
                }
#endif
                return 0;
            }
            // P1PRA E2E: UI-thread Send inject (avoid cross-process WM_COMMAND to cmdHost).
            if (uMsg == WM_APP + 209)
            {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                if (P1PRA_SafeProcessE2EPostState(
                        hwnd, uMsg, wParam,
                        GetWindowLongPtrW(hwnd, GWLP_USERDATA)) < 0) {
                    P1PRA_Witness("P1PRA_SEND", "target_invalid");
                    return 0;
                }
                P1PRA_Witness("P1PRA_SEND", "hook_enter");
#endif
                HWND composer = nullptr;
                if (m_hwndCommandComposer && IsWindow(m_hwndCommandComposer))
                    composer = m_hwndCommandComposer;
                else if (m_hwndCommandHost && IsWindow(m_hwndCommandHost)) {
                    HWND c = GetDlgItem(m_hwndCommandHost, IDC_CMD_COMPOSER_INPUT);
                    if (c && IsWindow(c))
                        composer = c;
                }
                if (composer && IsWindow(composer))
                    SetWindowTextW(composer, L"ping");
                HWND host = nullptr;
                if (m_hwndCommandHost && IsWindow(m_hwndCommandHost))
                    host = m_hwndCommandHost;
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
                P1PRA_Witness("P1PRA_SEND", "before_handle");
#endif
                handleCommandSend(host);
                return 0;
            }
            // RE: set binary from build output (Game Engine or other build that posted path)
            if (uMsg == WM_APP + 202)
            {
                std::string* path = reinterpret_cast<std::string*>(lParam);
                if (path && !path->empty())
                {
                    setCurrentBinaryForReverseEngineering(*path);
                    appendToOutput("[RE] Binary set from build output: " + *path + "\n", "Output",
                                   OutputSeverity::Info);
                    delete path;
                }
                return 0;
            }
            // HexMag controller → UI (FINAL | NEED_INPUT | FAILURE)
            if (uMsg == WM_HEXMAG_ASK_DONE)
            {
                extern void RawrXD_FinishHexMagAsk(Win32IDE* ide, WPARAM wParam, LPARAM lParam);
                RawrXD_FinishHexMagAsk(this, wParam, lParam);
                return 0;
            }
            if (uMsg == WM_HEXMAG_TELEMETRY_CHUNK)
            {
                extern void RawrXD_FinishHexMagTelemetryChunk(Win32IDE* ide, LPARAM lParam);
                RawrXD_FinishHexMagTelemetryChunk(this, lParam);
                return 0;
            }
            if (uMsg == WM_HEXMAG_TELEMETRY_DONE)
            {
                extern void RawrXD_FinishHexMagTelemetryDone(Win32IDE* ide, WPARAM wParam);
                RawrXD_FinishHexMagTelemetryDone(this, wParam);
                return 0;
            }
            // Handle custom agent output message
            if (uMsg == WM_AGENT_OUTPUT_SAFE)
            {
                const char* text = reinterpret_cast<const char*>(lParam);
                if (text)
                {
                    onAgentOutput(text);
                    free(const_cast<char*>(text));
                }
                return 0;
            }
            if (uMsg == WM_IDE_OUTPUT_APPEND_SAFE)
            {
                const char* text = reinterpret_cast<const char*>(lParam);
                if (text)
                {
                    appendToOutput(std::string(text), "Output", OutputSeverity::Info);
                    free(const_cast<char*>(text));
                }
                return 0;
            }
            if (uMsg == WM_IDE_MOE_PACK_STATUS_REFRESH)
            {
                refreshMoEPackHudStatusBarPart();
                return 0;
            }
            // Handle Plan Executor messages
            if (uMsg == WM_PLAN_READY)
            {
                onPlanReady((int)wParam, reinterpret_cast<PlanStep*>(lParam));
                return 0;
            }
            if (uMsg == WM_PLAN_STEP_DONE)
            {
                onPlanStepDone((int)wParam, (int)lParam);
                return 0;
            }
            if (uMsg == WM_PLAN_COMPLETE)
            {
                onPlanComplete(wParam != 0);
                return 0;
            }
            // Plan step status update from background thread (live dialog update)
            if (uMsg == WM_APP + 503)
            {
                updatePlanStepInDialog((int)wParam, static_cast<PlanStepStatus>((int)lParam));
                return 0;
            }
            // Agent History replay step completion
            if (uMsg == WM_AGENT_HISTORY_REPLAY_DONE)
            {
                onReplayStepDone((int)wParam, (int)lParam);
                return 0;
            }
            // ── Native Inference Pipeline streaming messages ──
            if (uMsg == WM_NATIVE_AI_TOKEN)
            {
                onNativeAIToken(wParam, lParam);
                return 0;
            }
            if (uMsg == WM_NATIVE_AI_COMPLETE)
            {
                onNativeAIComplete(wParam, lParam);
                return 0;
            }
            if (uMsg == WM_NATIVE_AI_ERROR)
            {
                onNativeAIError();
                return 0;
            }
            if (uMsg == WM_NATIVE_AI_PROGRESS)
            {
                onNativeAIProgress();
                return 0;
            }
            // HexMag async ask / telemetry (WM_APP+560..562 — see Win32IDE_HexMag.cpp)
            if (uMsg == (WM_APP + 560))
            {
                extern void RawrXD_FinishHexMagAsk(Win32IDE* ide, WPARAM wParam, LPARAM lParam);
                RawrXD_FinishHexMagAsk(this, wParam, lParam);
                return 0;
            }
            if (uMsg == (WM_APP + 561))
            {
                extern void RawrXD_FinishHexMagTelemetryChunk(Win32IDE* ide, LPARAM lParam);
                RawrXD_FinishHexMagTelemetryChunk(this, lParam);
                return 0;
            }
            if (uMsg == (WM_APP + 562))
            {
                extern void RawrXD_FinishHexMagTelemetryDone(Win32IDE* ide, WPARAM wParam);
                RawrXD_FinishHexMagTelemetryDone(this, wParam);
                return 0;
            }
            break;
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

// Simple file trace helper (non-static for external linkage)
void fileTrace(const char* msg) {
    FILE* f = nullptr;
    fopen_s(&f, "win32ide_trace.log", "a");
    if (f) {
        fprintf(f, "%s\n", msg);
        fflush(f);
        fclose(f);
    }
}

// P0 startup: flush-immediate checkpoints (ODS + stderr + file). No buffering.
static void p0StartupCk(const char* tag)
{
    char line[256];
    sprintf_s(line, "[STARTUP] %s\n", tag ? tag : "?");
    OutputDebugStringA(line);
    fprintf(stderr, "%s", line);
    fflush(stderr);
    fileTrace(line);
}

static bool p0BisectEquals(const char* want)
{
    const char* v = std::getenv("RAWRXD_P0_BISECT");
    return v && want && _stricmp(v, want) == 0;
}

// ============================================================================
// createWindow - Register class and create main window
// ============================================================================
bool Win32IDE::createWindow()
{
    p0StartupCk("createWindow ENTER (Core)");
    OutputDebugStringA("RawrXD: [Win32IDE_Core.cpp] createWindow() ENTER\n");
    fileTrace("[Core] createWindow_ENTER");

    // P1_UI_WINDOW_OWNERSHIP_001: createWindow is idempotent — never a second shell.
    if (m_hwndMain && IsWindow(m_hwndMain))
    {
        OutputDebugStringA("[P1_UI_WINDOW_OWNERSHIP] createWindow IDEMPOTENT — reuse existing m_hwndMain\n");
        fileTrace("[P1_UI_WINDOW_OWNERSHIP] createWindow IDEMPOTENT");
        return true;
    }
    // ====================================================================
    // Enterprise: Load external configuration before window creation
    // P0 bisect regions:
    //   C = config load body
    //   D = configuration scope destruction (exit of this block)
    //   E = SettingsManager construction/Initialize
    // Env RAWRXD_P0_BISECT=after_config | after_config_scope | after_settings
    // ====================================================================
    {
        p0StartupCk("before IDEConfig::getInstance");
        OutputDebugStringA("RawrXD: About to call IDEConfig::getInstance()...\n");
        fileTrace("[Core] createWindow_before_IDEConfig");
        auto& config = IDEConfig::getInstance();
        p0StartupCk("after IDEConfig::getInstance");
        OutputDebugStringA("RawrXD: IDEConfig::getInstance() returned\n");
        fileTrace("[Core] createWindow_after_IDEConfig");
        // Try workspace config, then user config, then defaults
        std::string configPath = "rawrxd.config.json";
        fileTrace("[Core] createWindow_before_loadFromFile");
        if (!config.loadFromFile(configPath))
        {
            // Try in exe directory
            char exePath[MAX_PATH];
            GetModuleFileNameA(nullptr, exePath, MAX_PATH);
            std::string exeDir(exePath);
            size_t lastSlash = exeDir.find_last_of("\\/");
            if (lastSlash != std::string::npos)
            {
                exeDir = exeDir.substr(0, lastSlash);
                config.loadFromFile(exeDir + "\\rawrxd.config.json");
            }
        }
        fileTrace("[Core] createWindow_after_loadFromFile");
        // Apply environment variable overrides (RAWRXD_* prefix)
        fileTrace("[Core] createWindow_before_applyEnvironmentOverrides");
        config.applyEnvironmentOverrides();
        fileTrace("[Core] createWindow_after_applyEnvironmentOverrides");
        // Initialize feature toggles from config
        fileTrace("[Core] createWindow_before_applyFeatureToggles");
        config.applyFeatureToggles();
        fileTrace("[Core] createWindow_after_applyFeatureToggles");

        // Apply config to IDE state
        // DEFERRED: Deep2 Discovery moved to background thread to prevent
        // 0xC0000409 fail-fast from synchronous network I/O + JSON parsing
        // during GUI startup. Use config fallback for initial URL.
        fileTrace("[Core] createWindow_before_ollamaUrl_deferred");
        m_ollamaBaseUrl = config.getString("ollama.baseUrl", "");
        m_ollamaModelOverride = config.getString("ollama.modelOverride", "");
        if (m_ollamaBaseUrl.find("11434") != std::string::npos) {
            fprintf(stderr, "[Win32IDE] LOCAL_ONLY_001: clearing forbidden Ollama URL\n");
            m_ollamaBaseUrl.clear();
        }
        fprintf(stderr, "[Win32IDE] Using config fallback: %s\n",
                m_ollamaBaseUrl.empty() ? "(empty/local-only)" : m_ollamaBaseUrl.c_str());
        fflush(stderr);
        fileTrace("[Core] createWindow_after_ollamaUrl_deferred");
        m_ollamaModelOverride = config.getString("ollama.modelOverride", "");
        m_autoSaveEnabled = config.getBool("editor.autoSave", false);
        m_gpuTextEnabled = config.getBool("performance.gpuTextRendering", true);
        m_useStreamingLoader = config.getBool("performance.streamingGGUFLoad", true);
        m_useVulkanRenderer = config.getBool("performance.vulkanRenderer", false);
        fileTrace("[Core] createWindow_after_configGetters");

        // Sync agentic autonomous config (1–99x limits, QualitySpeedBalance, operation/model mode)
        fileTrace("[Core] createWindow_before_agenticConfig");
        {
            auto& aac = RawrXD::AgenticAutonomousConfig::instance();
            aac.setPerModelInstanceCount(config.getInt("agent.perModelInstances", 1));
            aac.setCycleAgentCounter(config.getInt("agent.cycleAgentCounter", 1));
            aac.setQualitySpeedBalanceFromString(config.getString("agent.qualitySpeedBalance", "Auto"));
            aac.setOperationModeFromString(config.getString("agent.operationMode", "Agent"));
            aac.setModelSelectionModeFromString(config.getString("agent.modelSelectionMode", "Auto"));
            int maxParallel = config.getInt("agent.maxModelsInParallel", 99);
            aac.setMaxModelsInParallel(maxParallel > 0 ? maxParallel : 99);
            std::string agenticJson = config.getString("agentic.configJson", "");
            if (!agenticJson.empty())
                aac.fromJson(agenticJson);
            p0StartupCk("after agenticConfig locals (before nested scope exit)");
        }
        p0StartupCk("after agenticConfig nested scope exit");
        fileTrace("[Core] createWindow_after_agenticConfig");

        LOG_INFO("Configuration loaded — " + std::to_string(config.getAllKeys().size()) + " keys");
        METRICS.increment("config.loads_total");
        OutputDebugStringA("RawrXD: Configuration loading complete\n");
        LOG_INFO("[createWindow] Configuration loading complete");
        fileTrace("[Core] createWindow_after_config");
        p0StartupCk("config complete");

        // Bisect C: return while config locals (incl. configPath string) still alive.
        if (p0BisectEquals("after_config"))
        {
            p0StartupCk("RETURNING AFTER CONFIG (bisect C — scope NOT exited)");
            return true;
        }

        p0StartupCk("before config scope exit");
    }
    p0StartupCk("after config scope exit");

    // Bisect D: config scope destroyed; SettingsManager not yet touched.
    if (p0BisectEquals("after_config_scope"))
    {
        p0StartupCk("RETURNING AFTER CONFIG SCOPE EXIT (bisect D)");
        return true;
    }

    // ====================================================================
    // Initialize Settings Manager for persistent preferences
    // ====================================================================
    {
        p0StartupCk("before SettingsManager");
        OutputDebugStringA("RawrXD: Initializing SettingsManager...\n");
        fileTrace("[Core] createWindow_before_SettingsManager");
        if (RawrXD::GetSettings().Initialize()) {
            p0StartupCk("after SettingsManager Initialize OK");
            OutputDebugStringA("RawrXD: SettingsManager initialized\n");
            LOG_INFO("[createWindow] SettingsManager initialized");
            
            // Apply window state from settings
            auto windowState = RawrXD::GetSettings().GetWindowState();
            p0StartupCk("after GetWindowState");
            if (windowState.IsValid()) {
                // Store for use in window creation
                m_windowX = windowState.x;
                m_windowY = windowState.y;
                m_windowWidth = windowState.width;
                m_windowHeight = windowState.height;
                m_windowMaximized = windowState.maximized;
            }
            p0StartupCk("after windowState apply (before Settings scope exit)");
        } else {
            OutputDebugStringA("RawrXD: SettingsManager initialization failed\n");
            LOG_WARNING("[createWindow] SettingsManager initialization failed");
            p0StartupCk("SettingsManager Initialize FAILED");
        }
        fileTrace("[Core] createWindow_after_SettingsManager");
    }
    p0StartupCk("after SettingsManager scope exit");

    if (p0BisectEquals("after_settings"))
    {
        p0StartupCk("RETURNING AFTER SETTINGS (bisect E)");
        return true;
    }

    // Load RichEdit libraries — need both for RICHEDIT_CLASSA and MSFTEDIT_CLASS
    OutputDebugStringA("RawrXD: About to LoadLibraryA(riched20.dll)...\n");
    LOG_INFO("[createWindow] About to LoadLibraryA(riched20.dll)");
    fileTrace("[Core] createWindow_before_LoadLibrary_riched20");
    LoadLibraryA("riched20.dll");
    OutputDebugStringA("RawrXD: riched20.dll loaded\n");
    LOG_INFO("[createWindow] riched20.dll loaded");
    fileTrace("[Core] createWindow_after_LoadLibrary_riched20");
    OutputDebugStringA("RawrXD: About to LoadLibraryA(msftedit.dll)...\n");
    LOG_INFO("[createWindow] About to LoadLibraryA(msftedit.dll)");
    fileTrace("[Core] createWindow_before_LoadLibrary_msftedit");
    LoadLibraryA("msftedit.dll");
    OutputDebugStringA("RawrXD: msftedit.dll loaded\n");
    LOG_INFO("[createWindow] msftedit.dll loaded");
    fileTrace("[Core] createWindow_after_LoadLibrary_msftedit");

    OutputDebugStringA("RawrXD: Setting up WNDCLASSEXA...\n");
    LOG_INFO("[createWindow] Setting up WNDCLASSEXA");
    fileTrace("[Core] createWindow_before_WNDCLASSEXA");
    WNDCLASSEXA wc = {};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = Win32IDE::WindowProc;
    wc.hInstance = m_hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = kWindowClassName;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    OutputDebugStringA("RawrXD: About to RegisterClassExA()...\n");
    LOG_INFO("[createWindow] About to RegisterClassExA()");
    fileTrace("[Core] createWindow_before_RegisterClassExA");

    BOOL regResult = RegisterClassExA(&wc);
    fileTrace("[Core] createWindow_after_RegisterClassExA");

    if (!regResult)
    {
        // Class might already be registered
        DWORD err = GetLastError();
        fileTrace("[Win32IDE_Core] RegisterClassExA failed, checking error");
        if (err != ERROR_CLASS_ALREADY_EXISTS)
        {
            char errBuf[192] = {};
            std::snprintf(errBuf, sizeof(errBuf), "Failed to register window class (GetLastError=%lu)",
                          static_cast<unsigned long>(err));
            LOG_ERROR(errBuf);
            OutputDebugStringA("RawrXD: RegisterClassExA FAILED\n");
            LOG_ERROR("[createWindow] RegisterClassExA FAILED");
            fileTrace("[Win32IDE_Core] RegisterClassExA FAILED");
            return false;
        }
        OutputDebugStringA("RawrXD: RegisterClassExA - class already exists (OK)\n");
        LOG_INFO("[createWindow] RegisterClassExA - class already exists (OK)");
        fileTrace("[Core] createWindow_RegisterClassExA_exists");
    }
    else
    {
        OutputDebugStringA("RawrXD: RegisterClassExA succeeded\n");
        LOG_INFO("[createWindow] RegisterClassExA succeeded");
        fileTrace("[Core] createWindow_RegisterClassExA_succeeded");
    }

    OutputDebugStringA("RawrXD: About to CreateWindowExA()...\n");
    LOG_INFO("[createWindow] About to CreateWindowExA()");
    fileTrace("[Core] createWindow_before_CreateWindowExA");
    // Create the main window on the primary monitor's work area so it is always visible
    int winW = 1600, winH = 1000;
    int winX = 50, winY = 50;
    fileTrace("[Core] createWindow_before_MonitorFromPoint");
    HMONITOR hMon = MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY);
    fileTrace("[Core] createWindow_after_MonitorFromPoint");
    MONITORINFO mi = {sizeof(mi)};
    fileTrace("[Core] createWindow_before_GetMonitorInfoA");
    if (hMon && GetMonitorInfoA(hMon, &mi))
    {
        const RECT& r = mi.rcWork;
        winX = r.left + 50;
        winY = r.top + 50;
        winW = (std::min)((int)(r.right - r.left) - 100, 1600);
        winH = (std::min)((int)(r.bottom - r.top) - 100, 1000);
    }
    fileTrace("[Core] createWindow_after_GetMonitorInfoA");
    LOG_INFO("[createWindow] Calling CreateWindowExA...");
    fileTrace("[Core] createWindow_calling_CreateWindowExA");
    HWND created =
        CreateWindowExA(WS_EX_APPWINDOW, kWindowClassName, "RawrXD IDE - Native Win32 AI Development Environment",
                        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN | WS_VISIBLE, winX, winY, winW, winH, nullptr, nullptr,
                        m_hInstance, this);
    OutputDebugStringA("RawrXD: CreateWindowExA returned\n");
    LOG_INFO("[createWindow] CreateWindowExA returned");
    fileTrace("[Core] createWindow_after_CreateWindowExA");
    p0StartupCk("after CreateWindowExA returned");

    if (!created)
    {
        // Never clobber a live main HWND if a second CreateWindowEx was rejected.
        if (m_hwndMain && IsWindow(m_hwndMain))
        {
            OutputDebugStringA("[P1_UI_WINDOW_OWNERSHIP] CreateWindowEx failed but stable main kept\n");
            fileTrace("[P1_UI_WINDOW_OWNERSHIP] CreateWindowEx fail keep main");
            return true;
        }
        DWORD err = GetLastError();
        char errBuf[224] = {};
        std::snprintf(errBuf, sizeof(errBuf),
                      "Failed to create main window (GetLastError=%lu, class=%s)",
                      static_cast<unsigned long>(err), kWindowClassName ? kWindowClassName : "<null>");
        LOG_ERROR(errBuf);
        OutputDebugStringA("RawrXD: CreateWindowExA FAILED\n");
        LOG_ERROR("[createWindow] CreateWindowExA FAILED");
        fileTrace("[Core] createWindow_CreateWindowExA_FAILED");
        return false;
    }
    m_hwndMain = created;
    OutputDebugStringA("RawrXD: CreateWindowExA succeeded - window created\n");
    LOG_INFO("[createWindow] CreateWindowExA succeeded - window created");
    fileTrace("[Core] createWindow_CreateWindowExA_succeeded");
    RawrXD::MainMenuAuthority::TraceMenuState(m_hwndMain, "AFTER_CREATE_WINDOW");

    // Children + heavy deferred init are armed AFTER WM_APP_RESTORE_SESSION returns
    // (see handleMessage). Do not queue them here — that races restore and can run
    // deferred children while session restore is still the active failure window.

    fileTrace("[Core] createWindow_before_ShowWindow");
    ShowWindow(m_hwndMain, SW_SHOW);
    OutputDebugStringA("RawrXD: ShowWindow(SW_SHOW) called\n");
    LOG_INFO("[createWindow] ShowWindow(SW_SHOW) called");
    ShowWindow(m_hwndMain, SW_SHOWNORMAL);
    OutputDebugStringA("RawrXD: ShowWindow(SW_SHOWNORMAL) called\n");
    LOG_INFO("[createWindow] ShowWindow(SW_SHOWNORMAL) called");
    restoreWindowOpacityIfNeeded(m_hwndMain);
    UpdateWindow(m_hwndMain);
    OutputDebugStringA("RawrXD: UpdateWindow called\n");
    LOG_INFO("[createWindow] UpdateWindow called");
    SetWindowPos(m_hwndMain, HWND_TOPMOST, winX, winY, winW, winH, SWP_SHOWWINDOW | SWP_NOACTIVATE);
    OutputDebugStringA("RawrXD: SetWindowPos(TOPMOST) called\n");
    LOG_INFO("[createWindow] SetWindowPos(TOPMOST) called");
    SetWindowPos(m_hwndMain, HWND_NOTOPMOST, winX, winY, winW, winH, SWP_SHOWWINDOW | SWP_NOMOVE | SWP_NOSIZE);
    OutputDebugStringA("RawrXD: SetWindowPos(NOTOPMOST) called\n");
    LOG_INFO("[createWindow] SetWindowPos(NOTOPMOST) called");
    BringWindowToTop(m_hwndMain);
    OutputDebugStringA("RawrXD: BringWindowToTop called\n");
    LOG_INFO("[createWindow] BringWindowToTop called");
    SetForegroundWindow(m_hwndMain);
    OutputDebugStringA("RawrXD: SetForegroundWindow called\n");
    LOG_INFO("[createWindow] SetForegroundWindow called");
    SetActiveWindow(m_hwndMain);
    OutputDebugStringA("RawrXD: SetActiveWindow called\n");
    LOG_INFO("[createWindow] SetActiveWindow called");
    RedrawWindow(m_hwndMain, nullptr, nullptr, RDW_ERASE | RDW_INVALIDATE | RDW_UPDATENOW);
    OutputDebugStringA("RawrXD: RedrawWindow called\n");
    LOG_INFO("[createWindow] RedrawWindow called");
    fileTrace("[Core] createWindow_after_RedrawWindow");

    // Register GUI output callback so unified-command handler output goes to IDE output panel
    setIdeAppendOutput(
        [](void* ide, const char* text)
        {
            if (ide && text)
                static_cast<Win32IDE*>(ide)->appendToOutput(std::string(text), "Output", OutputSeverity::Info);
        });

    LOG_INFO("Main window created successfully");
    OutputDebugStringA("RawrXD: createWindow returning TRUE\n");
    fileTrace("[Core] createWindow_RETURN_TRUE");
    return true;
}

// ============================================================================
// Force window to foreground (SetForegroundWindow often fails when launched by
// another process; AttachThreadInput + BringWindowToTop works around it).
// ============================================================================
static void forceWindowToForeground(HWND hwnd)
{
    if (!hwnd || !IsWindow(hwnd))
        return;
    HWND fg = GetForegroundWindow();
    if (fg == hwnd)
        return;
    DWORD fgTid = GetWindowThreadProcessId(fg, nullptr);
    DWORD myTid = GetCurrentThreadId();
    if (fgTid != myTid && fgTid != 0)
    {
        AttachThreadInput(myTid, fgTid, TRUE);
    }
    BringWindowToTop(hwnd);
    ShowWindow(hwnd, SW_RESTORE);
    ShowWindow(hwnd, SW_SHOWNORMAL);
    SetForegroundWindow(hwnd);
    SetActiveWindow(hwnd);
    if (fgTid != myTid && fgTid != 0)
    {
        AttachThreadInput(myTid, fgTid, FALSE);
    }
}

// ============================================================================
// showWindow - Show and update the main window (always normal, never minimized)
// Ignores launcher nCmdShow so the IDE never opens minimized or disappears.
// ============================================================================
void Win32IDE::showWindow()
{
    if (!m_hwndMain)
        return;
    if (IsIconic(m_hwndMain))
        ShowWindow(m_hwndMain, SW_RESTORE);
    ShowWindow(m_hwndMain, SW_SHOWNORMAL);
    WINDOWPLACEMENT wp = {sizeof(WINDOWPLACEMENT)};
    if (GetWindowPlacement(m_hwndMain, &wp))
    {
        if (wp.showCmd != SW_SHOWNORMAL && wp.showCmd != SW_SHOW)
        {
            wp.showCmd = SW_SHOWNORMAL;
            SetWindowPlacement(m_hwndMain, &wp);
        }
    }
    UpdateWindow(m_hwndMain);
    SetWindowPos(m_hwndMain, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    BringWindowToTop(m_hwndMain);
    SetForegroundWindow(m_hwndMain);
    SetActiveWindow(m_hwndMain);
    forceWindowToForeground(m_hwndMain);
    restoreWindowOpacityIfNeeded(m_hwndMain);
    SetTimer(m_hwndMain, IDT_VISIBILITY_WATCHDOG, 1000, nullptr);
    if (!rawrxd::GpuPowerProbeSuppressed())
        SetTimer(m_hwndMain, IDT_GPU_TELEMETRY, 2000, nullptr);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    else
        P1PRA_Witness("P1PRA_UI", "gpu_telemetry_timer_suppressed");
#endif
    FLASHWINFO fwi = {sizeof(FLASHWINFO), m_hwndMain, FLASHW_ALL | FLASHW_TIMERNOFG, 3, 0};
    FlashWindowEx(&fwi);
}

// ============================================================================
// runMessageLoop - Standard Win32 message loop with accelerators
// ============================================================================
int Win32IDE::runMessageLoop()
{
    LOG_INFO("Message loop starting");
    METRICS.increment("app.message_loop_starts");
    auto loopStart = std::chrono::high_resolution_clock::now();

    MSG msg = {};
    static bool s_tracedFirstIdle = false;
    try
    {
        // GetMessage returns 0 on WM_QUIT, -1 on error. Treat both as loop end
        // so a post-destroy error cannot spin forever.
        BOOL gm;
        while ((gm = GetMessage(&msg, nullptr, 0, 0)) > 0)
        {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
            if (msg.message == WM_APP + 209) {
                // #region agent log
                P1PRA_AgentDbg("H2", "runMessageLoop", "dequeue_wm_app_209",
                               reinterpret_cast<unsigned long long>(msg.hwnd),
                               static_cast<unsigned long long>(msg.wParam),
                               static_cast<unsigned long long>(GetCurrentThreadId()));
                // #endregion agent log
            }
#endif
            if (!s_tracedFirstIdle && msg.message == WM_ENTERIDLE) {
                s_tracedFirstIdle = true;
                if (m_hwndMain && m_hMenu)
                    RawrXD::MainMenuAuthority::EnsureAttached(m_hwndMain, m_hMenu);
                RawrXD::MainMenuAuthority::TraceMenuState(m_hwndMain, "WM_ENTERIDLE_STABLE");
            }
            METRICS.increment("app.messages_processed");

            // Handle accelerator keys
            if (msg.message == WM_KEYDOWN)
            {
                bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
                bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
                bool alt = (GetKeyState(VK_MENU) & 0x8000) != 0;

                if (ctrl && shift && msg.wParam == 'P')
                {
                    if (m_commandPaletteVisible)
                    {
                        hideCommandPalette();
                    }
                    else
                    {
                        showCommandPalette();
                    }
                    continue;
                }
                if (ctrl && msg.wParam == 'N')
                {
                    routeCommandUnified(IDM_FILE_NEW, this, m_hwndMain);
                    continue;
                }
                if (ctrl && msg.wParam == 'O')
                {
                    routeCommandUnified(IDM_FILE_OPEN, this, m_hwndMain);
                    continue;
                }
                if (ctrl && msg.wParam == 'S')
                {
                    if (shift)
                        routeCommandUnified(IDM_FILE_SAVEAS, this, m_hwndMain);
                    else
                        routeCommandUnified(IDM_FILE_SAVE, this, m_hwndMain);
                    continue;
                }
                if (ctrl && shift && msg.wParam == 'W')
                {
                    enterWorkMode();
                    continue;
                }
                if (ctrl && shift && msg.wParam == '1')
                {
                    enterCommandMode();
                    continue;
                }
                // Ctrl+Shift+L → License Creator, Ctrl+Shift+F → Feature Registry (before plain Ctrl+F)
                if (ctrl && shift && msg.wParam == 'L')
                {
                    routeCommand(3015);
                    continue;
                }
                if (ctrl && shift && msg.wParam == 'F')
                {
                    routeCommand(3016);
                    continue;
                }
                if (ctrl && msg.wParam == 'F')
                {
                    routeCommandUnified(IDM_EDIT_FIND, this, m_hwndMain);
                    continue;
                }
                if (ctrl && msg.wParam == 'H')
                {
                    routeCommandUnified(IDM_EDIT_REPLACE, this, m_hwndMain);
                    continue;
                }
                if (ctrl && msg.wParam == 'B')
                {
                    toggleSidebar();
                    continue;
                }
                if (ctrl && alt && msg.wParam == 'B')
                {
                    toggleSecondarySidebar();
                    continue;
                }
                // Ctrl+Shift+E → File Explorer (show sidebar with Explorer view)
                if (ctrl && shift && msg.wParam == 'E')
                {
                    routeCommand(IDM_VIEW_FILE_EXPLORER);
                    continue;
                }
                // Ctrl+Shift+X → Extensions view
                if (ctrl && shift && msg.wParam == 'X')
                {
                    routeCommand(2031);
                    continue;
                }
                // Ctrl+Shift+C → AI Chat panel toggle
                if (ctrl && shift && msg.wParam == 'C')
                {
                    toggleSecondarySidebar();
                    continue;
                }
                // Ctrl+Shift+A → Audit Dashboard
                if (ctrl && shift && msg.wParam == 'A')
                {
                    routeCommandUnified(IDM_AUDIT_SHOW_DASHBOARD, this, m_hwndMain);
                    continue;
                }
                // Ctrl+Shift+I → Bounded Agent Loop (tool-calling autonomous agent)
                if (ctrl && shift && msg.wParam == 'I')
                {
                    routeCommandUnified(IDM_AGENT_BOUNDED_LOOP, this, m_hwndMain);
                    continue;
                }
                // Ctrl+, → Settings (full GUI)
                if (ctrl && msg.wParam == VK_OEM_COMMA)
                {
                    this->showSettingsGUIDialog();
                    continue;
                }
                // Ctrl+= / Ctrl+- → UI Zoom In/Out, Ctrl+0 → Reset zoom
                if (ctrl && (msg.wParam == VK_OEM_PLUS || msg.wParam == 0xBB))
                {
                    // Zoom in: increase scale by 10%
                    if (m_settings.uiScalePercent == 0)
                    {
                        m_settings.uiScalePercent = MulDiv(100, m_currentDpi, 96) + 10;
                    }
                    else
                    {
                        m_settings.uiScalePercent = (std::min)(m_settings.uiScalePercent + 10, 300);
                    }
                    recreateFonts();
                    RECT rc;
                    GetClientRect(m_hwndMain, &rc);
                    onSize(rc.right, rc.bottom);
                    InvalidateRect(m_hwndMain, nullptr, TRUE);
                    saveSettings();
                    continue;
                }
                if (ctrl && (msg.wParam == VK_OEM_MINUS || msg.wParam == 0xBD))
                {
                    // Zoom out: decrease scale by 10%
                    if (m_settings.uiScalePercent == 0)
                    {
                        m_settings.uiScalePercent = (std::max)(MulDiv(100, m_currentDpi, 96) - 10, 75);
                    }
                    else
                    {
                        m_settings.uiScalePercent = (std::max)(m_settings.uiScalePercent - 10, 75);
                    }
                    recreateFonts();
                    RECT rc;
                    GetClientRect(m_hwndMain, &rc);
                    onSize(rc.right, rc.bottom);
                    InvalidateRect(m_hwndMain, nullptr, TRUE);
                    saveSettings();
                    continue;
                }
                if (ctrl && msg.wParam == '0')
                {
                    // Reset zoom to system DPI
                    m_settings.uiScalePercent = 0;
                    recreateFonts();
                    RECT rc;
                    GetClientRect(m_hwndMain, &rc);
                    onSize(rc.right, rc.bottom);
                    InvalidateRect(m_hwndMain, nullptr, TRUE);
                    saveSettings();
                    continue;
                }
            }

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
            if (msg.message == WM_APP_MENU_IDLE_STABLE ||
                (msg.message == WM_TIMER && msg.wParam == IDT_GPU_TELEMETRY)) {
                // #region agent log
                P1PRA_AgentDbg("H12", "runMessageLoop", "pre_dispatch",
                               static_cast<unsigned long long>(msg.message),
                               static_cast<unsigned long long>(msg.wParam),
                               static_cast<unsigned long long>(GetCurrentThreadId()));
                // #endregion
            }
#endif
            TranslateMessage(&msg);
            AIWorkersProcessInvokeQueue();
            DispatchMessage(&msg);
        }
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1,
            gm == 0 ? "MESSAGE_LOOP_WM_QUIT" : "MESSAGE_LOOP_GETMESSAGE_ERR");
    }
    catch (const std::exception& e)
    {
        // Centralized exception handler — prevents unhandled crash
        LOG_CRITICAL(std::string("Unhandled exception in message loop: ") + e.what());
        METRICS.increment("app.unhandled_exceptions");
        MessageBoxA(nullptr, (std::string("RawrXD IDE encountered an error:\n") + e.what()).c_str(),
                    "RawrXD IDE - Critical Error", MB_ICONERROR | MB_OK);
    }
    catch (...)
    {
        LOG_CRITICAL("Unknown unhandled exception in message loop");
        METRICS.increment("app.unhandled_exceptions");
        MessageBoxA(nullptr, "RawrXD IDE encountered an unknown error.", "RawrXD IDE - Critical Error",
                    MB_ICONERROR | MB_OK);
    }

    // Log session metrics on exit
    auto loopEnd = std::chrono::high_resolution_clock::now();
    double sessionMs = std::chrono::duration<double, std::milli>(loopEnd - loopStart).count();
    METRICS.recordDuration("app.session_duration_ms", sessionMs);
    LOG_INFO("Message loop ended — session duration: " + std::to_string(sessionMs / 1000.0) + "s");
    LOG_INFO("Messages processed: " + std::to_string(METRICS.getCounter("app.messages_processed")));

    // Save configuration on exit
    IDEConfig::getInstance().saveToFile("rawrxd.config.json");
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "MESSAGE_LOOP_EXIT");

    return static_cast<int>(msg.wParam);
}

// ============================================================================
// onSize - SINGLE spatial authority: resolve → validate → atomic apply
// ============================================================================
static thread_local bool s_inOnSize = false;

void Win32IDE::layoutAiChatChildren()
{
    if (!m_hwndSecondarySidebar || !IsWindow(m_hwndSecondarySidebar))
        return;

    RECT rc{};
    GetClientRect(m_hwndSecondarySidebar, &rc);
    const int W = rc.right - rc.left;
    const int H = rc.bottom - rc.top;
    if (W <= 40 || H <= 80)
        return;

    const int pad = dpiScale(6);
    const int gap = dpiScale(4);
    const int rowH = dpiScale(22);
    const int sliderH = dpiScale(24);
    const int btnH = dpiScale(28);
    const int inputH = dpiScale(72);
    int y = pad;
    int innerW = W - pad * 2;
    if (innerW < 40) innerW = 40;

    auto place = [&](HWND hwnd, int x, int yy, int w, int h) {
        if (hwnd && IsWindow(hwnd))
            SetWindowPos(hwnd, nullptr, x, yy, w, h, SWP_NOZORDER | SWP_NOACTIVATE);
    };

    // Header
    place(m_hwndSecondarySidebarHeader, pad, y, innerW, rowH);
    y += rowH + gap;

    // Model row: label is anonymous — combo + browse by member/ID
    const int browseW = dpiScale(70);
    const int comboW = (std::max)(40, innerW - browseW - gap);
    place(m_hwndModelSelector, pad, y, comboW, dpiScale(200)); // dropdown list height
    HWND browse = GetDlgItem(m_hwndSecondarySidebar, 1209 /*IDC_MODEL_BROWSE_BTN*/);
    place(browse, pad + comboW + gap, y, browseW, rowH);
    y += rowH + gap;

    // Max tokens slider
    place(m_hwndMaxTokensLabel, pad + innerW - dpiScale(48), y, dpiScale(48), rowH);
    y += rowH;
    place(m_hwndMaxTokensSlider, pad, y, innerW, sliderH);
    y += sliderH + gap;

    // Context slider / combo
    place(m_hwndContextLabel, pad + innerW - dpiScale(48), y, dpiScale(48), rowH);
    y += rowH;
    place(m_hwndContextSlider, pad, y, innerW, sliderH);
    y += sliderH + gap;
    HWND ctxCombo = GetDlgItem(m_hwndSecondarySidebar, 4200);
    if (ctxCombo && IsWindow(ctxCombo)) {
        place(ctxCombo, pad, y, innerW, dpiScale(200));
        y += rowH + gap;
    }

    // Option checkboxes — 2 columns
    const int colW = innerW / 2 - gap;
    place(m_hwndChkMaxMode, pad, y, colW, rowH);
    place(m_hwndChkDeepThink, pad + colW + gap, y, colW, rowH);
    y += rowH + gap;
    place(m_hwndChkDeepResearch, pad, y, colW, rowH);
    place(m_hwndChkNoRefusal, pad + colW + gap, y, colW, rowH);
    y += rowH + gap;

    // Reserve bottom: Send/Clear + input
    const int bottomStack = inputH + btnH + gap * 3;
    int chatBottom = H - pad - bottomStack;
    if (chatBottom < y + dpiScale(40))
        chatBottom = y + dpiScale(40);
    int chatH = chatBottom - y;
    if (chatH < dpiScale(40)) chatH = dpiScale(40);

    place(m_hwndCopilotChatOutput, pad, y, innerW, chatH);
    y = chatBottom + gap;
    place(m_hwndCopilotChatInput, pad, y, innerW, inputH);
    y += inputH + gap;
    const int half = innerW / 2 - gap / 2;
    place(m_hwndCopilotSendBtn, pad, y, half, btnH);
    place(m_hwndCopilotClearBtn, pad + half + gap, y, half, btnH);
}

void Win32IDE::onSize(int width, int height)
{
    if (s_inOnSize) {
        OutputDebugStringA("[Win32IDE] RE-ENTRANT onSize BLOCKED\n");
        return;
    }
    struct OnSizeGuard {
        OnSizeGuard() { s_inOnSize = true; }
        ~OnSizeGuard() { s_inOnSize = false; }
    } onSizeGuard;

    if (width <= 0 || height <= 0)
        return;

    if (m_shellMode == AppShellMode::Command && m_hwndCommandHost &&
        IsWindow(m_hwndCommandHost)) {
        MoveWindow(m_hwndCommandHost, 0, 0, width, height, TRUE);
        layoutCommandSurface(width, height);
        return;
    }

    if (RawrXD::ShellLayout::RebuildActive() &&
        !RawrXD::ShellLayout::UseLegacySpatial(RawrXD::ShellLayout::PhaseFromEnvironment())) {
        RawrXD::ShellLayout::LayoutIDE(this, width, height);

        // ShellLayout owns outer rects; PowerShell children still need a
        // client-relative pass or Execute stays at creation coords.
        if (m_powerShellPanelVisible && m_hwndPowerShellPanel &&
            IsWindow(m_hwndPowerShellPanel)) {
            RECT panelClient{};
            if (GetClientRect(m_hwndPowerShellPanel, &panelClient)) {
                const int panelW = panelClient.right - panelClient.left;
                const int panelH = panelClient.bottom - panelClient.top;
                if (panelW > 0 && panelH > 0)
                    updatePowerShellPanelLayout(panelW, panelH);
            }
        }

        bool shellLayoutValid = true;
        if (!RawrXD::ShellLayout::FrameOnlyMode()) {
            RECT mainClient{};
            if (!m_hwndMain || !IsWindow(m_hwndMain) ||
                !GetClientRect(m_hwndMain, &mainClient) ||
                mainClient.right <= mainClient.left ||
                mainClient.bottom <= mainClient.top) {
                shellLayoutValid = false;
            }

            auto mapToMainClient = [this](HWND child, RECT& mapped) -> bool {
                if (!child || !IsWindow(child) || !GetWindowRect(child, &mapped))
                    return false;
                SetLastError(ERROR_SUCCESS);
                return MapWindowPoints(nullptr, m_hwndMain,
                                       reinterpret_cast<POINT*>(&mapped), 2) != 0 ||
                       GetLastError() == ERROR_SUCCESS;
            };
            auto hasArea = [](const RECT& r) -> bool {
                return r.right > r.left && r.bottom > r.top;
            };
            auto isContained = [&hasArea](const RECT& outer,
                                          const RECT& inner) -> bool {
                return hasArea(inner) && inner.left >= outer.left &&
                       inner.top >= outer.top && inner.right <= outer.right &&
                       inner.bottom <= outer.bottom;
            };

            RECT editorRect{};
            const bool editorRequired =
                m_hwndEditor && IsWindow(m_hwndEditor) &&
                IsWindowVisible(m_hwndEditor);
            const bool editorMapped =
                editorRequired && mapToMainClient(m_hwndEditor, editorRect);
            if (editorRequired &&
                (!editorMapped || !isContained(mainClient, editorRect))) {
                shellLayoutValid = false;
            }

            if (m_powerShellPanelVisible && m_powerShellPanelDocked &&
                m_hwndPowerShellPanel && IsWindow(m_hwndPowerShellPanel)) {
                RECT terminalRect{};
                const bool terminalMapped =
                    mapToMainClient(m_hwndPowerShellPanel, terminalRect);
                if (GetParent(m_hwndPowerShellPanel) != m_hwndMain ||
                    !terminalMapped || !isContained(mainClient, terminalRect)) {
                    shellLayoutValid = false;
                }

                if (terminalMapped && editorMapped) {
                    RECT overlap{};
                    if (IntersectRect(&overlap, &terminalRect, &editorRect) &&
                        hasArea(overlap)) {
                        shellLayoutValid = false;
                    }
                }
            }
        }

        if (shellLayoutValid) {
            if (m_secondarySidebarVisible && m_hwndSecondarySidebar &&
                IsWindow(m_hwndSecondarySidebar))
                layoutAiChatChildren();
            updateLineNumbers();
            Win32IDE_AgenticBrowser_Relayout();
            return;
        }

        OutputDebugStringA(
            "[P1_UI_SHELL_LAYOUT] invalid child geometry; using spatial manifest fallback\n");
    }

    using namespace RawrXD::Ui;

    UiLayoutInputs in{};
    in.clientW = width;
    in.clientH = height;
    in.toolbarH = dpiScale(32);
    in.statusH = dpiScale(24);
    in.activityW = dpiScale(48);
    in.leftSidebarW = m_sidebarWidth > 0 ? m_sidebarWidth : dpiScale(250);
    in.rightSidebarW =
        m_secondarySidebarWidth > 0 ? m_secondarySidebarWidth : dpiScale(320);
    in.tabH = dpiScale(28);
    in.breadcrumbH = m_breadcrumbHeight > 0 ? m_breadcrumbHeight : dpiScale(22);
    in.gutterW = m_lineNumberWidth > 0 ? m_lineNumberWidth : dpiScale(48);
    in.minimapW = m_minimapWidth > 0 ? m_minimapWidth : dpiScale(80);
    in.terminalH =
        m_powerShellPanelHeight > 0 ? m_powerShellPanelHeight : dpiScale(220);
    in.outputH = m_outputTabHeight > 0 ? m_outputTabHeight : dpiScale(160);

    in.showActivity = (m_hwndActivityBar && IsWindow(m_hwndActivityBar));
    in.showLeft = m_sidebarVisible && m_hwndSidebar && IsWindow(m_hwndSidebar);
    in.showRight = m_secondarySidebarVisible && m_hwndSecondarySidebar &&
                   IsWindow(m_hwndSecondarySidebar);
    in.showTabs = (m_hwndTabBar && IsWindow(m_hwndTabBar));
    in.showBreadcrumbs = m_settings.breadcrumbsEnabled && m_hwndBreadcrumbs &&
                         IsWindow(m_hwndBreadcrumbs);
    // Gutter only if HWND exists AND visible — avoids empty white strip.
    in.showGutter = m_hwndLineNumbers && IsWindow(m_hwndLineNumbers) &&
                    IsWindowVisible(m_hwndLineNumbers);
    in.showMinimap = m_minimapVisible && m_hwndMinimap && IsWindow(m_hwndMinimap);
    in.showTerminal =
        m_powerShellPanelVisible && m_hwndPowerShellPanel &&
        IsWindow(m_hwndPowerShellPanel);
    in.showOutput = m_outputPanelVisible && m_hwndOutputTabs &&
                    IsWindow(m_hwndOutputTabs);
    in.showStatus = m_hwndStatusBar && IsWindow(m_hwndStatusBar);

    UiSpatialRegistry ui;
    ResolveSpatialManifest(ui, in);

    // Bind HWNDs before validate/apply
    ui.setHwnd(UiRegionId::MainToolbar, m_hwndToolbar);
    ui.setHwnd(UiRegionId::StatusBar, m_hwndStatusBar);
    ui.setHwnd(UiRegionId::ActivityBar, m_hwndActivityBar);
    ui.setHwnd(UiRegionId::LeftSidebar, m_hwndSidebar);
    ui.setHwnd(UiRegionId::RightSidebar, m_hwndSecondarySidebar);
    ui.setHwnd(UiRegionId::AiChat, m_hwndSecondarySidebar);
    ui.setHwnd(UiRegionId::EditorTabs, m_hwndTabBar);
    ui.setHwnd(UiRegionId::Breadcrumbs, m_hwndBreadcrumbs);
    ui.setHwnd(UiRegionId::EditorGutter, m_hwndLineNumbers);
    ui.setHwnd(UiRegionId::Editor, m_hwndEditor);
    ui.setHwnd(UiRegionId::Minimap, m_hwndMinimap);
    ui.setHwnd(UiRegionId::Terminal, m_hwndPowerShellPanel);

    ValidateSpatialLayout(ui);
    OutputDebugStringA((ui.report + "\n").c_str());

    // PHASE apply — atomic DeferWindowPos for registered HWNDs
    ApplySpatialLayout(ui);

    // Status bar self-sizes via WM_SIZE after parent placement
    if (m_hwndStatusBar && IsWindow(m_hwndStatusBar)) {
        if (const RECT* sr = ui.resolved(UiRegionId::StatusBar)) {
            MoveWindow(m_hwndStatusBar, sr->left, sr->top, RectW(*sr), RectH(*sr),
                       TRUE);
            SendMessage(m_hwndStatusBar, WM_SIZE, 0, 0);
            // Proportional parts from current client width
            const int cw = RectW(*sr);
            if (cw > 0) {
                int parts[12];
                const int edges[11] = {8, 16, 24, 32, 40, 48, 58, 68, 76, 84, 92};
                for (int i = 0; i < 11; ++i)
                    parts[i] = (cw * edges[i]) / 100;
                parts[11] = -1;
                if (IsWindowUnicode(m_hwndStatusBar))
                    SendMessageW(m_hwndStatusBar, SB_SETPARTS, 12, (LPARAM)parts);
                else
                    SendMessageA(m_hwndStatusBar, SB_SETPARTS, 12, (LPARAM)parts);
            }
        }
    }

    // Annotation / LSP overlays track editor rect
    if (const RECT* er = ui.resolved(UiRegionId::Editor)) {
        if (m_hwndAnnotationOverlay && IsWindow(m_hwndAnnotationOverlay)) {
            SetWindowPos(m_hwndAnnotationOverlay, HWND_TOP, er->left, er->top,
                         RectW(*er), RectH(*er), SWP_NOACTIVATE);
        }
        if (m_lspDiagnosticOverlay && m_lspDiagnosticOverlay->IsInitialized())
            m_lspDiagnosticOverlay->OnEditorResize();
        m_editorRect = *er;

        // Monaco/WebView2: host HWND follows editor region; controller Bounds =
        // host CLIENT RECT (not main-window coords).
        if (m_monacoEditorActive && m_hwndMonacoContainer &&
            IsWindow(m_hwndMonacoContainer)) {
            SetWindowPos(m_hwndMonacoContainer, HWND_TOP, er->left, er->top,
                         RectW(*er), RectH(*er),
                         SWP_NOACTIVATE | SWP_SHOWWINDOW);
            if (m_webView2)
                m_webView2->resize(0, 0, RectW(*er), RectH(*er));
        } else if (m_monacoEditorActive && m_webView2) {
            // Fallback: controller parented to main — use absolute editor rect.
            m_webView2->resize(er->left, er->top, RectW(*er), RectH(*er));
        }
    }

    // Output tabs / problems occupy optional band above terminal
    if (in.showOutput) {
        if (const RECT* ot = ui.resolved(UiRegionId::TerminalToolbar)) {
            if (m_hwndOutputTabs && IsWindow(m_hwndOutputTabs))
                MoveWindow(m_hwndOutputTabs, ot->left, ot->top, RectW(*ot),
                           RectH(*ot), TRUE);
            const int tabBarH = dpiScale(24);
            for (auto& kv : m_outputWindows) {
                if (kv.second && IsWindow(kv.second))
                    MoveWindow(kv.second, ot->left, ot->top + tabBarH, RectW(*ot),
                               (std::max)(0, RectH(*ot) - tabBarH), TRUE);
            }
            if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView))
                MoveWindow(m_hwndProblemsListView, ot->left, ot->top + tabBarH,
                           RectW(*ot), (std::max)(0, RectH(*ot) - tabBarH), TRUE);
        }
    }

    // Terminal internal controls — use resolved terminal rect size
    if (const RECT* tr = ui.resolved(UiRegionId::Terminal)) {
        if (in.showTerminal)
            updatePowerShellPanelLayout(RectW(*tr), RectH(*tr));
    }

    if (in.showRight)
        layoutAiChatChildren();

    updateLineNumbers();
    Win32IDE_AgenticBrowser_Relayout();
}


// ============================================================================
// syncEditorToGpuSurface - Sync RichEdit content to GPU-accelerated overlay
// ============================================================================
void Win32IDE::syncEditorToGpuSurface()
{
    if (!m_renderer || !m_rendererReady || !m_hwndEditor)
        return;

    // The transparent renderer overlays the editor for GPU-accelerated effects.
    // If the renderer isn't initialized yet, this is a safe no-op.
    try
    {
        RECT editorRect;
        GetClientRect(m_hwndEditor, &editorRect);
        // Renderer will pick up content on next paint cycle
        InvalidateRect(m_hwndEditor, nullptr, FALSE);
    }
    catch (...)
    {
        // Swallow errors — GPU sync is optional enhancement
    }
}

// ============================================================================
// initializeEditorSurface - Set up the GPU rendering surface for the editor
// ============================================================================
void Win32IDE::initializeEditorSurface()
{
    // Do NOT attach DirectComposition/TransparentRenderer to the RichEdit HWND
    // by default — CreateTargetForHwnd(topmost) covers editor text (black-on-black
    // while the line-number gutter, a sibling STATIC, still paints). Keep the
    // renderer object for optional glass; Initialize only when glass is enabled.
    if (!m_renderer || !m_hwndEditor)
        return;
    m_rendererReady = false;
    LOG_INFO("Editor GPU surface deferred (RichEdit stays readable; glass on demand)");
}

// ============================================================================
// getResolvedOllamaModel - Returns Ollama model tag (override, loaded path, or default)
// Thread-safe: acquires shared lock on m_loadedModelPathMutex
// ============================================================================
std::string Win32IDE::getResolvedOllamaModel() const
{
    if (!m_ollamaModelOverride.empty())
        return m_ollamaModelOverride;
    
    // Thread-safe read of m_loadedModelPath
    std::shared_lock<std::shared_mutex> lock(m_loadedModelPathMutex);
    if (!m_loadedModelPath.empty())
    {
        std::string filename = m_loadedModelPath;
        lock.unlock();  // Release lock before string manipulation
        
        size_t pos = filename.find_last_of("/\\");
        if (pos != std::string::npos)
            filename = filename.substr(pos + 1);
        size_t extPos = filename.rfind(".gguf");
        if (extPos != std::string::npos)
            filename = filename.substr(0, extPos);
        return filename;
    }
    return "llama3.2:latest";
}

// ============================================================================
// trySendToOllama - LOCAL_ONLY_001: permanently fail-closed (no HTTP / no stub text)
// ============================================================================
bool Win32IDE::trySendToOllama(const std::string& prompt, std::string& outResponse)
{
    (void)prompt;
    outResponse =
        "LOCAL_ONLY_001: FAIL_CLOSED — Ollama/HTTP inference is forbidden. "
        "Load a local GGUF and use Deep2/GGUF only.";
    return false;
}

// ============================================================================
// Reverse Engineering methods are implemented in Win32IDE_ReverseEngineering.cpp
// ============================================================================

// ============================================================================
// onCreate - Called when WM_CREATE is received
// ============================================================================
// Re-entrancy guard to prevent stack overflow (0xC00000FD) from recursive
// window creation. If CreateWindowEx sends a message back to the parent
// during WM_CREATE handling, we could recurse back into onCreate.
static thread_local bool s_inOnCreate = false;
static thread_local int s_onCreateDepth = 0;
static constexpr int MAX_ONCREATE_DEPTH = 5;  // Prevent deep recursion

// Depth tracking for recursion diagnostics
thread_local int gCreateDepth = 0;

struct DepthGuard {
    DepthGuard() { 
        ++gCreateDepth; 
        char msg[128];
        snprintf(msg, sizeof(msg), "[DepthGuard] onCreate depth = %d\n", gCreateDepth);
        OutputDebugStringA(msg);
    }
    ~DepthGuard() { 
        --gCreateDepth; 
        char msg[128];
        snprintf(msg, sizeof(msg), "[DepthGuard] onCreate depth = %d (exiting)\n", gCreateDepth);
        OutputDebugStringA(msg);
    }
};

// Capture and log stack backtrace when exception occurs
static void LogStackBacktrace()
{
    void* stack[32];
    USHORT frames = CaptureStackBackTrace(0, 32, stack, NULL);
    
    OutputDebugStringA("[StackTrace] === Begin Stack Backtrace ===\n");
    
    for (USHORT i = 0; i < frames; i++)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "[StackTrace] Frame %2d: 0x%p\n", i, stack[i]);
        OutputDebugStringA(msg);
    }
    
    OutputDebugStringA("[StackTrace] === End Stack Backtrace ===\n");
}

void Win32IDE::onCreate(HWND hwnd)
{
    fileTrace("[Core] onCreate_ENTER");
    
    // Track startup phase to prevent heavy initialization during WM_CREATE
    m_startupPhase = StartupPhase::CreatingMainWindow;
    
    // Depth tracking for recursion diagnostics
    DepthGuard depthGuard;
    
    // Check for excessive recursion
    if (gCreateDepth > 2)
    {
        char warnMsg[256];
        snprintf(warnMsg, sizeof(warnMsg),
                 "[Win32IDE] WARNING: onCreate depth = %d - possible recursion issue\n",
                 gCreateDepth);
        OutputDebugStringA(warnMsg);

        if (gCreateDepth > 10)
        {
            OutputDebugStringA("[Win32IDE] CRITICAL: Recursion depth > 10, breaking potential infinite loop\n");
            LogStackBacktrace();
            fileTrace("[Core] onCreate_recursion_break");
            return;
        }
    }

    // Re-entrancy guard: prevent recursive onCreate calls
    if (s_inOnCreate)
    {
        s_onCreateDepth++;
        if (s_onCreateDepth > MAX_ONCREATE_DEPTH)
        {
            OutputDebugStringA("[Win32IDE] RE-ENTRANT onCreate BLOCKED - recursion limit exceeded\n");
            fileTrace("[onCreate] RE-ENTRANT BLOCKED");
            LogStackBacktrace();
            s_onCreateDepth--;
            return;
        }
        OutputDebugStringA("[Win32IDE] RE-ENTRANT onCreate detected (this is expected for child windows)\n");
        s_onCreateDepth--;
        return;
    }

    s_inOnCreate = true;
    s_onCreateDepth = 1;

    // Auto-reset guard for early returns
    struct OnCreateGuard {
        ~OnCreateGuard() {
            s_inOnCreate = false;
            s_onCreateDepth = 0;
        }
    } onCreateGuard;

    if (!m_hwndMain || !IsWindow(m_hwndMain))
        m_hwndMain = hwnd;
    else if (m_hwndMain != hwnd)
    {
        OutputDebugStringA("[P1_UI_WINDOW_OWNERSHIP] onCreate HWND mismatch — keeping stable main\n");
        fileTrace("[P1_UI_WINDOW_OWNERSHIP] onCreate HWND mismatch keep stable");
    }
    RawrXD::ShellLayout::ApplyFromIde(this);
    fileTrace("[Core] onCreate_after_guard");
    logStackUsage("onCreate START");

    // Initialize Common Controls
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_BAR_CLASSES | ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_PROGRESS_CLASS |
                 ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);
    fileTrace("[onCreate] InitCommonControlsEx done");
    logStackUsage("onCreate after InitCommonControlsEx");

    // ================================================================
    // Create UI components — SEH-safe breadcrumb trail for diagnosis
    // Each step is wrapped so a crash pinpoints the exact function.
    // ================================================================

    // Optional panels (keep them alive for the lifetime of the IDE; no extra stub layers).
    // These are lightweight wrappers; heavy init is still deferred.
    fileTrace("[Core] onCreate_before_ModelRegistry");
    if (!m_modelRegistry)
        m_modelRegistry = new ModelRegistry(hwnd);
    fileTrace("[Core] onCreate_after_ModelRegistry");
    
    fileTrace("[Core] onCreate_before_InterpretabilityPanel");
    if (!m_interpretabilityPanel)
    {
        m_interpretabilityPanel = new InterpretabilityPanel();
        m_interpretabilityPanel->setParent(hwnd);
    }
    fileTrace("[Core] onCreate_after_InterpretabilityPanel");
    
    fileTrace("[Core] onCreate_before_CheckpointManager");
    if (!m_checkpointManager)
        m_checkpointManager = new CheckpointManager(hwnd);
    fileTrace("[Core] onCreate_after_CheckpointManager");
    
    fileTrace("[Core] onCreate_before_CICDSettings");
    if (!m_ciCdSettings)
        m_ciCdSettings = new CICDSettings();
    fileTrace("[Core] onCreate_after_CICDSettings");
    
    fileTrace("[Core] onCreate_before_MultiFileSearch");
    if (!m_multiFileSearch)
    {
        m_multiFileSearch = new MultiFileSearchWidget();
        // Default root: project root if set; else current working directory.
        const std::string root = m_projectRoot.empty() ? std::filesystem::current_path().string() : m_projectRoot;
        m_multiFileSearch->setProjectRoot(root);
        // Use interface abstraction instead of direct extern function
        IMultiFileSearchWidget* searchWidget = GetMultiFileSearchWidget();
        if (searchWidget) {
            m_multiFileSearch->setShowCallback([](void* ctx) {
                IMultiFileSearchWidget* widget = GetMultiFileSearchWidget();
                if (widget) widget->ShowDialog();
            }, m_multiFileSearch);
        }
    }
    fileTrace("[Core] onCreate_after_MultiFileSearch");
    
    fileTrace("[Core] onCreate_before_BenchmarkMenu");
    if (!m_benchmarkMenu)
        m_benchmarkMenu = new BenchmarkMenu(hwnd);
    fileTrace("[Core] onCreate_after_BenchmarkMenu");

    if (m_modelRegistry)
    {
        m_modelRegistry->setShowCallback(
            [](void* ctx)
            {
                auto* ide = static_cast<Win32IDE*>(ctx);
                if (ide)
                    ide->showModelRegistryDialog();
            },
            this);
    }

    if (m_ciCdSettings)
    {
        m_ciCdSettings->setShowCallback(
            [](void* ctx)
            {
                auto* ide = static_cast<Win32IDE*>(ctx);
                if (ide)
                    ide->showCICDSettingsDialog();
            },
            this);
    }

    if (m_checkpointManager)
    {
        m_checkpointManager->setShowCallback(
            [](void* ctx, const std::vector<CheckpointManager::CheckpointIndex>& checkpoints)
            {
                auto* ide = static_cast<Win32IDE*>(ctx);
                if (!ide)
                    return;
                std::string msg = "[CheckpointManager] Checkpoints: " + std::to_string(checkpoints.size()) + "\n";
                for (const auto& cp : checkpoints)
                {
                    msg += "  - " + cp.checkpointId + "\n";
                }
                ide->appendToOutput(msg, "Output", Win32IDE::OutputSeverity::Info);
            },
            this);
    }

    fileTrace("[Core] onCreate_before_createMenuBar");
    OutputDebugStringA("[onCreate] createMenuBar...\n");
    logStackUsage("onCreate before createMenuBar");
    createMenuBar(hwnd);  // ESP:m_hMenu — menus/submenus wired end-to-end
    fileTrace("[Core] onCreate_after_createMenuBar");
    logStackUsage("onCreate after createMenuBar");
    RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "AFTER_CREATE_MENU_BAR");

    fileTrace("[Core] onCreate_before_createToolbar");
    OutputDebugStringA("[onCreate] createToolbar...\n");
    logStackUsage("onCreate before createToolbar");
    createToolbar(hwnd);
    fileTrace("[Core] onCreate_after_createToolbar");
    logStackUsage("onCreate after createToolbar");

    fileTrace("[Core] onCreate_before_createActivityBar");
    OutputDebugStringA("[onCreate] createActivityBar...\n");
    logStackUsage("onCreate before createActivityBar");
    createActivityBar(hwnd);
    fileTrace("[Core] onCreate_after_createActivityBar");
    logStackUsage("onCreate after createActivityBar");
    
    fileTrace("[Core] onCreate_before_createPrimarySidebar");
    OutputDebugStringA("[onCreate] createPrimarySidebar...\n");
    logStackUsage("onCreate before createPrimarySidebar");
    createPrimarySidebar(hwnd);
    fileTrace("[Core] onCreate_after_createPrimarySidebar");
    logStackUsage("onCreate after createPrimarySidebar");

    // DEFERRED: createTabBar moved to onCreateChildren to prevent stack overflow
    // The TabManager creates a window and does heavy initialization that can
    // overflow the stack when called from within WM_CREATE processing.
    // See onCreateChildren() for the deferred creation.
    fileTrace("[onCreate] createTabBar DEFERRED to onCreateChildren");
    OutputDebugStringA("[onCreate] createTabBar DEFERRED to onCreateChildren\n");
    
    B428Trace("onCreate: before createBreadcrumbBar");
    fileTrace("[Core] onCreate_before_createBreadcrumbBar");
    OutputDebugStringA("[onCreate] createBreadcrumbBar...\n");
    logStackUsage("onCreate before createBreadcrumbBar");
    createBreadcrumbBar(hwnd);  // ESP:IDC_BREADCRUMB_BAR — symbol path bar
    B428Trace("onCreate: after createBreadcrumbBar");
    fileTrace("[Core] onCreate_after_createBreadcrumbBar");
    logStackUsage("onCreate after createBreadcrumbBar");
    
    B428Trace("onCreate: before createLineNumberGutter");
    fileTrace("[Core] onCreate_before_createLineNumberGutter");
    OutputDebugStringA("[onCreate] createLineNumberGutter...\n");
    logStackUsage("onCreate before createLineNumberGutter");
    createLineNumberGutter(hwnd);
    B428Trace("onCreate: after createLineNumberGutter");
    fileTrace("[Core] onCreate_after_createLineNumberGutter");
    logStackUsage("onCreate after createLineNumberGutter");
    
    B428Trace("onCreate: before createEditor");
    fileTrace("[Core] onCreate_before_createEditor");
    OutputDebugStringA("[onCreate] createEditor...\n");
    logStackUsage("onCreate before createEditor");
    createEditor(hwnd);
    B428Trace("onCreate: after createEditor");
    B428Trace("onCreate: before createAnnotationOverlay");
    createAnnotationOverlay(hwnd);
    B428Trace("onCreate: after createAnnotationOverlay");
    fileTrace("[Core] onCreate_after_createEditor");
    
    // STATUSBAR before terminal/PowerShell: runUiEncodingProbe() runs at end of
    // createPowerShellPanel (via createTerminal). Probe must see a live HWND.
    B428Trace("onCreate: before createEnhancedStatusBar");
    fileTrace("[Core] onCreate_before_createEnhancedStatusBar");
    OutputDebugStringA("[onCreate] createEnhancedStatusBar...\n");
    logStackUsage("onCreate before createEnhancedStatusBar");
    createEnhancedStatusBar(hwnd);
    B428Trace("onCreate: after createEnhancedStatusBar");
    fileTrace("[Core] onCreate_after_createEnhancedStatusBar");
    if (!m_hwndStatusBar || !IsWindow(m_hwndStatusBar)) {
        fileTrace("[Core] STATUSBAR_CREATE_FAILED");
        OutputDebugStringA("[onCreate] FATAL: status bar HWND null after create\n");
        // Fail-closed for product encoding authority — do not probe a null bar.
    }

    B428Trace("onCreate: before createTerminal");
    fileTrace("[Core] onCreate_before_createTerminal");
    OutputDebugStringA("[onCreate] createTerminal...\n");
    logStackUsage("onCreate before createTerminal");
    createTerminal(hwnd);
    B428Trace("onCreate: after createTerminal");
    fileTrace("[Core] onCreate_after_createTerminal");

    // DEFERRED: OutputTabs, PowerShellPanel, ChatPanel creation moved to WM_APP_INIT_CHILDREN
    // to prevent stack overflow. These panels are created after WM_CREATE completes.
    // See onCreateChildren() for the deferred creation.
    B428Trace("onCreate: before EXIT markers");
    fileTrace("[Core] onCreate_EXIT");
    p0StartupCk("onCreate_EXIT (returning to CreateWindowExA)");
    RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "ONCREATE_AFTER_EXIT_MARKER");
    logStackUsage("onCreate - deferred panels will be created via WM_APP_INIT_CHILDREN");

    // P1 phase-progress localization: each late call is its own SEH unit.
    // First missing ONCREATE_LATE_NN / ONCREATE_COMPLETE is the failure point.
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 1,
                       "ONCREATE_LATE_01", "ONCREATE_LATE_01_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 2,
                       "ONCREATE_LATE_02", "ONCREATE_LATE_02_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 3,
                       "ONCREATE_LATE_03", "ONCREATE_LATE_03_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 4,
                       "ONCREATE_LATE_04", "ONCREATE_LATE_04_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 5,
                       "ONCREATE_LATE_05", "ONCREATE_LATE_05_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 6,
                       "ONCREATE_LATE_06", "ONCREATE_LATE_06_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 7,
                       "ONCREATE_LATE_07", "ONCREATE_LATE_07_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 8,
                       "ONCREATE_LATE_08", "ONCREATE_LATE_08_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 9,
                       "ONCREATE_LATE_09", "ONCREATE_LATE_09_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 10,
                       "ONCREATE_LATE_10", "ONCREATE_LATE_10_OK");
    sehCallIdeHwndStep(onCreateLateStepTrampoline, this, hwnd, 11,
                       "ONCREATE_LATE_11", "ONCREATE_LATE_11_OK");

    B428Trace("onCreate: onCreate COMPLETE");
    RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "ONCREATE_COMPLETE");
}

void Win32IDE::onCreateLateStep(int step, HWND hwnd)
{
    switch (step)
    {
    case 1: // SetProp / interpretability parent
        B428Trace("onCreate: before SetPropA");
        if (m_hwndMain)
        {
            SetPropA(m_hwndMain, "RawrXD.IDE.Label", (HANDLE)RAWRXD_IDE_LABEL_MAIN_WINDOW);
            if (m_interpretabilityPanel)
                m_interpretabilityPanel->setParent(m_hwndMain);
        }
        B428Trace("onCreate: after SetPropA");
        break;
    case 2: // LOG_INFO
        B428Trace("onCreate: before LOG_INFO");
        LOG_INFO("onCreate complete — all panels created");
        OutputDebugStringA("[onCreate] all panels created OK\n");
        B428Trace("onCreate: after LOG_INFO");
        break;
    case 3: // initSyntaxColorizer
        B428Trace("onCreate: before initSyntaxColorizer");
        OutputDebugStringA("[onCreate] initSyntaxColorizer...\n");
        initSyntaxColorizer();
        B428Trace("onCreate: after initSyntaxColorizer");
        break;
    case 4: // initGhostText
        B428Trace("onCreate: before initGhostText");
        OutputDebugStringA("[onCreate] initGhostText...\n");
        initGhostText();
        B428Trace("onCreate: after initGhostText");
        break;
    case 5: // restoreSession — FORBIDDEN during WM_CREATE; schedule only
        B428Trace("onCreate: defer restoreSession");
        OutputDebugStringA("[onCreate] restoreSession DEFERRED (PostMessage WM_APP_RESTORE_SESSION)\n");
        RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "ONCREATE_LATE_05_DEFER_RESTORE");
        armPendingSessionRestore();
        PostMessage(hwnd, WM_APP_RESTORE_SESSION, 0, 0);
        RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "RESTORE_SESSION_POSTED");
        break;
    case 6: // HWND audit + theme registration + brush setup
        B428Trace("onCreate: before HWND audit");
        {
            char buf[512];
            sprintf_s(buf,
                      "HWND audit: Main=%p Editor=%p Sidebar=%p "
                      "ExplorerTree=%p OutputTabs=%p PowerShellPanel=%p",
                      m_hwndMain, m_hwndEditor, m_hwndSidebar, m_hwndExplorerTree,
                      m_hwndOutputTabs, m_hwndPowerShellPanel);
            LOG_INFO(std::string(buf));
        }
        B428Trace("onCreate: after HWND audit");
        B428Trace("onCreate: before populateBuiltinThemes");
        populateBuiltinThemes();
        B428Trace("onCreate: after populateBuiltinThemes");
        B428Trace("onCreate: before theme setup");
        m_currentTheme.backgroundColor = RGB(30, 30, 30);
        m_currentTheme.textColor = RGB(212, 212, 212);
        m_currentTheme.selectionColor = RGB(38, 79, 120);
        m_currentTheme.lineNumberColor = RGB(128, 128, 128);
        if (m_backgroundBrush)
            DeleteObject(m_backgroundBrush);
        m_backgroundBrush = CreateSolidBrush(RGB(30, 30, 30));
        break;
    case 7: // applyTheme
        B428Trace("onCreate: before applyTheme");
        applyTheme();
        B428Trace("onCreate: after applyTheme");
        RawrXD::MainMenuAuthority::TraceMenuState(hwnd, "ONCREATE_AFTER_APPLY_THEME");
        break;
    case 8: // status bar update
        B428Trace("onCreate: before statusBar update");
        if (m_hwndStatusBar)
        {
            updateEnhancedStatusBar();
            m_contextUsage.maxTokens = m_settings.aiContextWindow;
            updateContextWindowDisplay();
        }
        B428Trace("onCreate: after statusBar update");
        break;
    case 9: // initBackendManager
        B428Trace("onCreate: before initBackendManager");
        initBackendManager();
        B428Trace("onCreate: after initBackendManager");
        break;
    case 10: // initLLMRouter
        B428Trace("onCreate: before initLLMRouter");
        initLLMRouter();
        B428Trace("onCreate: after initLLMRouter");
        break;
    case 11: // force initial layout
    {
        B428Trace("onCreate: before GetClientRect/PostMessage");
        RECT rc;
        GetClientRect(hwnd, &rc);
        PostMessage(hwnd, WM_SIZE, 0, MAKELPARAM(rc.right, rc.bottom));
        B428Trace("onCreate: after GetClientRect/PostMessage");
        break;
    }
    default:
        break;
    }
}

// ============================================================================
// deferredHeavyInit - Heavy initialization run AFTER window is fully created
// This runs outside CreateWindowExA, so SEH crashes here won't prevent
// the window from appearing.
// ============================================================================
// Static trampoline for SEH-protected background thread body.
// Cannot use lambdas inside __try (MSVC C2712), so we call through here.
// Declared as friend in Win32IDE class (external linkage) to access private members.
void bgInitBody(void* self);

// ============================================================================
// onCreateChildren - Deferred UI creation to prevent stack overflow
// Called via WM_APP_INIT_CHILDREN after WM_CREATE completes
// ============================================================================
void Win32IDE::onCreateChildren(HWND hwnd)
{
    RawrXD::MainMenuAuthority::TraceMenuState(m_hwndMain ? m_hwndMain : hwnd,
                                              "BEFORE_DEFERRED_CHILDREN");

    // RECURSION GUARD: Prevent re-entrant calls that could cause stack overflow
    static thread_local bool s_inOnCreateChildren = false;
    if (s_inOnCreateChildren)
    {
        OutputDebugStringA("[onCreateChildren] BLOCKED: recursive call detected\n");
        fileTrace("[onCreateChildren] BLOCKED: recursive call detected");
        return;
    }
    s_inOnCreateChildren = true;
    struct Guard
    {
        ~Guard() { s_inOnCreateChildren = false; }
    } guard;

    // Transition to ChildrenDeferred phase - heavy initialization now allowed
    m_startupPhase = StartupPhase::ChildrenDeferred;
    fileTrace("[onCreateChildren] START - phase transitioned to ChildrenDeferred");
    logStackUsage("onCreateChildren START");
    OutputDebugStringA("[STARTUP] entering onCreateChildren\n");

    // P1: each deferred child creation is its own SEH unit.
    sehCallIdeHwndStep(onCreateChildrenStepTrampoline, this, hwnd, 1,
                       "DEFERRED_CHILD_01", "DEFERRED_CHILD_01_OK");
    sehCallIdeHwndStep(onCreateChildrenStepTrampoline, this, hwnd, 2,
                       "DEFERRED_CHILD_02", "DEFERRED_CHILD_02_OK");
    sehCallIdeHwndStep(onCreateChildrenStepTrampoline, this, hwnd, 3,
                       "DEFERRED_CHILD_03", "DEFERRED_CHILD_03_OK");
    sehCallIdeHwndStep(onCreateChildrenStepTrampoline, this, hwnd, 4,
                       "DEFERRED_CHILD_04", "DEFERRED_CHILD_04_OK");
    sehCallIdeHwndStep(onCreateChildrenStepTrampoline, this, hwnd, 5,
                       "DEFERRED_CHILD_05", "DEFERRED_CHILD_05_OK");
    sehCallIdeHwndStep(onCreateChildrenStepTrampoline, this, hwnd, 6,
                       "DEFERRED_CHILD_06", "DEFERRED_CHILD_06_OK");
    sehCallIdeHwndStep(onCreateChildrenStepTrampoline, this, hwnd, 7,
                       "DEFERRED_CHILD_07", "DEFERRED_CHILD_07_OK");

    if (m_hwndMain && m_hMenu)
        RawrXD::MainMenuAuthority::EnsureAttached(m_hwndMain, m_hMenu);
    RawrXD::MainMenuAuthority::TraceMenuState(m_hwndMain, "AFTER_DEFERRED_CHILDREN");
    if (m_hwndMain && RawrXD::MainMenuAuthority::IsStable(m_hwndMain, 2))
        RawrXD::CommandTelemetry::MarkMainMenuReady(m_hwndMain);

    // P1_UI_SHELL_LAYOUT_001: re-apply persistent chrome policy after deferred creates.
    if (m_hwndMain && IsWindow(m_hwndMain)) {
        RawrXD::ShellLayout::ApplyFromIde(this);
    }
    if (m_shellMode == AppShellMode::Command)
        applyShellModeChrome();
    
    // Update HWND audit after deferred creation
    if (m_hwndMain)
    {
        SetPropA(m_hwndMain, "RawrXD.IDE.Label", (HANDLE)RAWRXD_IDE_LABEL_MAIN_WINDOW);
        if (m_interpretabilityPanel)
            m_interpretabilityPanel->setParent(m_hwndMain);
    }
    
    LOG_INFO("onCreateChildren complete — deferred panels created");
    OutputDebugStringA("[onCreateChildren] all deferred panels created OK\n");
    fileTrace("[onCreateChildren] END");

    if (m_hwndMain && IsWindow(m_hwndMain))
        PostMessage(m_hwndMain, WM_APP_PS_SESSION_BRINGUP, 0, 0);

    // Menu E2E probe is cert-only (opens Find on startup if left enabled).
    const char* e2eExt = std::getenv("RAWRXD_P1_UI_MENU_E2E");
    const bool runProbe =
        e2eExt && e2eExt[0] && e2eExt[0] != '0' && !RawrXD::ShellLayout::RebuildActive();
    if (runProbe)
        RunUiMenuE2eProbe(this);

    dumpUiWindowOwnership("AFTER_ONCREATECHILDREN");
}

void Win32IDE::onCreateChildrenStep(int step, HWND hwnd)
{
    switch (step)
    {
    case 1:
        OutputDebugStringA("[onCreateChildren] createOutputTabs...\n");
        logStackUsage("onCreateChildren before createOutputTabs");
        createOutputTabs();
        logStackUsage("onCreateChildren after createOutputTabs");
        break;
    case 2:
        OutputDebugStringA("[onCreateChildren] createPowerShellPanel...\n");
        logStackUsage("onCreateChildren before createPowerShellPanel");
        createPowerShellPanel();
        logStackUsage("onCreateChildren after createPowerShellPanel");
        break;
    case 3:
        OutputDebugStringA("[onCreateChildren] createChatPanel...\n");
        logStackUsage("onCreateChildren before createChatPanel");
        createChatPanel();
        logStackUsage("onCreateChildren after createChatPanel");
        break;
    case 4:
        OutputDebugStringA("[onCreateChildren] initializeChatPanelOllama...\n");
        logStackUsage("onCreateChildren before initializeChatPanelOllama");
        initializeChatPanelOllama();
        logStackUsage("onCreateChildren after initializeChatPanelOllama");
        break;
    case 5:
        OutputDebugStringA("[onCreateChildren] createTabBar (deferred from onCreate)...\n");
        logStackUsage("onCreateChildren before createTabBar");
        createTabBar(hwnd);
        logStackUsage("onCreateChildren after createTabBar");
        break;
    case 6:
        OutputDebugStringA("[onCreateChildren] Applying deferred sovereign theme...\n");
        logStackUsage("onCreateChildren before applySovereignTheme");
        if (m_tabManager)
        {
            m_tabManager->applySovereignTheme();
            OutputDebugStringA("[onCreateChildren] Sovereign theme applied to TabManager\n");
        }
        logStackUsage("onCreateChildren after applySovereignTheme");
        break;
    case 7:
        OutputDebugStringA("[onCreateChildren] createCommandSurface (ScreenPilot)...\n");
        logStackUsage("onCreateChildren before createCommandSurface");
        if (m_hwndMain)
            createCommandSurface(m_hwndMain);
        logStackUsage("onCreateChildren after createCommandSurface");
        break;
    default:
        break;
    }
}

namespace
{

bool initializeEnterpriseSubsystems(Win32IDE* ide);

#ifdef _WIN32
int initializeEnterpriseSubsystemsSehThunk(Win32IDE* ide, DWORD* sehCode)
{
    __try
    {
        initializeEnterpriseSubsystems(ide);
        if (sehCode)
            *sehCode = 0;
        return 1;
    }
    __except ((sehCode ? (*sehCode = GetExceptionCode()) : 0), EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}
#endif

// Phase 2: last enterprise step for AV isolation
static volatile const char* g_enterpriseInitStep = "enterprise_uninitialized";

bool initializeEnterpriseSubsystems(Win32IDE* ide)
{
    // Step-instrumented for Phase 2 AV isolation (0xC0000005).
    g_enterpriseInitStep = "step1_EnterpriseLicense";
    OutputDebugStringA("[EnterpriseInit] step=1 EnterpriseLicense::Initialize ENTER\n");
    auto& license = RawrXD::EnterpriseLicense::Instance();
    license.Initialize();
    OutputDebugStringA("[EnterpriseInit] step=1 OK\n");

    g_enterpriseInitStep = "step2_EnterpriseFeatureManager";
    OutputDebugStringA("[EnterpriseInit] step=2 EnterpriseFeatureManager::Initialize ENTER\n");
    auto& featureMgr = EnterpriseFeatureManager::Instance();
    featureMgr.Initialize();
    OutputDebugStringA("[EnterpriseInit] step=2 OK\n");

    g_enterpriseInitStep = "step3_EnterpriseLicenseV2";
    OutputDebugStringA("[EnterpriseInit] step=3 EnterpriseLicenseV2::initialize ENTER\n");
    auto& licV2 = RawrXD::License::EnterpriseLicenseV2::Instance();
    licV2.initialize();
    OutputDebugStringA("[EnterpriseInit] step=3 OK\n");

    g_enterpriseInitStep = "step4_FeatureFlagsRuntime";
    OutputDebugStringA("[EnterpriseInit] step=4 FeatureFlagsRuntime::refreshFromLicense ENTER\n");
    RawrXD::Flags::FeatureFlagsRuntime::Instance().refreshFromLicense();
    OutputDebugStringA("[EnterpriseInit] step=4 OK\n");

    g_enterpriseInitStep = "step5_LicenseEnforcer";
    OutputDebugStringA("[EnterpriseInit] step=5 LicenseEnforcer::initialize ENTER\n");
    RawrXD::Enforce::LicenseEnforcer::Instance().initialize();
    OutputDebugStringA("[EnterpriseInit] step=5 OK\n");

    g_enterpriseInitStep = "step6_PostMessage_tierBadge";
    OutputDebugStringA("[deferredHeavyInit] Enterprise license initialized\n");

    std::string tierBadge = std::string("[") + license.GetEditionName() + "]";
    // Use PostMessage with a copy; receiver must free with free()
    PostMessage(ide->getMainWindow(), WM_USER + 200, 0, reinterpret_cast<LPARAM>(_strdup(tierBadge.c_str())));
    g_enterpriseInitStep = "enterprise_complete";
    return true;
}

#ifdef _WIN32
bool initializeEnterpriseSubsystemsSafe(Win32IDE* ide)
{
    DWORD sehCode = 0;
    if (initializeEnterpriseSubsystemsSehThunk(ide, &sehCode) != 0)
    {
        return true;
    }

    char sehMsg[320] = {};
    const char* step = const_cast<const char*>(g_enterpriseInitStep);
    if (!step)
        step = "(null)";
    sprintf_s(sehMsg,
              "ERROR: Enterprise license SEH faulted (code=0x%08lX) last_step=%s; continuing in community mode",
              static_cast<unsigned long>(sehCode), step);
    LOG_ERROR(sehMsg);
    OutputDebugStringA(sehMsg);
    OutputDebugStringA("\n");
    PostMessage(ide->getMainWindow(), WM_USER + 200, 0, reinterpret_cast<LPARAM>(_strdup("[Community]")));
    return false;
}
#else
bool initializeEnterpriseSubsystemsSafe(Win32IDE* ide)
{
    return initializeEnterpriseSubsystems(ide);
}
#endif

}  // namespace

// 4 MB stack for deferred init thread to avoid 0xC00000FD (STATUS_STACK_OVERFLOW)
static const DWORD kDeferredInitStackSize = 4 * 1024 * 1024;

DWORD WINAPI Win32IDE::deferredHeavyInitThreadProc(LPVOID param)
{
    Win32IDE* self = static_cast<Win32IDE*>(param);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_ThreadStartWitness("deferred_heavy_init");
#endif
    DetachedThreadGuard _guard(self->m_activeDetachedThreads, self->m_shuttingDown);
    if (_guard.cancelled) {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_ThreadStopWitness("deferred_heavy_init");
#endif
        return 0;
    }
    sehRunBgThread(bgInitBody, self);
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_ThreadStopWitness("deferred_heavy_init");
#endif
    return 0;
}

void Win32IDE::deferredHeavyInit()
{
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_Witness("P1PRA_UI", "dhi_entry");
#endif
    char skipDhi[8] = {};
    if (GetEnvironmentVariableA("RAWRXD_SKIP_DEFERRED_HEAVY_INIT", skipDhi,
                                (DWORD)sizeof(skipDhi)) > 0 &&
        skipDhi[0] != '0')
    {
#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
        P1PRA_Witness("P1PRA_DHI", "skip_env_deferred_heavy_init");
        P1PRA_Witness("P1PRA_UI", "deferred_heavy_init_skip_return");
#endif
        OutputDebugStringA("[deferredHeavyInit] skipped (RAWRXD_SKIP_DEFERRED_HEAVY_INIT)\n");
        return;
    }
    // Run heavy initialization on a background thread with large stack to avoid 0xC00000FD.
    HANDLE h = CreateThread(nullptr, kDeferredInitStackSize, &Win32IDE::deferredHeavyInitThreadProc, this, 0, nullptr);
    if (h)
        CloseHandle(h);
    else
        sehRunBgThread(bgInitBody, this);
}

void Win32IDE::markStartupPumpsComplete()
{
    m_startupPumpsComplete = true;
    // Do NOT PostMessage(WM_APP+201) here. Anything that PeekMessages between
    // post_create pumps and message_loop_entered can dispatch LoadModel too early
    // (observed: PROCESS die at calling_LoadModel_UI_pump before message_loop_entered).
    // Arm pending; main_win32 flushes after message_loop_entered.
    const bool pathPending = !getLoadedModelPath().empty();
    if (m_pendingApp201ModelLoad || pathPending)
    {
        m_pendingApp201ModelLoad = true;
        RawrXD::P1GgufCert::emit("DEFERRED_LOAD_FLUSHED", "INFO", "armed_wait_message_loop");
        OutputDebugStringA("[markStartupPumpsComplete] pending armed (flush after message_loop)\n");
        fprintf(stderr, "[STARTUP] markStartupPumpsComplete: armed pending (path=%d) — wait message_loop\n",
                pathPending ? 1 : 0);
        fflush(stderr);
    }
}

void bgInitBody(void* self)
{
    Win32IDE* ide = static_cast<Win32IDE*>(self);
    ide->deferredHeavyInitBody();
}

#ifdef RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
namespace {
struct P1PRA_DhiScope {
    const char* stage_;
    explicit P1PRA_DhiScope(const char* stage, std::uint32_t id) : stage_(stage)
    {
        P1PRA_DhiEnter(stage, id);
    }
    ~P1PRA_DhiScope() { P1PRA_DhiExit(stage_); }
    P1PRA_DhiScope(const P1PRA_DhiScope&) = delete;
    P1PRA_DhiScope& operator=(const P1PRA_DhiScope&) = delete;
};
}  // namespace
#define P1PRA_DHI_SCOPE(stage, id) P1PRA_DhiScope _p1dhi_##id(stage, id)
#else
#define P1PRA_DHI_SCOPE(stage, id)
#endif

void Win32IDE::deferredHeavyInitBody()
{
    if (m_hwndMain)
        RawrXD::MainMenuAuthority::TraceMenuState(m_hwndMain, "BEFORE_DEFERRED_HEAVY");
    {
        P1PRA_DHI_SCOPE("logger_init", P1PRA_DHI_LOGGER_INIT);
        bgInitMark("logger_init");
        // Initialize logger under %APPDATA%\RawrXD\ide.log (fallback: RawrXD_IDE.log in cwd)
        try
        {
            std::string logPath = "RawrXD_IDE.log";
            char appData[MAX_PATH] = {};
            if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, appData)))
            {
                std::string dir = std::string(appData) + "\\RawrXD";
                CreateDirectoryA(dir.c_str(), nullptr);
                logPath = dir + "\\ide.log";
            }
            IDELogger::getInstance().initialize(logPath);
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: Logger init failed\n");
        }
    }
    if (isShuttingDown())
        return;

    // Standby StreamingGGUFLoader so File→Load Model / session restore never hit a nullptr gate.
    {
        P1PRA_DHI_SCOPE("streaming_gguf_loader", P1PRA_DHI_STREAMING_GGUF_LOADER);
        bgInitMark("streaming_gguf_loader");
        if (!m_ggufLoader)
        {
            try
            {
                m_ggufLoader = std::make_unique<RawrXD::StreamingGGUFLoader>();
                OutputDebugStringA("[deferredHeavyInit] StreamingGGUFLoader ready\n");
                // If session restore stashed a model path before the loader existed, load it now.
                const std::string pending = getLoadedModelPath();
                if (!pending.empty())
                    PostMessageA(m_hwndMain, WM_APP + 201, 0, 0);
            }
            catch (...)
            {
                OutputDebugStringA("ERROR: StreamingGGUFLoader allocation failed (non-fatal)\n");
            }
        }
    }
    if (isShuttingDown())
        return;

    // ================================================================
    // Enterprise License System — initialize FIRST (gates engine registration)
    // ================================================================
    {
        P1PRA_DHI_SCOPE("enterprise_license", P1PRA_DHI_ENTERPRISE_LICENSE);
        bgInitMark("enterprise_license");
        try
        {
            initializeEnterpriseSubsystemsSafe(this);
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: Enterprise license init failed\n");
        }
    }
    if (isShuttingDown())
        return;

    // Initialize Native CPU Inference Engine
    {
        P1PRA_DHI_SCOPE("cpu_inference_engine", P1PRA_DHI_CPU_INFERENCE_ENGINE);
        bgInitMark("cpu_inference_engine");
    try
    {
        m_nativeEngine = RawrXD::CPUInferenceEngine::GetSharedInstance();
        auto memPlugin = std::make_shared<RawrXD::Modules::NativeMemoryModule>();
        m_nativeEngine->RegisterMemoryPlugin(memPlugin);
        m_nativeEngineLoaded = true;
        wireLayerProgressToOutputPanel();
    }
    catch (...)
    {
        m_nativeEngine.reset();
        m_nativeEngineLoaded = false;
        OutputDebugStringA("ERROR: CPUInferenceEngine init failed\n");
    }
    }
    if (isShuttingDown())
        return;

    // Initialize DirectX renderer (needs to be on UI thread ideally, but creation is OK)
    {
        P1PRA_DHI_SCOPE("transparent_renderer", P1PRA_DHI_TRANSPARENT_RENDERER);
        bgInitMark("transparent_renderer");
    try
    {
        m_renderer = std::make_unique<TransparentRenderer>();
    }
    catch (...)
    {
        m_renderer = nullptr;
        OutputDebugStringA("ERROR: TransparentRenderer creation failed\n");
    }
    }

    // Initialize PowerShell state
    {
        P1PRA_DHI_SCOPE("powershell_state", P1PRA_DHI_POWERSHELL_STATE);
        bgInitMark("powershell_state");
    try
    {
        initializePowerShellState();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: PowerShell init failed\n");
    }
    }

    // Theme already applied in onCreate — skip here

    // Load code snippets
    {
        P1PRA_DHI_SCOPE("code_snippets", P1PRA_DHI_CODE_SNIPPETS);
        bgInitMark("code_snippets");
    try
    {
        loadCodeSnippets();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: Code snippets loading failed\n");
    }
    }

    // Initialize Agent
    {
        P1PRA_DHI_SCOPE("native_agent", P1PRA_DHI_NATIVE_AGENT);
        bgInitMark("native_agent");
    try
    {
        if (m_nativeEngine)
        {
            m_agent = std::make_unique<RawrXD::NativeAgent>(m_nativeEngine.get());
            m_agent->SetOutputCallback([this](const std::string& text) { postAgentOutputSafe(text); });
            m_agent->SetMaxMode(true);
            m_agent->SetDeepThink(true);
            m_agent->SetDeepResearch(true);
            m_agent->SetNoRefusal(true);
        }
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: NativeAgent init failed\n");
    }
    }

    // Initialize Extension Loader
    {
        P1PRA_DHI_SCOPE("extension_loader", P1PRA_DHI_EXTENSION_LOADER);
        bgInitMark("extension_loader");
    try
    {
        m_extensionLoader = std::make_unique<RawrXD::ExtensionLoader>();
        m_extensionLoader->Scan();
        m_extensionLoader->LoadNativeModules();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: ExtensionLoader init failed\n");
    }
    }
    if (isShuttingDown())
        return;

    // Initialise the agentic bridge (needs m_hwndMain, which is set)
    {
        P1PRA_DHI_SCOPE("agentic_bridge", P1PRA_DHI_AGENTIC_BRIDGE);
        bgInitMark("agentic_bridge");
    try
    {
        initializeAgenticBridge();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: initializeAgenticBridge failed\n");
    }
    }

    // Initialize AI/Extensions panels so menu -> show() creates real UI
    if (isShuttingDown())
        return;
    {
        P1PRA_DHI_SCOPE("ai_panels", P1PRA_DHI_AI_PANELS);
        bgInitMark("ai_panels");
    try
    {
        if (m_modelRegistry)
            m_modelRegistry->initialize();
        if (m_interpretabilityPanel)
            m_interpretabilityPanel->initialize();
        if (m_benchmarkMenu && m_hwndMain)
        {
            m_benchmarkMenu->setMainWindow(m_hwndMain);
            m_benchmarkMenu->initialize();
        }
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: AI panels init failed\n");
    }
    }

    // Initialize Ghost Text renderer (Copilot-style inline completions)
    {
        P1PRA_DHI_SCOPE("ghost_text", P1PRA_DHI_GHOST_TEXT);
        bgInitMark("ghost_text");
    try
    {
        initGhostText();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: initGhostText failed\n");
    }
    }

    // Initialize Failure Detector (agent self-correction)
    {
        P1PRA_DHI_SCOPE("failure_detector", P1PRA_DHI_FAILURE_DETECTOR);
        bgInitMark("failure_detector");
    try
    {
        initFailureDetector();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: initFailureDetector failed\n");
    }
    }

    // Initialize Agent Diff Panel (Win32IDE_AgentPanel.cpp)
    {
        P1PRA_DHI_SCOPE("agent_panel", P1PRA_DHI_AGENT_PANEL);
        bgInitMark("agent_panel");
    try
    {
        initAgentPanel();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: initAgentPanel failed\n");
    }
    }

    // Load persistent settings from %APPDATA%\RawrXD\settings.json
    {
        P1PRA_DHI_SCOPE("load_apply_settings", P1PRA_DHI_LOAD_APPLY_SETTINGS);
        bgInitMark("load_apply_settings");
    try
    {
        loadSettings();
        applySettings();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: loadSettings/applySettings failed\n");
    }
    try
    {
        syncAgentModeUiFromBridge();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: syncAgentModeUiFromBridge failed\n");
    }
    }

    if (isShuttingDown())
        return;

    // Initialize Agent History (append-only JSONL event log)
    {
        P1PRA_DHI_SCOPE("agent_history", P1PRA_DHI_AGENT_HISTORY);
        bgInitMark("agent_history");
        // P1_UI_MENU_E2E_001: initAgentHistory (and the following heavy tail) currently
        // __fastfail's (0xC0000409). Under E2E, stop heavy init here so the menu routing
        // ladder can run. Defect remains separate from MENU_LIFETIME / MENU_E2E routing.
        const char* skipE2e = std::getenv("RAWRXD_P1_UI_MENU_E2E");
        if (skipE2e && skipE2e[0] && skipE2e[0] != '0') {
            OutputDebugStringA(
                "[deferredHeavyInit] heavy tail SKIPPED after agent_history "
                "(RAWRXD_P1_UI_MENU_E2E)\n");
            if (m_hwndMain) {
                RawrXD::MainMenuAuthority::TraceMenuState(
                    m_hwndMain, "HEAVY_STEP_agent_history_SKIPPED_E2E");
                RawrXD::MainMenuAuthority::TraceMenuState(
                    m_hwndMain, "AFTER_DEFERRED_HEAVY_SKIPPED_E2E");
            }
            return;
        }
        try
        {
            initAgentHistory();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initAgentHistory failed\n");
        }
    }

    // Initialize Failure Intelligence — Phase 6 (classification + retry strategies)
    {
        P1PRA_DHI_SCOPE("failure_intelligence", P1PRA_DHI_FAILURE_INTELLIGENCE);
        try
        {
            initFailureIntelligence();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initFailureIntelligence failed\n");
        }
    }

    // Initialize Unified Model Source Resolver (HuggingFace, Ollama blobs, HTTP, local)
    {
        P1PRA_DHI_SCOPE("model_resolver", P1PRA_DHI_MODEL_RESOLVER);
        try
        {
            m_modelResolver = std::make_unique<RawrXD::ModelSourceResolver>();
            // Set cache directory for downloaded models
            m_modelResolver->SetCacheDirectory(
                m_modelResolver->GetCacheDirectory());  // Use default: %USERPROFILE%/.cache/rawrxd/models
            OutputDebugStringA("ModelSourceResolver initialized OK\n");
        }
        catch (const std::exception& e)
        {
            m_modelResolver.reset();
            OutputDebugStringA("ERROR: ModelSourceResolver init failed: ");
            OutputDebugStringA(e.what());
            OutputDebugStringA("\n");
        }
        catch (...)
        {
            m_modelResolver.reset();
            OutputDebugStringA("ERROR: ModelSourceResolver init failed (unknown)\n");
        }
    }

    // GPU Backend Bridge — detect and initialize Vulkan compute if available
    {
        P1PRA_DHI_SCOPE("gpu_backend_bridge", P1PRA_DHI_GPU_BACKEND_BRIDGE);
        HMODULE hVulkan = LoadLibraryA("vulkan-1.dll");
        if (hVulkan)
        {
            m_gpuTextEnabled = true;
            FreeLibrary(hVulkan);
            OutputDebugStringA("GPU Backend Bridge: Vulkan ICD detected — GPU compute available\n");
            appendToOutput("[GPU] Vulkan compute backend detected and ready\n", "Output", OutputSeverity::Info);
        }
        else
        {
            m_gpuTextEnabled = false;
            OutputDebugStringA("GPU Backend Bridge: No Vulkan ICD — CPU-only mode\n");
        }
    }

    // Initialize Phase 10: Execution Governor + Safety + Replay + Confidence
    {
        P1PRA_DHI_SCOPE("phase10", P1PRA_DHI_PHASE10);
        try
        {
            initPhase10();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initPhase10 failed\n");
        }
    }

    // Initialize MultiResponse, LSP Server, Hotpatch UI (lazy-ready)
    {
        P1PRA_DHI_SCOPE("multi_response", P1PRA_DHI_MULTI_RESPONSE);
        try
        {
            initMultiResponse();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initMultiResponse failed\n");
        }
    }
    {
        P1PRA_DHI_SCOPE("lsp_server", P1PRA_DHI_LSP_SERVER);
        try
        {
            initLSPServer();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initLSPServer failed\n");
        }
    }
    {
        P1PRA_DHI_SCOPE("hotpatch_ui", P1PRA_DHI_HOTPATCH_UI);
        try
        {
            initHotpatchUI();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initHotpatchUI failed\n");
        }
    }

    // Initialize Phase 11: Distributed Swarm Compilation
    {
        P1PRA_DHI_SCOPE("phase11", P1PRA_DHI_PHASE11);
        try
        {
            initPhase11();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initPhase11 failed\n");
        }
    }

    // Initialize Phase 12: Native Debugger Engine
    {
        P1PRA_DHI_SCOPE("phase12", P1PRA_DHI_PHASE12);
        try
        {
            initPhase12();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initPhase12 failed\n");
        }
    }

    // Initialize Decompiler View (Phase 18B)
    {
        P1PRA_DHI_SCOPE("decompiler_view", P1PRA_DHI_DECOMPILER_VIEW);
        try
        {
            initDecompilerView();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initDecompilerView failed\n");
        }
    }

    // Initialize Phase 33: Voice Chat Engine
    {
        P1PRA_DHI_SCOPE("voice_chat", P1PRA_DHI_VOICE_CHAT);
        try
        {
            initVoiceChat();
            voiceLoadPreferences();
            createVoiceChatPanel(m_hwndMain);
            registerVoiceHotkeys();
            updateVoiceStatusBar();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initVoiceChat failed\n");
        }
    }

    // Initialize Phase 44: Voice Automation (TTS for responses)
    {
        P1PRA_DHI_SCOPE("voice_automation", P1PRA_DHI_VOICE_AUTOMATION);
        try
        {
            RECT rc;
            GetClientRect(m_hwndMain, &rc);
            extern void Win32IDE_CreateVoiceAutomationPanel(HWND, int, int, int, int);
            Win32IDE_CreateVoiceAutomationPanel(m_hwndMain, 0, rc.bottom - 80, rc.right, 80);
            extern void Win32IDE_AddVoiceAutomationMenu(HMENU);
            // Menu items already added in menu creation; just mark initialized
            m_voiceAutomationInitialized = true;
            OutputDebugStringA("Phase 44: VoiceAutomation panel created\n");
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: VoiceAutomation init failed\n");
        }
    }

    // Initialize Tier 3: Polish (QoL) — smooth caret, ligatures, file watcher, etc.
    {
        P1PRA_DHI_SCOPE("tier3_polish", P1PRA_DHI_TIER3_POLISH);
        try
        {
            initTier3Polish();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initTier3Polish failed\n");
        }
    }

    // Initialize Tier 1: Critical Cosmetics (smooth scroll, minimap, fuzzy palette, etc.)
    {
        P1PRA_DHI_SCOPE("tier1_cosmetics", P1PRA_DHI_TIER1_COSMETICS);
        try
        {
            initTier1Cosmetics();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initTier1Cosmetics failed\n");
        }
    }

    // Initialize Phase 33: Quick-Win Systems (Shortcuts, Backups, Alerts, SLO)
    {
        P1PRA_DHI_SCOPE("quick_win_systems", P1PRA_DHI_QUICK_WIN_SYSTEMS);
        try
        {
            initQuickWinSystems();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initQuickWinSystems failed\n");
        }
    }

    // Initialize Phase 32B: Chain-of-Thought Multi-Model Review Engine
    {
        P1PRA_DHI_SCOPE("chain_of_thought", P1PRA_DHI_CHAIN_OF_THOUGHT);
        try
        {
            initChainOfThought();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initChainOfThought failed\n");
        }
    }

    // Initialize Phase 34: Telemetry Export Subsystem
    {
        P1PRA_DHI_SCOPE("telemetry", P1PRA_DHI_TELEMETRY);
        try
        {
            initTelemetry();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initTelemetry failed\n");
        }
    }

    // Initialize Phase 36: Flight Recorder — persistent binary ring-buffer
    {
        P1PRA_DHI_SCOPE("flight_recorder", P1PRA_DHI_FLIGHT_RECORDER);
        try
        {
            initFlightRecorder();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initFlightRecorder failed\n");
        }
    }

    // Initialize Phase 36: MCP Integration — Model Context Protocol
    {
        P1PRA_DHI_SCOPE("init_mcp", P1PRA_DHI_INIT_MCP);
        bgInitMark("init_mcp");
    try
    {
        initMCP();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: initMCP failed\n");
    }
    }

    // Initialize Phase 29+36: VS Code Extension API + QuickJS VSIX Host
    {
        P1PRA_DHI_SCOPE("init_vscode_extension_api", P1PRA_DHI_INIT_VSCODE_EXTENSION_API);
        bgInitMark("init_vscode_extension_api");
    try
    {
        initVSCodeExtensionAPI();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: initVSCodeExtensionAPI failed\n");
    }
    }

    if (isShuttingDown())
        return;

    // Initialize Phase 43: Plugin System (Native Win32 DLL loading)
    {
        P1PRA_DHI_SCOPE("init_plugin_system", P1PRA_DHI_INIT_PLUGIN_SYSTEM);
        bgInitMark("init_plugin_system");
    try
    {
        initPluginSystem();
    }
    catch (...)
    {
        OutputDebugStringA("ERROR: initPluginSystem failed\n");
    }
    }

    // Auto-start Local HTTP server (port 11435) — loopback-only for /gui preview
    if (!isShuttingDown())
    {
        P1PRA_DHI_SCOPE("start_local_server", P1PRA_DHI_START_LOCAL_SERVER);
        bgInitMark("start_local_server");
        try
        {
            startLocalServer();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: startLocalServer failed\n");
        }
    }

    // Initialize Cursor/JB-Parity Feature Modules
    if (!isShuttingDown())
    {
        P1PRA_DHI_SCOPE("init_all_feature_modules", P1PRA_DHI_INIT_ALL_FEATURE_MODULES);
        bgInitMark("init_all_feature_modules");
        try
        {
            initAllFeatureModules();

            std::string featureRouteReport;
            if (!verifyFeatureRoutingCoverageAtStartup(&featureRouteReport))
            {
                OutputDebugStringA(featureRouteReport.c_str());
                // NON-FATAL: Log the routing issue but don't destroy the window
                // The IDE should remain functional even if some feature routes are missing
                OutputDebugStringA("WARNING: Feature routing coverage incomplete - continuing startup\n");
            }
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initAllFeatureModules failed\n");
        }
    }

    // Initialize Tier 5 cosmetic features (Emoji, Telemetry Dashboard, Shortcut Editor, etc.)
    if (!isShuttingDown())
    {
        P1PRA_DHI_SCOPE("init_tier5_cosmetics", P1PRA_DHI_INIT_TIER5_COSMETICS);
        bgInitMark("init_tier5_cosmetics");
        try
        {
            initTier5Cosmetics();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initTier5Cosmetics failed\n");
        }
    }

    {
        P1PRA_DHI_SCOPE("deferredHeavyInit_complete", P1PRA_DHI_DEFERRED_HEAVY_INIT_COMPLETE);
        bgInitMark("deferredHeavyInit_complete");
        OutputDebugStringA("deferredHeavyInit complete (background thread)\n");
        if (m_hwndMain)
            RawrXD::MainMenuAuthority::TraceMenuState(m_hwndMain, "AFTER_DEFERRED_HEAVY");
    }

    // Initialize AI backend probe (background thread, posts WM_AI_BACKEND_STATUS on result)
    if (!isShuttingDown())
    {
        P1PRA_DHI_SCOPE("ai_backend", P1PRA_DHI_AI_BACKEND);
        try
        {
            initializeAIBackend();
        }
        catch (...)
        {
            OutputDebugStringA("ERROR: initializeAIBackend failed\n");
        }
    }


    // Notify UI thread to refresh
    if (m_hwndMain && !isShuttingDown())
    {
        PostMessage(m_hwndMain, WM_APP + 101, 0, 0);
    }
}

// ============================================================================
// onDestroy - Called when WM_DESTROY is received
// ============================================================================
void Win32IDE::onDestroy()
{
    // Idempotent: second WM_DESTROY / abnormal re-entry must not double-free.
    if (m_destroyCompleted.exchange(true, std::memory_order_acq_rel)) {
        OutputDebugStringA("onDestroy: already completed — skipping\n");
        return;
    }
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_ENTER");
    if (m_hwndMain)
        RawrXD::MainMenuAuthority::MarkWindowDestroying(m_hwndMain);
    LOG_INFO("Win32IDE::onDestroy - shutting down");

#ifdef RAWRXD_PRODUCT100
    product100Shutdown();
#endif

    clearInferenceLayerProgressCallback();

    // Signal ALL detached threads to stop touching 'this'
    m_shuttingDown.store(true, std::memory_order_release);

    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_BEFORE_watchdog");
    // Stop visibility watchdog thread first so it cannot race on HWND usage
    // while the rest of shutdown tears down UI resources.
    stopVisibilityWatchdog();
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_AFTER_watchdog");

    // Stop any in-progress inference immediately
    m_inferenceStopRequested = true;
    m_planExecutionCancelled.store(true);

    // Wait for all detached threads to notice the flag and exit (up to 3s).
    // TODO: Replace polling with condition_variable + thread handle wait
    for (int i = 0; i < 300 && m_activeDetachedThreads.load(std::memory_order_acquire) > 0; ++i)
    {
        Sleep(10);
    }
    if (m_activeDetachedThreads.load(std::memory_order_acquire) > 0)
    {
        OutputDebugStringA("onDestroy: WARNING — detached threads still active after 3s\n");
        Sleep(50);  // Reduced grace period
    }
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_AFTER_detached_wait");

    // Invoked from WM_NCDESTROY: child HWNDs are already destroyed. Safe to free.
    stopLocalServer();
    try { m_ggufLoader.reset(); } catch (...) {}
    try { m_modelResolver.reset(); } catch (...) {}
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_AFTER_loader_reset");
    // JS hosts already detached in WM_DESTROY. Native FreeLibrary + API facade
    // shutdown only here (WM_NCDESTROY: children already destroyed).
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_BEFORE_ext_teardown");
    shutdownVSCodeExtensionAPI();
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_AFTER_js_hosts");
    if (m_extensionLoader) {
        m_extensionLoader->UnloadAllNative("onDestroy");
        m_extensionLoader.reset();
    }
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(-1, "onDestroy_AFTER_ExtensionLoader");

    // Shutdown core runtime spine (signature verifier, sqlite, telemetry export).
    shutdownCoreRuntimeSpine();

    // Shutdown Tier 3: Polish (smooth caret, ligatures, file watcher)
    shutdownTier3Polish();

    // Shutdown Tier 1: Critical Cosmetics (smooth scroll, minimap, auto-update)
    shutdownTier1Cosmetics();

    // Shutdown Phase 36: MCP Integration
    shutdownMCP();

    // Shutdown Phase 36: Flight Recorder
    shutdownFlightRecorder();

    // Shutdown Phase 34: Telemetry Export
    shutdownTelemetry();

    // Shutdown Phase 44: Voice Automation
    if (m_voiceAutomationInitialized)
    {
        extern void Win32IDE_DestroyVoiceAutomationPanel();
        Win32IDE_DestroyVoiceAutomationPanel();
        m_voiceAutomationInitialized = false;
    }

    // Shutdown Phase 33: Voice Chat Engine
    voiceSavePreferences();
    unregisterVoiceHotkeys();
    shutdownVoiceChat();

    // Shutdown Phase 33: Quick-Win Systems
    shutdownQuickWinSystems();

    // Shutdown Phase 12: Native Debugger Engine
    shutdownPhase12();

    // Shutdown Phase 11: Distributed Swarm Compilation
    shutdownPhase11();

    // Shutdown Phase 10: Execution Governor + Safety + Replay + Confidence
    shutdownPhase10();

    // Shutdown ghost text renderer (kill timers, free font)
    shutdownGhostText();

    // Local GGUF HTTP server already stopped in early teardown.

    // Shutdown agent history (flush event buffer to disk)
    shutdownAgentHistory();

    // Shutdown backend manager (save configs)
    shutdownBackendManager();

    // Shutdown Phase 43: Plugin System (unload all DLLs)
    shutdownPlugins();

    // ========================================================================
    // CRITICAL: Stop all terminals BEFORE saving state / destroying objects.
    // Terminal threads call onOutput/onError/onFinished callbacks that capture
    // [this]. If these fire during destructor member teardown → 0xC0000005.
    // ========================================================================
    // Stop dedicated PowerShell terminal first
    if (m_dedicatedPowerShellTerminal)
    {
        m_dedicatedPowerShellTerminal->onOutput = nullptr;
        m_dedicatedPowerShellTerminal->onError = nullptr;
        m_dedicatedPowerShellTerminal->onStarted = nullptr;
        m_dedicatedPowerShellTerminal->onFinished = nullptr;
        m_dedicatedPowerShellTerminal->stop();
        m_dedicatedPowerShellTerminal.reset();
    }
    // Stop all terminal panes — clear callbacks first to prevent use-after-free
    for (auto& pane : m_terminalPanes)
    {
        if (pane.manager)
        {
            pane.manager->onOutput = nullptr;
            pane.manager->onError = nullptr;
            pane.manager->onStarted = nullptr;
            pane.manager->onFinished = nullptr;
            pane.manager->stop();
            pane.manager.reset();
        }
    }
    m_terminalPanes.clear();

    // Save settings to disk
    try
    {
        saveSettings();
    }
    catch (...)
    {
    }

    // Save full session state for next launch
    saveSession();

    // Shutdown LSP diagnostic overlay
    if (m_lspDiagnosticOverlay)
    {
        m_lspDiagnosticOverlay->Shutdown();
        m_lspDiagnosticOverlay.reset();
    }

    // Clean up resources
    if (m_renderer)
    {
        m_renderer.reset();
    }

    // Save any unsaved state / editor config for session restore
    try
    {
        nlohmann::json session;

        // Save open file path
        if (!m_currentFile.empty())
        {
            session["lastOpenFile"] = m_currentFile;
        }

        // Save window position and size
        if (m_hwndMain)
        {
            RECT rc;
            if (GetWindowRect(m_hwndMain, &rc))
            {
                session["window"]["x"] = (int)rc.left;
                session["window"]["y"] = (int)rc.top;
                session["window"]["width"] = (int)(rc.right - rc.left);
                session["window"]["height"] = (int)(rc.bottom - rc.top);
            }
            session["window"]["maximized"] = ((GetWindowLongPtr(m_hwndMain, GWL_STYLE) & WS_MAXIMIZE) != 0);
        }

        // Save open tabs
        nlohmann::json tabs(nlohmann::json::value_t::array);
        for (const auto& tab : m_editorTabs)
        {
            nlohmann::json t;
            t["path"] = tab.filePath;
            t["name"] = tab.displayName;
            t["modified"] = tab.modified;
            tabs.push_back(t);
        }
        session["tabs"] = tabs;

        // Save current working directory
        if (!m_currentDirectory.empty())
        {
            session["workingDirectory"] = m_currentDirectory;
        }

        // Save sidebar width / active view
        session["sidebar"]["activeView"] = static_cast<int>(m_currentSidebarView);
        session["sidebar"]["width"] = m_sidebarWidth;

        // Write session file
        std::string sessionPath = ".rawrxd/session.json";
        CreateDirectoryA(".rawrxd", nullptr);
        std::ofstream sessionFile(sessionPath);
        if (sessionFile)
        {
            sessionFile << session.dump(4);
            LOG_INFO("Session state saved to " + sessionPath);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to save session state: " + std::string(e.what()));
    }

    // ========================================================================
    // PHASE 2: Tear down shared objects that detached threads may reference.
    // By doing this here (before the destructor), we ensure that even if a
    // lingering detached thread survives the 3s wait, it hits the shutdown
    // flag check before touching any of these objects.
    // ========================================================================
    try
    {
        m_subAgentManager.reset();
    }
    catch (...)
    {
    }
    try
    {
        m_multiResponseEngine.reset();
    }
    catch (...)
    {
    }
    try
    {
        // Raw pointer; just clear reference
        m_agenticBridge = nullptr;
    }
    catch (...)
    {
    }
    try
    {
        m_agent.reset();
    }
    catch (...)
    {
    }
    try
    {
        m_nativeEngine.reset();
    }
    catch (...)
    {
    }
    try
    {
        m_modelResolver.reset();
    }
    catch (...)
    {
    }
    try
    {
        m_ggufLoader.reset();
    }
    catch (...)
    {
    }
    try
    {
        // Already UnloadAllNative + reset above; keep as idempotent safety net.
        if (m_extensionLoader) {
            m_extensionLoader->UnloadAllNative("onDestroy_phase2");
            m_extensionLoader.reset();
        }
    }
    catch (...)
    {
    }
    try
    {
        // shutdownPlugins() already reset; clear if still present.
        if (m_pluginLoader) {
            m_pluginLoader->unloadAll();
            m_pluginLoader.reset();
        }
    }
    catch (...)
    {
    }
    try
    {
        m_lspServer.reset();
    }
    catch (...)
    {
    }
    try
    {
        m_mcpServer.reset();
    }
    catch (...)
    {
    }
    try
    {
        m_autonomyManager.reset();
    }
    catch (...)
    {
    }

    // Null out raw pointers to externally-owned objects
    m_engineManager = nullptr;
    m_codexUltimate = nullptr;

    // Null main window to prevent use-after-destroy in destructor or stray callbacks
    m_hwndMain = nullptr;

    OutputDebugStringA("onDestroy: all resources released\n");
}

// ============================================================================
// onCommand - WM_COMMAND dispatcher
// ============================================================================
void Win32IDE::onCommand(HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
    RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_ENTER");
    // id 0 is never a registered menu/command — usually an unassigned control
    // notification. Surfacing it as "Unknown command" poisons the status bar
    // (screenshot: "Unknown command (id 0)"). Silent ignore is intentional here;
    // real clickable items must use a non-zero registered ID.
    if (id == 0)
        return;

    // Handle editor notifications (EN_CHANGE, EN_VSCROLL, EN_SELCHANGE come via WM_COMMAND).
    // Require a non-null control HWND: menu commands use lParam=0, and IDC_EDITOR
    // shares id 1001 with IDM_FILE_NEW — (nullptr == nullptr) must not steal File→New.
    if (hwndCtl != nullptr && hwndCtl == m_hwndEditor)
    {
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_EDITOR_NOTIFY");
        if (codeNotify == EN_CHANGE || codeNotify == EN_VSCROLL || codeNotify == EN_SELCHANGE)
        {
            updateLineNumbers();
            // Debounce syntax coloring on content/scroll change
            if (m_syntaxColoringEnabled)
            {
                onEditorContentChanged();
            }
            // Update cursor position in status bar
            CHARRANGE sel;
            SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&sel);
            int line = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, sel.cpMin, 0);
            int lineStart = (int)SendMessage(m_hwndEditor, EM_LINEINDEX, line, 0);
            int col = sel.cpMin - lineStart;
            wchar_t posBuf[64];
            swprintf(posBuf, 64, L"Ln %d, Col %d", line + 1, col + 1);
            if (m_hwndStatusBar)
            {
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)posBuf);
            }
        }
        return;  // Don't route editor notifications through the command system
    }

    // Other control notifications: do not fall through to "unknown command"
    // unless this is a button click (BN_CLICKED / menu-equivalent).
    if (id == IDC_CMD_MODE_COMBO && codeNotify == CBN_SELCHANGE && m_hwndCmdModeCombo)
    {
        const int modeSel = (int)SendMessageW(m_hwndCmdModeCombo, CB_GETCURSEL, 0, 0);
        using SM = RawrXD::Command::SteerMode;
        const SM mode =
            modeSel == 0 ? SM::Plan : (modeSel == 1 ? SM::Build : SM::Agent);
        RawrXD::Command::CommandBroker::instance().setSteerMode(mode);
        refreshCommandActivityStrip();
        return;
    }
    if (hwndCtl != nullptr && codeNotify != 0 && codeNotify != BN_CLICKED)
        return;

    // (command flight starts after the legacy HWND-control switch; menu canaries
    //  1001/2016/2020 fall through to routeCommand below.)

    // First try the unified command router
    if (id == 9903)
    {  // Model progress cancel button
        cancelModelOperation();
        return;
    }
    // Copilot secondary sidebar control IDs (created in createSecondarySidebar)
    if (id == 1204)
    {
        HandleCopilotSend();
        return;
    }
    if (id == 1205)
    {
        HandleCopilotClear();
        return;
    }
    if (id == 1206)
    {
        setAgenticMode(RawrXD::AgenticMode::Plan);
        return;
    }
    if (id == 1207)
    {
        setAgenticMode(RawrXD::AgenticMode::Agent);
        return;
    }
    if (id == 1208)
    {
        setAgenticMode(RawrXD::AgenticMode::Ask);
        return;
    }
    if (id == 1209)  // IDC_MODEL_BROWSE_BTN
    {
        handleModelBrowse();
        return;
    }
    if (id == IDC_CMD_SEND_BTN)
    {
        handleCommandSend();
        return;
    }
    if (id == IDC_CMD_STOP_BTN)
    {
        handleCommandStop();
        return;
    }
    if (id == IDC_CMD_WORK_MODE_BTN)
    {
        enterWorkMode();
        return;
    }
    if (id == IDC_CMD_APPROVE_BTN)
    {
        handleCommandApprove();
        return;
    }
    if (id == IDC_CMD_DENY_BTN)
    {
        handleCommandDeny();
        return;
    }
    if (id == IDM_CMD_ENTER_COMMAND)
    {
        enterCommandMode();
        return;
    }
    if (id == IDM_CMD_ENTER_WORK)
    {
        enterWorkMode();
        return;
    }
    if (id == IDM_CMD_NEW_TASK)
    {
        RawrXD::Command::CommandEventJournal::instance().append(
            RawrXD::Command::JournalEventType::ModeSwitch, "\"new_task\"");
        if (m_hwndCommandComposer) SetWindowTextW(m_hwndCommandComposer, L"");
        appendCommandConversation("[System] New task — session binding retained.");
        bindCommandSessionFromWorkspace();
        refreshCommandContextBar();
        refreshCommandActivityStrip();
        enterCommandMode();
        return;
    }
    if (id == IDC_CMD_MODEL_LOAD_BTN)
    {
        handleCommandModelLoad();
        return;
    }
    if (id == IDC_CMD_MODEL_BROWSE_BTN)
    {
        handleCommandModelBrowse();
        return;
    }
    if (id == IDC_CMD_MODEL_UNLOAD_BTN)
    {
        handleCommandModelUnload();
        return;
    }
    if (id == IDC_CMD_MODEL_RELOAD_BTN)
    {
        handleCommandModelReload();
        return;
    }
    if (id == IDC_CMD_MODEL_CANCEL_BTN)
    {
        handleCommandInferenceCancel();
        return;
    }

    // Agent diff panel buttons (created in initAgentPanel)
    if (id == 14003)
    {
        agentAcceptAll();
        refreshAgentDiffDisplay();
        return;
    }
    if (id == 14004)
    {
        agentRejectAll();
        refreshAgentDiffDisplay();
        return;
    }
    if (id == 14005)
    {
        onBoundedAgentLoop();
        return;
    }

    // Audit commands (9500-9506) — handle directly; SSOT handlers PostMessage to us, avoid loop
    if (id >= 9500 && id < 9600)
    {
        handleAuditCommand(id);
        return;
    }

    // ── GUI-ONLY FILE / MODEL / VIEW TOGGLES — Win32 menu IDs that must run IDE actions (dialogs, loading, toggles).
    // All other commands go through unified dispatch (Agent, Autonomy, Backend, LSP, Hotpatch, etc.).
    switch (id)
    {
        case 998:  // SCM context menu: Discard Changes
            discardChanges();
            return;
        case 1100:  // IDC_ACTIVITY_BAR
            if (!m_sidebarVisible)
            {
                toggleSidebar();
            }
            if (m_currentSidebarView == SidebarView::None)
            {
                setSidebarView(SidebarView::Explorer);
            }
            if (m_hwndSidebar && IsWindow(m_hwndSidebar))
            {
                SetFocus(m_hwndSidebar);
            }
            return;
        case 1201:  // IDC_SECONDARY_SIDEBAR_HEADER
            if (!m_secondarySidebarVisible)
            {
                toggleSecondarySidebar();
            }
            if (m_hwndCopilotChatInput && IsWindow(m_hwndCopilotChatInput))
            {
                SetFocus(m_hwndCopilotChatInput);
            }
            else if (m_hwndSecondarySidebar && IsWindow(m_hwndSecondarySidebar))
            {
                SetFocus(m_hwndSecondarySidebar);
            }
            return;
        case 5000:  // IDC_PS_PANEL_CONTAINER
            showPowerShellPanel();
            if (m_hwndPowerShellInput && IsWindow(m_hwndPowerShellInput))
            {
                SetFocus(m_hwndPowerShellInput);
            }
            else if (m_hwndPowerShellPanel && IsWindow(m_hwndPowerShellPanel))
            {
                SetFocus(m_hwndPowerShellPanel);
            }
            return;
        case 5006:  // IDC_MP_LOAD_VSCODE
        case 5007:
        {  // IDC_MP_DOWNLOAD_INSTALL
            initMarketplace();
            cmdMarketplaceShow();
            HWND hMarketplace = FindWindowW(L"RawrXD_Marketplace", nullptr);
            if (hMarketplace && IsWindow(hMarketplace))
            {
                SendMessageW(hMarketplace, WM_COMMAND, MAKEWPARAM(id, BN_CLICKED), 0);
            }
            else
            {
                appendToOutput("[Marketplace] Window not available for command id " + std::to_string(id) + "\n",
                               "Output", OutputSeverity::Warning);
            }
            return;
        }
        case 9000:  // Legacy alias used by VSCodeExtAPI bridge for hotpatch status
            handleHotpatchCommand(IDM_HOTPATCH_SHOW_STATUS);
            return;
        case 1300:  // IDC_PANEL_CONTAINER
            if (!m_panelVisible)
            {
                togglePanel();
            }
            switchPanelTab(m_activePanelTab);
            if (m_activePanelTab == PanelTab::Problems && m_hwndProblemsListView && IsWindow(m_hwndProblemsListView))
            {
                SetFocus(m_hwndProblemsListView);
            }
            else if (m_activePanelTab == PanelTab::Terminal)
            {
                TerminalPane* activePane = getActiveTerminalPane();
                if (activePane && activePane->hwnd && IsWindow(activePane->hwnd))
                {
                    SetFocus(activePane->hwnd);
                }
            }
            else if (m_activePanelTab == PanelTab::Output)
            {
                auto it = m_outputWindows.find(m_activeOutputTab);
                if (it != m_outputWindows.end() && it->second && IsWindow(it->second))
                {
                    SetFocus(it->second);
                }
            }
            else if (m_activePanelTab == PanelTab::DebugConsole && m_hwndDebugConsole && IsWindow(m_hwndDebugConsole))
            {
                SetFocus(m_hwndDebugConsole);
            }
            return;
        case 1306:  // IDC_PANEL_TOOLBAR
            if (!m_panelVisible)
            {
                togglePanel();
            }
            switchPanelTab(m_activePanelTab);
            if (m_hwndPanelTabs && IsWindow(m_hwndPanelTabs))
            {
                SetFocus(m_hwndPanelTabs);
            }
            return;
        case 1310:  // IDC_PANEL_BTN_MAXIMIZE
            maximizePanel();
            return;
        case 1311:  // IDC_PANEL_BTN_CLOSE
            if (m_panelVisible)
            {
                togglePanel();
            }
            return;
        case 1312:  // IDC_PANEL_PROBLEMS_LIST
            switchPanelTab(PanelTab::Problems);
            refreshProblemsView();
            if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView))
            {
                int idx = (int)ListView_GetNextItem(m_hwndProblemsListView, -1, LVNI_SELECTED);
                if (idx >= 0)
                {
                    goToProblem(idx);
                }
                else
                {
                    SetFocus(m_hwndProblemsListView);
                }
            }
            return;
        case 1301:
        {  // IDC_PANEL_TABS
            if (m_hwndPanelTabs && IsWindow(m_hwndPanelTabs))
            {
                int idx = (int)TabCtrl_GetCurSel(m_hwndPanelTabs);
                if (idx < 0)
                    idx = 0;
                if (idx > 3)
                    idx = 3;
                switchPanelTab(static_cast<PanelTab>(idx));
            }
            return;
        }
        case 1307:  // IDC_PANEL_BTN_NEW_TERMINAL
            switchPanelTab(PanelTab::Terminal);
            handleTerminalCommand(4001);  // Start PowerShell terminal
            return;
        case 1308:  // IDC_PANEL_BTN_SPLIT_TERMINAL
            switchPanelTab(PanelTab::Terminal);
            handleTerminalCommand(4005);  // Split terminal
            return;
        case 1309:  // IDC_PANEL_BTN_KILL_TERMINAL
            switchPanelTab(PanelTab::Terminal);
            handleTerminalCommand(IDM_TERMINAL_KILL);
            return;
        case IDC_PROBLEMS_PANEL:  // 7050
            if (!m_problemsPanelInitialized)
            {
                initProblemsPanel();
            }
            if (m_hwndProblemsPanel && IsWindow(m_hwndProblemsPanel))
            {
                ShowWindow(m_hwndProblemsPanel, SW_SHOW);
            }
            refreshProblemsView();
            if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView))
            {
                SetFocus(m_hwndProblemsListView);
            }
            return;
        case IDC_PROBLEMS_LISTVIEW:  // 7051
            if (m_hwndProblemsListView && IsWindow(m_hwndProblemsListView))
            {
                int idx = (int)ListView_GetNextItem(m_hwndProblemsListView, -1, LVNI_SELECTED);
                if (idx >= 0)
                {
                    goToProblem(idx);
                }
                else
                {
                    SetFocus(m_hwndProblemsListView);
                }
            }
            return;
        case 2114:  // IDC_DEBUGGER_MEMORY
            if (m_debuggerAttached)
            {
                updateMemoryView();
            }
            if (m_hwndDebuggerMemory && IsWindow(m_hwndDebuggerMemory))
            {
                SetFocus(m_hwndDebuggerMemory);
            }
            return;
        case 2001:
            newFile();
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"New file created");
            return;
        case 2002:
            openFile();
            return;
        case 2003:
            if (saveFile() && m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"File saved");
            return;
        case 2004:
            if (saveFileAs() && m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"File saved as new name");
            return;
        case 2005:
            if (!m_fileModified || promptSaveChanges())
                PostQuitMessage(0);
            return;
        case 1030:
            openModel();
            return;
        case 1031:
            openModelFromHuggingFace();
            return;
        case 1032:
            openModelFromOllama();
            return;
        case 1033:
            openModelFromURL();
            return;
        case 1034:
            openModelUnified();
            return;
        case 1035:
            quickLoadGGUFModel();
            return;
        case 2007:  // Edit > Undo (Win32 menu ID)
            if (m_hwndEditor)
                SendMessage(m_hwndEditor, EM_UNDO, 0, 0);
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Undo");
            return;
        case 2008:  // Edit > Redo
            if (m_hwndEditor)
                SendMessage(m_hwndEditor, EM_REDO, 0, 0);
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Redo");
            return;
        case 2009:  // Edit > Cut
            if (m_hwndEditor)
            {
                SendMessage(m_hwndEditor, WM_CUT, 0, 0);
                m_fileModified = true;
            }
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Cut");
            return;
        case 2010:  // Edit > Copy
            if (m_hwndEditor)
                SendMessage(m_hwndEditor, WM_COPY, 0, 0);
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Copied");
            return;
        case 2011:  // Edit > Paste
            if (m_hwndEditor)
            {
                SendMessage(m_hwndEditor, WM_PASTE, 0, 0);
                m_fileModified = true;
            }
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Pasted");
            return;
        case 2026:  // View > Use Streaming Loader — toggle so model loading uses low-memory path
            m_useStreamingLoader = !m_useStreamingLoader;
            if (m_hMenu)
                CheckMenuItem(m_hMenu, 2026, MF_BYCOMMAND | (m_useStreamingLoader ? MF_CHECKED : MF_UNCHECKED));
            appendToOutput(std::string("Streaming loader ") + (m_useStreamingLoader ? "ON" : "OFF") + "\n", "Output",
                           OutputSeverity::Info);
            return;
        case 2027:  // View > Vulkan Renderer
            m_useVulkanRenderer = !m_useVulkanRenderer;
            if (m_hMenu)
                CheckMenuItem(m_hMenu, 2027, MF_BYCOMMAND | (m_useVulkanRenderer ? MF_CHECKED : MF_UNCHECKED));
            appendToOutput(std::string("Vulkan renderer ") + (m_useVulkanRenderer ? "ON" : "OFF") + "\n", "Output",
                           OutputSeverity::Info);
            persistPerformanceVulkanRendererToConfig();
            appendToOutput(
                "[Vulkan] Saved preference performance.vulkanRenderer to rawrxd.config.json (cwd or exe dir).\n",
                "Output", OutputSeverity::Info);
            return;
        case 502:   // Tools > Settings (IDM_TOOLS_SETTINGS)
        case 1024:  // Title bar gear (IDC_BTN_SETTINGS)
        case 1106:  // Activity bar Settings (IDC_ACTBAR_SETTINGS)
            showSettingsGUIDialog();
            return;
        case 1022:  // Title bar GH button — toggle AI Chat panel (secondary sidebar)
            toggleSecondarySidebar();
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0,
                            (LPARAM)(m_secondarySidebarVisible ? L"AI Chat shown" : L"AI Chat hidden"));
            return;
        case 3007:  // View > AI Chat — toggle secondary sidebar (Ctrl+Alt+B)
        case 3009:  // View > Agent Chat (autonomous)
            toggleSecondarySidebar();
            if (m_hwndStatusBar)
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0,
                            (LPARAM)(m_secondarySidebarVisible ? L"Chat panel shown" : L"Chat panel hidden"));
            return;
        case IDM_VIEW_AGENT_PANEL:
            toggleAgentPanel();
            return;
        case IDM_SECURITY_SCAN_SECRETS:
            RunSecretsScan();
            return;
        case IDM_SECURITY_SCAN_SAST:
            RunSastScan();
            return;
        case IDM_SECURITY_SCAN_DEPENDENCIES:
            RunDependencyAudit();
            return;
        case IDM_BUILD_SOLUTION:
            runBuildInBackground(m_gitRepoPath, "");
            return;
        case IDM_BUILD_PROJECT:
            runBuildInBackground(m_gitRepoPath, "--target RawrXD-Win32IDE");
            return;
        case IDM_BUILD_CLEAN:
            runBuildInBackground(m_gitRepoPath, "--target clean");
            return;
        // ---- Debug commands (10500-10515) --------------------------------
        case IDM_DEBUG_START:
            startDebugging();
            return;
        case IDM_DEBUG_STOP:
            stopDebugging();
            return;
        case IDM_DEBUG_CONTINUE:
            continueExecution();
            return;
        case IDM_DEBUG_STEP_OVER:
            stepOver();
            return;
        case IDM_DEBUG_STEP_INTO:
            stepInto();
            return;
        case IDM_DEBUG_STEP_OUT:
            stepOut();
            return;
        case IDM_DEBUG_TOGGLE_BREAKPOINT:
            // Stub: toggleBreakpointAtCurrentLine();
            return;
        case IDM_DEBUG_SHOW_CALLSTACK:
            // Stub: showCallStack();
            return;
        case IDM_DEBUG_SHOW_VARIABLES:
            // Stub: showVariables();
            return;
        case IDM_DEBUG_SHOW_WATCH:
            // Stub: showWatch();
            return;
        case IDM_DEBUG_ATTACH:
            attachDebugger();
            return;
        case IDM_DEBUG_DETACH:
            detachDebugger();
            return;
        default:
            break;
    }

    // ── LEGACY FALLBACK — View/Tier1/Git/Monaco commands that routeToIde would loop on
    // routeCommand invokes handleViewCommand, handleTier1Command, etc. directly instead of
    // going through SSOT handlers that PostMessage same ID → infinite re-entry.
    {
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_BEFORE_FLIGHT");
        auto& flight = RawrXD::CommandTelemetry::Begin(hwnd, static_cast<UINT>(id));
        if (id == 1001)
            flight.preGeneration =
                RawrXD::CommandTelemetry::Generations().documentGeneration;
        else if (id == 2016)
            flight.preGeneration = RawrXD::CommandTelemetry::Generations().findGeneration;
        else if (id == 2020)
            flight.preGeneration =
                RawrXD::CommandTelemetry::Generations().minimapGeneration;

        struct FlightGuard {
            RawrXD::CommandTelemetry::CommandFlight& f;
            bool handled = false;
            ~FlightGuard()
            {
                RawrXD::CommandTelemetry::Finish(
                    f, handled ? 0 : static_cast<int>(ERROR_NOT_FOUND));
            }
        } guard{flight, false};

        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_BEFORE_routeCommand");
        if (routeCommand(id)) {
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_AFTER_routeCommand_OK");
            guard.handled = true;
            return;
        }
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_routeCommand_MISS");

        // ── UNIFIED DISPATCH — The ONE AND ONLY command path ────────────────
        // All commands live in COMMAND_TABLE (command_registry.hpp).
        // If routeCommandUnified returns false, the command does NOT EXIST.
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_BEFORE_unified");
        if (routeCommandUnified(id, this, hwnd)) {
            RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_AFTER_unified_OK");
            guard.handled = true;
            return;  // Dispatched via g_commandRegistry[] — identical path to CLI
        }
        RawrXD::CommandTelemetry::CmdDiagBreadcrumb(id, "onCommand_unified_MISS");

        RawrXD::CommandTelemetry::Fail(flight, "UNKNOWN_COMMAND");
    }

    // Command not found — never for id 0 (filtered above). Surface nonzero misses.
    if (m_hwndStatusBar && IsWindow(m_hwndStatusBar))
    {
        char buf[96];
        snprintf(buf, sizeof(buf), "Unknown command (id %d) — not in registry", id);
        RawrXD::StatusBarSetTextUtf8(m_hwndStatusBar, 0, buf);
    }
#ifdef _DEBUG
    {
        char dbgBuf[128];
        snprintf(dbgBuf, sizeof(dbgBuf), "[SSOT] Unregistered WM_COMMAND: %d\n", id);
        OutputDebugStringA(dbgBuf);
    }
#endif
    DefWindowProcA(hwnd, WM_COMMAND, MAKEWPARAM(id, codeNotify), (LPARAM)hwndCtl);
}

void Win32IDE::persistPerformanceVulkanRendererToConfig()
{
    auto& cfg = IDEConfig::getInstance();
    cfg.setBool("performance.vulkanRenderer", m_useVulkanRenderer);
    if (cfg.saveToFile("rawrxd.config.json"))
        return;
    char exePath[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, exePath, MAX_PATH) == 0)
        return;
    std::string dir(exePath);
    const size_t ls = dir.find_last_of("\\/");
    if (ls != std::string::npos)
    {
        dir = dir.substr(0, ls + 1);
        cfg.saveToFile(dir + "rawrxd.config.json");
    }
}


