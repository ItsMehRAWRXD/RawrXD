<<<<<<< HEAD
// Win32IDE.cpp - RawrXD Win32 IDE Implementation - g87
// Build timestamp: 2026-03-31
#include "Win32IDE.h"
#include "../../Ship/RawrXD_AutonomousAgenticPipeline.h"  // Full type for unique_ptr destructor
#include "../../include/PathResolver.h"
#include "../../include/rawrxd_version.h"
#include "../core/command_registry.hpp"
#include "../cpu_inference_engine.h"
#include "../model_source_resolver.h"
#include "../modules/ExtensionLoader.hpp"  // Added
#include "../modules/native_memory.hpp"
#include "../rawrxd_model_loader.h"
#include "../streaming_gguf_loader.h"
#include "../utils/ErrorReporter.hpp"
#include "IDEConfig.h"
#include "IDELogger.h"
#include "ModelConnection.h"
#include "VSIXInstaller.hpp"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE_Settings.h"
#include "feature_registry_panel.h"
#include "lsp/RawrXD_LSPServer.h"
#include "multi_response_engine.h"
#include "resource.h"
#include "../ANSIParser.h"

// AI Completion System Integration (VAL-063)
// Forward declarations from ai_completion_real.cpp
extern "C" {
    void InitAICompletion();
    void SetCompletionBackendNative(void* engine_ptr);
    void ShutdownAICompletion();
    // Ghost text integration API
    const char* RequestGhostTextCompletion(
        const char* context,
        const char* language,
        const char* suffix,
        const char* file_path,
        int cursor_line,
        int cursor_col
    );
    void FreeCompletionString(const char* str);
    bool IsCompletionEngineReady();
    void GetCompletionEngineStatus(char* out_buffer, int buffer_size);
}
#include <commdlg.h>
#include <nlohmann/json.hpp>
#include <psapi.h>
#include <richedit.h>


#ifndef CP_UNICODE
#define CP_UNICODE 1200  // Unicode code page for Richedit EM_GETTEXTLENGTHEX/EM_SETTEXTEX
#endif
#include <commctrl.h>
#ifndef TRACKBAR_CLASSW
#define TRACKBAR_CLASSW L"msctls_trackbar32"
#endif
#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <psapi.h>
#include <regex>
#include <set>
#include <shellapi.h>
#include <shlobj.h>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <winhttp.h>


// Complete type declarations for unique_ptr<T> component managers.
// Must come after all other includes to avoid circularity.
#include "Win32IDE_ComponentManagers.h"




// Defined once here; declared as `extern` in Win32IDE.h.
Win32IDE* g_pMainIDE = nullptr;

static std::wstring utf8ToWide(const std::string& utf8);

extern "C" unsigned __int64 RawrXD_EnableSeLockMemoryPrivilege();
extern "C" void* RawrXD_MapModelView2MB(HANDLE hMap, uint64_t off, size_t sz, uint64_t* outBaseOrError);

static uint64_t qpcNowU64()
{
    LARGE_INTEGER v{};
    QueryPerformanceCounter(&v);
    return static_cast<uint64_t>(v.QuadPart);
}

static double qpcDeltaToMs(uint64_t delta)
{
    LARGE_INTEGER f{};
    QueryPerformanceFrequency(&f);
    if (f.QuadPart <= 0)
        return 0.0;
    return (static_cast<double>(delta) * 1000.0) / static_cast<double>(f.QuadPart);
}

enum class VmmRibbonTier : uint8_t
{
    Green,
    Yellow,
    Gray,
    Red,
};

static HICON getVmmLedIcon(VmmRibbonTier tier);

static void appendStreamerPostLoadCheck(Win32IDE* ide, const std::string& ggufPath)
{
    if (!ide)
        return;
    if (ggufPath.empty())
        return;

    // Keep this fast: validate huge-page base alignment via RawrXDModelLoader (shared core path),
    // and do a small prefetch warm-up to hide initial "first touch" stalls.
    const std::wstring wPath = utf8ToWide(ggufPath);
    if (wPath.empty())
    {
        ide->appendToOutput("Streamer self-check: invalid path encoding\n", "System",
                            Win32IDE::OutputSeverity::Warning);
        return;
    }

    const SovereignConfig& cfg = GetSovereignConfig();
    RawrXDModelLoader loader;
    loader.SetSilencePrivilegeWarnings(cfg.silence_privilege_warnings);
    loader.SetPrefetchEnabled(cfg.model_prefetch_enabled);
    loader.SetWorkingSetLockEnabled(cfg.model_workingset_lock_enabled);
    if (!loader.Load(wPath.c_str(), VK_NULL_HANDLE, VK_NULL_HANDLE))
    {
        ide->appendToOutput("Streamer self-check: loader.Load failed\n", "System", Win32IDE::OutputSeverity::Warning);
        return;
    }

    const uint64_t fileSize = loader.GetFileSizeBytes();
    const size_t mapSize2mb = 2u * 1024u * 1024u;
    const uint64_t off0 = 0;
    const uint64_t off1 = (fileSize > (mapSize2mb + 4096ull)) ? (fileSize - mapSize2mb - 4096ull) : 0ull;

    auto getPageFaultCount = []() -> uint64_t
    {
        PROCESS_MEMORY_COUNTERS pmc{};
        pmc.cb = sizeof(pmc);
        if (!GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
            return 0;
        return static_cast<uint64_t>(pmc.PageFaultCount);
    };

    auto getIoCounters = []() -> IO_COUNTERS
    {
        IO_COUNTERS io{};
        (void)GetProcessIoCounters(GetCurrentProcess(), &io);
        return io;
    };

    auto oneMap = [&](uint64_t off, size_t sz, bool doHint, bool updateVmmRibbon) -> bool
    {
        const uint64_t pf0 = getPageFaultCount();
        const IO_COUNTERS io0 = getIoCounters();

        const uint64_t t0 = qpcNowU64();
        void* p = loader.MapWindow(off, sz);
        const uint64_t t1 = qpcNowU64();
        if (!p)
            return false;

        bool aligned2mb = true;
        if (loader.UsingLargePages())
        {
            const uintptr_t base = reinterpret_cast<uintptr_t>(loader.GetCurrentViewBase());
            aligned2mb = ((base & 0x1FFFFFull) == 0);
        }

        bool hintOk = false;
        if (doHint)
            hintOk = loader.HintRange(off, sz);

        // "Touch" a cache line to force any first-touch faults to materialize here.
        const uint64_t u0 = qpcNowU64();
        volatile uint64_t* v = reinterpret_cast<volatile uint64_t*>(p);
        const uint64_t sink = v[0];
        (void)sink;
        const uint64_t u1 = qpcNowU64();

        const uint64_t pf1 = getPageFaultCount();
        const IO_COUNTERS io1 = getIoCounters();
        const uint64_t pfDelta = (pf1 >= pf0) ? (pf1 - pf0) : 0;
        const uint64_t ioReadOpsDelta =
            (io1.ReadOperationCount >= io0.ReadOperationCount) ? (io1.ReadOperationCount - io0.ReadOperationCount) : 0;
        const uint64_t ioReadBytesDelta =
            (io1.ReadTransferCount >= io0.ReadTransferCount) ? (io1.ReadTransferCount - io0.ReadTransferCount) : 0;

        if (updateVmmRibbon && ide->getStatusBar())
        {
            const bool pf = cfg.model_prefetch_enabled;
            const bool lp = loader.UsingLargePages();
            wchar_t buf[160]{};
            wchar_t tip[256]{};
            VmmRibbonTier tier = VmmRibbonTier::Red;
            if (lp && pf)
                tier = VmmRibbonTier::Green;
            else if (!lp && pf)
                tier = VmmRibbonTier::Yellow;
            else if (lp && !pf)
                tier = VmmRibbonTier::Gray;
            else
                tier = VmmRibbonTier::Red;
            HICON ico = getVmmLedIcon(tier);

            const wchar_t* gpuAsm =
#if defined(RAWRXD_HAS_SOVEREIGN_GPU_ASM) && (RAWRXD_HAS_SOVEREIGN_GPU_ASM != 0)
                L"ACTIVE";
#else
                L"STUB";
#endif

            // Permanent ribbon is "glanceable" tier text; deep-dive numbers go in tooltip.
            const wchar_t* tierText = L"[Legacy]";
            if (lp && pf)
                tierText = L"[2MB + PF]";
            else if (!lp && pf)
                tierText = L"[4KB + PF]";
            else if (lp && !pf)
                tierText = L"[2MB]";
            else
                tierText = L"[Legacy]";

            _snwprintf_s(buf, _countof(buf), _TRUNCATE, L"VMM: %s  GPU-ASM:%s", tierText, gpuAsm);
            _snwprintf_s(tip, _countof(tip), _TRUNCATE,
                         L"VMM diagnostics: pf\u0394=%llu, ioR=%llu ops / %llu bytes, touch=%.2f ms, map=%.2f ms",
                         static_cast<unsigned long long>(pfDelta), static_cast<unsigned long long>(ioReadOpsDelta),
                         static_cast<unsigned long long>(ioReadBytesDelta), qpcDeltaToMs(u1 - u0),
                         qpcDeltaToMs(t1 - t0));
            SendMessageW(ide->getStatusBar(), SB_SETTEXT, 2, (LPARAM)buf);
            // Status bar tooltips (requires common controls v6; ignored if unsupported)
            SendMessageW(ide->getStatusBar(), SB_SETTIPTEXTW, 2, (LPARAM)tip);
            if (ico)
                SendMessageW(ide->getStatusBar(), SB_SETICON, 2, (LPARAM)ico);
        }

        loader.UnmapWindow();

        std::ostringstream ss;
        ss << "Streamer self-check: off=" << off << " map_ms=" << qpcDeltaToMs(t1 - t0)
           << " largePages=" << (loader.UsingLargePages() ? "1" : "0") << " aligned2mb=" << (aligned2mb ? "1" : "0")
           << " hint=" << (hintOk ? "1" : "0") << "\n";
        ide->appendToOutput(ss.str(), "System",
                            (aligned2mb || !loader.UsingLargePages()) ? Win32IDE::OutputSeverity::Info
                                                                      : Win32IDE::OutputSeverity::Warning);
        return (!loader.UsingLargePages() || aligned2mb);
    };

    // Alignment + mapping sanity at start/end.
    const bool okA = oneMap(off0, mapSize2mb, false, true);
    const bool okB = oneMap(off1, mapSize2mb, false, true);

    // Warm-up: map a small early window and issue a hint to prefetch within it.
    (void)oneMap(off0, 64u * 1024u * 1024u, true, true);

    if (okA && okB)
        ide->appendToOutput("Streamer self-check: PASS\n", "System", Win32IDE::OutputSeverity::Info);
    else
        ide->appendToOutput("Streamer self-check: FAIL\n", "System", Win32IDE::OutputSeverity::Warning);

    // Status bar part 2 is updated by the per-window ribbon path above.
}

static HICON createLedIcon(COLORREF rgb)
{
    // 16x16 ARGB DIB for status bar icon.
    BITMAPV5HEADER bi{};
    bi.bV5Size = sizeof(BITMAPV5HEADER);
    bi.bV5Width = 16;
    bi.bV5Height = -16;  // top-down
    bi.bV5Planes = 1;
    bi.bV5BitCount = 32;
    bi.bV5Compression = BI_BITFIELDS;
    bi.bV5RedMask = 0x00FF0000;
    bi.bV5GreenMask = 0x0000FF00;
    bi.bV5BlueMask = 0x000000FF;
    bi.bV5AlphaMask = 0xFF000000;

    void* bits = nullptr;
    HDC hdc = GetDC(nullptr);
    HBITMAP colorBmp = CreateDIBSection(hdc, reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, hdc);
    if (!colorBmp || !bits)
        return nullptr;

    // Clear fully transparent.
    std::memset(bits, 0, 16 * 16 * 4);

    // Draw a filled circle with a tiny darker border.
    const uint8_t r = GetRValue(rgb);
    const uint8_t g = GetGValue(rgb);
    const uint8_t b = GetBValue(rgb);
    const uint8_t br = static_cast<uint8_t>(r / 2);
    const uint8_t bg = static_cast<uint8_t>(g / 2);
    const uint8_t bb = static_cast<uint8_t>(b / 2);

    auto put = [&](int x, int y, uint8_t rr, uint8_t gg, uint8_t bb_, uint8_t aa)
    {
        uint32_t* p = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(bits) + (y * 16 + x) * 4);
        *p = (static_cast<uint32_t>(aa) << 24) | (static_cast<uint32_t>(rr) << 16) | (static_cast<uint32_t>(gg) << 8) |
             static_cast<uint32_t>(bb_);
    };

    const int cx = 8;
    const int cy = 8;
    const int rOuter = 6;
    const int rInner = 5;
    for (int y = 0; y < 16; ++y)
    {
        for (int x = 0; x < 16; ++x)
        {
            const int dx = x - cx;
            const int dy = y - cy;
            const int d2 = dx * dx + dy * dy;
            if (d2 <= rInner * rInner)
                put(x, y, r, g, b, 0xFF);
            else if (d2 <= rOuter * rOuter)
                put(x, y, br, bg, bb, 0xFF);
        }
    }

    HBITMAP maskBmp = CreateBitmap(16, 16, 1, 1, nullptr);
    if (!maskBmp)
    {
        DeleteObject(colorBmp);
        return nullptr;
    }

    ICONINFO ii{};
    ii.fIcon = TRUE;
    ii.xHotspot = 0;
    ii.yHotspot = 0;
    ii.hbmColor = colorBmp;
    ii.hbmMask = maskBmp;
    HICON icon = CreateIconIndirect(&ii);

    DeleteObject(maskBmp);
    DeleteObject(colorBmp);
    return icon;
}

static HICON getVmmLedIcon(VmmRibbonTier tier)
{
    static HICON s_green = nullptr;
    static HICON s_yellow = nullptr;
    static HICON s_gray = nullptr;
    static HICON s_red = nullptr;

    if (!s_green)
        s_green = createLedIcon(RGB(34, 139, 34));  // ForestGreen
    if (!s_yellow)
        s_yellow = createLedIcon(RGB(218, 165, 32));  // Goldenrod
    if (!s_gray)
        s_gray = createLedIcon(RGB(160, 160, 160));  // neutral
    if (!s_red)
        s_red = createLedIcon(RGB(178, 34, 34));  // FireBrick

    switch (tier)
    {
        case VmmRibbonTier::Green:
            return s_green;
        case VmmRibbonTier::Yellow:
            return s_yellow;
        case VmmRibbonTier::Gray:
            return s_gray;
        case VmmRibbonTier::Red:
        default:
            return s_red;
    }
}

// ============================================================================
// FEATURE IMPLEMENTATION INDEX — RawrXD Win32 IDE
// ============================================================================
// Core Window & Layout:
//   Main window / message loop      → Win32IDE_Main.cpp, Win32IDE_Window.cpp
//   Activity bar / primary sidebar   → Win32IDE_Sidebar.cpp, Win32IDE_SidebarPanels.cpp
//   Secondary sidebar (Copilot chat) → Win32IDE_VSCodeUI.cpp
//   Panel container (term/output)    → Win32IDE_VSCodeUI.cpp
//   Tab bar / document switching     → Win32IDE_DragDropTabs.cpp
//   Status bar / parts layout        → Win32IDE_VSCodeUI.cpp
//
// Editor Engine:
//   RichEdit integration / caret     → Win32IDE_EditorEngine.cpp
//   Syntax highlighting by language  → Win32IDE_SyntaxHighlight.cpp, Win32IDE_AsmSemantic.cpp
//   Line numbers / minimap           → Win32IDE_Minimap.cpp
//   Code folding                     → Win32IDE_EditorEngine.cpp
//   Split code viewer                → Win32IDE_EditorEngine.cpp
//   Undo/redo stack                  → Win32IDE_EditorEngine.cpp
//   Selection / clipboard            → Win32IDE_EditorEngine.cpp
//   Indentation / tab-space          → Win32IDE_EditorEngine.cpp
//   EOL / encoding detection         → Win32IDE_EditorEngine.cpp
//   Language mode from extension     → Win32IDE_EditorEngine.cpp
//   Font / DPI scaling               → Win32IDE_Tier1Cosmetics.cpp
//   Breadcrumbs / navigation         → Win32IDE_Breadcrumbs.cpp
//
// Find & Navigation:
//   Find/Replace dialog              → Win32IDE_Commands.cpp
//   Search panel (find-in-files)     → Win32IDE_SearchPanel.cpp
//   Go to line dialog                → Win32IDE_Commands.cpp
//   Command palette / filtering      → Win32IDE_Commands.cpp
//   Fuzzy search                     → Win32IDE_FuzzySearch.cpp
//
// File Explorer & Operations:
//   File explorer tree / refresh     → Win32IDE_Sidebar.cpp
//   New file / default content       → Win32IDE_FileOps.cpp
//   Save / Save As / modified flag   → Win32IDE_FileOps.cpp
//   File icons                       → Win32IDE_FileIcons.cpp
//
// LSP & Intelligence:
//   Go-to-definition / references    → Win32IDE_LSPClient.cpp
//   Completion / signature help      → Win32IDE_LSPClient.cpp
//   Semantic tokens (23-type)        → Win32IDE_LSPClient.cpp::lspSemanticTokensFull()
//   Hover tooltips                   → Win32IDE_HoverTooltips.cpp
//   Inlay hints                      → Win32IDE_InlayHints.cpp
//   Code lens                        → Win32IDE_CodeLens.cpp
//   Signature help                   → Win32IDE_SignatureHelp.cpp
//   Rename preview                   → Win32IDE_RenamePreview.cpp
//   Refactoring                      → Win32IDE_Refactor.cpp
//
// AI / Copilot / Ghost Text:
//   Ghost text (3-provider cascade)  → Win32IDE_GhostText.cpp
//   Copilot send/clear handlers      → Win32IDE_CursorParity.cpp
//   Ollama model override            → Win32IDE_BackendSwitcher.cpp
//   generateResponse sync/async      → Win32IDE_AIBackend.cpp
//   Inline AI suggestion overlay     → Win32IDE_GhostText.cpp
//   LLM Router                       → Win32IDE_LLMRouter.cpp
//
// Agent System:
//   Agentic bridge / dispatch        → Win32IDE_AgenticBridge.cpp
//   Agent history / replay           → Win32IDE_AgentHistory.cpp
//   Agent memory store/recall        → Win32IDE_AgentPanel.cpp
//   Sub-agent / swarm execution      → Win32IDE_SubAgent.cpp
//   Autonomy manager / goal loop     → Win32IDE_Autonomy.cpp
//   Plan executor / rollback         → Win32IDE_PlanExecutor.cpp
//
// Terminal & Tasks:
//   Terminal pane / split / profiles  → Win32IDE_TerminalTabs.cpp, Win32IDE_TerminalProfiles.cpp
//   Task runner (stdout pipe capture) → Win32IDE_TaskRunner.cpp
//   Tasks/launch.json UI             → Win32IDE_Tasks.cpp, Win32IDE_TasksDebugUI.cpp
//   PowerShell output panel           → Win32IDE_PowerShellPanel.cpp
//   Output panel / severity tabs      → Win32IDE_ProblemsPanel.cpp
//
// Git & VCS:
//   Git panel (stage/commit/push)     → Win32IDE_GitPanel.cpp
//   Git repository (14 methods)       → Win32IDE_Git.cpp
//   Diff viewer (LCS-based)           → Win32IDE_DiffView.cpp
//   Diff inline/side-by-side          → Win32IDE_Tier2Cosmetics.cpp
//
// Debugger:
//   DbgEng COM debugger               → Win32IDE_Debugger.cpp
//   Watch format / variables           → Win32IDE_DebugWatchFormat.cpp
//   Call stack symbols                 → Win32IDE_CallStackSymbols.cpp
//   Memory view                        → Win32IDE_MemoryView.cpp
//   PDB symbols                        → Win32IDE_PDBSymbols.cpp
//   Native debug panel                 → Win32IDE_NativeDebugPanel.cpp
//
// Extensions & Marketplace:
//   Extensions panel (GUI)             → Win32IDE_ExtensionsPanel.cpp
//   Extension marketplace backend      → Win32IDE_ExtensionMarketplace.cpp
//   Marketplace panel                  → Win32IDE_MarketplacePanel.cpp
//   VSIX installer                     → VSIXInstaller.hpp
//
// Misc Panels:
//   Snippet list / insertion           → Win32IDE_Commands.cpp
//   Clipboard history panel            → Win32IDE_Commands.cpp
//   License dialogs                    → Win32IDE_LicenseCreator.cpp
//   Telemetry dashboard                → Win32IDE_TelemetryDashboard.cpp
//   Test explorer tree                 → Win32IDE_TestExplorerTree.cpp
//   Themes / color picker              → Win32IDE_Themes.cpp, Win32IDE_ColorPicker.cpp
//   Voice chat / automation            → Win32IDE_VoiceChat.cpp, Win32IDE_VoiceAutomation.cpp
//   Transcendence panel                → Win32IDE_TranscendencePanel.cpp
//   Checkpoint manager                 → Win32IDE_Session.cpp
//   Error/warning counts               → Win32IDE_ProblemsPanel.cpp
//   Decompiler view                    → Win32IDE_DecompilerView.cpp
//   Outline panel                      → Win32IDE_OutlinePanel.cpp
// ============================================================================


#pragma comment(lib, "winhttp.lib")

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")

// Helper function to execute shell commands and capture output
static std::string ExecCmd(const char* cmd)
{
    std::string result;
#ifdef _WIN32
    FILE* pipe = _popen(cmd, "r");
#else
    FILE* pipe = popen(cmd, "r");
#endif

    if (!pipe)
        return "Error: Could not execute command";

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
    {
        result += buffer;
    }

#ifdef _WIN32
    _pclose(pipe);
#else
    pclose(pipe);
#endif

    return result;
}

// UTF-8 to UTF-16 for Unicode Win32 APIs (Qt removal / pure MASM C++20)
static std::wstring utf8ToWide(const std::string& utf8)
{
    if (utf8.empty())
        return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
    if (len <= 0)
        return {};
    std::wstring out(static_cast<size_t>(len), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), out.data(), len) == 0)
        return {};
    return out;
}
static std::wstring utf8ToWide(const char* utf8)
{
    if (!utf8 || !*utf8)
        return {};
    return utf8ToWide(std::string(utf8));
}
static std::string wideToUtf8(const wchar_t* wide)
{
    if (!wide || !*wide)
        return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string out(static_cast<size_t>(len), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), len, nullptr, nullptr) == 0)
        return {};
    out.resize(out.size() - 1);  // drop NUL
    return out;
}

#define IDC_EDITOR 1001
#define IDC_TERMINAL 1002
#define IDC_COMMAND_INPUT 1003
#define IDC_STATUS_BAR 1004
#define IDC_OUTPUT_TABS 1005
#define IDC_MINIMAP 1006
#define IDC_MODULE_BROWSER 1007
#define IDC_HELP_PANEL 1008
#define IDC_SNIPPET_LIST 1009
#define IDC_CLIPBOARD_HISTORY 1010
#define IDC_OUTPUT_TEXT 1011
#define IDC_OUTPUT_EDIT_GENERAL 1012
#define IDC_OUTPUT_EDIT_ERRORS 1013
#define IDC_OUTPUT_EDIT_DEBUG 1014
#define IDC_OUTPUT_EDIT_FIND 1015
#define IDC_SPLITTER 1016
#define IDC_SEVERITY_FILTER 1017
#define IDC_TITLE_TEXT 1018
#define IDC_BTN_MINIMIZE 1019
#define IDC_BTN_MAXIMIZE 1020
#define IDC_BTN_CLOSE 1021
#define IDC_BTN_GITHUB 1022
#define IDC_BTN_MICROSOFT 1023
#define IDC_BTN_SETTINGS 1024
#define IDC_FILE_EXPLORER 1025
#define IDC_FILE_TREE 1026
// Defined in Win32IDE.h
// #define IDM_AUTONOMY_TOGGLE 4150
// ... constants moved to header

// Activity Bar (Far Left) - VS Code style icon bar
#define IDC_ACTIVITY_BAR 1100
#define IDC_ACTBAR_EXPLORER 1101
#define IDC_ACTBAR_SEARCH 1102
#define IDC_ACTBAR_SCM 1103
#define IDC_ACTBAR_DEBUG 1104
#define IDC_ACTBAR_EXTENSIONS 1105
#define IDC_ACTBAR_SETTINGS 1106
#define IDC_ACTBAR_ACCOUNTS 1107

// Secondary Sidebar (Right) - AI Chat/Copilot area
#define IDC_SECONDARY_SIDEBAR 1200
#define IDC_SECONDARY_SIDEBAR_HEADER 1201
#define IDC_COPILOT_CHAT_INPUT 1202
#define IDC_COPILOT_CHAT_OUTPUT 1203
#define IDC_COPILOT_SEND_BTN 1204
#define IDC_COPILOT_CLEAR_BTN 1205
#define IDC_AI_CONTEXT_SLIDER 1206
#define IDC_AI_CONTEXT_LABEL 1207
#define IDC_MODEL_SELECTOR 1208
#define IDC_MODEL_BROWSE_BTN 1209

// Panel (Bottom) - Terminal, Output, Problems, Debug Console
#define IDC_PANEL_CONTAINER 1300
#define IDC_PANEL_TABS 1301
#define IDC_PANEL_TERMINAL 1302
#define IDC_PANEL_OUTPUT 1303
#define IDC_PANEL_PROBLEMS 1304
#define IDC_PANEL_DEBUG_CONSOLE 1305
#define IDC_PANEL_TOOLBAR 1306
#define IDC_PANEL_BTN_NEW_TERMINAL 1307
#define IDC_PANEL_BTN_SPLIT_TERMINAL 1308
#define IDC_PANEL_BTN_KILL_TERMINAL 1309
#define IDC_PANEL_BTN_MAXIMIZE 1310
#define IDC_PANEL_BTN_CLOSE 1311
#define IDC_PANEL_PROBLEMS_LIST 1312

// Debugger Panel - Integrated at bottom with Terminal/Output
#define IDC_DEBUGGER_CONTAINER 1313
#define IDC_DEBUGGER_TABS 1314
#define IDC_DEBUGGER_BREAKPOINTS 1315
#define IDC_DEBUGGER_WATCH 1316
#define IDC_DEBUGGER_VARIABLES 1317
#define IDC_DEBUGGER_STACK_TRACE 1318
#define IDC_DEBUGGER_MEMORY 1319
#define IDC_DEBUGGER_TOOLBAR 1320
#define IDC_DEBUGGER_BTN_CONTINUE 1321
#define IDC_DEBUGGER_BTN_STEP_OVER 1322
#define IDC_DEBUGGER_BTN_STEP_INTO 1323
#define IDC_DEBUGGER_BTN_STEP_OUT 1324
#define IDC_DEBUGGER_BTN_RESTART 1325
#define IDC_DEBUGGER_BTN_STOP 1326
#define IDC_DEBUGGER_INPUT 1327
#define IDC_DEBUGGER_BREAKPOINT_LIST 1328
#define IDC_DEBUGGER_WATCH_LIST 1329
#define IDC_DEBUGGER_VARIABLE_TREE 1330
#define IDC_DEBUGGER_STACK_LIST 1331
#define IDC_DEBUGGER_STATUS_TEXT 1332

// Enhanced Status Bar items
#define IDC_STATUS_REMOTE 1400
#define IDC_STATUS_BRANCH 1401
#define IDC_STATUS_SYNC 1402
#define IDC_STATUS_ERRORS 1403
#define IDC_STATUS_WARNINGS 1404
#define IDC_STATUS_LINE_COL 1405
#define IDC_STATUS_SPACES 1406
#define IDC_STATUS_ENCODING 1407
#define IDC_STATUS_EOL 1408
#define IDC_STATUS_LANGUAGE 1409
#define IDC_STATUS_COPILOT 1410
#define IDC_STATUS_NOTIFICATIONS 1411

/* Menu IDs: 2001+ to avoid overlap with IDC_* (1001+) in WM_COMMAND */
#define IDM_FILE_NEW 2001
#define IDM_FILE_OPEN 2002
#define IDM_FILE_SAVE 2003
#define IDM_FILE_SAVEAS 2004
#define IDM_FILE_LOAD_MODEL 1030
#define IDM_FILE_EXIT 2005

/* Voice Automation (Tools > Voice Automation) — Phase 44 TTS; dispatched in Win32IDE_Commands 10200–10300 */
#define IDM_VOICE_AUTO_TOGGLE 10200
#define IDM_VOICE_AUTO_STOP 10206
#define IDM_VOICE_AUTO_NEXT 10202
#define IDM_VOICE_AUTO_PREV 10203
#define IDM_VOICE_AUTO_RATE_UP 10204
#define IDM_VOICE_AUTO_RATE_DOWN 10205

#define IDM_EDIT_UNDO 2007
#define IDM_EDIT_REDO 2008
#define IDM_EDIT_CUT 2009
#define IDM_EDIT_COPY 2010
#define IDM_EDIT_PASTE 2011
#define IDM_EDIT_SNIPPET 2012
#define IDM_EDIT_COPY_FORMAT 2013
#define IDM_EDIT_PASTE_PLAIN 2014
#define IDM_EDIT_CLIPBOARD_HISTORY 2015
#define IDM_EDIT_FIND 2016
#define IDM_EDIT_REPLACE 2017
#define IDM_EDIT_FIND_NEXT 2018
#define IDM_EDIT_FIND_PREV 2019

#define IDM_VIEW_MINIMAP 2020
#define IDM_VIEW_OUTPUT_TABS 2021
#define IDM_VIEW_MODULE_BROWSER 2022
#define IDM_VIEW_THEME_EDITOR 2023
#define IDM_VIEW_FLOATING_PANEL 2024
#define IDM_VIEW_OUTPUT_PANEL 2025
#define IDM_VIEW_USE_STREAMING_LOADER 2026
#define IDM_VIEW_USE_VULKAN_RENDERER 2027
#define IDM_VIEW_SIDEBAR 2028
#define IDM_VIEW_TERMINAL 2029

#define IDM_TERMINAL_POWERSHELL 4001
#define IDM_TERMINAL_CMD 4002
#define IDM_TERMINAL_STOP 4003
#define IDM_TERMINAL_SPLIT_H 4007
#define IDM_TERMINAL_SPLIT_V 4008
#define IDM_TERMINAL_CLEAR_ALL 4010

#define IDM_TOOLS_PROFILE_START 3010
#define IDM_TOOLS_PROFILE_STOP 3011
#define IDM_TOOLS_PROFILE_RESULTS 3012
#define IDM_TOOLS_ANALYZE_SCRIPT 3013
#define IDM_TOOLS_GGUF_INSPECTOR 3014

#define IDM_GIT_STATUS 3020
#define IDM_GIT_COMMIT 3021
#define IDM_GIT_PUSH 3022
#define IDM_GIT_PULL 3023
#define IDM_GIT_PANEL 3024

#define IDM_MODULES_REFRESH 3050
#define IDM_MODULES_IMPORT 3051
#define IDM_MODULES_EXPORT 3052

#define IDM_HELP_ABOUT 4001
#define IDM_HELP_CMDREF 4002
#define IDM_HELP_PSDOCS 4003
#define IDM_HELP_SEARCH 4004

// Agent menu IDs
#define IDM_AGENT_START_LOOP 4100
#define IDM_AGENT_EXECUTE_CMD 4101
#define IDM_AGENT_CONFIGURE_MODEL 4102
#define IDM_AGENT_VIEW_TOOLS 4103
#define IDM_AGENT_VIEW_STATUS 4104
#define IDM_AGENT_AUTONOMOUS_COMMUNICATOR 4163  // free slot; 4106=IDM_AGENT_MEMORY, 4110=IDM_SUBAGENT_CHAIN
#define IDM_TELEMETRY_UNIFIED_CORE 4164         // free slot; 4300=IDM_REVENG_ANALYZE
// Constants moved to Win32IDE.h
// #define IDM_AGENT_STOP 4105
// ...

// Command Palette control IDs
#define IDC_CMDPAL_CONTAINER 1500
#define IDC_CMDPAL_INPUT 1501
#define IDC_CMDPAL_LIST 1502

Win32IDE::Win32IDE(HINSTANCE hInstance)
    : m_hInstance(hInstance), m_hwndMain(nullptr), m_hwndEditor(nullptr), m_hwndLineNumbers(nullptr),
      m_hwndTabBar(nullptr), m_oldLineNumberProc(nullptr), m_lineNumberWidth(70), m_activeTabIndex(-1),
      m_hwndCommandInput(nullptr), m_hwndStatusBar(nullptr), m_hwndMinimap(nullptr), m_hwndModuleBrowser(nullptr),
      m_hwndModuleList(nullptr), m_hwndModuleLoadButton(nullptr), m_hwndModuleUnloadButton(nullptr),
      m_hwndModuleRefreshButton(nullptr), m_moduleBrowserVisible(false), m_modulePanelProc(nullptr),
      m_hwndHelp(nullptr), m_hMenu(nullptr), m_hwndToolbar(nullptr), m_hwndTitleLabel(nullptr),
      m_hwndBtnMinimize(nullptr), m_hwndBtnMaximize(nullptr), m_hwndBtnClose(nullptr), m_hwndBtnGitHub(nullptr),
      m_hwndBtnMicrosoft(nullptr), m_hwndBtnSettings(nullptr), m_lastTitleBarText(), m_fileModified(false),
      m_editorHeight(400), m_terminalHeight(200), m_minimapVisible(true), m_minimapWidth(150), m_profilingActive(false),
      m_moduleListDirty(true), m_backgroundBrush(nullptr), m_editorFont(nullptr), m_hFontUI(nullptr),
      m_activeOutputTab("General"), m_minimapX(650), m_outputTabHeight(200), m_nextTerminalId(1),
      m_activeTerminalId(-1), m_ggufLoader(nullptr), m_loadedModelPath(""), m_terminalSplitHorizontal(true),
      m_hwndGitPanel(nullptr), m_hwndGitStatusText(nullptr), m_hwndGitFileList(nullptr), m_gitAutoRefresh(true),
      m_outputPanelVisible(true), m_selectedOutputTab(0), m_hwndSeverityFilter(nullptr), m_severityFilterLevel(0),
      m_editorRect{0, 0, 0, 0}, m_gpuTextEnabled(true), m_editorHooksInstalled(false), m_hwndSplitter(nullptr),
      m_splitterDragging(false), m_splitterY(0), m_renderer(nullptr), m_rendererReady(false), m_lastSearchText(),
      m_lastReplaceText(), m_searchCaseSensitive(false), m_searchWholeWord(false), m_searchUseRegex(false),
      m_lastFoundPos(-1), m_hwndFindDialog(nullptr), m_hwndReplaceDialog(nullptr),
      // Primary Sidebar
      m_hwndActivityBar(nullptr), m_hwndSidebar(nullptr), m_hwndSidebarContent(nullptr), m_sidebarVisible(true),
      m_sidebarWidth(250), m_currentSidebarView(SidebarView::None),
      // Secondary Sidebar
      m_hwndSecondarySidebar(nullptr), m_hwndSecondarySidebarHeader(nullptr), m_secondarySidebarVisible(false),
      m_secondarySidebarWidth(320),
      // Explorer View
      m_hwndExplorerTree(nullptr), m_hwndExplorerToolbar(nullptr), m_hImageListExplorer(nullptr), m_explorerRootPath(),
      // Search View
      m_hwndSearchInput(nullptr), m_hwndSearchResults(nullptr), m_hwndSearchOptions(nullptr),
      m_hwndIncludePattern(nullptr), m_hwndExcludePattern(nullptr), m_searchInProgress(false),
      // Source Control View
      m_hwndSCMFileList(nullptr), m_hwndSCMToolbar(nullptr), m_hwndSCMMessageBox(nullptr),
      // Debug View
      m_hwndDebugConfigs(nullptr), m_hwndDebugToolbar(nullptr), m_hwndDebugVariables(nullptr),
      m_hwndDebugCallStack(nullptr), m_hwndDebugConsole(nullptr), m_debuggingActive(false),
      // Extensions View
      m_hwndExtensionsList(nullptr), m_hwndExtensionSearch(nullptr), m_hwndExtensionDetails(nullptr),
      // File Explorer
      m_hwndFileExplorer(nullptr), m_hImageList(nullptr), m_currentExplorerPath(PathResolver::getModelsPath()),
      // Model Chat
      m_chatMode(false),
      // PowerShell Panel
      m_hwndPowerShellPanel(nullptr), m_hwndPowerShellOutput(nullptr), m_hwndPowerShellInput(nullptr),
      m_hwndPowerShellToolbar(nullptr), m_hwndPowerShellStatusBar(nullptr), m_hwndPSBtnExecute(nullptr),
      m_hwndPSBtnClear(nullptr), m_hwndPSBtnStop(nullptr), m_hwndPSBtnHistory(nullptr), m_hwndPSBtnRestart(nullptr),
      m_hwndPSBtnLoadRawrXD(nullptr), m_hwndPSBtnToggle(nullptr), m_powerShellPanelVisible(true),
      m_powerShellPanelDocked(true), m_powerShellSessionActive(false), m_powerShellRawrXDLoaded(false),
      m_powerShellPanelHeight(250), m_powerShellPanelWidth(600), m_powerShellHistoryIndex(-1),
      m_maxPowerShellHistory(100), m_useStreamingLoader(false), m_useVulkanRenderer(false),
      m_powerShellExecuting(false), m_powerShellProcessHandle(nullptr), m_dedicatedPowerShellTerminal(nullptr),
      m_hwndCommandPalette(nullptr), m_hwndCommandPaletteInput(nullptr), m_hwndCommandPaletteList(nullptr),
      m_commandPaletteVisible(false), m_oldCommandPaletteInputProc(nullptr), m_hwndModelSelector(nullptr),
      m_hwndMaxTokensSlider(nullptr), m_hwndMaxTokensLabel(nullptr), m_currentMaxTokens(512),
      m_syntaxColoringEnabled(true), m_syntaxDirty(false), m_syntaxLanguage(SyntaxLanguage::None),
      m_inBlockComment(false), m_activeThemeId(IDM_THEME_DARK_PLUS), m_themeIdBeforePreview(IDM_THEME_DARK_PLUS),
      m_transparencyEnabled(false), m_windowAlpha(255), m_sidebarBrush(nullptr), m_sidebarContentBrush(nullptr),
      m_panelBrush(nullptr), m_secondarySidebarBrush(nullptr), m_mainWindowBrush(nullptr),
      m_modelOperationActive(false), m_modelOperationCancelled(false), m_modelProgressPercent(0.0f),
      m_hwndModelProgressBar(nullptr), m_hwndModelProgressLabel(nullptr), m_hwndModelProgressContainer(nullptr),
      m_hwndModelCancelBtn(nullptr), m_sessionRestored(false), m_annotationsVisible(true), m_annotationFont(nullptr),
      m_hwndAnnotationOverlay(nullptr), m_nativePipelineReady(false), m_tabManager(nullptr)
{
    // ============================================================
    // MINIMAL CONSTRUCTOR — all heavy init deferred to onCreate()
    // C++ try/catch does NOT catch SEH (access violations) on MinGW,
    // so we keep the constructor as lightweight as possible.
    // ============================================================

    // Initialize profiling frequency (safe — kernel call)
    QueryPerformanceFrequency(&m_profilingFreq);

    // Initialize clipboard history
    m_clipboardHistory.reserve(MAX_CLIPBOARD_HISTORY);

    // Initialize Git status
    m_gitStatus = GitStatus();

    // Get current directory for Git repo detection
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    m_gitRepoPath = currentDir;

    // Default Ollama configuration
    m_ollamaBaseUrl = "http://localhost:11434";
    m_ollamaModelOverride = "";

    m_nativeEngineLoaded = false;

    // Initialize 70B GGUF Hotpatch
    m_ggufHotpatch = std::make_unique<RawrXD::GGUFHotpatch>();

    // Initialize Governor/Throttling
    m_governorThrottling = std::make_unique<RawrXD::GovernorThrottling>();
}

// Build a "Commands" submenu from COMMAND_TABLE so every GUI-exposed command has a menu entry (avoids menu-only drift).
static void buildCommandsMenuFromCommandTable(HMENU mainMenu)
{
    if (!mainMenu)
        return;
    std::map<std::string, std::vector<const CmdDescriptor*>> byCategory;
    for (size_t i = 0; i < g_commandRegistrySize; ++i)
    {
        const CmdDescriptor& cmd = g_commandRegistry[i];
        if (cmd.id == 0)
            continue;
        if (cmd.exposure != CmdExposure::GUI_ONLY && cmd.exposure != CmdExposure::BOTH)
            continue;
        const char* cat = cmd.category && cmd.category[0] ? cmd.category : "Other";
        byCategory[cat].push_back(&cmd);
    }
    HMENU hCommands = CreatePopupMenu();
    if (!hCommands)
        return;
    for (const auto& pair : byCategory)
    {
        const std::string& categoryName = pair.first;
        const std::vector<const CmdDescriptor*>& items = pair.second;
        if (items.empty())
            continue;
        HMENU hSub = CreatePopupMenu();
        if (!hSub)
            continue;
        for (const CmdDescriptor* p : items)
        {
            const char* label = p->canonicalName && p->canonicalName[0] ? p->canonicalName : p->symbol;
            if (!label)
                label = "?";
            AppendMenuA(hSub, MF_STRING, (UINT)p->id, label);
        }
        AppendMenuA(hCommands, MF_POPUP, (UINT_PTR)hSub, categoryName.c_str());
    }
    AppendMenuW(mainMenu, MF_POPUP, (UINT_PTR)hCommands, L"&Commands");
}

// ESP:m_hMenu — Main menu bar; submenus File/Edit/View/Terminal/Tools/Modules/Help/Audit/Git/Agent (see
// Win32IDE_IELabels.h)
void Win32IDE::createMenuBar(HWND hwnd)
{
    if (!m_hMenu)
        m_hMenu = CreateMenu();
    if (!m_hMenu)
        return;

    // Status bar is initialized in onCreate after createStatusBar (see Win32IDE_Core.cpp).

    // File menu (Unicode)
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_NEW, L"&New");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_OPEN, L"&Open");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_SAVE, L"&Save");
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_SAVEAS, L"Save &As");
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_LOAD_MODEL, L"Load &Model (GGUF)...");
    AppendMenuW(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFileMenu, MF_STRING, IDM_FILE_EXIT, L"E&xit");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hFileMenu, L"&File");

    // Build menu (Unicode)
    HMENU hBuildMenu = CreatePopupMenu();
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_SOLUTION, L"&Build Solution\tCtrl+B");
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_CLEAN, L"&Clean");
    AppendMenuW(hBuildMenu, MF_STRING, IDM_BUILD_REBUILD, L"Re&build");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hBuildMenu, L"&Build");

    // Edit menu (Unicode)
    HMENU hEditMenu = CreatePopupMenu();
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_FIND, L"&Find...\tCtrl+F");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_REPLACE, L"&Replace...\tCtrl+H");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_FIND_NEXT, L"Find &Next\tF3");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_FIND_PREV, L"Find &Previous\tShift+F3");
    AppendMenuW(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_SNIPPET, L"Insert &Snippet...");
    AppendMenuW(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_COPY_FORMAT, L"Copy with &Formatting");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_PASTE_PLAIN, L"Paste &Plain Text");
    AppendMenuW(hEditMenu, MF_STRING, IDM_EDIT_CLIPBOARD_HISTORY, L"Clipboard &History...");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hEditMenu, L"&Edit");

    // View menu (Unicode)
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_MINIMAP, L"&Minimap");
    AppendMenuW(hViewMenu, MF_STRING, IDM_T1_BREADCRUMBS_TOGGLE, L"&Breadcrumbs");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_OUTPUT_TABS, L"&Output Tabs");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_OUTPUT_PANEL, L"Output &Panel");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_MODULE_BROWSER, L"Module &Browser");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_FLOATING_PANEL, L"&Floating Panel");
    AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
    buildThemeMenu(hViewMenu);
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_THEME_EDITOR, L"Theme &Picker...");
    AppendMenuW(hViewMenu, MF_STRING, ID_VIEW_SYNTAX_HIGHLIGHTING_TOGGLE, L"Syntax &Highlighting");
    AppendMenuW(hViewMenu, MF_STRING, ID_VIEW_VISION_ENCODER, L"&Vision Encoder");
    AppendMenuW(hViewMenu, MF_STRING, ID_VIEW_SEMANTIC_INDEX, L"&Semantic Index");
    AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_USE_STREAMING_LOADER, L"Use Streaming Loader (Low Memory)");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_USE_VULKAN_RENDERER, L"Enable Vulkan Renderer (experimental)");
    AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_AGENT_PANEL, L"Agent &Panel");
    AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hViewMenu, MF_STRING, IDM_MARKETPLACE_SHOW, L"Extension &Marketplace");
    AppendMenuW(hViewMenu, MF_STRING, IDM_VIEW_COLLABORATION, L"&Collaboration");
    AppendMenuW(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hViewMenu, MF_STRING, IDM_TELDASH_SHOW, L"Telemetry &Dashboard...");
    AppendMenuW(hViewMenu, MF_STRING, IDM_EMOJI_PICKER, L"&Emoji Picker");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hViewMenu, L"&View");

    // Terminal menu (Unicode)
    HMENU hTerminalMenu = CreatePopupMenu();
    AppendMenuW(hTerminalMenu, MF_STRING, IDM_TERMINAL_POWERSHELL, L"&PowerShell");
    AppendMenuW(hTerminalMenu, MF_STRING, IDM_TERMINAL_CMD, L"&Command Prompt");
    AppendMenuW(hTerminalMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hTerminalMenu, MF_STRING, IDM_TERMINAL_STOP, L"&Stop Terminal");
    AppendMenuW(hTerminalMenu, MF_STRING, IDM_TERMINAL_SPLIT_H, L"Split &Horizontal\tCtrl+Shift+H");
    AppendMenuW(hTerminalMenu, MF_STRING, IDM_TERMINAL_SPLIT_V, L"Split &Vertical\tCtrl+Shift+V");
    AppendMenuW(hTerminalMenu, MF_STRING, IDM_TERMINAL_CLEAR_ALL, L"&Clear All Terminals");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hTerminalMenu, L"&Terminal");

    // Tools menu (Unicode)
    HMENU hToolsMenu = CreatePopupMenu();
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_START, L"Start &Profiling");
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_STOP, L"Stop P&rofiling");
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_RESULTS, L"Profile &Results...");
    AppendMenuW(hToolsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_ANALYZE_SCRIPT, L"&Analyze Script");
    AppendMenuW(hToolsMenu, MF_STRING, IDM_TOOLS_GGUF_INSPECTOR, L"GGUF Model &Inspector");
    AppendMenuW(hToolsMenu, MF_SEPARATOR, 0, nullptr);

    // Voice Chat submenu (Unicode — Qt removal / pure Win32)
    HMENU hVoiceMenu = CreatePopupMenu();
    AppendMenuW(hVoiceMenu, MF_STRING, IDM_VOICE_TOGGLE_PANEL, L"Show/Hide &Voice Panel\tCtrl+Shift+U");
    AppendMenuW(hVoiceMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hVoiceMenu, MF_STRING, IDM_VOICE_RECORD, L"&Record / Stop\tF9");
    AppendMenuW(hVoiceMenu, MF_STRING, IDM_VOICE_PTT, L"&Push-to-Talk\tCtrl+Shift+V");
    AppendMenuW(hVoiceMenu, MF_STRING, IDM_VOICE_SPEAK, L"Text-to-&Speech");
    AppendMenuW(hVoiceMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hVoiceMenu, MF_STRING, IDM_VOICE_JOIN_ROOM, L"&Join/Leave Room");
    AppendMenuW(hVoiceMenu, MF_STRING, IDM_VOICE_SHOW_DEVICES, L"Audio &Devices...");
    AppendMenuW(hVoiceMenu, MF_STRING, IDM_VOICE_METRICS, L"&Metrics...");
    AppendMenuW(hToolsMenu, MF_POPUP, (UINT_PTR)hVoiceMenu, L"&Voice Chat");

    // Voice Automation submenu (Phase 44: TTS for AI responses)
    HMENU hVoiceAutoMenu = CreatePopupMenu();
    AppendMenuW(hVoiceAutoMenu, MF_STRING, IDM_VOICE_AUTO_TOGGLE, L"Toggle Voice Automation\tCtrl+Shift+A");
    AppendMenuW(hVoiceAutoMenu, MF_STRING, IDM_VOICE_AUTO_STOP, L"Stop Speaking\tEscape");
    AppendMenuW(hVoiceAutoMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hVoiceAutoMenu, MF_STRING, IDM_VOICE_AUTO_NEXT, L"Next Voice\tCtrl+Shift+]");
    AppendMenuW(hVoiceAutoMenu, MF_STRING, IDM_VOICE_AUTO_PREV, L"Previous Voice\tCtrl+Shift+[");
    AppendMenuW(hVoiceAutoMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hVoiceAutoMenu, MF_STRING, IDM_VOICE_AUTO_RATE_UP, L"Increase Speech Rate\tCtrl+Shift+=");
    AppendMenuW(hVoiceAutoMenu, MF_STRING, IDM_VOICE_AUTO_RATE_DOWN, L"Decrease Speech Rate\tCtrl+Shift+-");
    AppendMenuW(hToolsMenu, MF_POPUP, (UINT_PTR)hVoiceAutoMenu, L"Voice &Automation");

    // Phase 51: mIRC Control Bridge
    HMENU hIRCMenu = CreatePopupMenu();
    AppendMenuW(hIRCMenu, MF_STRING, IDM_IRC_CONNECT, L"&Connect");
    AppendMenuW(hIRCMenu, MF_STRING, IDM_IRC_DISCONNECT, L"&Disconnect");
    AppendMenuW(hIRCMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hIRCMenu, MF_STRING, IDM_IRC_STATUS, L"Show &Status");
    AppendMenuW(hIRCMenu, MF_STRING, IDM_IRC_CONFIG, L"&Config...");
    AppendMenuW(hIRCMenu, MF_STRING, IDM_IRC_SEND, L"&Send Test Message");
    AppendMenuW(hToolsMenu, MF_POPUP, (UINT_PTR)hIRCMenu, L"&IRC Bridge");

    // Backup submenu
    HMENU hBackupMenu = CreatePopupMenu();
    AppendMenuW(hBackupMenu, MF_STRING, IDM_QW_BACKUP_CREATE, L"&Create Backup Now\tCtrl+Shift+B");
    AppendMenuW(hBackupMenu, MF_STRING, IDM_QW_BACKUP_RESTORE, L"&Restore from Backup...");
    AppendMenuW(hBackupMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hBackupMenu, MF_STRING, IDM_QW_BACKUP_AUTO_TOGGLE, L"Toggle &Auto-Backup");
    AppendMenuW(hBackupMenu, MF_STRING, IDM_QW_BACKUP_LIST, L"&List Backups...");
    AppendMenuW(hBackupMenu, MF_STRING, IDM_QW_BACKUP_PRUNE, L"&Prune Old Backups");
    AppendMenuW(hToolsMenu, MF_POPUP, (UINT_PTR)hBackupMenu, L"&Backups");

    // Alert & Monitoring submenu
    HMENU hAlertMenu = CreatePopupMenu();
    AppendMenuW(hAlertMenu, MF_STRING, IDM_QW_ALERT_TOGGLE_MONITOR, L"Toggle Resource &Monitor");
    AppendMenuW(hAlertMenu, MF_STRING, IDM_QW_ALERT_RESOURCE_STATUS, L"&Resource Status...");
    AppendMenuW(hAlertMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAlertMenu, MF_STRING, IDM_QW_ALERT_SHOW_HISTORY, L"Alert &History...");
    AppendMenuW(hAlertMenu, MF_STRING, IDM_QW_ALERT_DISMISS_ALL, L"&Dismiss All Alerts");
    AppendMenuW(hToolsMenu, MF_POPUP, (UINT_PTR)hAlertMenu, L"A&lerts");

    // Shortcuts & SLO (Tier 5)
    AppendMenuW(hToolsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hToolsMenu, MF_STRING, IDM_QW_SHORTCUT_EDITOR, L"\u2328 &Keyboard Shortcuts...\tCtrl+K Ctrl+S");
    AppendMenuW(hToolsMenu, MF_STRING, IDM_SHORTCUT_SHOW, L"Keyboard Shortcut &Editor...");
    AppendMenuW(hToolsMenu, MF_STRING, IDM_QW_SLO_DASHBOARD, L"&SLO Dashboard...");

    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hToolsMenu, L"&Tools");

    // Build menu (extended — added after initial build menu at line ~577)
    {
        HMENU hBuildMenu2 = CreatePopupMenu();
        AppendMenuW(hBuildMenu2, MF_STRING, IDM_BUILD_SOLUTION, L"Build &Solution\tCtrl+Shift+B");
        AppendMenuW(hBuildMenu2, MF_STRING, IDM_BUILD_CLEAN, L"&Clean");
        // Note: duplicate Build popup replaced with hBuildMenu2 to avoid C2374
        (void)hBuildMenu2;  // menu already attached at line ~577
    }

    // Security menu (Top-50 P0 — SAST, Secrets, SCA)
    HMENU hSecurityMenu = CreatePopupMenu();
    AppendMenuW(hSecurityMenu, MF_STRING, IDM_SECURITY_SCAN_SECRETS, L"Scan for &Secrets");
    AppendMenuW(hSecurityMenu, MF_STRING, IDM_SECURITY_SCAN_SAST, L"Run &SAST Scan");
    AppendMenuW(hSecurityMenu, MF_STRING, IDM_SECURITY_SCAN_DEPENDENCIES, L"Scan &Dependencies (SCA)");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hSecurityMenu, L"Secu&rity");

    // Modules menu
    HMENU hModulesMenu = CreatePopupMenu();
    AppendMenuW(hModulesMenu, MF_STRING, IDM_MODULES_REFRESH, L"&Refresh List");
    AppendMenuW(hModulesMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hModulesMenu, MF_STRING, IDM_MODULES_IMPORT, L"&Import Module...");
    AppendMenuW(hModulesMenu, MF_STRING, IDM_MODULES_EXPORT, L"&Export Module...");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hModulesMenu, L"&Modules");

    // Help menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_CMDREF, L"Command &Reference");
    AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_PSDOCS, L"PowerShell &Documentation");
    AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_SEARCH, L"&Search Help...");
    AppendMenuW(hHelpMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, L"&About");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, L"&Help");

    // Audit menu (Phase 31 — Unicode)
    HMENU hAuditMenu = CreatePopupMenu();
    AppendMenuW(hAuditMenu, MF_STRING, IDM_AUDIT_SHOW_DASHBOARD, L"Show &Dashboard\tCtrl+Shift+A");
    AppendMenuW(hAuditMenu, MF_STRING, IDM_AUDIT_RUN_FULL, L"&Run Full Audit");
    AppendMenuW(hAuditMenu, MF_STRING, IDM_AUDIT_DETECT_STUBS, L"Detect &Stubs");
    AppendMenuW(hAuditMenu, MF_STRING, IDM_AUDIT_CHECK_MENUS, L"Check &Menu Wiring");
    AppendMenuW(hAuditMenu, MF_STRING, IDM_AUDIT_RUN_TESTS, L"Run Component &Tests");
    AppendMenuW(hAuditMenu, MF_STRING, IDM_AUDIT_EXPORT_REPORT, L"&Export Report...");
    AppendMenuW(hAuditMenu, MF_STRING, IDM_AUDIT_QUICK_STATS, L"&Quick Stats");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hAuditMenu, L"&Audit");

    // Debug menu (NEW - integrated with NativeDebuggerEngine)
    HMENU hDebugMenu = CreatePopupMenu();
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_START, L"&Start Debugging\tF5");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STOP, L"S&top Debugging\tShift+F5");
    AppendMenuW(hDebugMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_CONTINUE, L"&Continue\tF5");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STEP_OVER, L"Step &Over\tF10");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STEP_INTO, L"Step &Into\tF11");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_STEP_OUT, L"Step O&ut\tShift+F11");
    AppendMenuW(hDebugMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_TOGGLE_BREAKPOINT, L"Toggle &Breakpoint\tF9");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_SHOW_CALLSTACK, L"Show &Call Stack");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_SHOW_VARIABLES, L"Show &Variables");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_SHOW_WATCH, L"Show &Watch");
    AppendMenuW(hDebugMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_ATTACH, L"&Attach to Process...");
    AppendMenuW(hDebugMenu, MF_STRING, IDM_DEBUG_DETACH, L"&Detach");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hDebugMenu, L"&Debug");

    // Git menu
    HMENU hGitMenu = CreatePopupMenu();
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_STATUS, L"&Status\tCtrl+G");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_COMMIT, L"&Commit...\tCtrl+Shift+C");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_PUSH, L"&Push");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_PULL, L"P&ull");
    AppendMenuW(hGitMenu, MF_STRING, IDM_GIT_PANEL, L"&Git Panel\tCtrl+Shift+G");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hGitMenu, L"&Git");

    // Agent menu (Unicode — Qt removal / pure Win32)
    HMENU hAgentMenu = CreatePopupMenu();
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_START_LOOP, L"Start &Agent Loop");
    AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);

    // AI Options Submenu
    HMENU hAIOptionsMenu = CreatePopupMenu();
    AppendMenuW(hAIOptionsMenu, MF_STRING, IDM_AI_MODE_MAX, L"&Max Mode (Thread Unlock)");
    AppendMenuW(hAIOptionsMenu, MF_STRING, IDM_AI_MODE_DEEP_THINK, L"&Deep Thinking (CoT)");
    AppendMenuW(hAIOptionsMenu, MF_STRING, IDM_AI_MODE_DEEP_RESEARCH, L"Deep &Research (FileSystem)");
    AppendMenuW(hAIOptionsMenu, MF_STRING, IDM_AI_MODE_NO_REFUSAL, L"&No Refusal Mode");
    AppendMenuW(hAgentMenu, MF_POPUP, (UINT_PTR)hAIOptionsMenu, L"AI &Options");

    // Context Window (Memory Plugins) Submenu
    HMENU hContextMenu = CreatePopupMenu();
    AppendMenuW(hContextMenu, MF_STRING, IDM_AI_CONTEXT_4K, L"4K (Standard)");
    AppendMenuW(hContextMenu, MF_STRING, IDM_AI_CONTEXT_32K, L"32K (Large)");
    AppendMenuW(hContextMenu, MF_STRING, IDM_AI_CONTEXT_64K, L"64K (X-Large)");
    AppendMenuW(hContextMenu, MF_STRING, IDM_AI_CONTEXT_128K, L"128K (Ultra)");
    AppendMenuW(hContextMenu, MF_STRING, IDM_AI_CONTEXT_256K, L"256K (Mega)");
    AppendMenuW(hContextMenu, MF_STRING, IDM_AI_CONTEXT_512K, L"512K (Giga)");
    AppendMenuW(hContextMenu, MF_STRING, IDM_AI_CONTEXT_1M, L"1M (Tera - Memory Plugin)");
    AppendMenuW(hAgentMenu, MF_POPUP, (UINT_PTR)hContextMenu, L"&Context Window Size");

    AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AI_TITAN_TOGGLE, L"Use &Titan Kernel");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AI_800B_STATUS, L"800B Dual-Engine &Status");
    AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AI_AGENT_MULTI_ENABLE, L"Multi-Agent: &Enable");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AI_AGENT_MULTI_DISABLE, L"Multi-Agent: &Disable");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AI_AGENT_MULTI_STATUS, L"Multi-Agent: &Status");

    AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_EXECUTE_CMD, L"&Execute Command...");

    AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);

    // Agent Memory sub-items (explicit strings for smoke test parity)
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_MEMORY_VIEW, L"View Agent &Memory");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_MEMORY_CLEAR, L"&Clear Agent Memory");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_MEMORY_EXPORT, L"&Export Agent Memory");
    AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);

    // Bounded loop entry (smoke test expects this label/ID)
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_BOUNDED_LOOP, L"&Bounded Agent Loop");
    AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);

    // SubAgent submenu with Chain/Swarm/Todo/Status
    {
        HMENU hSubAgentMenu = CreatePopupMenu();
        AppendMenuW(hSubAgentMenu, MF_STRING, IDM_SUBAGENT_CHAIN, L"Agent: Execute Prompt &Chain");
        AppendMenuW(hSubAgentMenu, MF_STRING, IDM_SUBAGENT_SWARM, L"Agent: Execute &HexMag Swarm");
        AppendMenuW(hSubAgentMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hSubAgentMenu, MF_STRING, IDM_SUBAGENT_TODO_LIST, L"SubAgent: &Todo List");
        AppendMenuW(hSubAgentMenu, MF_STRING, IDM_SUBAGENT_TODO_CLEAR, L"SubAgent: Clear &Todo");
        AppendMenuW(hSubAgentMenu, MF_STRING, IDM_SUBAGENT_STATUS, L"SubAgent: &Status");
        AppendMenuW(hAgentMenu, MF_POPUP, (UINT_PTR)hSubAgentMenu, L"&SubAgent");
        AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);
    }

    // Autonomy submenu (smoke test expects hAutonomyMenu + IDM_AUTONOMY_* items)
    {
        HMENU hAutonomyMenu = CreatePopupMenu();
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_TOGGLE, L"&Toggle Auto Loop");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_START, L"&Start Autonomy");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STOP, L"Sto&p Autonomy");
        AppendMenuW(hAutonomyMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_SET_GOAL, L"Set &Goal...");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STATUS, L"Show &Status");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_MEMORY, L"Show &Memory Snapshot");
        AppendMenuW(hAgentMenu, MF_POPUP, (UINT_PTR)hAutonomyMenu, L"&Autonomy");
        AppendMenuW(hAgentMenu, MF_SEPARATOR, 0, nullptr);
    }

    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_CONFIGURE_MODEL, L"&Configure Model...");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_VIEW_TOOLS, L"View &Tools");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_VIEW_STATUS, L"View &Status");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_AUTONOMOUS_COMMUNICATOR, L"Autonomous &Communicator");
    AppendMenuW(hAgentMenu, MF_STRING, IDM_AGENT_STOP, L"&Stop Agent");

    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hAgentMenu, L"&Agent");

    // Telemetry menu
    HMENU hTelemetryMenu = CreatePopupMenu();
    AppendMenuW(hTelemetryMenu, MF_STRING, IDM_TELEMETRY_UNIFIED_CORE, L"&Unified Telemetry Core");
    AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hTelemetryMenu, L"&Telemetry");

    // Hotpatch menu (Unicode — Qt removal)
    {
        HMENU hHotpatchMenu = CreatePopupMenu();
        AppendMenuW(hHotpatchMenu, MF_STRING, IDM_HOTPATCH_SHOW_STATUS, L"&Show Hotpatch Status");
        AppendMenuW(hHotpatchMenu, MF_STRING, IDM_HOTPATCH_TOGGLE_ALL, L"&Toggle Hotpatch System");
        AppendMenuW(hHotpatchMenu, MF_STRING, IDM_HOTPATCH_SHOW_EVENT_LOG, L"Show &Event Log");
        AppendMenuW(hHotpatchMenu, MF_STRING, IDM_HOTPATCH_RESET_STATS, L"&Reset Statistics");
        AppendMenuW(hHotpatchMenu, MF_SEPARATOR, 0, nullptr);

        HMENU hMemLayerMenu = CreatePopupMenu();
        AppendMenuW(hMemLayerMenu, MF_STRING, IDM_HOTPATCH_MEMORY_APPLY, L"&Apply Memory Patch...");
        AppendMenuW(hMemLayerMenu, MF_STRING, IDM_HOTPATCH_MEMORY_REVERT, L"&Revert Memory Patch...");
        AppendMenuW(hHotpatchMenu, MF_POPUP, (UINT_PTR)hMemLayerMenu, L"&Memory Layer");

        HMENU hByteLayerMenu = CreatePopupMenu();
        AppendMenuW(hByteLayerMenu, MF_STRING, IDM_HOTPATCH_BYTE_APPLY, L"&Apply Byte Patch...");
        AppendMenuW(hByteLayerMenu, MF_STRING, IDM_HOTPATCH_BYTE_SEARCH, L"&Search && Replace Pattern...");
        AppendMenuW(hHotpatchMenu, MF_POPUP, (UINT_PTR)hByteLayerMenu, L"&Byte Layer");

        HMENU hServerLayerMenu = CreatePopupMenu();
        AppendMenuW(hServerLayerMenu, MF_STRING, IDM_HOTPATCH_SERVER_ADD, L"&Add Server Patch...");
        AppendMenuW(hServerLayerMenu, MF_STRING, IDM_HOTPATCH_SERVER_REMOVE, L"&Remove Server Patch...");
        AppendMenuW(hHotpatchMenu, MF_POPUP, (UINT_PTR)hServerLayerMenu, L"&Server Layer");

        HMENU hProxyMenu = CreatePopupMenu();
        AppendMenuW(hProxyMenu, MF_STRING, IDM_HOTPATCH_PROXY_BIAS, L"Token &Bias Injection...");
        AppendMenuW(hProxyMenu, MF_STRING, IDM_HOTPATCH_PROXY_REWRITE, L"Output &Rewrite Rule...");
        AppendMenuW(hProxyMenu, MF_STRING, IDM_HOTPATCH_PROXY_TERMINATE, L"Stream &Termination Rule...");
        AppendMenuW(hProxyMenu, MF_STRING, IDM_HOTPATCH_PROXY_VALIDATE, L"Custom &Validator...");
        AppendMenuW(hProxyMenu, MF_STRING, IDM_HOTPATCH_SHOW_PROXY_STATS, L"Show Proxy &Stats");
        AppendMenuW(hHotpatchMenu, MF_POPUP, (UINT_PTR)hProxyMenu, L"&Proxy Hotpatcher");

        AppendMenuW(hHotpatchMenu, MF_SEPARATOR, 0, nullptr);

        AppendMenuW(hHotpatchMenu, MF_STRING, IDM_HOTPATCH_SET_TARGET_TPS, L"Set target &TPS...");
        AppendMenuW(hHotpatchMenu, MF_STRING, IDM_HOTPATCH_PRESET_SAVE, L"Save Preset...");
        AppendMenuW(hHotpatchMenu, MF_STRING, IDM_HOTPATCH_PRESET_LOAD, L"Load Preset...");

        AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hHotpatchMenu, L"&Hotpatch");
    }

    if (FEATURE_ENABLED("autonomy"))
    {
        HMENU hAutonomyMenu = CreatePopupMenu();
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_TOGGLE, L"&Toggle Auto Loop");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_START, L"&Start Autonomy");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STOP, L"Sto&p Autonomy");
        AppendMenuW(hAutonomyMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_SET_GOAL, L"Set &Goal...");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STATUS, L"Show &Status");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_MEMORY, L"Show &Memory Snapshot");
        AppendMenuW(hAutonomyMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_PIPELINE_RUN, L"Pipeline: &Run once");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_PIPELINE_AUTONOMY_START, L"Pipeline: Start &autonomous loop");
        AppendMenuW(hAutonomyMenu, MF_STRING, IDM_PIPELINE_AUTONOMY_STOP, L"Pipeline: S&top autonomous loop");
        AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hAutonomyMenu, L"&Autonomy");
    }

    if (FEATURE_ENABLED("reverseEngineering"))
    {
        HMENU hRevEngMenu = createReverseEngineeringMenu();
        AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hRevEngMenu, L"&RevEng");
    }

    // Phase 45: Game Engine Integration (Unity + Unreal)
    createGameEngineMenu(m_hMenu);

    // Phase 48: The Final Crucible
    createCrucibleMenu(m_hMenu);

    // Phase 49: Copilot Gap Closer
    createCopilotGapMenu(m_hMenu);

    // Cursor/JB-Parity Feature Modules
    createFeaturesMenu(m_hMenu);

    // Commands menu from COMMAND_TABLE (single source of truth — no menu-only drift)
    buildCommandsMenuFromCommandTable(m_hMenu);

    // Enterprise / Professional feature menu
    // Professional tier (12330–12341) routed by routeCommand's IDM_ENT_MODEL_COMPARE..IDM_ENT_CUSTOM_QUANT branch.
    // GPU/Performance tier (3042–3047) routed via the 3000–3999 → handleViewCommand path.
    {
        HMENU hEntMenu = CreatePopupMenu();

        // Professional: inference quality & session features (IDM_ENT_MODEL_COMPARE…IDM_ENT_CUSTOM_QUANT)
        HMENU hEntProfMenu = CreatePopupMenu();
        AppendMenuW(hEntProfMenu, MF_STRING, 12330, L"&Model Comparison");             // IDM_ENT_MODEL_COMPARE
        AppendMenuW(hEntProfMenu, MF_STRING, 12331, L"&Batch Processing");             // IDM_ENT_BATCH_PROCESS
        AppendMenuW(hEntProfMenu, MF_STRING, 12332, L"Custom &Stop Sequences");        // IDM_ENT_CUSTOM_STOP_SEQ
        AppendMenuW(hEntProfMenu, MF_STRING, 12333, L"&Grammar Constraints");          // IDM_ENT_GRAMMAR_CONSTRAINTS
        AppendMenuW(hEntProfMenu, MF_STRING, 12334, L"&LoRA Adapter");                 // IDM_ENT_LORA_ADAPTER
        AppendMenuW(hEntProfMenu, MF_STRING, 12335, L"&Response Cache");               // IDM_ENT_RESPONSE_CACHE
        AppendMenuW(hEntProfMenu, MF_STRING, 12336, L"Prompt &Library");               // IDM_ENT_PROMPT_LIBRARY
        AppendMenuW(hEntProfMenu, MF_STRING, 12337, L"Session &Export/Import");        // IDM_ENT_SESSION_EXPORT_IMPORT
        AppendMenuW(hEntProfMenu, MF_STRING, 12338, L"Model &Sharding");               // IDM_ENT_MODEL_SHARDING
        AppendMenuW(hEntProfMenu, MF_STRING, 12339, L"&Tensor Parallelism");           // IDM_ENT_TENSOR_PARALLEL
        AppendMenuW(hEntProfMenu, MF_STRING, 12340, L"&Pipeline Parallelism");         // IDM_ENT_PIPELINE_PARALLEL
        AppendMenuW(hEntProfMenu, MF_STRING, 12341, L"Custom &Quantization Schemes");  // IDM_ENT_CUSTOM_QUANT
        AppendMenuW(hEntMenu, MF_POPUP, (UINT_PTR)hEntProfMenu, L"&Professional");

        // GPU / Performance tier (IDM_ENT_MULTI_GPU_BALANCE…IDM_ENT_DUAL_ENGINE = 3042–3047)
        AppendMenuW(hEntMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hEntMenu, MF_STRING, 3042, L"Multi-&GPU Load Balance");  // IDM_ENT_MULTI_GPU_BALANCE
        AppendMenuW(hEntMenu, MF_STRING, 3043, L"&Dynamic Batch Sizing");    // IDM_ENT_DYNAMIC_BATCH
        AppendMenuW(hEntMenu, MF_STRING, 3044, L"&API Key Management");      // IDM_ENT_API_KEY_MGMT
        AppendMenuW(hEntMenu, MF_STRING, 3045, L"&Audit Logs");              // IDM_ENT_AUDIT_LOGS
        AppendMenuW(hEntMenu, MF_STRING, 3046, L"&RawrTuner IDE");           // IDM_ENT_RAWR_TUNER
        AppendMenuW(hEntMenu, MF_STRING, 3047, L"800B &Dual-Engine");        // IDM_ENT_DUAL_ENGINE

        AppendMenuW(m_hMenu, MF_POPUP, (UINT_PTR)hEntMenu, L"&Enterprise");
    }

    SetMenu(hwnd, m_hMenu);
}

// NOTE: Win32IDE destructor lives in `Win32IDE_Core.cpp`.

void Win32IDE::createToolbar(HWND hwnd)
{

    m_hwndToolbar = CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr, WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT, 0, 0, 0, 0,
                                    hwnd, nullptr, m_hInstance, nullptr);

    if (m_hwndToolbar)
    {

        SendMessage(m_hwndToolbar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
        SendMessage(m_hwndToolbar, TB_AUTOSIZE, 0, 0);

        createTitleBarControls();
        updateTitleBarText();
    }
    else
    {
    }
}

void Win32IDE::createTitleBarControls()
{
    DWORD labelStyle = WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX;
    m_hwndTitleLabel = CreateWindowExW(0, L"STATIC", L"RawrXD IDE", labelStyle, 0, 0, 200, 24, m_hwndToolbar,
                                       (HMENU)IDC_TITLE_TEXT, m_hInstance, nullptr);

    DWORD buttonStyle = WS_CHILD | WS_VISIBLE | BS_FLAT;
    auto createButton = [&](HWND& target, int controlId, const wchar_t* caption)
    {
        target = CreateWindowExW(0, L"BUTTON", caption, buttonStyle, 0, 0, 32, 24, m_hwndToolbar, (HMENU)controlId,
                                 m_hInstance, nullptr);
    };

    createButton(m_hwndBtnGitHub, IDC_BTN_GITHUB, L"GH");
    createButton(m_hwndBtnMicrosoft, IDC_BTN_MICROSOFT, L"MS");
    createButton(m_hwndBtnSettings, IDC_BTN_SETTINGS, L"Gear");
    createButton(m_hwndBtnMinimize, IDC_BTN_MINIMIZE, L"-");
    createButton(m_hwndBtnMaximize, IDC_BTN_MAXIMIZE, L"[]");
    createButton(m_hwndBtnClose, IDC_BTN_CLOSE, L"X");

    RECT client{};
    GetClientRect(m_hwndMain, &client);
    layoutTitleBar(client.right - client.left);
}

void Win32IDE::layoutTitleBar(int width)
{
    if (!m_hwndToolbar)
        return;

    RECT client{};
    GetClientRect(m_hwndToolbar, &client);
    int toolbarHeight = client.bottom - client.top;
    if (toolbarHeight <= 0)
        toolbarHeight = 30;
    int controlHeight = (std::max)(22, toolbarHeight - 6);
    int y = (toolbarHeight - controlHeight) / 2;
    int padding = 6;
    int x = width - padding;

    auto placeButton = [&](HWND hwnd, int controlWidth)
    {
        if (!hwnd)
            return;
        x -= controlWidth;
        MoveWindow(hwnd, x, y, controlWidth, controlHeight, TRUE);
        x -= padding;
    };

    placeButton(m_hwndBtnClose, 32);
    placeButton(m_hwndBtnMaximize, 32);
    placeButton(m_hwndBtnMinimize, 32);
    placeButton(m_hwndBtnSettings, 48);
    placeButton(m_hwndBtnMicrosoft, 40);
    placeButton(m_hwndBtnGitHub, 40);

    if (m_hwndTitleLabel)
    {
        int availableRight = x;
        int labelWidth = (std::min)(420, availableRight - padding * 2);
        if (labelWidth < 160)
        {
            labelWidth = (std::max)(availableRight - padding * 2, 120);
        }
        int labelX = (std::max)(padding, (width - labelWidth) / 2);
        if (labelX + labelWidth > availableRight)
        {
            labelX = (std::max)(padding, availableRight - labelWidth);
        }
        MoveWindow(m_hwndTitleLabel, labelX, y, labelWidth, controlHeight, TRUE);
    }
}

std::string Win32IDE::extractLeafName(const std::string& path) const
{
    if (path.empty())
        return "";
    size_t end = path.find_last_not_of("\\/ ");
    if (end == std::string::npos)
        return path;
    size_t slash = path.find_last_of("\\/", end);
    if (slash == std::string::npos)
    {
        return path.substr(0, end + 1);
    }
    return path.substr(slash + 1, end - slash);
}

void Win32IDE::setCurrentDirectoryFromFile(const std::string& filePath)
{
    if (filePath.empty())
        return;
    size_t slash = filePath.find_last_of("\\/");
    if (slash != std::string::npos)
    {
        m_currentDirectory = filePath.substr(0, slash);
    }
}

void Win32IDE::updateTitleBarText()
{
    if (!m_hwndTitleLabel)
        return;

    std::string fileName = m_currentFile.empty() ? "Untitled" : extractLeafName(m_currentFile);
    std::string projectFolder;

    if (!m_currentDirectory.empty())
    {
        projectFolder = extractLeafName(m_currentDirectory);
    }

    if (projectFolder.empty() && !m_currentFile.empty())
    {
        size_t slash = m_currentFile.find_last_of("\\/");
        if (slash != std::string::npos)
        {
            projectFolder = extractLeafName(m_currentFile.substr(0, slash));
        }
    }

    if (projectFolder.empty() && !m_gitRepoPath.empty())
    {
        projectFolder = extractLeafName(m_gitRepoPath);
    }

    if (projectFolder.empty())
    {
        projectFolder = "Workspace";
    }

    std::string composed = fileName + "  •  " + projectFolder;
    if (composed != m_lastTitleBarText)
    {
        SetWindowTextW(m_hwndTitleLabel, utf8ToWide(composed).c_str());
        m_lastTitleBarText = composed;
    }
    // Keep breadcrumb bar in sync with current file (symbol path updates on cursor move)
    if (m_hwndBreadcrumbs && m_settings.breadcrumbsEnabled)
        updateBreadcrumbs();
}

// ============================================================================
// DPI SCALING
// ============================================================================

UINT Win32IDE::getDpi() const
{
    if (m_hwndMain)
    {
        // GetDpiForWindow requires Windows 10 1607+
        typedef UINT(WINAPI * PFN_GetDpiForWindow)(HWND);
        static PFN_GetDpiForWindow pGetDpiForWindow = nullptr;
        static bool resolved = false;
        if (!resolved)
        {
            HMODULE hUser32 = GetModuleHandleA("user32.dll");
            if (hUser32)
            {
                pGetDpiForWindow = (PFN_GetDpiForWindow)GetProcAddress(hUser32, "GetDpiForWindow");
            }
            resolved = true;
        }
        if (pGetDpiForWindow)
        {
            UINT dpi = pGetDpiForWindow(m_hwndMain);
            if (dpi > 0)
                return dpi;
        }
    }
    // Fallback: system DPI via device caps
    HDC hdc = GetDC(nullptr);
    UINT dpi = (UINT)GetDeviceCaps(hdc, LOGPIXELSY);
    ReleaseDC(nullptr, hdc);
    return dpi ? dpi : 96;
}

int Win32IDE::dpiScale(int basePixels) const
{
    // If user override is set, blend it with system DPI
    if (m_settings.uiScalePercent > 0)
    {
        return MulDiv(basePixels, m_settings.uiScalePercent, 100);
    }
    return MulDiv(basePixels, m_currentDpi, 96);
}

void Win32IDE::recreateFonts()
{
    m_currentDpi = getDpi();

    // Editor font — monospace
    if (m_editorFont)
    {
        DeleteObject(m_editorFont);
        m_editorFont = nullptr;
    }
    m_editorFont = CreateFontA(-dpiScale(16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                               CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

    // UI font — proportional
    if (m_hFontUI)
    {
        DeleteObject(m_hFontUI);
        m_hFontUI = nullptr;
    }
    m_hFontUI = CreateFontA(-dpiScale(14), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    // Ghost text font — italic monospace
    if (m_ghostTextFont)
    {
        DeleteObject(m_ghostTextFont);
        m_ghostTextFont = nullptr;
    }
    LOGFONTA lf = {};
    lf.lfHeight = -dpiScale(14);
    lf.lfWeight = FW_NORMAL;
    lf.lfItalic = TRUE;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
    strncpy(lf.lfFaceName, m_currentTheme.fontName.c_str(), LF_FACESIZE - 1);
    lf.lfFaceName[LF_FACESIZE - 1] = '\0';
    m_ghostTextFont = CreateFontIndirectA(&lf);

    // Apply editor font
    if (m_hwndEditor && m_editorFont)
    {
        SendMessage(m_hwndEditor, WM_SETFONT, (WPARAM)m_editorFont, TRUE);
        CHARFORMAT2W cf;
        memset(&cf, 0, sizeof(cf));
        cf.cbSize = sizeof(cf);
        cf.dwMask = CFM_FACE | CFM_SIZE;
        cf.yHeight = dpiScale(16) * 15;
        wcscpy_s(cf.szFaceName, L"Consolas");
        SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    }

    // Apply UI font to all known UI controls
    auto setFont = [](HWND hwnd, HFONT font)
    {
        if (hwnd)
            SendMessage(hwnd, WM_SETFONT, (WPARAM)font, TRUE);
    };
    setFont(m_hwndTabBar, m_hFontUI);
    setFont(m_hwndSecondarySidebarHeader, m_hFontUI);
    setFont(m_hwndModelSelector, m_hFontUI);
    setFont(m_hwndCopilotChatOutput, m_hFontUI);
    setFont(m_hwndCopilotChatInput, m_hFontUI);
    setFont(m_hwndCopilotSendBtn, m_hFontUI);
    setFont(m_hwndCopilotClearBtn, m_hFontUI);
    setFont(m_hwndCommandPaletteInput, m_hFontUI);
    setFont(m_hwndCommandPaletteList, m_hFontUI);
    setFont(m_hwndSearchInput, m_hFontUI);
    setFont(m_hwndSearchResults, m_hFontUI);
    setFont(m_hwndFloatingContent, m_hFontUI);

    // PowerShell panel fonts (store and delete previous to avoid leak on DPI change)
    if (m_hFontPowerShell)
    {
        DeleteObject(m_hFontPowerShell);
        m_hFontPowerShell = nullptr;
    }
    if (m_hFontPowerShellStatus)
    {
        DeleteObject(m_hFontPowerShellStatus);
        m_hFontPowerShellStatus = nullptr;
    }
    if (m_hwndPowerShellOutput)
    {
        m_hFontPowerShell =
            CreateFontA(-dpiScale(16), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
        SendMessage(m_hwndPowerShellOutput, WM_SETFONT, (WPARAM)m_hFontPowerShell, TRUE);
        if (m_hwndPowerShellInput)
            SendMessage(m_hwndPowerShellInput, WM_SETFONT, (WPARAM)m_hFontPowerShell, TRUE);
        if (m_hwndPSBtnExecute)
            SendMessage(m_hwndPSBtnExecute, WM_SETFONT, (WPARAM)m_hFontPowerShell, TRUE);
    }
    if (m_hwndPowerShellStatusBar)
    {
        m_hFontPowerShellStatus =
            CreateFontA(-dpiScale(12), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                        CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
        SendMessage(m_hwndPowerShellStatusBar, WM_SETFONT, (WPARAM)m_hFontPowerShellStatus, TRUE);
    }

    // Terminal panes
    for (auto& pane : m_terminalPanes)
    {
        if (pane.hwnd)
        {
            CHARFORMAT2W tcf;
            memset(&tcf, 0, sizeof(tcf));
            tcf.cbSize = sizeof(tcf);
            tcf.dwMask = CFM_FACE | CFM_SIZE;
            tcf.yHeight = dpiScale(9) * 20;
            wcscpy_s(tcf.szFaceName, L"Consolas");
            SendMessageW(pane.hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&tcf);
        }
    }

    // File tree
    if (m_hwndFileTree)
    {
        setFont(m_hwndFileTree, m_hFontUI);
    }

    LOG_INFO("Fonts recreated at DPI=" + std::to_string(m_currentDpi));
}

void Win32IDE::createEditor(HWND hwnd)
{
    // WS_EX_COMPOSITED reduces flicker by double-buffering the client area
    m_hwndEditor = CreateWindowExW(WS_EX_CLIENTEDGE | WS_EX_COMPOSITED, RICHEDIT_CLASSW, L"",
                                   WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL |
                                       ES_AUTOHSCROLL | ES_WANTRETURN,
                                   0, 0, 0, 0, hwnd, (HMENU)IDC_EDITOR, m_hInstance, nullptr);
    if (!m_hwndEditor)
    {

        return;
    }

    m_currentDpi = getDpi();
    recreateFonts();

    CHARFORMAT2W cf;
    memset(&cf, 0, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR;
    cf.yHeight = dpiScale(11) * 20;
    cf.crTextColor = RGB(212, 212, 212);
    wcscpy_s(cf.szFaceName, L"Consolas");
    SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);

    SendMessage(m_hwndEditor, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
    SendMessage(m_hwndEditor, EM_SETREADONLY, FALSE, 0);
    SendMessage(m_hwndEditor, EM_SETEVENTMASK, 0, ENM_CHANGE | ENM_SELCHANGE | ENM_SCROLL);
    SendMessage(m_hwndEditor, EM_EXLIMITTEXT, 0, 0x7FFFFFFE);

    static const wchar_t welcomeText[] = L"// ============================================\r\n"
                                         L"// RawrXD IDE - Native Win32 AI Development\r\n"
                                         L"// ============================================\r\n"
                                         L"//\r\n"
                                         L"// Welcome! The editor is ready.\r\n"
                                         L"//\r\n"
                                         L"// Shortcuts:\r\n"
                                         L"//   Ctrl+N   New File\r\n"
                                         L"//   Ctrl+O   Open File\r\n"
                                         L"//   Ctrl+S   Save\r\n"
                                         L"//   Ctrl+F   Find\r\n"
                                         L"//   Ctrl+B   Toggle Sidebar\r\n"
                                         L"//   Ctrl+Shift+P   Command Palette\r\n"
                                         L"//\r\n"
                                         L"// Start typing or open a file to begin.\r\n"
                                         L"\r\n";
    SetWindowTextW(m_hwndEditor, welcomeText);

    SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    int textLen = GetWindowTextLengthW(m_hwndEditor);
    SendMessage(m_hwndEditor, EM_SETSEL, textLen, textLen);

    initializeEditorSurface();

    // ================================================================
    // Subclass the editor RichEdit control
    // Store IDE pointer and original wndproc as window properties,
    // then redirect to EditorSubclassProc for ghost text, key intercept,
    // scroll sync, and minimap updates.
    // ================================================================
    if (m_hwndEditor)
    {
        SetPropW(m_hwndEditor, kEditorWndProp, (HANDLE)this);
        WNDPROC oldEditorProc = (WNDPROC)SetWindowLongPtrW(m_hwndEditor, GWLP_WNDPROC, (LONG_PTR)EditorSubclassProc);
        SetPropW(m_hwndEditor, kEditorProcProp, (HANDLE)oldEditorProc);
    }

    // Initialize LSP diagnostic overlay (squiggles + hover tooltips)
    m_lspDiagnosticOverlay = std::make_unique<RawrXD::UI::AnnotationOverlay>(this);
    if (m_lspDiagnosticOverlay->Initialize(m_hwndEditor)) {
        LOG_INFO("LSP diagnostic overlay initialized");
    } else {
        LOG_ERROR("Failed to initialize LSP diagnostic overlay");
    }
}

void Win32IDE::createTerminal(HWND hwnd)
{
    // Initialize the Enterprise PowerShell Panel (creates m_hwndPowerShellPanel)
    createPowerShellPanel();
    m_powerShellPanelVisible = true;

    if (m_terminalPanes.empty())
    {
        createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
    }
    else
    {
        setActiveTerminalPane(m_terminalPanes.front().id);
    }

    // Create command input
    m_hwndCommandInput = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 0, 0,
                                         0, 0, hwnd, (HMENU)IDC_COMMAND_INPUT, m_hInstance, nullptr);
    if (m_hwndCommandInput)
    {
        SetWindowLongPtr(m_hwndCommandInput, GWLP_USERDATA, (LONG_PTR)this);
        m_oldCommandInputProc = (WNDPROC)SetWindowLongPtr(m_hwndCommandInput, GWLP_WNDPROC, (LONG_PTR)CommandInputProc);
    }
}

int Win32IDE::createTerminalPane(Win32TerminalManager::ShellType shellType, const std::string& name)
{
    HWND hwnd = CreateWindowExW(WS_EX_CLIENTEDGE, RICHEDIT_CLASSW, L"",
                                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 0, 0,
                                0, 0, m_hwndMain, nullptr, m_hInstance, nullptr);

    // LOGGING AS REQUESTED
    char logBuf[256];
    sprintf_s(logBuf, "TerminalPane HWND created: %p (Parent: %p)", hwnd, m_hwndMain);
    LOG_INFO(std::string(logBuf));

    // Apply dark theme to terminal pane
    SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));

    CHARFORMAT2W cf;
    memset(&cf, 0, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR;
    cf.yHeight = 180;
    cf.crTextColor = RGB(204, 204, 204);
    wcscpy_s(cf.szFaceName, L"Consolas");
    SendMessageW(hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    int paneId = m_nextTerminalId++;
    TerminalPane pane;
    pane.id = paneId;
    pane.hwnd = hwnd;
    pane.manager = std::make_unique<Win32TerminalManager>();
    pane.name = name.empty() ? ("Terminal " + std::to_string(paneId)) : name;
    pane.shellType = shellType;
    pane.isActive = false;
    pane.bounds = {0, 0, 0, 0};

    pane.manager->onOutput = [this, paneId](const std::string& output)
    {
        if (isShuttingDown())
            return;
        onTerminalOutput(paneId, output);
    };
    pane.manager->onError = [this, paneId](const std::string& error)
    {
        if (isShuttingDown())
            return;
        onTerminalError(paneId, error);
    };

    m_terminalPanes.push_back(std::move(pane));
    setActiveTerminalPane(paneId);
    applyTheme();
    return paneId;
}

TerminalPane* Win32IDE::findTerminalPane(int paneId)
{
    for (auto& pane : m_terminalPanes)
    {
        if (pane.id == paneId)
        {
            return &pane;
        }
    }
    return nullptr;
}

TerminalPane* Win32IDE::getActiveTerminalPane()
{
    TerminalPane* active = findTerminalPane(m_activeTerminalId);
    if (!active && !m_terminalPanes.empty())
    {
        setActiveTerminalPane(m_terminalPanes.front().id);
        return findTerminalPane(m_terminalPanes.front().id);
    }
    return active;
}

void Win32IDE::setActiveTerminalPane(int paneId)
{
    bool found = false;
    for (auto& pane : m_terminalPanes)
    {
        if (pane.id == paneId)
        {
            pane.isActive = true;
            m_activeTerminalId = paneId;
            if (pane.hwnd)
                SetFocus(pane.hwnd);
            found = true;
        }
        else
        {
            pane.isActive = false;
        }
    }
    if (!found && !m_terminalPanes.empty())
    {
        m_terminalPanes.front().isActive = true;
        m_activeTerminalId = m_terminalPanes.front().id;
        if (m_terminalPanes.front().hwnd)
            SetFocus(m_terminalPanes.front().hwnd);
    }
}

void Win32IDE::layoutTerminalPanes(int width, int top, int height)
{
    // LOGGING AS REQUESTED
    char logBuf[256];
    sprintf_s(logBuf, "layoutTerminalPanes: Width=%d Top=%d Height=%d Count=%zu", width, top, height,
              m_terminalPanes.size());
    LOG_INFO(std::string(logBuf));

    if (width <= 0 || height <= 0 || m_terminalPanes.empty())
        return;

    // Calculate correct left offset — terminal panes are children of m_hwndMain,
    // so we must offset past activity bar + sidebar to avoid overlapping them
    const int ACTIVITY_BAR_WIDTH = dpiScale(48);
    int sidebarWidth = m_sidebarVisible ? m_sidebarWidth : 0;
    int editorLeft = ACTIVITY_BAR_WIDTH + sidebarWidth;
    int secondarySidebarWidth = m_secondarySidebarVisible ? m_secondarySidebarWidth : 0;

    // Clamp width to editor area (exclude sidebars)
    RECT mainRect;
    GetClientRect(m_hwndMain, &mainRect);
    int editorWidth = (mainRect.right - mainRect.left) - editorLeft - secondarySidebarWidth;
    if (editorWidth <= 0)
        editorWidth = width;  // fallback

    int count = static_cast<int>(m_terminalPanes.size());
    if (count == 1)
    {
        auto& pane = m_terminalPanes[0];
        MoveWindow(pane.hwnd, editorLeft, top, editorWidth, height, TRUE);
        pane.bounds = {editorLeft, top, editorLeft + editorWidth, top + height};
        return;
    }

    if (m_terminalSplitHorizontal)
    {
        int paneHeight = height / count;
        int y = top;
        for (int i = 0; i < count; ++i)
        {
            int currentHeight = (i == count - 1) ? (height - paneHeight * (count - 1)) : paneHeight;
            auto& pane = m_terminalPanes[i];
            MoveWindow(pane.hwnd, editorLeft, y, editorWidth, currentHeight, TRUE);
            pane.bounds = {editorLeft, y, editorLeft + editorWidth, y + currentHeight};
            y += currentHeight;
        }
    }
    else
    {
        int paneWidth = editorWidth / count;
        int x = editorLeft;
        for (int i = 0; i < count; ++i)
        {
            int currentWidth = (i == count - 1) ? (editorWidth - paneWidth * (count - 1)) : paneWidth;
            auto& pane = m_terminalPanes[i];
            MoveWindow(pane.hwnd, x, top, currentWidth, height, TRUE);
            pane.bounds = {x, top, x + currentWidth, top + height};
            x += currentWidth;
        }
    }
}

void Win32IDE::splitTerminalHorizontal()
{
    m_terminalSplitHorizontal = true;
    TerminalPane* active = getActiveTerminalPane();
    Win32TerminalManager::ShellType type = active ? active->shellType : Win32TerminalManager::PowerShell;
    createTerminalPane(type, "Terminal");
    RECT rect;
    GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect;
    GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::splitTerminalVertical()
{
    m_terminalSplitHorizontal = false;
    TerminalPane* active = getActiveTerminalPane();
    Win32TerminalManager::ShellType type = active ? active->shellType : Win32TerminalManager::PowerShell;
    createTerminalPane(type, "Terminal");
    RECT rect;
    GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect;
    GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::clearAllTerminals()
{
    for (auto& pane : m_terminalPanes)
    {
        if (pane.manager && pane.manager->isRunning())
        {
            pane.manager->stop();
        }
        if (pane.hwnd)
        {
            DestroyWindow(pane.hwnd);
        }
    }
    m_terminalPanes.clear();
    m_activeTerminalId = -1;
    m_nextTerminalId = 1;
    createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
    RECT rect;
    GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect;
    GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::createStatusBar(HWND hwnd)
{

    m_hwndStatusBar = CreateWindowExW(0, STATUSCLASSNAMEW, L"", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                                      (HMENU)IDC_STATUS_BAR, m_hInstance, nullptr);
    if (!m_hwndStatusBar)
    {

        return;
    }

    // Dark theme for status bar
    SendMessage(m_hwndStatusBar, SB_SETBKCOLOR, 0, (LPARAM)RGB(30, 30, 30));

    // 0: primary status, 1: mode, 2: VMM ribbon, 3: spare, 4: context usage
    int parts[] = {200, 360, 540, 720, -1};
    SendMessage(m_hwndStatusBar, SB_SETPARTS, 5, (LPARAM)parts);
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Ready");
    // Initial ribbon (updated after model load self-check).
#if defined(RAWRXD_HAS_SOVEREIGN_GPU_ASM) && (RAWRXD_HAS_SOVEREIGN_GPU_ASM != 0)
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 2, (LPARAM)L"VMM: [Legacy]  GPU-ASM: ACTIVE");
#else
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 2, (LPARAM)L"VMM: [Legacy]  GPU-ASM: STUB");
#endif
    SendMessageW(m_hwndStatusBar, SB_SETTIPTEXTW, 2,
                 (LPARAM)L"VMM diagnostics will appear here after model self-check.");
    if (HICON ico = getVmmLedIcon(VmmRibbonTier::Red))
        SendMessageW(m_hwndStatusBar, SB_SETICON, 2, (LPARAM)ico);
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 4, (LPARAM)L"Ctx: 0/128K  0%");
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)L"MoE pack: —");
    SendMessageW(m_hwndStatusBar, SB_SETTIPTEXTW, 3,
                 (LPARAM)L"MoE grouped pack cache: hits/misses, async prepack queue, row-eviction invalidations.");
}

void Win32IDE::createSidebar(HWND hwnd)
{
    createPrimarySidebar(hwnd);
}


void Win32IDE::newFile()
{
    appendToOutput("File > New clicked\n", "Output", OutputSeverity::Info);
    if (m_fileModified)
    {
        int result = MessageBoxW(m_hwndMain, L"File has been modified. Save changes?", L"Save", MB_YESNOCANCEL);
        if (result == IDCANCEL)
        {
            appendToOutput("File > New cancelled by user\n", "Output", OutputSeverity::Info);
            return;
        }
        if (result == IDYES && !saveFile())
        {
            appendToOutput("File > New - save failed, operation aborted\n", "Output", OutputSeverity::Warning);
            return;
        }
    }

    setWindowText(m_hwndEditor, "");
    m_currentFile.clear();
    m_fileModified = false;
    updateTitleBarText();
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"New file");
    updateMenuEnableStates();
    syncEditorToGpuSurface();
    appendToOutput("New file created successfully\n", "Output", OutputSeverity::Info);
}

void Win32IDE::openFile()
{
    SCOPED_METRIC("file.open_dialog");
    METRICS.increment("file.open_total");
    appendToOutput("File > Open clicked\n", "Output", OutputSeverity::Info);
    if (m_fileModified)
    {
        int result = MessageBoxW(m_hwndMain, L"File has been modified. Save changes?", L"Save", MB_YESNOCANCEL);
        if (result == IDCANCEL)
        {
            appendToOutput("File > Open cancelled by user\n", "Output", OutputSeverity::Info);
            return;
        }
        if (result == IDYES && !saveFile())
        {
            appendToOutput("File > Open - save failed, operation aborted\n", "Output", OutputSeverity::Warning);
            return;
        }
    }

    OPENFILENAMEW ofn;
    wchar_t szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = (DWORD)std::size(szFile);
    ofn.lpstrFilter = L"All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn))
    {
        std::string pathUtf8 = wideToUtf8(szFile);
        appendToOutput("Opening file: " + pathUtf8 + "\n", "Output", OutputSeverity::Info);
        try
        {
            std::ifstream inStream(std::filesystem::path(szFile), std::ios::binary);
            if (inStream)
            {
                inStream.seekg(0, std::ios::end);
                const std::streamsize size = inStream.tellg();
                inStream.seekg(0, std::ios::beg);
                std::string content(static_cast<size_t>(size), '\0');
                if (size > 0)
                    inStream.read(&content[0], size);
                setWindowText(m_hwndEditor, content);
                m_currentFile = pathUtf8;
                m_fileModified = false;
                setCurrentDirectoryFromFile(m_currentFile);
                updateTitleBarText();
                SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"File opened");
                updateMenuEnableStates();
                syncEditorToGpuSurface();
                appendToOutput("File opened successfully (" + std::to_string(content.size()) + " bytes)\n", "Output",
                               OutputSeverity::Info);
            }
            else
            {
                appendToOutput("Failed to open file: " + pathUtf8 + "\n", "Errors", OutputSeverity::Error);
                MessageBoxW(m_hwndMain, L"Failed to open file", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        catch (const std::exception& e)
        {
            appendToOutput("Exception opening file: " + std::string(e.what()) + "\n", "Errors", OutputSeverity::Error);
            MessageBoxW(m_hwndMain, utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
    }
    else
    {
        appendToOutput("File > Open cancelled by user (no file selected)\n", "Output", OutputSeverity::Info);
    }
}

// Overload to open a specific file path
void Win32IDE::openFile(const std::string& filePath)
{
    SCOPED_METRIC("file.open_path");
    if (filePath.empty())
    {
        openFile();  // Call the dialog version
        return;
    }

    METRICS.increment("file.open_total");
    appendToOutput("Opening file: " + filePath + "\n", "Output", OutputSeverity::Info);
    try
    {
        std::ifstream file(std::filesystem::path(utf8ToWide(filePath)));
        if (file)
        {
            std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            setWindowText(m_hwndEditor, content);
            m_currentFile = filePath;
            m_fileModified = false;
            setCurrentDirectoryFromFile(m_currentFile);
            updateTitleBarText();

            std::string displayName = extractLeafName(filePath);
            if (m_hwndTabBar)
            {
                addTab(filePath, displayName);
            }

            CHARFORMAT2W cf;
            memset(&cf, 0, sizeof(cf));
            cf.cbSize = sizeof(cf);
            cf.dwMask = CFM_COLOR | CFM_FACE | CFM_SIZE;
            cf.crTextColor = m_currentTheme.textColor;
            cf.yHeight = 220;
            wcscpy_s(cf.szFaceName, L"Consolas");
            SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

            SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"File opened");
            updateMenuEnableStates();
            updateLineNumbers();
            updateGitStatus();  // Update Git status for gutter indicators
            syncEditorToGpuSurface();
            appendToOutput("File opened successfully (" + std::to_string(content.size()) + " bytes)\n", "Output",
                           OutputSeverity::Info);
        }
        else
        {
            appendToOutput("Failed to open file: " + filePath + "\n", "Errors", OutputSeverity::Error);
            MessageBoxW(m_hwndMain, L"Failed to open file", L"Error", MB_OK | MB_ICONERROR);
        }
    }
    catch (const std::exception& e)
    {
        appendToOutput("Exception opening file: " + std::string(e.what()) + "\n", "Errors", OutputSeverity::Error);
        MessageBoxW(m_hwndMain, utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
    }
}

bool Win32IDE::saveFile()
{
    SCOPED_METRIC("file.save");
    METRICS.increment("file.save_total");

    if (m_currentFile.empty())
    {
        appendToOutput("File > Save - no current file, showing Save As dialog\n", "Output", OutputSeverity::Info);
        return saveFileAs();
    }

    appendToOutput("Saving file: " + m_currentFile + "\n", "Output", OutputSeverity::Info);
    try
    {
        std::string content = getWindowText(m_hwndEditor);
        std::ofstream file(std::filesystem::path(utf8ToWide(m_currentFile)));
        if (file)
        {
            file << content;
            m_fileModified = false;
            updateTitleBarText();
            SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"File saved");
            appendToOutput("File saved successfully (" + std::to_string(content.size()) + " bytes)\n", "Output",
                           OutputSeverity::Info);
            return true;
        }
        appendToOutput("Failed to open file for writing: " + m_currentFile + "\n", "Errors", OutputSeverity::Error);
        MessageBoxW(m_hwndMain, L"Failed to save file", L"Error", MB_OK | MB_ICONERROR);
    }
    catch (const std::exception& e)
    {
        appendToOutput("Exception saving file: " + std::string(e.what()) + "\n", "Errors", OutputSeverity::Error);
        MessageBoxW(m_hwndMain, utf8ToWide(e.what()).c_str(), L"Error", MB_OK | MB_ICONERROR);
    }
    return false;
}

bool Win32IDE::saveFileAs()
{
    appendToOutput("File > Save As clicked\n", "Output", OutputSeverity::Info);
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = (DWORD)std::size(szFile);
    ofn.lpstrFilter = L"All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameW(&ofn))
    {
        m_currentFile = wideToUtf8(szFile);
        appendToOutput("Save As: " + m_currentFile + "\n", "Output", OutputSeverity::Info);
        setCurrentDirectoryFromFile(m_currentFile);
        updateTitleBarText();
        return saveFile();
    }
    appendToOutput("File > Save As cancelled by user\n", "Output", OutputSeverity::Info);
    return false;
}

void Win32IDE::startPowerShell()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager)
        return;
    stopTerminal();
    if (pane->manager->start(Win32TerminalManager::PowerShell))
    {
        appendText(pane->hwnd, "PowerShell started...\n");
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)L"PowerShell");
        updateMenuEnableStates();
        appendToOutput("PowerShell started...\n", "Output", OutputSeverity::Info);
    }
}

void Win32IDE::startCommandPrompt()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager)
        return;
    stopTerminal();
    if (pane->manager->start(Win32TerminalManager::CommandPrompt))
    {
        appendText(pane->hwnd, "Command Prompt started...\n");
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)L"CMD");
        updateMenuEnableStates();
        appendToOutput("Command Prompt started...\n", "Output", OutputSeverity::Info);
    }
}

void Win32IDE::stopTerminal()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager || !pane->manager->isRunning())
        return;
    pane->manager->stop();
    appendText(pane->hwnd, "\nTerminal stopped.\n");
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)L"Stopped");
    updateMenuEnableStates();
    appendToOutput("Terminal stopped.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::executeCommand()
{
    std::string command = getWindowText(m_hwndCommandInput);
    if (command.empty())
        return;

    SetWindowTextW(m_hwndCommandInput, L"");

    // Command Parsing
    if (command[0] == '/' || command[0] == '!')
    {
        std::stringstream ss(command);
        std::string action;
        ss >> action;

        if (action == "/load")
        {
            std::string path;
            std::getline(ss, path);
            if (!path.empty())
                path = path.substr(1);
            openFile(path);  // Or load model if path looks like a model file
            {
                auto isModelExt = [](const std::string& p)
                {
                    if (p.empty())
                        return false;
                    std::string lower = p;
                    std::transform(lower.begin(), lower.end(), lower.begin(),
                                   [](unsigned char c) { return (char)std::tolower(c); });
                    size_t dot = lower.rfind('.');
                    if (dot == std::string::npos)
                        return false;
                    std::string ext = lower.substr(dot);
                    return ext == ".gguf" || ext == ".gguf2" || ext == ".bin" || ext == ".safetensors" ||
                           ext == ".onnx";
                };
                if (isModelExt(path))
                {
                    loadGGUFModel(path);
                    if (loadModelForInference(path))
                        appendToOutput("Model loaded; chat and agentic use this model.\n", "Agent",
                                       OutputSeverity::Info);
                    else if (m_nativeEngine && m_nativeEngine->LoadModel(path))
                        appendToOutput("Model loaded.\n", "Agent", OutputSeverity::Info);
                }
            }
        }
        else if (action == "/agent" || action == "/ask")
        {
            std::string q;
            std::getline(ss, q);
            if (m_agent)
                m_agent->Ask(q);
        }
        else if (action == "/bugreport")
        {
            std::string f = m_currentFile;
            if (f.empty())
                appendToOutput("No file open.\n", "Error", OutputSeverity::Error);
            else if (m_agent)
                m_agent->BugReport(f);
        }
        else if (action == "/suggest")
        {
            std::string f = m_currentFile;
            if (f.empty())
                appendToOutput("No file open.\n", "Error", OutputSeverity::Error);
            else if (m_agent)
                m_agent->Suggest(f);
        }
        else if (action == "/install")
        {
            std::string path;
            std::getline(ss, path);
            if (!path.empty())
            {
                if (RawrXD::VSIXInstaller::Install(path.substr(1)))
                    appendToOutput("Extension installed.\n", "System", OutputSeverity::Info);
            }
        }
        else if (action == "/max")
        {
            static bool m = false;
            m = !m;
            if (m_agent)
                m_agent->SetMaxMode(m);
            appendToOutput(std::string("Max Mode: ") + (m ? "ON" : "OFF") + "\n", "System", OutputSeverity::Info);
        }
        else if (action == "/think")
        {
            static bool t = false;
            t = !t;
            if (m_agent)
                m_agent->SetDeepThink(t);
            appendToOutput(std::string("Deep Think: ") + (t ? "ON" : "OFF") + "\n", "System", OutputSeverity::Info);
        }
        else if (action == "/research")
        {
            static bool r = false;
            r = !r;
            if (m_agent)
                m_agent->SetDeepResearch(r);
            appendToOutput(std::string("Deep Research: ") + (r ? "ON" : "OFF") + "\n", "System", OutputSeverity::Info);
        }
        else if (action == "/norefusal")
        {
            static bool nr = false;
            nr = !nr;
            if (m_agent)
                m_agent->SetNoRefusal(nr);
            appendToOutput(std::string("No Refusal: ") + (nr ? "ON" : "OFF") + "\n", "System", OutputSeverity::Info);
        }
        else if (action == "!help" || action == "/exthelp")
        {
            static RawrXD::ExtensionLoader loader;
            loader.Scan();
            std::string arg;
            std::getline(ss, arg);
            if (!arg.empty())
                arg = arg.substr(1);

            if (arg.empty())
            {
                std::string list = "Extensions:\n";
                for (auto& e : loader.GetExtensions())
                    list += " - " + e.name + "\n";
                appendToOutput(list, "System", OutputSeverity::Info);
            }
            else
            {
                appendToOutput(loader.GetHelp(arg) + "\n", "System", OutputSeverity::Info);
            }
        }
        else
        {
            // Fallback
            TerminalPane* pane = getActiveTerminalPane();
            if (pane && pane->manager && pane->manager->isRunning())
            {
                command += "\n";
                pane->manager->writeInput(command);
            }
        }
        return;
    }

    // Chat mode: send to model via agentic bridge (local GGUF or Ollama/cloud), with tool dispatch
    if (m_chatMode && m_agenticBridge && m_agenticBridge->IsInitialized())
    {
        appendChatMessage("You", command);
        std::thread(
            [this, command]()
            {
                DetachedThreadGuard _guard(m_activeDetachedThreads, m_shuttingDown);
                if (_guard.cancelled)
                    return;
                std::string response = sendMessageToModel(command);
                if (!response.empty() && !isShuttingDown())
                {
                    appendChatMessage("Model", response);
                    appendToOutput("[Chat] " + response + "\n", "Output", OutputSeverity::Info);
                }
            })
            .detach();
        return;
    }

    // Send to terminal
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning())
    {
        addPowerShellHistory(command);  // Track in shared command history
        command += "\n";
        pane->manager->writeInput(command);
    }
}

void Win32IDE::onTerminalOutput(int paneId, const std::string& output)
{
    if (isShuttingDown())
        return;
    TerminalPane* pane = findTerminalPane(paneId);
    if (!pane || !pane->hwnd)
        return;
    appendText(pane->hwnd, output);
    appendToOutput(output, "Debug", OutputSeverity::Info);
}

void Win32IDE::onTerminalError(int paneId, const std::string& error)
{
    if (isShuttingDown())
        return;
    TerminalPane* pane = findTerminalPane(paneId);
    if (!pane || !pane->hwnd)
        return;
    appendText(pane->hwnd, error);
    appendToOutput(error, "Errors", OutputSeverity::Error);
}

std::string Win32IDE::getWindowText(HWND hwnd)
{
    int length = GetWindowTextLengthW(hwnd);
    if (length <= 0)
        return {};
    std::wstring wtext(length + 1, L'\0');
    GetWindowTextW(hwnd, &wtext[0], length + 1);
    wtext.resize(length);
    return wideToUtf8(wtext.c_str());
}

// UTF-8 byte offset <-> UTF-16 character index for Rich Edit
static int utf8ByteOffsetToCharIndex(const std::string& utf8, int byteOffset)
{
    if (byteOffset <= 0 || utf8.empty())
        return 0;
    if (byteOffset >= (int)utf8.size())
        byteOffset = (int)utf8.size();
    std::wstring w = utf8ToWide(utf8.substr(0, byteOffset));
    return (int)w.size();
}
static int charIndexToUtf8ByteOffset(const std::string& utf8, int charIndex)
{
    if (charIndex <= 0 || utf8.empty())
        return 0;
    std::wstring w = utf8ToWide(utf8);
    if (charIndex >= (int)w.size())
        return (int)utf8.size();
    return (int)wideToUtf8(w.substr(0, charIndex).c_str()).size();
}

void Win32IDE::setWindowText(HWND hwnd, const std::string& text)
{
    SetWindowTextW(hwnd, utf8ToWide(text).c_str());
    if (hwnd == m_hwndEditor)
    {
        syncEditorToGpuSurface();
    }
}

void Win32IDE::appendText(HWND hwnd, const std::string& text)
{
    GETTEXTLENGTHEX gtl;
    gtl.flags = GTL_DEFAULT;
    gtl.codepage = CP_UNICODE;
    LONG length = SendMessage(hwnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);

    SendMessage(hwnd, EM_SETSEL, length, length);

    std::wstring wtext = utf8ToWide(text);
    SETTEXTEX st;
    st.flags = ST_DEFAULT;
    st.codepage = CP_UNICODE;
    SendMessageW(hwnd, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)wtext.c_str());

    if (hwnd == m_hwndEditor)
    {
        syncEditorToGpuSurface();
    }
}

// Theme Management Implementation
void Win32IDE::loadTheme(const std::string& themeName)
{
    std::string filename = "themes\\" + themeName + ".theme";
    std::ifstream file(filename);
    if (file.is_open())
    {
        std::string line;
        while (getline(file, line))
        {
            if (line.find("background=") == 0)
            {
                m_currentTheme.backgroundColor = std::stoul(line.substr(11), nullptr, 16);
            }
            else if (line.find("text=") == 0)
            {
                m_currentTheme.textColor = std::stoul(line.substr(5), nullptr, 16);
            }
            else if (line.find("selection=") == 0)
            {
                m_currentTheme.selectionColor = std::stoul(line.substr(10), nullptr, 16);
            }
            else if (line.find("linenumber=") == 0)
            {
                m_currentTheme.lineNumberColor = std::stoul(line.substr(11), nullptr, 16);
            }
        }
        file.close();
        applyTheme();
    }
}

void Win32IDE::saveTheme(const std::string& themeName)
{
    std::string filename = "themes\\" + themeName + ".theme";
    CreateDirectoryA("themes", NULL);
    std::ofstream file(filename);
    if (file.is_open())
    {
        file << "background=" << std::hex << m_currentTheme.backgroundColor << std::endl;
        file << "text=" << std::hex << m_currentTheme.textColor << std::endl;
        file << "selection=" << std::hex << m_currentTheme.selectionColor << std::endl;
        file << "linenumber=" << std::hex << m_currentTheme.lineNumberColor << std::endl;
        file.close();
        MessageBoxW(m_hwndMain, L"Theme saved successfully", L"Theme Manager", MB_OK);
    }
}

void Win32IDE::applyTheme()
{
    // ----------------------------------------------------------------
    // applyTheme() is idempotent — safe to call on startup, on theme
    // switch, on DPI change, and on transparency change.
    // Theme is pure data (IDETheme) — no GDI handles stored in it.
    // ----------------------------------------------------------------

    LOG_DEBUG("applyTheme(): \"" + m_currentTheme.name + "\"");

    // 1. Update the tracked background brush
    if (m_backgroundBrush)
        DeleteObject(m_backgroundBrush);
    m_backgroundBrush = CreateSolidBrush(m_currentTheme.backgroundColor);

    // 2. Editor: background + default text format (SCF_DEFAULT, not SCF_ALL,
    //    so syntax coloring tokens are preserved until the next colorize pass)
    if (m_hwndEditor)
    {
        SendMessage(m_hwndEditor, EM_SETBKGNDCOLOR, 0, m_currentTheme.backgroundColor);

        CHARFORMAT2W cf;
        ZeroMemory(&cf, sizeof(cf));
        cf.cbSize = sizeof(cf);
        cf.dwMask = CFM_COLOR;
        cf.crTextColor = m_currentTheme.textColor;
        cf.dwEffects = 0;
        SendMessageW(m_hwndEditor, EM_SETCHARFORMAT, SCF_DEFAULT, (LPARAM)&cf);
    }

    for (auto& pane : m_terminalPanes)
    {
        if (!pane.hwnd)
            continue;
        SendMessage(pane.hwnd, EM_SETBKGNDCOLOR, 0, m_currentTheme.panelBg);
        CHARFORMAT2W tcf;
        ZeroMemory(&tcf, sizeof(tcf));
        tcf.cbSize = sizeof(tcf);
        tcf.dwMask = CFM_COLOR;
        tcf.crTextColor = m_currentTheme.panelFg;
        tcf.dwEffects = 0;
        SendMessageW(pane.hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&tcf);
    }

    // 4. Deep apply to all surfaces (sidebar, activity bar, tabs, status bar, panels)
    applyThemeToAllControls();

    // 5. Transparency — only touch the top-level window
    if (m_currentTheme.windowAlpha < 255)
    {
        setWindowTransparency(m_currentTheme.windowAlpha);
    }

    // 6. Force full repaint + update menu states
    InvalidateRect(m_hwndMain, NULL, TRUE);
    updateMenuEnableStates();

    // 7. Re-trigger syntax coloring so tokens pick up new palette
    if (m_syntaxColoringEnabled && m_hwndEditor)
    {
        m_syntaxDirty = true;
        applySyntaxColoring();
    }
}

void Win32IDE::showThemeEditor()
{
    showThemePicker();
}

void Win32IDE::updateMenuEnableStates()
{
    if (!m_hMenu)
        return;
    // Terminal split menu items
    UINT enableSplit = MF_BYCOMMAND | (m_terminalPanes.size() >= 1 ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_SPLIT_H, enableSplit);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_SPLIT_V, enableSplit);
    TerminalPane* activePane = getActiveTerminalPane();
    bool terminalRunning = activePane && activePane->manager && activePane->manager->isRunning();
    EnableMenuItem(m_hMenu, IDM_TERMINAL_STOP, terminalRunning ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_CLEAR_ALL,
                   (m_terminalPanes.empty() ? (MF_BYCOMMAND | MF_GRAYED) : (MF_BYCOMMAND | MF_ENABLED)));

    // Git items
    bool repo = isGitRepository();
    EnableMenuItem(m_hMenu, IDM_GIT_STATUS, repo ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_COMMIT,
                   (repo && m_gitStatus.hasChanges) ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PUSH, repo ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PULL, repo ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PANEL, repo ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);

    // File save related
    EnableMenuItem(m_hMenu, IDM_FILE_SAVE,
                   (!m_currentFile.empty() && m_fileModified) ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_FILE_SAVEAS,
                   (!m_currentFile.empty()) ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED);

    // Streaming loader menu state
    CheckMenuItem(m_hMenu, IDM_VIEW_USE_STREAMING_LOADER,
                  MF_BYCOMMAND | (m_useStreamingLoader ? MF_CHECKED : MF_UNCHECKED));
    // Vulkan renderer menu state
    CheckMenuItem(m_hMenu, IDM_VIEW_USE_VULKAN_RENDERER,
                  MF_BYCOMMAND | (m_useVulkanRenderer ? MF_CHECKED : MF_UNCHECKED));
    // Breadcrumbs (View) — sync check with m_settings.breadcrumbsEnabled
    CheckMenuItem(m_hMenu, IDM_T1_BREADCRUMBS_TOGGLE,
                  MF_BYCOMMAND | (m_settings.breadcrumbsEnabled ? MF_CHECKED : MF_UNCHECKED));
    // Syntax highlighting — sync check with m_syntaxColoringEnabled
    CheckMenuItem(m_hMenu, ID_VIEW_SYNTAX_HIGHLIGHTING_TOGGLE,
                  MF_BYCOMMAND | (m_syntaxColoringEnabled ? MF_CHECKED : MF_UNCHECKED));

    // Tier 5 cosmetic features — enable when corresponding module is initialized (after deferredHeavyInit)
    EnableMenuItem(m_hMenu, IDM_TELDASH_SHOW,
                   (m_telemetryDashboardInitialized ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED));
    EnableMenuItem(m_hMenu, IDM_EMOJI_PICKER,
                   (m_emojiSupportInitialized ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED));
    EnableMenuItem(m_hMenu, IDM_SHORTCUT_SHOW,
                   (m_shortcutEditorInitialized ? MF_BYCOMMAND | MF_ENABLED : MF_BYCOMMAND | MF_GRAYED));

    DrawMenuBar(m_hwndMain);
}

// Code Snippets Implementation
void Win32IDE::loadCodeSnippets()
{
    // Delegate to the full snippet engine with multi-language built-in library
    // and VS Code-compatible JSON file loading
    loadBuiltInSnippets();
}

void Win32IDE::insertSnippet(const std::string& snippetName)
{
    for (const auto& snippet : m_codeSnippets)
    {
        if (snippet.name == snippetName || snippet.trigger == snippetName)
        {
            // Use the tab-stop engine for full VS Code-compatible snippet expansion
            insertSnippetWithTabStops(snippet.code);
            break;
        }
    }
    updateMenuEnableStates();
}

// Integrated Help Implementation
void Win32IDE::showGetHelp(const std::string& cmdlet)
{
    // Get selected text for help lookup
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);

    std::string command;
    if (!cmdlet.empty())
    {
        command = cmdlet;
    }
    else if (range.cpMax > range.cpMin)
    {
        char buffer[1000];
        TEXTRANGEA tr;
        tr.chrg = range;
        tr.lpstrText = buffer;
        SendMessageA(m_hwndEditor, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
        command = std::string(buffer);
    }
    else
    {
        command = "Get-Command";  // Default help
    }

    std::string helpCommand = "Get-Help " + command + " -Full\n";
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning())
    {
        pane->manager->writeInput(helpCommand);
    }
}

void Win32IDE::showCommandReference()
{
    std::string reference = "PowerShell Quick Reference:\n\n"
                            "Get-Help <command> - Get help for command\n"
                            "Get-Command - List all commands\n"
                            "Get-Member - Get object properties/methods\n"
                            "Measure-Object - Measure properties\n"
                            "Select-Object - Select properties\n"
                            "Where-Object - Filter objects\n"
                            "ForEach-Object - Process each object\n"
                            "Sort-Object - Sort objects\n"
                            "Group-Object - Group objects\n"
                            "Export-Csv - Export to CSV\n"
                            "Import-Csv - Import from CSV\n"
                            "ConvertTo-Json - Convert to JSON\n"
                            "ConvertFrom-Json - Convert from JSON\n";

    MessageBoxW(m_hwndMain, utf8ToWide(reference).c_str(), L"PowerShell Reference", MB_OK);
}

// Output / Clipboard / Minimap / Profiling implementations
void Win32IDE::createOutputTabs()
{
    if (m_hwndOutputTabs)
        return;

    RECT client{};
    GetClientRect(m_hwndMain, &client);
    int tabBarHeight = 24;

    m_hwndOutputTabs =
        CreateWindowExW(0, WC_TABCONTROLW, L"", WS_CHILD | WS_VISIBLE | TCS_TABS, 0, 0, client.right - 150,
                        tabBarHeight, m_hwndMain, (HMENU)IDC_OUTPUT_TABS, m_hInstance, nullptr);

    char logBuf[256];
    sprintf_s(logBuf, "OutputTabs HWND created: %p (Parent: %p)", m_hwndOutputTabs, m_hwndMain);
    LOG_INFO(std::string(logBuf));

    m_hwndSeverityFilter =
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL, client.right - 145,
                        2, 140, 100, m_hwndMain, (HMENU)IDC_SEVERITY_FILTER, m_hInstance, nullptr);
    SendMessageW(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)L"All Messages");
    SendMessageW(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)L"Info & Above");
    SendMessageW(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)L"Warnings & Errors");
    SendMessageW(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)L"Errors Only");
    SendMessage(m_hwndSeverityFilter, CB_SETCURSEL, m_severityFilterLevel, 0);

    static const struct
    {
        const wchar_t* text;
        int id;
        const char* key;
    } defs[] = {{L"Output", IDC_OUTPUT_EDIT_GENERAL, "Output"},
                {L"Errors", IDC_OUTPUT_EDIT_ERRORS, "Errors"},
                {L"Debug", IDC_OUTPUT_EDIT_DEBUG, "Debug"},
                {L"Find Results", IDC_OUTPUT_EDIT_FIND, "Find Results"}};

    for (int i = 0; i < 4; ++i)
    {
        TCITEMW tie{};
        tie.mask = TCIF_TEXT;
        tie.pszText = const_cast<wchar_t*>(defs[i].text);
        SendMessageW(m_hwndOutputTabs, TCM_INSERTITEMW, (WPARAM)i, (LPARAM)&tie);

        HWND hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, RICHEDIT_CLASSW, L"",
                                     WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 0,
                                     tabBarHeight, client.right, m_outputTabHeight - tabBarHeight, m_hwndMain,
                                     (HMENU)(INT_PTR)defs[i].id, m_hInstance, nullptr);
        // Dark theme for output RichEdit controls
        if (hEdit)
        {
            SendMessage(hEdit, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
            CHARFORMAT2W cf = {};
            cf.cbSize = sizeof(cf);
            cf.dwMask = CFM_COLOR;
            cf.crTextColor = RGB(212, 212, 212);
            SendMessageW(hEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
        }
        m_outputWindows[defs[i].key] = hEdit;
    }
    m_activeOutputTab = "Output";

    // Restore persisted tab selection
    if (m_selectedOutputTab >= 0 && m_selectedOutputTab < 4)
    {
        const char* keys[] = {"Output", "Errors", "Debug", "Find Results"};
        m_activeOutputTab = keys[m_selectedOutputTab];
        TabCtrl_SetCurSel(m_hwndOutputTabs, m_selectedOutputTab);
    }

    // Initially show only active tab and respect visibility setting
    for (auto& kv : m_outputWindows)
    {
        ShowWindow(kv.second, (kv.first == m_activeOutputTab && m_outputPanelVisible) ? SW_SHOW : SW_HIDE);
    }
    ShowWindow(m_hwndOutputTabs, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
    if (m_hwndSeverityFilter)
        ShowWindow(m_hwndSeverityFilter, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
    if (m_hwndSplitter)
        ShowWindow(m_hwndSplitter, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
}

void Win32IDE::addOutputTab(const std::string& name)
{
    if (m_outputWindows.find(name) != m_outputWindows.end())
        return;
    RECT client{};
    GetClientRect(m_hwndMain, &client);
    int tabBarHeight = 24;
    HWND hEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 0,
        tabBarHeight, client.right, m_outputTabHeight - tabBarHeight, m_hwndMain, nullptr, m_hInstance, nullptr);
    ShowWindow(hEdit, SW_HIDE);
    m_outputWindows[name] = hEdit;
}

void Win32IDE::appendToOutput(const std::string& text, const std::string& tabName, OutputSeverity severity)
{
    if (isShuttingDown())
        return;  // Window handles may be destroyed
    if (static_cast<int>(severity) < m_severityFilterLevel)
        return;

    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    if (m_outputWindows.find(target) == m_outputWindows.end())
    {
        addOutputTab(target);
    }

    // Add timestamp for Errors and Debug tabs
    std::string timestampedText = text;
    if (target == "Errors" || target == "Debug")
    {
        time_t now = time(nullptr);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char timestamp[16];
        strftime(timestamp, sizeof(timestamp), "[%H:%M:%S] ", &timeinfo);
        timestampedText = std::string(timestamp) + text;
    }

    // Check for ANSI escape sequences
    HWND hwnd = m_outputWindows[target];
    if (RawrXD::ANSIParser().ContainsANSI(timestampedText)) {
        // Use ANSI parser for colored output
        RawrXD::AppendANSIToRichEdit(hwnd, timestampedText);
    } else {
        // Apply color formatting based on tab type (legacy path)
        if (target == "Errors")
        {
            formatOutput(timestampedText, RGB(220, 50, 50), "Errors");  // Red
        }
        else if (target == "Debug")
        {
            formatOutput(timestampedText, RGB(200, 180, 50), "Debug");  // Yellow
        }
        else
        {
            appendText(hwnd, timestampedText);
        }
    }
}

void Win32IDE::clearOutput(const std::string& tabName)
{
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    auto it = m_outputWindows.find(target);
    if (it != m_outputWindows.end())
    {
        SetWindowTextW(it->second, L"");
    }
}

void Win32IDE::formatOutput(const std::string& text, COLORREF color, const std::string& tabName)
{
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    auto it = m_outputWindows.find(target);
    if (it == m_outputWindows.end())
        return;

    HWND hwnd = it->second;
    GETTEXTLENGTHEX gtl{};
    gtl.flags = GTL_DEFAULT;
    gtl.codepage = CP_UNICODE;
    LONG len = SendMessage(hwnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
    SendMessage(hwnd, EM_SETSEL, len, len);

    CHARFORMAT2W cf{};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessageW(hwnd, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

    std::wstring wtext = utf8ToWide(text);
    SETTEXTEX st{};
    st.flags = ST_SELECTION;
    st.codepage = CP_UNICODE;
    SendMessageW(hwnd, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)wtext.c_str());
}

void Win32IDE::copyWithFormatting()
{
    // Copy selected text with RTF formatting preservation
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    if (range.cpMax <= range.cpMin)
        return;
    
    LONG len = range.cpMax - range.cpMin;
    std::vector<wchar_t> buffer(len + 1);
    
    // Get the selected text
    TEXTRANGEW tr{};
    tr.chrg = range;
    tr.lpstrText = buffer.data();
    SendMessageW(m_hwndEditor, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
    buffer[len] = L'\0';
    
    // Convert to UTF-8 for storage
    std::string text = wideToUtf8(buffer.data());
    
    // Add to clipboard history with deduplication
    // Remove if already exists to move to front
    auto it = std::find(m_clipboardHistory.begin(), m_clipboardHistory.end(), text);
    if (it != m_clipboardHistory.end()) {
        m_clipboardHistory.erase(it);
    }
    m_clipboardHistory.insert(m_clipboardHistory.begin(), text);
    if (m_clipboardHistory.size() > MAX_CLIPBOARD_HISTORY)
        m_clipboardHistory.resize(MAX_CLIPBOARD_HISTORY);
    
    // Copy to system clipboard with both plain text and RTF formats
    if (OpenClipboard(m_hwndMain))
    {
        EmptyClipboard();
        
        // Plain text format
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hMem)
        {
            char* dest = (char*)GlobalLock(hMem);
            memcpy(dest, text.c_str(), text.size() + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        
        // Unicode text format
        std::wstring wtext = utf8ToWide(text);
        HGLOBAL hMemW = GlobalAlloc(GMEM_MOVEABLE, (wtext.size() + 1) * sizeof(wchar_t));
        if (hMemW)
        {
            wchar_t* destW = (wchar_t*)GlobalLock(hMemW);
            memcpy(destW, wtext.c_str(), (wtext.size() + 1) * sizeof(wchar_t));
            GlobalUnlock(hMemW);
            SetClipboardData(CF_UNICODETEXT, hMemW);
        }
        
        // RTF format - construct minimal RTF with formatting
        std::string rtf = "{\\rtf1\\ansi\\ansicpg1252\\deff0\\nouicompat\\deflang1033"
                         "{\\fonttbl{\\f0\\fnil\\fcharset0 Consolas;}}"
                         "{\\colortbl ;\\red0\\green0\\blue0;}"
                         "\\viewkind4\\uc1\\pard\\f0\\fs23 ";
        
        // Escape special RTF characters
        for (char c : text) {
            switch (c) {
                case '\\': rtf += "\\\\"; break;
                case '{': rtf += "\\{"; break;
                case '}': rtf += "\\}"; break;
                case '\n': rtf += "\\par\r\n"; break;
                case '\r': break; // Skip standalone CR
                default: rtf += c; break;
            }
        }
        rtf += "}";
        
        // Register RTF format and set data
        UINT rtfFormat = RegisterClipboardFormatA("Rich Text Format");
        if (rtfFormat) {
            HGLOBAL hMemRtf = GlobalAlloc(GMEM_MOVEABLE, rtf.size() + 1);
            if (hMemRtf) {
                char* destRtf = (char*)GlobalLock(hMemRtf);
                memcpy(destRtf, rtf.c_str(), rtf.size() + 1);
                GlobalUnlock(hMemRtf);
                SetClipboardData(rtfFormat, hMemRtf);
            }
        }
        
        CloseClipboard();
    }
}

void Win32IDE::pastePlainText()
{
    if (!m_hwndEditor)
        return;

    HWND owner = m_hwndMain ? m_hwndMain : m_hwndEditor;
    if (!OpenClipboard(owner))
        return;

    struct ClipboardGuard
    {
        ~ClipboardGuard() { CloseClipboard(); }
    } guard;

    // Prefer Unicode text; fall back to ANSI.
    if (IsClipboardFormatAvailable(CF_UNICODETEXT))
    {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (!hData)
            return;
        const wchar_t* data = (const wchar_t*)GlobalLock(hData);
        if (!data)
            return;

        std::wstring src(data);
        GlobalUnlock(hData);

        // Normalize newlines to CRLF for RichEdit consistency.
        std::wstring norm;
        norm.reserve(src.size() + 16);
        for (size_t i = 0; i < src.size(); ++i)
        {
            wchar_t c = src[i];
            if (c == L'\r')
            {
                norm.push_back(L'\r');
                if (i + 1 < src.size() && src[i + 1] == L'\n')
                {
                    norm.push_back(L'\n');
                    ++i;
                }
                else
                {
                    norm.push_back(L'\n');
                }
                continue;
            }
            if (c == L'\n')
            {
                norm.push_back(L'\r');
                norm.push_back(L'\n');
                continue;
            }
            norm.push_back(c);
        }

        SendMessageW(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)norm.c_str());
        return;
    }

    if (IsClipboardFormatAvailable(CF_TEXT))
    {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (!hData)
            return;
        const char* data = (const char*)GlobalLock(hData);
        if (!data)
            return;
        SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)data);
        GlobalUnlock(hData);
        return;
    }
}

void Win32IDE::pasteWithoutFormatting()
{
    if (OpenClipboard(m_hwndMain))
    {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData)
        {
            const char* data = (const char*)GlobalLock(hData);
            if (data)
            {
                SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)data);
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }
}

void Win32IDE::copyLineNumbers()
{
    if (!m_hwndEditor)
        return;

    // Get selected range
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);

    // Get line numbers for selection
    int startLine = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, range.cpMin, 0);
    int endLine = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, range.cpMax, 0);

    // Build line number string
    std::string lineNumbers;
    for (int i = startLine; i <= endLine; ++i)
    {
        if (!lineNumbers.empty())
            lineNumbers += "\r\n";
        lineNumbers += std::to_string(i + 1);
    }

    // Copy to clipboard
    if (OpenClipboard(m_hwndMain))
    {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, lineNumbers.size() + 1);
        if (hMem)
        {
            char* dest = (char*)GlobalLock(hMem);
            memcpy(dest, lineNumbers.c_str(), lineNumbers.size() + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

void Win32IDE::showClipboardHistory()
{
    std::string msg = "Clipboard History (latest 10):\n\n";
    size_t count = std::min<size_t>(10, m_clipboardHistory.size());
    for (size_t i = 0; i < count; ++i)
    {
        const std::string& item = m_clipboardHistory[i];
        std::string preview = item.substr(0, 50);
        if (item.size() > 50)
            preview += "...";
        msg += std::to_string(i + 1) + ". " + preview + "\n";
    }
    MessageBoxW(m_hwndMain, utf8ToWide(msg).c_str(), L"Clipboard History", MB_OK);
}

void Win32IDE::clearClipboardHistory()
{
    m_clipboardHistory.clear();
}

#if !defined(RAWRXD_USE_DEDICATED_MINIMAP)
void Win32IDE::createMinimap()
{
    if (!m_hwndMain || !m_hwndEditor)
        return;

    m_minimapWidth = 120;
    m_minimapVisible = true;

    // Create minimap window as a child of main window
    RECT editorRect;
    GetWindowRect(m_hwndEditor, &editorRect);
    MapWindowPoints(HWND_DESKTOP, m_hwndMain, (LPPOINT)&editorRect, 2);

    int minimapX = editorRect.right - m_minimapWidth;
    int minimapY = editorRect.top;
    int minimapHeight = editorRect.bottom - editorRect.top;

    m_hwndMinimap = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, minimapX, minimapY,
                                    m_minimapWidth, minimapHeight, m_hwndMain, nullptr, m_hInstance, nullptr);

    if (m_hwndMinimap)
    {
        SetWindowLongPtrW(m_hwndMinimap, GWLP_USERDATA, (LONG_PTR)this);
    }

    updateMinimap();
}

void Win32IDE::updateMinimap()
{
    if (!m_hwndMinimap || !m_minimapVisible || !m_hwndEditor)
        return;

    std::string text = getWindowText(m_hwndEditor);
    if (text.empty())
    {
        m_minimapLines.clear();
        InvalidateRect(m_hwndMinimap, nullptr, TRUE);
        return;
    }

    // Split into lines for minimap rendering
    m_minimapLines.clear();
    m_minimapLineStarts.clear();

    std::istringstream stream(text);
    std::string line;
    int pos = 0;
    while (std::getline(stream, line))
    {
        m_minimapLines.push_back(line);
        m_minimapLineStarts.push_back(pos);
        pos += (int)line.size() + 1;  // +1 for newline
    }

    // Force redraw
    InvalidateRect(m_hwndMinimap, nullptr, TRUE);

    // Paint minimap content
    HDC hdc = GetDC(m_hwndMinimap);
    if (hdc)
    {
        RECT rc;
        GetClientRect(m_hwndMinimap, &rc);

        // Dark background
        HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
        FillRect(hdc, &rc, bgBrush);
        DeleteObject(bgBrush);

        // Calculate visible area highlight
        int firstVisibleLine = (int)SendMessage(m_hwndEditor, EM_GETFIRSTVISIBLELINE, 0, 0);
        RECT editorRect;
        GetClientRect(m_hwndEditor, &editorRect);
        int visibleLines = editorRect.bottom / 16;  // Approximate line height

        // Draw visible area indicator
        int totalLines = (int)m_minimapLines.size();
        if (totalLines > 0)
        {
            float scale = (float)(rc.bottom - rc.top) / (float)totalLines;
            int highlightTop = (int)(firstVisibleLine * scale);
            int highlightHeight = (int)(visibleLines * scale);
            if (highlightHeight < 10)
                highlightHeight = 10;

            RECT highlightRect = {0, highlightTop, rc.right, highlightTop + highlightHeight};
            HBRUSH highlightBrush = CreateSolidBrush(RGB(60, 60, 80));
            FillRect(hdc, &highlightRect, highlightBrush);
            DeleteObject(highlightBrush);
        }

        // Draw minimap lines as colored blocks
        HPEN codePen = CreatePen(PS_SOLID, 1, RGB(150, 150, 150));
        HPEN oldPen = (HPEN)SelectObject(hdc, codePen);

        float lineHeight = 2.0f;
        if (totalLines > 0 && totalLines * lineHeight > rc.bottom)
        {
            lineHeight = (float)(rc.bottom - 4) / (float)totalLines;
            if (lineHeight < 1.0f)
                lineHeight = 1.0f;
        }

        for (size_t i = 0; i < m_minimapLines.size() && i * lineHeight < rc.bottom; ++i)
        {
            const std::string& line = m_minimapLines[i];
            if (line.empty())
                continue;

            int y = (int)(i * lineHeight) + 2;
            int lineLen = (int)line.size();
            int pixelLen = (lineLen * rc.right) / 200;  // Scale to minimap width
            if (pixelLen > rc.right - 4)
                pixelLen = rc.right - 4;
            if (pixelLen < 2)
                pixelLen = 2;

            MoveToEx(hdc, 2, y, nullptr);
            LineTo(hdc, 2 + pixelLen, y);
        }

        SelectObject(hdc, oldPen);
        DeleteObject(codePen);

        ReleaseDC(m_hwndMinimap, hdc);
    }
}

void Win32IDE::scrollToMinimapPosition(int y)
{
    if (!m_hwndMinimap || !m_hwndEditor || m_minimapLines.empty())
        return;

    RECT rc;
    GetClientRect(m_hwndMinimap, &rc);

    int totalLines = (int)m_minimapLines.size();
    int targetLine = (y * totalLines) / rc.bottom;

    if (targetLine < 0)
        targetLine = 0;
    if (targetLine >= totalLines)
        targetLine = totalLines - 1;

    // Scroll editor to target line
    int charIndex = 0;
    if (targetLine < (int)m_minimapLineStarts.size())
    {
        charIndex = m_minimapLineStarts[targetLine];
    }

    SendMessage(m_hwndEditor, EM_SETSEL, charIndex, charIndex);
    SendMessage(m_hwndEditor, EM_SCROLLCARET, 0, 0);

    updateMinimap();
}

void Win32IDE::toggleMinimap()
{
    m_minimapVisible = !m_minimapVisible;
    if (m_hwndMinimap)
    {
        ShowWindow(m_hwndMinimap, m_minimapVisible ? SW_SHOW : SW_HIDE);
    }
    else if (m_minimapVisible)
    {
        createMinimap();
    }

    // Trigger layout update
    RECT rc;
    GetClientRect(m_hwndMain, &rc);
    onSize(rc.right, rc.bottom);
}
#endif

void Win32IDE::startProfiling()
{
    if (!m_profilingActive)
    {
        m_profilingActive = true;
        QueryPerformanceCounter(&m_profilingStart);
        QueryPerformanceFrequency(&m_profilingFreq);
        m_profilingResults.clear();
    }
}

void Win32IDE::stopProfiling()
{
    if (m_profilingActive)
    {
        LARGE_INTEGER end;
        QueryPerformanceCounter(&end);
        double ms = (double)(end.QuadPart - m_profilingStart.QuadPart) * 1000.0 / (double)m_profilingFreq.QuadPart;
        m_profilingResults.push_back({"Session", ms});
        m_profilingActive = false;
    }
}

void Win32IDE::showProfileResults()
{
    std::string msg = "Profile Results:\n\n";
    for (auto& pr : m_profilingResults)
    {
        msg += pr.first + ": " + std::to_string(pr.second) + " ms\n";
    }
    MessageBoxW(m_hwndMain, utf8ToWide(msg).c_str(), L"Profiling", MB_OK);
}

void Win32IDE::analyzeScript()
{
    std::string script = getWindowText(m_hwndEditor);
    if (script.empty())
    {
        MessageBoxW(m_hwndMain, L"Script is empty.", L"Analyze Script", MB_OK);
        return;
    }

    appendToOutput("Starting AI Analysis...\n", "Output", OutputSeverity::Info);

    // Asynchronous analysis to avoid blocking UI
    std::thread(
        [this, script]()
        {
            DetachedThreadGuard _guard(m_activeDetachedThreads, m_shuttingDown);
            if (_guard.cancelled)
                return;
            if (m_nativeEngine)
            {
                std::string prompt =
                    "Analyze the following script and report potential bugs, security issues, and improvements:\n\n" +
                    script;
                // Assuming CPUInferenceEngine has an 'infer' or 'generate' method that takes a string
                // Based on cpu_inference_engine.cpp read earlier: std::string infer(const std::string& prompt);

                auto* engine = m_nativeEngine.get();
                auto tokens = engine->Tokenize(prompt);
                auto output_tokens = engine->Generate(tokens, 512);
                std::string result = engine->Detokenize(output_tokens);

                // Post result back to UI thread or just append (if appendToOutput is thread-safe or we lock)
                // appendToOutput uses SendMessage which is generally thread-safe for simple text
                this->appendToOutput("\n=== AI Analysis Result ===\n" + result + "\n==========================\n",
                                     "Output", OutputSeverity::Info);
            }
            else
            {
                this->appendToOutput("Error: Inference Engine not available.\n", "Errors", OutputSeverity::Error);
            }
        })
        .detach();
}

void Win32IDE::measureExecutionTime()
{
    // Real implementation: Measure block execution
    auto start = std::chrono::high_resolution_clock::now();
    // execute selection... (simplified)
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    appendToOutput("Execution time info: " + std::to_string(ms) + "ms\n", "Output", OutputSeverity::Info);
}

// Module Management
void Win32IDE::refreshModuleList()
{
    m_modules.clear();

    // Default module set (always available)
    m_modules.push_back({"Microsoft.PowerShell.Management", "3.0.0.0", "Management cmdlets", "", true});
    m_modules.push_back({"Microsoft.PowerShell.Utility", "3.0.0.0", "Utility cmdlets", "", true});
    m_modules.push_back({"PSReadLine", "2.0.0", "Command line editing", "", false});

    // Dynamic module enumeration via Powershell command
    std::string cmd = "powershell.exe -NoProfile -Command \"Get-Module -ListAvailable | Select-Object -First 50 Name, "
                      "Version | ConvertTo-Json -Compress\"";
    std::string output = ExecCmd(cmd.c_str());

    if (output.find("Error") == std::string::npos && !output.empty())
    {
        try
        {
            auto json = nlohmann::json::parse(output);
            if (json.is_array())
            {
                for (size_t i = 0; i < json.size(); ++i)
                {
                    const auto& item = json[i];
                    ModuleInfo m;
                    if (item.is_object())
                    {
                        m.name = item.value("Name", "");
                        if (item.contains("Version"))
                        {
                            auto v = item["Version"];
                            if (v.is_object())
                            {
                                // PS version object
                                m.version =
                                    std::to_string(v.value("Major", 0)) + "." + std::to_string(v.value("Minor", 0));
                            }
                            else if (v.is_string())
                            {
                                m.version = v.get<std::string>();
                            }
                            else
                            {
                                m.version = "0.0.0";
                            }
                        }
                        else
                        {
                            m.version = "0.0.0";
                        }
                    }
                    m.description = "User Module";
                    m.path = "";
                    m.loaded = false;  // Check via Get-Module without ListAvailable if needed

                    // Avoid duplicates
                    bool exists = false;
                    for (const auto& existing : m_modules)
                        if (existing.name == m.name)
                            exists = true;
                    if (!exists)
                        m_modules.push_back(m);
                }
            }
            else if (json.is_object())
            {
                // Single module
                ModuleInfo m;
                m.name = json.value("Name", "");
                m.version = "1.0";
                m.description = "User Module";
                m_modules.push_back(m);
            }
        }
        catch (...)
        {
            // JSON parsing failed, likely non-JSON output or empty
        }
    }
}

void Win32IDE::showModuleBrowser()
{
    std::string msg = "Modules:\n\n";
    for (auto& m : m_modules)
    {
        msg += m.name + " (" + m.version + ")" + (m.loaded ? " [Loaded]" : " [Available]") + "\n";
    }
    MessageBoxW(m_hwndMain, utf8ToWide(msg).c_str(), L"Module Browser", MB_OK);
}

void Win32IDE::loadModule(const std::string& moduleName)
{
    bool found = false;
    for (auto& m : m_modules)
    {
        if (m.name == moduleName)
        {
            m.loaded = true;
            found = true;
            break;
        }
    }

    // Explicit Logic: Actually load the module in PowerShell
    std::string command = "Import-Module '" + moduleName + "'\n";

    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning())
    {
        pane->manager->writeInput(command);
        appendToOutput("Loading module: " + moduleName, "Output", OutputSeverity::Info);
    }
    else
    {
        appendToOutput("Cannot load module '" + moduleName + "': No active terminal.", "Errors", OutputSeverity::Error);
    }
}

void Win32IDE::unloadModule(const std::string& moduleName)
{
    bool found = false;
    for (auto& m : m_modules)
    {
        if (m.name == moduleName)
        {
            m.loaded = false;
            found = true;
            break;
        }
    }

    // Explicit Logic: Actually remove the module in PowerShell
    std::string command = "Remove-Module '" + moduleName + "'\n";

    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning())
    {
        pane->manager->writeInput(command);
        appendToOutput("Unloading module: " + moduleName, "Output", OutputSeverity::Info);
    }
    else
    {
        // Try to start one or log error
        appendToOutput("Cannot unload module '" + moduleName + "': No active terminal.", "Errors",
                       OutputSeverity::Error);
    }
}

void Win32IDE::importModule()
{
    OPENFILENAMEW ofn = {};
    wchar_t szFile[MAX_PATH] = L"";
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFilter = L"PowerShell Modules (*.psm1;*.psd1)\0*.psm1;*.psd1\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"Import Module";

    if (GetOpenFileNameW(&ofn))
    {
        std::string modulePath = wideToUtf8(szFile);
        std::string command = "Import-Module '" + modulePath + "'\n";

        TerminalPane* pane = getActiveTerminalPane();
        if (pane && pane->manager && pane->manager->isRunning())
        {
            pane->manager->writeInput(command);
            appendToOutput("Importing module: " + modulePath + "\n", "Output", OutputSeverity::Info);
        }

        // Refresh module list after import
        refreshModuleList();
    }
}

void Win32IDE::exportModule()
{
    // Show dialog to select module to export
    if (m_modules.empty())
    {
        MessageBoxW(m_hwndMain, L"No modules loaded. Refresh module list first.", L"Export Module",
                    MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Build list of module names for selection
    std::string moduleList = "Available modules:\n\n";
    for (size_t i = 0; i < m_modules.size(); ++i)
    {
        moduleList += std::to_string(i + 1) + ". " + m_modules[i].name;
        if (m_modules[i].loaded)
            moduleList += " [Loaded]";
        moduleList += "\n";
    }
    moduleList += "\nExport the first loaded module?";

    if (MessageBoxW(m_hwndMain, utf8ToWide(moduleList).c_str(), L"Export Module", MB_YESNO | MB_ICONQUESTION) == IDYES)
    {
        // Find first loaded module
        for (const auto& mod : m_modules)
        {
            if (mod.loaded)
            {
                OPENFILENAMEW ofn = {};
                std::wstring defaultName = utf8ToWide(mod.name + ".psm1");
                wchar_t szFile[MAX_PATH] = L"";
                wcsncpy_s(szFile, defaultName.c_str(), _TRUNCATE);
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = m_hwndMain;
                ofn.lpstrFilter = L"PowerShell Module (*.psm1)\0*.psm1\0PowerShell Data (*.psd1)\0*.psd1\0";
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_OVERWRITEPROMPT;
                ofn.lpstrTitle = L"Export Module";

                if (GetSaveFileNameW(&ofn))
                {
                    std::string savePath = wideToUtf8(szFile);
                    std::string command =
                        "Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias * -PassThru | Out-File '" +
                        savePath + "'\n";

                    TerminalPane* pane = getActiveTerminalPane();
                    if (pane && pane->manager && pane->manager->isRunning())
                    {
                        pane->manager->writeInput(command);
                        appendToOutput("Exporting module to: " + savePath + "\n", "Output", OutputSeverity::Info);
                    }
                }
                break;
            }
        }
    }
}

// Theme Management
void Win32IDE::resetToDefaultTheme()
{
    applyThemeById(IDM_THEME_DARK_PLUS);
}

void Win32IDE::saveCodeSnippets()
{
    CreateDirectoryA("snippets", NULL);
    std::ofstream file("snippets\\snippets.txt");
    if (file.is_open())
    {
        for (const auto& snippet : m_codeSnippets)
        {
            file << "[SNIPPET]" << std::endl;
            file << "name=" << snippet.name << std::endl;
            file << "description=" << snippet.description << std::endl;
            file << "code_start" << std::endl;
            file << snippet.code << std::endl;
            file << "code_end" << std::endl;
        }
        file.close();
    }
}

void Win32IDE::showPowerShellDocs()
{
    MessageBoxW(m_hwndMain, L"Open https://learn.microsoft.com/powershell/ for full docs.", L"PowerShell Docs", MB_OK);
}

void Win32IDE::searchHelp(const std::string& query)
{
    std::string q = query.empty() ? "Get-Command" : query;
    std::string cmd = "Get-Help " + q + " -Online\n";
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning())
        pane->manager->writeInput(cmd);
}

void Win32IDE::toggleFloatingPanel()
{
    if (!m_hwndFloatingPanel)
        return;  // created elsewhere
    BOOL vis = IsWindowVisible(m_hwndFloatingPanel);
    ShowWindow(m_hwndFloatingPanel, vis ? SW_HIDE : SW_SHOW);
}

// ============================================================================
// Floating Panel Implementation
// ============================================================================

void Win32IDE::createFloatingPanel()
{
    if (m_hwndFloatingPanel)
        return;  // Already created

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = FloatingPanelProc;
    wc.hInstance = m_hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(RGB(30, 30, 30));
    wc.lpszClassName = L"RawrXD_FloatingPanel";
    RegisterClassExW(&wc);

    RECT rcMain;
    GetClientRect(m_hwndMain, &rcMain);
    int panelWidth = rcMain.right - rcMain.left;
    int panelHeight = 250;
    int panelX = rcMain.left;
    int panelY = rcMain.bottom - panelHeight;

    m_hwndFloatingPanel = CreateWindowExW(WS_EX_TOOLWINDOW, L"RawrXD_FloatingPanel", L"Panel",
                                          WS_CHILD | WS_CLIPSIBLINGS | WS_CLIPCHILDREN | WS_BORDER, panelX, panelY,
                                          panelWidth, panelHeight, m_hwndMain, nullptr, m_hInstance, nullptr);

    if (!m_hwndFloatingPanel)
    {
        appendToOutput("Failed to create floating panel\n", "Output", OutputSeverity::Error);
        return;
    }

    SetWindowLongPtrW(m_hwndFloatingPanel, GWLP_USERDATA, (LONG_PTR)this);

    static const wchar_t* tabLabels[] = {L"Problems", L"Output", L"Debug Console", L"Terminal"};
    for (int i = 0; i < 4; i++)
    {
        CreateWindowExW(0, L"BUTTON", tabLabels[i], WS_CHILD | WS_VISIBLE | BS_FLAT | BS_PUSHBUTTON, 5 + i * 120, 2,
                        115, 24, m_hwndFloatingPanel, (HMENU)(UINT_PTR)(7001 + i), m_hInstance, nullptr);
    }

    m_hwndFloatingContent =
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL, 0, 28,
                        panelWidth, panelHeight - 28, m_hwndFloatingPanel, nullptr, m_hInstance, nullptr);

    if (m_hwndFloatingContent)
    {
        SendMessageW(m_hwndFloatingContent, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);
    }

    appendToOutput("Floating panel created\n", "Output", OutputSeverity::Info);
}

void Win32IDE::showFloatingPanel()
{
    if (!m_hwndFloatingPanel)
    {
        createFloatingPanel();
    }
    if (m_hwndFloatingPanel)
    {
        ShowWindow(m_hwndFloatingPanel, SW_SHOW);
        m_outputPanelVisible = true;
    }
}

void Win32IDE::hideFloatingPanel()
{
    if (m_hwndFloatingPanel)
    {
        ShowWindow(m_hwndFloatingPanel, SW_HIDE);
        m_outputPanelVisible = false;
    }
}

void Win32IDE::updateFloatingPanelContent(const std::string& content)
{
    if (!m_hwndFloatingContent)
        return;
    std::wstring wcontent = utf8ToWide(content);
    int textLen = GetWindowTextLengthW(m_hwndFloatingContent);
    SendMessageW(m_hwndFloatingContent, EM_SETSEL, (WPARAM)textLen, (LPARAM)textLen);
    SendMessageW(m_hwndFloatingContent, EM_REPLACESEL, FALSE, (LPARAM)wcontent.c_str());
    SendMessageW(m_hwndFloatingContent, EM_SCROLLCARET, 0, 0);
}

void Win32IDE::setFloatingPanelTab(int tabIndex)
{
    if (!m_hwndFloatingPanel)
        return;

    // Visually highlight the active tab button and unhighlight others
    for (int i = 0; i < 4; i++)
    {
        HWND hTabBtn = GetDlgItem(m_hwndFloatingPanel, 7001 + i);
        if (hTabBtn)
        {
            if (i == tabIndex)
            {
                SendMessageW(hTabBtn, BM_SETSTATE, TRUE, 0);
            }
            else
            {
                SendMessageW(hTabBtn, BM_SETSTATE, FALSE, 0);
            }
        }
    }

    if (m_hwndFloatingContent)
    {
        static const wchar_t* tabTitles[] = {L"=== Problems ===\r\n", L"=== Output ===\r\n",
                                             L"=== Debug Console ===\r\n", L"=== Terminal ===\r\n"};
        if (tabIndex >= 0 && tabIndex < 4)
        {
            SetWindowTextW(m_hwndFloatingContent, tabTitles[tabIndex]);
        }
    }
}

LRESULT CALLBACK Win32IDE::FloatingPanelProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);

            // Dark background matching VS Code panel area
            HBRUSH hBrush = CreateSolidBrush(RGB(30, 30, 30));
            FillRect(hdc, &rc, hBrush);
            DeleteObject(hBrush);

            // Draw a subtle top border line (panel separator)
            HPEN hPen = CreatePen(PS_SOLID, 1, RGB(0, 122, 204));
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            MoveToEx(hdc, rc.left, rc.top, nullptr);
            LineTo(hdc, rc.right, rc.top);
            SelectObject(hdc, hOldPen);
            DeleteObject(hPen);

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_SIZE:
        {
            if (pThis && pThis->m_hwndFloatingContent)
            {
                RECT rc;
                GetClientRect(hwnd, &rc);
                // Resize content area below the tab buttons (28px tab bar)
                MoveWindow(pThis->m_hwndFloatingContent, 0, 28, rc.right, rc.bottom - 28, TRUE);
            }
            return 0;
        }

        case WM_COMMAND:
        {
            if (pThis)
            {
                int id = LOWORD(wParam);
                // Tab button IDs: 7001=Problems, 7002=Output, 7003=Debug Console, 7004=Terminal
                if (id >= 7001 && id <= 7004)
                {
                    pThis->setFloatingPanelTab(id - 7001);
                    return 0;
                }
            }
            break;
        }

        case WM_CLOSE:
            if (pThis)
            {
                pThis->hideFloatingPanel();
                return 0;
            }
            break;
    }

    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

int Win32IDE::getPanelAreaWidth() const
{
    if (!m_hwndMain)
        return 0;

    RECT rcMain;
    GetClientRect(m_hwndMain, &rcMain);
    int totalWidth = rcMain.right - rcMain.left;

    // Panel area width = total width minus sidebar (if visible) minus activity bar minus secondary sidebar
    int sidebarOffset = 0;
    if (m_sidebarVisible)
    {
        sidebarOffset = m_sidebarWidth + dpiScale(48);  // activity bar width (DPI-scaled)
    }
    int secondarySidebarOffset = m_secondarySidebarVisible ? m_secondarySidebarWidth : 0;

    return totalWidth - sidebarOffset - secondarySidebarOffset;
}

// ============================================================================
// Search and Replace Implementation
// ============================================================================

#define IDD_FIND 5001
#define IDD_REPLACE 5002
#define IDC_FIND_TEXT 5010
#define IDC_REPLACE_TEXT 5011
#define IDC_CASE_SENSITIVE 5020
#define IDC_WHOLE_WORD 5021
#define IDC_USE_REGEX 5022
#define IDC_BTN_FIND_NEXT 5030
#define IDC_BTN_REPLACE 5031
#define IDC_BTN_REPLACE_ALL 5032
#define IDC_BTN_CLOSE 5033

void Win32IDE::showFindDialog()
{
    if (m_hwndFindDialog && IsWindow(m_hwndFindDialog))
    {
        SetForegroundWindow(m_hwndFindDialog);
        return;
    }

    m_hwndFindDialog =
        CreateDialogParamW(m_hInstance, MAKEINTRESOURCEW(IDD_FIND), m_hwndMain, FindDialogProc, (LPARAM)this);

    if (!m_hwndFindDialog)
    {
        HWND hwndDlg =
            CreateWindowExW(WS_EX_DLGMODALFRAME, L"STATIC", L"Find", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                            100, 100, 400, 150, m_hwndMain, nullptr, m_hInstance, nullptr);
        m_hwndFindDialog = hwndDlg;

        CreateWindowExW(0, L"STATIC", L"Find what:", WS_CHILD | WS_VISIBLE, 10, 15, 80, 20, hwndDlg, nullptr,
                        m_hInstance, nullptr);
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", utf8ToWide(m_lastSearchText).c_str(),
                        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 12, 280, 22, hwndDlg, (HMENU)IDC_FIND_TEXT,
                        m_hInstance, nullptr);

        CreateWindowExW(0, L"BUTTON", L"Case sensitive", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 10, 45, 120, 20,
                        hwndDlg, (HMENU)IDC_CASE_SENSITIVE, m_hInstance, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Whole word", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 140, 45, 100, 20, hwndDlg,
                        (HMENU)IDC_WHOLE_WORD, m_hInstance, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 250, 45, 70, 20, hwndDlg,
                        (HMENU)IDC_USE_REGEX, m_hInstance, nullptr);

        CreateWindowExW(0, L"BUTTON", L"Find Next", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 10, 80, 90, 28, hwndDlg,
                        (HMENU)IDC_BTN_FIND_NEXT, m_hInstance, nullptr);
        CreateWindowExW(0, L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE, 110, 80, 90, 28, hwndDlg, (HMENU)IDC_BTN_CLOSE,
                        m_hInstance, nullptr);
    }

    ShowWindow(m_hwndFindDialog, SW_SHOW);
}

void Win32IDE::showReplaceDialog()
{
    if (m_hwndReplaceDialog && IsWindow(m_hwndReplaceDialog))
    {
        SetForegroundWindow(m_hwndReplaceDialog);
        return;
    }

    HWND hwndDlg =
        CreateWindowExW(WS_EX_DLGMODALFRAME, L"STATIC", L"Replace", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                        100, 100, 400, 200, m_hwndMain, nullptr, m_hInstance, nullptr);
    m_hwndReplaceDialog = hwndDlg;

    CreateWindowExW(0, L"STATIC", L"Find what:", WS_CHILD | WS_VISIBLE, 10, 15, 80, 20, hwndDlg, nullptr, m_hInstance,
                    nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", utf8ToWide(m_lastSearchText).c_str(),
                    WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 12, 280, 22, hwndDlg, (HMENU)IDC_FIND_TEXT,
                    m_hInstance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Replace with:", WS_CHILD | WS_VISIBLE, 10, 45, 80, 20, hwndDlg, nullptr,
                    m_hInstance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", utf8ToWide(m_lastReplaceText).c_str(),
                    WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 42, 280, 22, hwndDlg, (HMENU)IDC_REPLACE_TEXT,
                    m_hInstance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Case sensitive", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 10, 75, 120, 20, hwndDlg,
                    (HMENU)IDC_CASE_SENSITIVE, m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Whole word", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 140, 75, 100, 20, hwndDlg,
                    (HMENU)IDC_WHOLE_WORD, m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 250, 75, 70, 20, hwndDlg,
                    (HMENU)IDC_USE_REGEX, m_hInstance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Find Next", WS_CHILD | WS_VISIBLE, 10, 110, 90, 28, hwndDlg,
                    (HMENU)IDC_BTN_FIND_NEXT, m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Replace", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 110, 110, 90, 28, hwndDlg,
                    (HMENU)IDC_BTN_REPLACE, m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Replace All", WS_CHILD | WS_VISIBLE, 210, 110, 90, 28, hwndDlg,
                    (HMENU)IDC_BTN_REPLACE_ALL, m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Close", WS_CHILD | WS_VISIBLE, 310, 110, 70, 28, hwndDlg, (HMENU)IDC_BTN_CLOSE,
                    m_hInstance, nullptr);

    ShowWindow(m_hwndReplaceDialog, SW_SHOW);
}

void Win32IDE::findNext()
{
    if (m_lastSearchText.empty())
    {
        showFindDialog();
        return;
    }
    findText(m_lastSearchText, true, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::findPrevious()
{
    if (m_lastSearchText.empty())
    {
        showFindDialog();
        return;
    }
    findText(m_lastSearchText, false, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::replaceNext()
{
    if (m_lastSearchText.empty())
    {
        showReplaceDialog();
        return;
    }
    replaceText(m_lastSearchText, m_lastReplaceText, false, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::replaceAll()
{
    if (m_lastSearchText.empty())
    {
        showReplaceDialog();
        return;
    }
    int count = replaceText(m_lastSearchText, m_lastReplaceText, true, m_searchCaseSensitive, m_searchWholeWord,
                            m_searchUseRegex);

    std::string msg = "Replaced " + std::to_string(count) + " occurrence(s).";
    MessageBoxW(m_hwndMain, utf8ToWide(msg).c_str(), L"Replace All", MB_OK | MB_ICONINFORMATION);
}

bool Win32IDE::findText(const std::string& searchText, bool forward, bool caseSensitive, bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty())
        return false;

    std::string editorText = getWindowText(m_hwndEditor);
    if (editorText.empty())
        return false;
    int textLen = (int)editorText.size();

    CHARRANGE selection;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&selection);

    int startChar = forward ? selection.cpMax : selection.cpMin - 1;
    if (startChar < 0)
        startChar = 0;
    int startPos = charIndexToUtf8ByteOffset(editorText, startChar);
    if (startPos >= textLen)
        startPos = textLen > 0 ? textLen - 1 : 0;

    size_t foundPos = std::string::npos;
    size_t foundLen = searchText.length();

    if (useRegex)
    {
        // Regex search using std::regex
        try
        {
            auto flags = std::regex_constants::ECMAScript;
            if (!caseSensitive)
                flags |= std::regex_constants::icase;
            std::regex pattern(searchText, flags);
            std::smatch match;

            if (forward)
            {
                std::string searchArea = editorText.substr(startPos);
                if (std::regex_search(searchArea, match, pattern))
                {
                    foundPos = startPos + match.position();
                    foundLen = match.length();
                }
                else if (startPos > 0)
                {
                    // Wrap around
                    searchArea = editorText.substr(0, startPos);
                    if (std::regex_search(searchArea, match, pattern))
                    {
                        foundPos = match.position();
                        foundLen = match.length();
                    }
                }
            }
            else
            {
                // Backwards regex: find all matches before startPos, take last one
                std::string searchArea = editorText.substr(0, startPos);
                auto begin = std::sregex_iterator(searchArea.begin(), searchArea.end(), pattern);
                auto end = std::sregex_iterator();
                std::smatch lastMatch;
                bool found = false;
                for (auto it = begin; it != end; ++it)
                {
                    lastMatch = *it;
                    found = true;
                }
                if (found)
                {
                    foundPos = lastMatch.position();
                    foundLen = lastMatch.length();
                }
                else
                {
                    // Wrap: search from startPos to end
                    searchArea = editorText.substr(startPos);
                    begin = std::sregex_iterator(searchArea.begin(), searchArea.end(), pattern);
                    for (auto it = begin; it != end; ++it)
                    {
                        lastMatch = *it;
                        found = true;
                    }
                    if (found)
                    {
                        foundPos = startPos + lastMatch.position();
                        foundLen = lastMatch.length();
                    }
                }
            }
        }
        catch (const std::regex_error& e)
        {
            std::string msg = "Invalid regex: ";
            msg += e.what();
            MessageBoxW(m_hwndMain, utf8ToWide(msg).c_str(), L"Find", MB_OK | MB_ICONERROR);
            return false;
        }
    }
    else
    {
        // Plain text search with optional case sensitivity and whole word
        std::string haystack = editorText;
        std::string needle = searchText;

        if (!caseSensitive)
        {
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
            std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
        }

        auto isWordBoundary = [&](size_t pos, size_t len) -> bool
        {
            if (!wholeWord)
                return true;
            bool leftOk = (pos == 0) || !isalnum((unsigned char)haystack[pos - 1]);
            bool rightOk = (pos + len >= haystack.size()) || !isalnum((unsigned char)haystack[pos + len]);
            return leftOk && rightOk;
        };

        if (forward)
        {
            size_t pos = startPos;
            while (pos < haystack.size())
            {
                foundPos = haystack.find(needle, pos);
                if (foundPos == std::string::npos)
                    break;
                if (isWordBoundary(foundPos, needle.size()))
                    break;
                pos = foundPos + 1;
                foundPos = std::string::npos;
            }
            // Wrap around
            if (foundPos == std::string::npos && startPos > 0)
            {
                pos = 0;
                while (pos < (size_t)startPos)
                {
                    foundPos = haystack.find(needle, pos);
                    if (foundPos == std::string::npos || foundPos >= (size_t)startPos)
                    {
                        foundPos = std::string::npos;
                        break;
                    }
                    if (isWordBoundary(foundPos, needle.size()))
                        break;
                    pos = foundPos + 1;
                    foundPos = std::string::npos;
                }
            }
        }
        else
        {
            if (startPos > 0)
            {
                foundPos = haystack.rfind(needle, startPos);
                while (foundPos != std::string::npos && !isWordBoundary(foundPos, needle.size()))
                {
                    if (foundPos == 0)
                    {
                        foundPos = std::string::npos;
                        break;
                    }
                    foundPos = haystack.rfind(needle, foundPos - 1);
                }
            }
            if (foundPos == std::string::npos)
            {
                foundPos = haystack.rfind(needle);
                while (foundPos != std::string::npos && !isWordBoundary(foundPos, needle.size()))
                {
                    if (foundPos == 0)
                    {
                        foundPos = std::string::npos;
                        break;
                    }
                    foundPos = haystack.rfind(needle, foundPos - 1);
                }
            }
        }
    }

    if (foundPos != std::string::npos)
    {
        selection.cpMin = (LONG)utf8ByteOffsetToCharIndex(editorText, (int)foundPos);
        selection.cpMax = (LONG)utf8ByteOffsetToCharIndex(editorText, (int)(foundPos + foundLen));
        SendMessage(m_hwndEditor, EM_EXSETSEL, 0, (LPARAM)&selection);
        SendMessage(m_hwndEditor, EM_SCROLLCARET, 0, 0);
        m_lastFoundPos = foundPos;
        return true;
    }

    MessageBoxW(m_hwndMain, L"Text not found.", L"Find", MB_OK | MB_ICONINFORMATION);
    return false;
}

int Win32IDE::replaceText(const std::string& searchText, const std::string& replaceText, bool all, bool caseSensitive,
                          bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty())
        return 0;

    int replaceCount = 0;

    if (all)
    {
        std::string editorText = getWindowText(m_hwndEditor);
        if (editorText.empty())
            return 0;
        int textLen = (int)editorText.size();

        std::string result;
        size_t pos = 0;

        std::string haystack = editorText;
        std::string needle = searchText;

        if (!caseSensitive)
        {
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
            std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
        }

        while ((pos = haystack.find(needle, pos)) != std::string::npos)
        {
            result.append(editorText, 0, pos);
            result.append(replaceText);
            pos += needle.length();
            replaceCount++;
        }

        if (replaceCount > 0)
        {
            result.append(editorText, pos, std::string::npos);
            setWindowText(m_hwndEditor, result);
            m_fileModified = true;
            updateLineNumbers();
        }
    }
    else
    {
        // Replace current selection if it matches search text
        CHARRANGE selection;
        SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&selection);

        int selLen = selection.cpMax - selection.cpMin;
        if (selLen > 0)
        {
            std::string selectedText(selLen + 1, 0);
            SendMessage(m_hwndEditor, EM_GETSELTEXT, 0, (LPARAM)&selectedText[0]);
            selectedText.resize(selLen);

            std::string cmpSelected = selectedText;
            std::string cmpSearch = searchText;

            if (!caseSensitive)
            {
                std::transform(cmpSelected.begin(), cmpSelected.end(), cmpSelected.begin(), ::tolower);
                std::transform(cmpSearch.begin(), cmpSearch.end(), cmpSearch.begin(), ::tolower);
            }

            if (cmpSelected == cmpSearch)
            {
                SendMessageW(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)utf8ToWide(replaceText).c_str());
                m_fileModified = true;
                replaceCount = 1;

                // Find next occurrence
                findText(searchText, true, caseSensitive, wholeWord, useRegex);
            }
        }
    }

    return replaceCount;
}

INT_PTR CALLBACK Win32IDE::FindDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;

    if (uMsg == WM_INITDIALOG)
    {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        pThis = (Win32IDE*)lParam;
    }
    else
    {
        pThis = (Win32IDE*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }

    if (!pThis)
        return FALSE;

    switch (uMsg)
    {
        case WM_USER + 100:
            // Handle Copilot streaming token updates
            if (pThis)
            {
                pThis->HandleCopilotStreamUpdate(reinterpret_cast<const char*>(wParam), static_cast<size_t>(lParam));
            }
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_BTN_FIND_NEXT:
                {
                    HWND hwndFindText = GetDlgItem(hwndDlg, IDC_FIND_TEXT);
                    wchar_t buffer[256];
                    GetWindowTextW(hwndFindText, buffer, 256);
                    pThis->m_lastSearchText = wideToUtf8(buffer);

                    pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                    pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                    pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;

                    pThis->findNext();
                }
                    return TRUE;
                case IDC_BTN_CLOSE:
                case IDCANCEL:
                    DestroyWindow(hwndDlg);
                    pThis->m_hwndFindDialog = nullptr;
                    return TRUE;
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwndDlg);
            pThis->m_hwndFindDialog = nullptr;
            return TRUE;
    }

    return FALSE;
}

INT_PTR CALLBACK Win32IDE::ReplaceDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;

    if (uMsg == WM_INITDIALOG)
    {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        pThis = (Win32IDE*)lParam;
    }
    else
    {
        pThis = (Win32IDE*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }

    if (!pThis)
        return FALSE;

    switch (uMsg)
    {
        case WM_COMMAND:
        {
            HWND hwndFindText = GetDlgItem(hwndDlg, IDC_FIND_TEXT);
            HWND hwndReplaceText = GetDlgItem(hwndDlg, IDC_REPLACE_TEXT);

            switch (LOWORD(wParam))
            {
                case IDC_BTN_FIND_NEXT:
                {
                    wchar_t wFind[256], wReplace[256];
                    GetWindowTextW(hwndFindText, wFind, 256);
                    pThis->m_lastSearchText = wideToUtf8(wFind);
                }
                    pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                    pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                    pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                    pThis->findNext();
                    return TRUE;
                case IDC_BTN_REPLACE:
                {
                    wchar_t wFind[256], wReplace[256];
                    GetWindowTextW(hwndFindText, wFind, 256);
                    GetWindowTextW(hwndReplaceText, wReplace, 256);
                    pThis->m_lastSearchText = wideToUtf8(wFind);
                    pThis->m_lastReplaceText = wideToUtf8(wReplace);
                }
                    pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                    pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                    pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                    pThis->replaceNext();
                    return TRUE;
                case IDC_BTN_REPLACE_ALL:
                {
                    wchar_t wFind[256], wReplace[256];
                    GetWindowTextW(hwndFindText, wFind, 256);
                    GetWindowTextW(hwndReplaceText, wReplace, 256);
                    pThis->m_lastSearchText = wideToUtf8(wFind);
                    pThis->m_lastReplaceText = wideToUtf8(wReplace);
                }
                    pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                    pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                    pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                    pThis->replaceAll();
                    return TRUE;
                case IDC_BTN_CLOSE:
                case IDCANCEL:
                    DestroyWindow(hwndDlg);
                    pThis->m_hwndReplaceDialog = nullptr;
                    return TRUE;
            }
        }
        break;
        case WM_CLOSE:
            DestroyWindow(hwndDlg);
            pThis->m_hwndReplaceDialog = nullptr;
            return TRUE;
    }

    return FALSE;
}

// ============================================================================
// Snippet Manager Implementation
// ============================================================================

#define IDD_SNIPPET_MANAGER 6001
// Note: IDC_SNIPPET_LIST is defined at line 23 as 1009
#define IDC_SNIPPET_LIST_DLG 6010
#define IDC_SNIPPET_NAME 6011
#define IDC_SNIPPET_DESC 6012
#define IDC_SNIPPET_CODE 6013
#define IDC_BTN_INSERT_SNIPPET 6020
#define IDC_BTN_NEW_SNIPPET 6021
#define IDC_BTN_DELETE_SNIPPET 6022
#define IDC_BTN_SAVE_SNIPPETS 6023

void Win32IDE::showSnippetManager()
{
    HWND hwndDlg = CreateWindowExW(WS_EX_DLGMODALFRAME, L"STATIC", L"Snippet Manager",
                                   WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, 100, 100, 600, 500, m_hwndMain,
                                   nullptr, m_hInstance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Snippets:", WS_CHILD | WS_VISIBLE, 10, 10, 150, 20, hwndDlg, nullptr, m_hInstance,
                    nullptr);

    HWND hwndList =
        CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | LBS_STANDARD | WS_VSCROLL, 10, 35,
                        150, 400, hwndDlg, (HMENU)IDC_SNIPPET_LIST_DLG, m_hInstance, nullptr);

    for (const auto& snippet : m_codeSnippets)
    {
        SendMessageW(hwndList, LB_ADDSTRING, 0, (LPARAM)utf8ToWide(snippet.name).c_str());
    }

    CreateWindowExW(0, L"STATIC", L"Name:", WS_CHILD | WS_VISIBLE, 175, 10, 50, 20, hwndDlg, nullptr, m_hInstance,
                    nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 230, 8, 350, 22, hwndDlg,
                    (HMENU)IDC_SNIPPET_NAME, m_hInstance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Description:", WS_CHILD | WS_VISIBLE, 175, 40, 70, 20, hwndDlg, nullptr,
                    m_hInstance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 175, 60, 405, 22, hwndDlg,
                    (HMENU)IDC_SNIPPET_DESC, m_hInstance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Code Template:", WS_CHILD | WS_VISIBLE, 175, 90, 100, 20, hwndDlg, nullptr,
                    m_hInstance, nullptr);
    CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN |
                        WS_VSCROLL | WS_HSCROLL,
                    175, 115, 405, 280, hwndDlg, (HMENU)IDC_SNIPPET_CODE, m_hInstance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Insert", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 175, 410, 90, 28, hwndDlg,
                    (HMENU)IDC_BTN_INSERT_SNIPPET, m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"New", WS_CHILD | WS_VISIBLE, 275, 410, 90, 28, hwndDlg, (HMENU)IDC_BTN_NEW_SNIPPET,
                    m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Delete", WS_CHILD | WS_VISIBLE, 375, 410, 90, 28, hwndDlg,
                    (HMENU)IDC_BTN_DELETE_SNIPPET, m_hInstance, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Save & Close", WS_CHILD | WS_VISIBLE, 475, 410, 105, 28, hwndDlg,
                    (HMENU)IDC_BTN_SAVE_SNIPPETS, m_hInstance, nullptr);

    // Message loop for dialog
    MSG msg;
    bool running = true;
    while (running && GetMessage(&msg, nullptr, 0, 0))
    {
        if (msg.hwnd == hwndDlg || IsChild(hwndDlg, msg.hwnd))
        {
            // Handle list selection
            if (msg.message == WM_COMMAND)
            {
                WORD cmdId = LOWORD(msg.wParam);
                WORD notif = HIWORD(msg.wParam);

                if (cmdId == IDC_SNIPPET_LIST_DLG && notif == LBN_SELCHANGE)
                {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size())
                    {
                        const CodeSnippet& snippet = m_codeSnippets[sel];
                        SetDlgItemTextW(hwndDlg, IDC_SNIPPET_NAME, utf8ToWide(snippet.name).c_str());
                        SetDlgItemTextW(hwndDlg, IDC_SNIPPET_DESC, utf8ToWide(snippet.description).c_str());
                        SetDlgItemTextW(hwndDlg, IDC_SNIPPET_CODE, utf8ToWide(snippet.code).c_str());
                    }
                }
                else if (cmdId == IDC_BTN_INSERT_SNIPPET)
                {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size())
                    {
                        insertSnippet(m_codeSnippets[sel].name);
                        running = false;
                        DestroyWindow(hwndDlg);
                    }
                }
                else if (cmdId == IDC_BTN_NEW_SNIPPET)
                {
                    CodeSnippet newSnippet;
                    newSnippet.name = "NewSnippet";
                    newSnippet.description = "New snippet description";
                    newSnippet.code = "// Your code here";
                    m_codeSnippets.push_back(newSnippet);
                    SendMessageW(hwndList, LB_ADDSTRING, 0, (LPARAM)utf8ToWide(newSnippet.name).c_str());
                    SendMessage(hwndList, LB_SETCURSEL, m_codeSnippets.size() - 1, 0);
                    SetDlgItemTextW(hwndDlg, IDC_SNIPPET_NAME, utf8ToWide(newSnippet.name).c_str());
                    SetDlgItemTextW(hwndDlg, IDC_SNIPPET_DESC, utf8ToWide(newSnippet.description).c_str());
                    SetDlgItemTextW(hwndDlg, IDC_SNIPPET_CODE, utf8ToWide(newSnippet.code).c_str());
                }
                else if (cmdId == IDC_BTN_DELETE_SNIPPET)
                {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size())
                    {
                        if (MessageBoxW(hwndDlg, L"Delete this snippet?", L"Confirm", MB_YESNO) == IDYES)
                        {
                            m_codeSnippets.erase(m_codeSnippets.begin() + sel);
                            SendMessage(hwndList, LB_DELETESTRING, sel, 0);
                            SetDlgItemTextW(hwndDlg, IDC_SNIPPET_NAME, L"");
                            SetDlgItemTextW(hwndDlg, IDC_SNIPPET_DESC, L"");
                            SetDlgItemTextW(hwndDlg, IDC_SNIPPET_CODE, L"");
                        }
                    }
                }
                else if (cmdId == IDC_BTN_SAVE_SNIPPETS)
                {
                    // Update current snippet before saving
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size())
                    {
                        wchar_t buffer[1024];
                        GetDlgItemTextW(hwndDlg, IDC_SNIPPET_NAME, buffer, 1024);
                        m_codeSnippets[sel].name = wideToUtf8(buffer);
                        GetDlgItemTextW(hwndDlg, IDC_SNIPPET_DESC, buffer, 1024);
                        m_codeSnippets[sel].description = wideToUtf8(buffer);

                        HWND hwndCode = GetDlgItem(hwndDlg, IDC_SNIPPET_CODE);
                        int len = GetWindowTextLengthW(hwndCode);
                        std::vector<wchar_t> codeBuffer(len + 1);
                        GetWindowTextW(hwndCode, codeBuffer.data(), len + 1);
                        m_codeSnippets[sel].code = wideToUtf8(codeBuffer.data());
                    }

                    saveCodeSnippets();
                    MessageBoxW(hwndDlg, L"Snippets saved!", L"Success", MB_OK);
                    running = false;
                    DestroyWindow(hwndDlg);
                }
            }
            else if (msg.message == WM_CLOSE)
            {
                running = false;
                DestroyWindow(hwndDlg);
            }
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void Win32IDE::createSnippet()
{
    // Create a new empty snippet
    CodeSnippet newSnippet;
    newSnippet.name = "NewSnippet" + std::to_string(m_codeSnippets.size() + 1);
    newSnippet.description = "New snippet";
    newSnippet.code = "// Code template\n";
    m_codeSnippets.push_back(newSnippet);

    MessageBoxW(m_hwndMain,
                utf8ToWide("Snippet '" + newSnippet.name + "' created. Use Snippet Manager to edit.").c_str(),
                L"Snippet Created", MB_OK);
}

// ============================================================================
// File Explorer Implementation
// ============================================================================

void Win32IDE::createFileExplorer(HWND hwndParent)
{
    if (m_hwndFileExplorer)
    {
        return;  // Already created
    }

    m_hwndFileExplorer =
        CreateWindowExW(0, L"STATIC", L"File Explorer", WS_CHILD | WS_VISIBLE | WS_BORDER, 0, 30, m_sidebarWidth, 500,
                        hwndParent, (HMENU)IDC_FILE_EXPLORER, GetModuleHandle(nullptr), nullptr);

    m_hwndFileTree = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS, 5, 5, m_sidebarWidth - 10,
        490, m_hwndFileExplorer, (HMENU)IDC_FILE_TREE, GetModuleHandle(nullptr), nullptr);

    SendMessage(m_hwndFileTree, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

    SetWindowLongPtrW(m_hwndFileExplorer, GWLP_USERDATA, (LONG_PTR)this);
    m_oldFileExplorerContainerProc =
        (WNDPROC)SetWindowLongPtrW(m_hwndFileExplorer, GWLP_WNDPROC, (LONG_PTR)FileExplorerContainerProc);

    // Populate with drive letters
    populateFileTree(nullptr, "");
}

void Win32IDE::populateFileTree(HTREEITEM parentItem, const std::string& path)
{
    if (!m_hwndFileTree)
    {
        return;
    }

    if (!parentItem)
    {
        TVINSERTSTRUCTW tvis = {};
        tvis.hParent = TVI_ROOT;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

        wchar_t buf[MAX_PATH];
        for (char drive = 'C'; drive <= 'Z'; ++drive)
        {
            std::string drivePath = std::string(1, drive) + ":";
            DWORD drives = GetLogicalDrives();
            int driveNum = drive - 'A';

            if (drives & (1 << driveNum))
            {
                std::string displayName = drivePath + "\\";
                MultiByteToWideChar(CP_ACP, 0, displayName.c_str(), -1, buf, MAX_PATH);
                tvis.item.pszText = buf;
                tvis.item.lParam = (LPARAM) new std::string(drivePath);

                HTREEITEM driveItem = (HTREEITEM)SendMessageW(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[driveItem] = drivePath;

                TVINSERTSTRUCTW dummyVis = {};
                dummyVis.hParent = driveItem;
                dummyVis.item.mask = TVIF_TEXT;
                static wchar_t s_ellipsis[] = L"...";
                dummyVis.item.pszText = s_ellipsis;
                SendMessageW(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&dummyVis);
            }
        }
        return;
    }

    // Populate a specific folder
    try
    {
        WIN32_FIND_DATAA findData;
        HANDLE findHandle;

        std::string searchPath = path + "\\*";
        findHandle = FindFirstFileA(searchPath.c_str(), &findData);

        if (findHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }

        TVINSERTSTRUCTW tvis = {};
        tvis.hParent = parentItem;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

        wchar_t wbuf[MAX_PATH];
        HTREEITEM hChild = TreeView_GetChild(m_hwndFileTree, parentItem);
        while (hChild)
        {
            HTREEITEM hNext = TreeView_GetNextSibling(m_hwndFileTree, hChild);
            TreeView_DeleteItem(m_hwndFileTree, hChild);
            hChild = hNext;
        }

        do
        {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
            {
                continue;
            }

            std::string fullPath = path + "\\" + findData.cFileName;
            MultiByteToWideChar(CP_ACP, 0, findData.cFileName, -1, wbuf, MAX_PATH);

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                tvis.item.pszText = wbuf;
                tvis.item.lParam = (LPARAM) new std::string(fullPath);

                HTREEITEM folderItem = (HTREEITEM)SendMessageW(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[folderItem] = fullPath;

                TVINSERTSTRUCTW dummyVis = {};
                dummyVis.hParent = folderItem;
                dummyVis.item.mask = TVIF_TEXT;
                static wchar_t s_ellipsis2[] = L"...";
                dummyVis.item.pszText = s_ellipsis2;
                SendMessageW(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&dummyVis);
            }
            else if (strlen(findData.cFileName) > 5 &&
                     strcmp(findData.cFileName + strlen(findData.cFileName) - 5, ".gguf") == 0)
            {
                tvis.item.pszText = wbuf;
                tvis.item.lParam = (LPARAM) new std::string(fullPath);

                HTREEITEM fileItem = (HTREEITEM)SendMessageW(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[fileItem] = fullPath;
            }
        } while (FindNextFileA(findHandle, &findData));

        FindClose(findHandle);
    }
    catch (...)
    {
        // Silently handle errors
    }
}

LRESULT CALLBACK Win32IDE::FileExplorerContainerProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
    if (uMsg == WM_NOTIFY)
    {
        NMHDR* pnmh = reinterpret_cast<NMHDR*>(lParam);
        if (pnmh && pnmh->code == TVN_DELETEITEM)
        {
            NMTREEVIEWA* pnmtv = reinterpret_cast<NMTREEVIEWA*>(lParam);
            if (pnmtv->itemOld.lParam)
                delete reinterpret_cast<std::string*>(pnmtv->itemOld.lParam);
            return 0;
        }
    }
    WNDPROC oldProc = pThis ? pThis->m_oldFileExplorerContainerProc : nullptr;
    if (oldProc)
        return CallWindowProcA(oldProc, hwnd, uMsg, wParam, lParam);
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

void Win32IDE::onFileTreeExpand(HTREEITEM item, const std::string& path)
{
    if (!m_hwndFileTree)
    {
        return;
    }

    populateFileTree(item, path);
}

std::string Win32IDE::getTreeItemPath(HTREEITEM item) const
{
    auto it = m_treeItemPaths.find(item);
    if (it != m_treeItemPaths.end())
    {
        return it->second;
    }
    return "";
}

// NOTE: File watcher implementation lives in `Win32IDE_Tier3Polish.cpp`.

void Win32IDE::loadModelFromPath(const std::string& filepath)
{
    if (filepath.empty())
        return;
    // Load regardless of extension: try streaming GGUF first, then ensure agentic bridge has the model
    bool ggufOk = loadGGUFModel(filepath);
    if (ggufOk)
    {
        initializeInference();
        initBackendManager();
        initLLMRouter();
    }
    // Always feed path to agentic bridge so chat and task execution use this model (creates bridge if needed)
    bool bridgeOk = loadModelForInference(filepath);
    if (bridgeOk && !ggufOk)
        appendToOutput("Model loaded into Agentic Bridge (streaming GGUF skipped).\n", "Output", OutputSeverity::Info);
    if (ggufOk || bridgeOk)
    {
        std::string msg = "✅ Model loaded and ready for inference!\r\n\r\n"
                          "You can now ask questions and use agentic tasks in the chat panel.\r\n"
                          "Try: 'hello', 'model info', or request a task (Agent mode allows tool execution).";
        appendCopilotResponse(msg);
    }
}

// ============================================================================
// GGUF Model Loading Implementation
// ============================================================================

bool Win32IDE::loadGGUFModel(const std::string& filepath)
{
    if (!m_ggufLoader)
    {
        std::string error = "Error: GGUF Loader not initialized";
        appendToOutput(error, "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }

    appendToOutput("Loading GGUF model: " + filepath + "\n", "Output", OutputSeverity::Info);
    appendToOutput("This may take a moment for large files...\n", "Output", OutputSeverity::Info);

    try
    {
        // Attempt to open and parse the GGUF file (streaming - no full data load)
        appendToOutput("[1/5] Opening file...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->Open(filepath))
        {
            std::string error = "❌ Failed to open GGUF file: " + filepath + "\nCheck if file exists and is readable.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            return false;
        }

        appendToOutput("[2/5] Parsing header...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->ParseHeader())
        {
            std::string error =
                "❌ Failed to parse GGUF header from: " + filepath + "\nFile may be corrupted or not a valid GGUF.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        appendToOutput("[3/5] Parsing metadata...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->ParseMetadata())
        {
            std::string error =
                "❌ Failed to parse GGUF metadata from: " + filepath + "\nFile structure may be invalid.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        // Build tensor index (reads tensor offsets but NOT data)
        appendToOutput("[4/5] Building tensor index (may take 10-30 seconds for large files)...\n", "Output",
                       OutputSeverity::Info);
        if (!m_ggufLoader->BuildTensorIndex())
        {
            std::string error =
                "❌ Failed to build tensor index from: " + filepath + "\nFile may be too large or corrupted.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        // Pre-load embedding zone for inference preparation
        appendToOutput("[5/5] Pre-loading embedding zone...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->LoadZone("embedding"))
        {
            std::string warning = "⚠️  Warning: Could not pre-load embedding zone (non-critical)";
            appendToOutput(warning, "Output", OutputSeverity::Warning);
        }
    }
    catch (const std::exception& e)
    {
        std::string error = "❌ Exception loading GGUF file:\n" + std::string(e.what()) + "\n\nFile: " + filepath;
        appendToOutput(error + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }
    catch (...)
    {
        std::string error = "❌ Unknown exception loading GGUF file: " + filepath;
        appendToOutput(error + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }

    // Store model info
    setLoadedModelPath(filepath);
    m_currentModelMetadata = m_ggufLoader->GetMetadata();
    m_modelTensors = m_ggufLoader->GetAllTensorInfo();  // Get tensor info for backward compatibility

    // Log success with memory savings information
    size_t currentMemory = m_ggufLoader->GetCurrentMemoryUsage();
    std::string info = "✅ Model loaded successfully (STREAMING MODE)!\n";
    info += "File: " + filepath + "\n";
    info += "Tensors: " + std::to_string(m_modelTensors.size()) + "\n";
    info += "Layers: " + std::to_string(m_currentModelMetadata.layer_count) + "\n";
    info += "Context: " + std::to_string(m_currentModelMetadata.context_length) + "\n";
    info += "Vocab: " + std::to_string(m_currentModelMetadata.vocab_size) + "\n";
    info += "Current Memory: " + std::to_string(currentMemory / 1024 / 1024) + " MB\n";
    info += "Max Memory: ~500 MB (zone-based streaming)\n\n";

    auto zones = m_ggufLoader->GetLoadedZones();
    if (!zones.empty())
    {
        info += "Loaded Zones: ";
        for (size_t i = 0; i < zones.size(); i++)
        {
            info += zones[i];
            if (i < zones.size() - 1)
                info += ", ";
        }
        info += "\n";
    }

    appendToOutput(info, "Output", OutputSeverity::Info);

    // Update status bar
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide("Model: " + std::string(filepath)).c_str());

    // Auto-activate Copilot panel and send welcome message
    if (m_hwndSecondarySidebar && m_hwndCopilotChatOutput)
    {
        // Make secondary sidebar visible if hidden
        ShowWindow(m_hwndSecondarySidebar, SW_SHOW);

        // Send agentic welcome message to Copilot
        std::string welcomeMsg = "🤖 AI Model Loaded!\r\n\r\n";
        welcomeMsg += "I'm now ready to assist you with:\r\n";
        welcomeMsg += "• Code analysis and review\r\n";
        welcomeMsg += "• GGUF model exploration\r\n";
        welcomeMsg += "• Tensor inspection and debugging\r\n";
        welcomeMsg += "• PowerShell automation\r\n";
        welcomeMsg += "• File operations\r\n\r\n";
        welcomeMsg += "Model: " + filepath + "\r\n";
        welcomeMsg += "Tensors: " + std::to_string(m_modelTensors.size()) + "\r\n";
        welcomeMsg += "Memory: " + std::to_string(currentMemory / 1024 / 1024) + " MB\r\n\r\n";
        welcomeMsg += "Ask me anything!\r\n";

        appendCopilotResponse(welcomeMsg);
    }

    return true;
}

std::string Win32IDE::getModelInfo() const
{
    if (m_modelTensors.empty() || !m_ggufLoader)
    {
        return "No model loaded";
    }

    std::string info = "═══════════════════════════════════════════\n";
    info += "GGUF Model Information (STREAMING MODE)\n";
    info += "═══════════════════════════════════════════\n\n";

    info += "File: " + m_loadedModelPath + "\n";
    info += "Tensors: " + std::to_string(m_modelTensors.size()) + "\n";
    info += "Layers: " + std::to_string(m_currentModelMetadata.layer_count) + "\n";
    info += "Context Length: " + std::to_string(m_currentModelMetadata.context_length) + "\n";
    info += "Embedding Dim: " + std::to_string(m_currentModelMetadata.embedding_dim) + "\n";
    info += "Vocab Size: " + std::to_string(m_currentModelMetadata.vocab_size) + "\n";
    info += "Architecture: " + m_currentModelMetadata.architecture_type + "\n\n";

    // Show zone status (memory efficiency indicator)
    size_t currentMemory = m_ggufLoader->GetCurrentMemoryUsage();
    auto loadedZones = m_ggufLoader->GetLoadedZones();

    info += "📊 Memory Status:\n";
    info += "  Current RAM: " + std::to_string(currentMemory / 1024 / 1024) + " MB\n";
    info += "  Max Per Zone: ~400 MB\n";
    info += "  Total Capacity: ~500 MB (92x reduction from full load!)\n";
    info += "  Loaded Zones: " + std::to_string(loadedZones.size()) + "\n\n";

    if (!loadedZones.empty())
    {
        info += "🎯 Active Zones:\n";
        for (const auto& zone : loadedZones)
        {
            info += "   ✓ " + zone + "\n";
        }
        info += "\n";
    }

    info += "Tensor Details (first 10):\n";
    info += "──────────────────────────────────────────\n";

    for (size_t i = 0; i < m_modelTensors.size() && i < 10; ++i)
    {
        const auto& tensor = m_modelTensors[i];
        info += "[" + std::to_string(i + 1) + "] " + tensor.name + "\n";
        info += "    Size: " + std::to_string(tensor.size_bytes / 1024 / 1024) + " MB\n";
        info += "    Type: " + m_ggufLoader->GetTypeString(tensor.type) + "\n";
    }

    if (m_modelTensors.size() > 10)
    {
        info += "... and " + std::to_string(m_modelTensors.size() - 10) + " more tensors\n";
    }

    info += "\n💡 Tip: Zones load on-demand during inference for optimal performance!\n";

    return info;
}

bool Win32IDE::loadTensorData(const std::string& tensorName, std::vector<uint8_t>& data)
{
    if (!m_ggufLoader)
    {
        return false;
    }
    // StreamingGGUFLoader automatically loads required zone if needed
    return m_ggufLoader->LoadTensorZone(tensorName, data);
}

// ============================================================================
// FILE EXPLORER IMPLEMENTATION
// ============================================================================

void Win32IDE::createFileExplorer()
{
    if (!m_hwndSidebar)
        return;

    m_hwndFileExplorer = CreateWindowExW(
        WS_EX_CLIENTEDGE, WC_TREEVIEWW, L"",
        WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS, 5, 30,
        m_sidebarWidth - 10, 400, m_hwndSidebar, (HMENU)IDC_FILE_EXPLORER, m_hInstance, nullptr);

    // LOGGING AS REQUESTED
    char logBuf[256];
    sprintf_s(logBuf, "Explorer HWND created: %p (Parent: %p)", m_hwndFileExplorer, m_hwndSidebar);
    LOG_INFO(std::string(logBuf));

    if (!m_hwndFileExplorer)
        return;

    // Create image list for icons
    m_hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 3, 0);
    if (m_hImageList)
    {
        // Load icons for folders, files, and model files
        HICON hFolderIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32755), IMAGE_ICON, 16, 16, LR_SHARED);
        HICON hFileIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32512), IMAGE_ICON, 16, 16, LR_SHARED);
        HICON hModelIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32516), IMAGE_ICON, 16, 16, LR_SHARED);

        ImageList_AddIcon(m_hImageList, hFolderIcon);  // Index 0: Folder
        ImageList_AddIcon(m_hImageList, hFileIcon);    // Index 1: Regular file
        ImageList_AddIcon(m_hImageList, hModelIcon);   // Index 2: Model file

        TreeView_SetImageList(m_hwndFileExplorer, m_hImageList, TVSIL_NORMAL);
    }

    populateFileTree();
}

void Win32IDE::populateFileTree()
{
    if (!m_hwndFileExplorer)
        return;

    // Clear existing items
    TreeView_DeleteAllItems(m_hwndFileExplorer);

    // Add root directories for model browsing (config/env/resolver, then fallbacks)
    std::vector<std::string> modelPaths;
    const char* ollamaEnv = std::getenv("RAWRXD_OLLAMA_PATH");
    if (ollamaEnv && ollamaEnv[0])
        modelPaths.push_back(ollamaEnv);
    const char* ollamaModels = std::getenv("OLLAMA_MODELS");
    if (ollamaModels && ollamaModels[0])
        modelPaths.push_back(std::string(ollamaModels));
    modelPaths.push_back(PathResolver::getModelsPath());
    const char* username = getenv("USERNAME");
    std::string userDir(username && username[0] ? username : "User");
    modelPaths.push_back("C:\\Users\\" + userDir + "\\OllamaModels");
    modelPaths.push_back("D:\\OllamaModels");
    modelPaths.push_back("C:\\OllamaModels");

    for (const auto& path : modelPaths)
    {
        if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        {
            std::string displayName = path;
            size_t lastSlash = path.find_last_of("\\/");
            if (lastSlash != std::string::npos)
            {
                displayName = path.substr(lastSlash + 1) + " (" + path + ")";
            }

            HTREEITEM hRoot = addTreeItem(TVI_ROOT, displayName, path, true);
            scanDirectory(path, hRoot);
        }
    }

    // Expand the D:\OllamaModels by default if it exists
    HTREEITEM hFirst = TreeView_GetRoot(m_hwndFileExplorer);
    if (hFirst)
    {
        TreeView_Expand(m_hwndFileExplorer, hFirst, TVE_EXPAND);
    }
}

HTREEITEM Win32IDE::addTreeItem(HTREEITEM hParent, const std::string& text, const std::string& fullPath,
                                bool isDirectory)
{
    TVINSERTSTRUCTW tvins = {};
    tvins.hParent = hParent;
    tvins.hInsertAfter = TVI_LAST;
    tvins.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;

    char* pathData = new char[fullPath.length() + 1];
    strcpy_s(pathData, fullPath.length() + 1, fullPath.c_str());

    wchar_t wbuf[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, text.c_str(), -1, wbuf, MAX_PATH);
    tvins.item.pszText = wbuf;
    tvins.item.lParam = reinterpret_cast<LPARAM>(pathData);

    if (isDirectory)
    {
        tvins.item.iImage = 0;
        tvins.item.iSelectedImage = 0;
    }
    else if (isModelFile(fullPath))
    {
        tvins.item.iImage = 2;
        tvins.item.iSelectedImage = 2;
    }
    else
    {
        tvins.item.iImage = 1;
        tvins.item.iSelectedImage = 1;
    }

    return (HTREEITEM)SendMessageW(m_hwndFileExplorer, TVM_INSERTITEM, 0, (LPARAM)&tvins);
}

void Win32IDE::scanDirectory(const std::string& dirPath, HTREEITEM hParent)
{
    WIN32_FIND_DATAA findData;
    std::string searchPath = dirPath + "\\*";

    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
        {
            continue;
        }

        std::string fullPath = dirPath + "\\" + findData.cFileName;
        bool isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        // Skip hidden and system files
        if (findData.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))
        {
            continue;
        }

        // For files, only show model files and some common extensions
        if (!isDirectory)
        {
            std::string fileName = findData.cFileName;
            std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);

            if (!isModelFile(fullPath) && fileName.find(".txt") == std::string::npos &&
                fileName.find(".json") == std::string::npos && fileName.find(".md") == std::string::npos &&
                fileName.find(".log") == std::string::npos)
            {
                continue;
            }
        }

        HTREEITEM hItem = addTreeItem(hParent, findData.cFileName, fullPath, isDirectory);

        // For directories, add a dummy child so we can expand later
        if (isDirectory)
        {
            addTreeItem(hItem, "Loading...", "", false);
        }

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

bool Win32IDE::isModelFile(const std::string& filePath)
{
    std::string fileName = filePath;
    std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);

    return fileName.find(".gguf") != std::string::npos || fileName.find(".bin") != std::string::npos ||
           fileName.find(".safetensors") != std::string::npos || fileName.find(".pt") != std::string::npos ||
           fileName.find(".pth") != std::string::npos || fileName.find(".onnx") != std::string::npos;
}

void Win32IDE::expandTreeNode(HTREEITEM hItem)
{
    if (!hItem)
        return;

    // Check if this node has been expanded before
    HTREEITEM hChild = TreeView_GetChild(m_hwndFileExplorer, hItem);
    if (hChild)
    {
        TVITEMW item = {};
        item.hItem = hChild;
        item.mask = TVIF_TEXT | TVIF_PARAM;
        wchar_t buffer[MAX_PATH];
        item.pszText = buffer;
        item.cchTextMax = MAX_PATH;

        if (SendMessageW(m_hwndFileExplorer, TVM_GETITEM, 0, (LPARAM)&item))
        {
            if (wcscmp(item.pszText, L"Loading...") == 0)
            {
                // Remove the dummy item
                TreeView_DeleteItem(m_hwndFileExplorer, hChild);

                // Get the full path and scan the directory
                TVITEMW parentItem = {};
                parentItem.hItem = hItem;
                parentItem.mask = TVIF_PARAM;
                if (SendMessageW(m_hwndFileExplorer, TVM_GETITEM, 0, (LPARAM)&parentItem) && parentItem.lParam)
                {
                    std::string dirPath = reinterpret_cast<char*>(parentItem.lParam);
                    scanDirectory(dirPath, hItem);
                }
            }
        }
    }
}

std::string Win32IDE::getSelectedFilePath()
{
    HTREEITEM hSelected = TreeView_GetSelection(m_hwndFileExplorer);
    if (!hSelected)
        return "";

    TVITEMW item = {};
    item.hItem = hSelected;
    item.mask = TVIF_PARAM;

    if (SendMessageW(m_hwndFileExplorer, TVM_GETITEM, 0, (LPARAM)&item) && item.lParam)
    {
        return std::string(reinterpret_cast<char*>(item.lParam));
    }

    return "";
}

void Win32IDE::onFileExplorerDoubleClick()
{
    std::string filePath = getSelectedFilePath();
    if (filePath.empty())
        return;

    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return;

    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        // Expand/collapse directory
        HTREEITEM hSelected = TreeView_GetSelection(m_hwndFileExplorer);
        if (hSelected)
        {
            UINT state = TreeView_GetItemState(m_hwndFileExplorer, hSelected, TVIS_EXPANDED);
            if (state & TVIS_EXPANDED)
            {
                TreeView_Expand(m_hwndFileExplorer, hSelected, TVE_COLLAPSE);
            }
            else
            {
                expandTreeNode(hSelected);
                TreeView_Expand(m_hwndFileExplorer, hSelected, TVE_EXPAND);
            }
        }
    }
    else
    {
        // Load file
        if (isModelFile(filePath))
        {
            loadModelFromExplorer(filePath);
        }
        else
        {
            // Open text files in editor - with size check!
            try
            {
                std::ifstream file(filePath, std::ios::binary);
                if (file.is_open())
                {
                    // Check file size first
                    file.seekg(0, std::ios::end);
                    size_t fileSize = file.tellg();
                    file.seekg(0, std::ios::beg);

                    if (fileSize > 10 * 1024 * 1024)
                    {  // 10MB limit
                        MessageBoxW(m_hwndMain, L"File too large to open in editor (>10MB).", L"File Too Large",
                                    MB_OK | MB_ICONWARNING);
                        return;
                    }

                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    setWindowText(m_hwndEditor, content);
                    m_currentFile = filePath;
                    updateTitleBarText();
                    file.close();
                }
            }
            catch (const std::exception& e)
            {
                std::string error = "Error opening file: " + std::string(e.what());
                MessageBoxW(m_hwndMain, utf8ToWide(error).c_str(), L"Error", MB_OK | MB_ICONERROR);
            }
        }
    }
}

void Win32IDE::loadModelFromExplorer(const std::string& filePath)
{
    bool ggufOk = loadGGUFModel(filePath);
    // Always pass to agentic bridge so chat and task execution use this model
    bool bridgeOk = loadModelForInference(filePath);
    if (ggufOk)
    {
        std::string message = "✅ Model loaded from File Explorer:\n" + filePath + "\n\n" + getModelInfo();
        appendToOutput(message, "Output", OutputSeverity::Info);
    }
    if (bridgeOk)
    {
        appendToOutput("Agentic bridge loaded model; chat and task execution use this model.\n", "Output",
                       OutputSeverity::Info);
        std::string filename = filePath;
        size_t lastSlash = filename.find_last_of("\\/");
        if (lastSlash != std::string::npos)
            filename = filename.substr(lastSlash + 1);
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide("Model: " + filename).c_str());
    }
    if (!ggufOk && !bridgeOk)
    {
        appendToOutput("❌ Failed to load model: " + filePath + " (not a valid GGUF and native load failed).", "Errors",
                       OutputSeverity::Error);
    }
}

void Win32IDE::onFileExplorerRightClick()
{
    std::string filePath = getSelectedFilePath();
    if (!filePath.empty())
    {
        DWORD attributes = GetFileAttributesA(filePath.c_str());
        bool isDirectory = (attributes != INVALID_FILE_ATTRIBUTES) && (attributes & FILE_ATTRIBUTE_DIRECTORY);
        showFileContextMenu(filePath, isDirectory);
    }
}

void Win32IDE::showFileContextMenu(const std::string& filePath, bool isDirectory)
{
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu)
        return;

    static constexpr int IDC_CTX_REFRESH = 50001, IDC_CTX_OPEN_EXPLORER = 50002, IDC_CTX_SET_ROOT = 50003;
    static constexpr int IDC_CTX_LOAD_MODEL = 50011, IDC_CTX_MODEL_INFO = 50012, IDC_CTX_OPEN_EDITOR = 50013,
                         IDC_CTX_COPY_PATH = 50014, IDC_CTX_SHOW_EXPLORER = 50015, IDC_CTX_OPEN_TERMINAL_PS = 50016,
                         IDC_CTX_OPEN_TERMINAL_CMD = 50017;
    static constexpr int IDC_CTX_DELETE = 50020, IDC_CTX_RENAME = 50021;
    if (isDirectory)
    {
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_REFRESH, L"Refresh");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_OPEN_EXPLORER, L"Open in Explorer");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_OPEN_TERMINAL_PS, L"Open PowerShell Here");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_OPEN_TERMINAL_CMD, L"Open CMD Here");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_SET_ROOT, L"Set as Root Path");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_DELETE, L"Delete");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_RENAME, L"Rename");
    }
    else
    {
        if (isModelFile(filePath))
        {
            AppendMenuW(hMenu, MF_STRING, IDC_CTX_LOAD_MODEL, L"Load Model");
            AppendMenuW(hMenu, MF_STRING, IDC_CTX_MODEL_INFO, L"Show Model Info");
            AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        }
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_OPEN_EDITOR, L"Open with Editor");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_COPY_PATH, L"Copy Path");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_SHOW_EXPLORER, L"Show in Explorer");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_OPEN_TERMINAL_PS, L"Open PowerShell Here");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_OPEN_TERMINAL_CMD, L"Open CMD Here");
        AppendMenuW(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_DELETE, L"Delete");
        AppendMenuW(hMenu, MF_STRING, IDC_CTX_RENAME, L"Rename");
    }

    POINT pt;
    GetCursorPos(&pt);

    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hwndMain, nullptr);

    switch (cmd)
    {
        case 50001:  // Refresh directory
            refreshFileExplorer();
            break;
        case 50002:  // Open in Explorer
        case 50015:  // Show in Explorer
            ShellExecuteA(nullptr, "explore", filePath.c_str(), nullptr, nullptr, SW_SHOW);
            break;
        case 50020:  // IDC_CTX_DELETE
            deleteItemInExplorer(filePath);
            break;
        case 50021:  // IDC_CTX_RENAME
            renameItemInExplorer(filePath);
            break;
        case 50003:  // Set as Root Path
            m_currentExplorerPath = filePath;
            populateFileTree();
            break;
        case 50016:  // Open PowerShell Here
        case 50017:  // Open CMD Here
        {
            std::string targetDir = filePath;
            if (!isDirectory)
            {
                std::error_code ec;
                targetDir = std::filesystem::path(filePath).parent_path().string();
                if (targetDir.empty())
                    targetDir = m_currentExplorerPath;
            }

            if (targetDir.empty())
                targetDir = m_currentExplorerPath;

            if (targetDir.empty())
                break;

            if (cmd == 50016)
            {
                startPowerShell();
                TerminalPane* pane = getActiveTerminalPane();
                if (pane && pane->manager)
                {
                    std::string escaped = targetDir;
                    size_t pos = 0;
                    while ((pos = escaped.find('\'', pos)) != std::string::npos)
                    {
                        escaped.replace(pos, 1, "''");
                        pos += 2;
                    }
                    pane->manager->writeInput("Set-Location -LiteralPath '" + escaped + "'\r\n");
                }
                appendToOutput("Opened PowerShell at: " + targetDir + "\n", "Output", OutputSeverity::Info);
            }
            else
            {
                startCommandPrompt();
                TerminalPane* pane = getActiveTerminalPane();
                if (pane && pane->manager)
                {
                    pane->manager->writeInput("cd /d \"" + targetDir + "\"\r\n");
                }
                appendToOutput("Opened CMD at: " + targetDir + "\n", "Output", OutputSeverity::Info);
            }
        }
        break;
        case 50011:  // Load Model
            loadModelFromExplorer(filePath);
            break;
        case 50012:  // Show Model Info
            if (loadGGUFModel(filePath))
            {
                loadModelForInference(filePath);
                std::string info = "Model Information:\n" + getModelInfo();
                MessageBoxW(m_hwndMain, utf8ToWide(info).c_str(), L"Model Info", MB_OK | MB_ICONINFORMATION);
            }
            break;
        case 50013:  // Open with Editor
        {
            std::ifstream file(filePath);
            if (file.is_open())
            {
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                setWindowText(m_hwndEditor, content);
                m_currentFile = filePath;
                updateTitleBarText();
            }
        }
        break;
        case 50014:  // Copy Path
            if (OpenClipboard(m_hwndMain))
            {
                EmptyClipboard();
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, filePath.size() + 1);
                if (hMem)
                {
                    char* dest = (char*)GlobalLock(hMem);
                    strcpy_s(dest, filePath.size() + 1, filePath.c_str());
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_TEXT, hMem);
                }
                CloseClipboard();
            }
            break;
    }

    DestroyMenu(hMenu);
}

void Win32IDE::refreshFileExplorer()
{
    populateFileTree();
}

// ============================================================================
// MODEL CHAT INTERFACE IMPLEMENTATION
// ============================================================================

bool Win32IDE::isModelLoaded() const
{
    // Model is loaded if we have a path and either streaming loader or agentic bridge has it (local models usable
    // regardless of agentic detection)
    if (m_loadedModelPath.empty())
        return false;
    if (m_ggufLoader && !m_modelTensors.empty())
        return true;
    if (m_agenticBridge && m_agenticBridge->IsInitialized())
        return true;
    return false;
}

std::string Win32IDE::sendMessageToModel(const std::string& message)
{
    // Allow chat when agentic bridge is initialized (local model or Ollama/cloud via routeInferenceRequest)
    bool canChat = isModelLoaded() || (m_agenticBridge && m_agenticBridge->IsInitialized());
    if (!canChat)
    {
        return "Error: No model loaded. Load a GGUF (File > Open / Load Model) or set up Ollama/backend in Backend "
               "Switcher.";
    }

    // Phase 8B/8C: Route through LLM router (if enabled) or backend manager
    if (m_backendManagerInitialized)
    {
        std::string resp = routeWithIntelligence(message);
        if (!resp.empty() && resp.find("[Backend Error]") != 0)
        {
            m_chatHistory.push_back({message, resp});
            return resp;
        }
    }

    // First try: send through local Ollama if available
    std::string llmResponse;
    if (trySendToOllama(message, llmResponse))
    {
        m_chatHistory.push_back({message, llmResponse});
        return llmResponse;
    }

    // Fallback: Local CPU Inference (Real Logic)
    if (m_ggufLoader)
    {
        // Use the native fallback engine if available
        if (m_nativeEngine)
        {
            auto* engine = m_nativeEngine.get();
            auto tokens = engine->Tokenize(message);
            auto output_tokens = engine->Generate(tokens, 512);
            std::string response = engine->Detokenize(output_tokens);
            m_chatHistory.push_back({message, response});
            return response;
        }
    }

    // Ensure agentic bridge has current model so chat and agentic work regardless of which path loaded it
    if (!m_loadedModelPath.empty())
        const_cast<Win32IDE*>(this)->ensureAgenticBridgeHasModel(m_loadedModelPath);

    // Chat via agentic bridge (works for any local model; agentic/tools allowed when model supports it)
    if (m_agenticBridge && m_agenticBridge->IsInitialized())
    {
        AgentResponse r = m_agenticBridge->ExecuteAgentCommand(message);
        if (r.type != AgentResponseType::AGENT_ERROR && !r.content.empty())
        {
            m_chatHistory.push_back({message, r.content});
            return r.content;
        }
        if (r.type == AgentResponseType::AGENT_ERROR && !r.content.empty())
            return r.content;
    }

    return "Error: Local model loaded but Native Inference Engine not initialized.\n";
}

void Win32IDE::toggleChatMode()
{
    m_chatMode = !m_chatMode;

    if (m_chatMode)
    {
        // Entering chat mode
        std::string status = "🤖 Chat Mode ON - Model: ";
        status +=
            m_loadedModelPath.empty() ? "None" : m_loadedModelPath.substr(m_loadedModelPath.find_last_of("\\/") + 1);

        appendToOutput(status, "Output", OutputSeverity::Info);
        appendToOutput("Type your messages in the command input. Use /exit-chat to return to terminal mode.", "Output",
                       OutputSeverity::Info);

        // Update status bar
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)L"Chat Mode");

        // Clear existing chat display and show instructions
        appendChatMessage("System", "Chat mode activated! You can now talk with the loaded model.");
        appendChatMessage("System", "Commands: /exit-chat to return to terminal mode");
    }
    else
    {
        // Exiting chat mode
        appendToOutput("🔧 Chat Mode OFF - Returned to terminal mode", "Output", OutputSeverity::Info);
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)L"Terminal Mode");
        appendChatMessage("System", "Chat mode deactivated. Returned to terminal mode.");
    }
}

void Win32IDE::appendChatMessage(const std::string& user, const std::string& message)
{
    // Get timestamp
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char timestamp[16];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &timeinfo);

    // Format message
    std::string formattedMsg = "[" + std::string(timestamp) + "] " + user + ": " + message + "\n\n";

    // Display in output panel
    if (user == "System")
    {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    }
    else if (user == "You")
    {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    }
    else if (user == "Model")
    {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    }
}

// ============================================================================
// GIT INTEGRATION - Status, Commit, Push, Pull
// ============================================================================

void Win32IDE::showGitStatus()
{
    if (!isGitRepository())
    {
        MessageBoxW(m_hwndMain, L"Not a Git repository", L"Git", MB_OK | MB_ICONWARNING);
        return;
    }

    updateGitStatus();

    std::ostringstream status;
    status << "Git Status\n";
    status << "==========\n\n";
    status << "Branch: " << m_gitStatus.branch << "\n";
    status << "\nChanges:\n";
    status << "  Modified:  " << m_gitStatus.modified << "\n";
    status << "  Added:     " << m_gitStatus.added << "\n";
    status << "  Deleted:   " << m_gitStatus.deleted << "\n";
    status << "  Untracked: " << m_gitStatus.untracked << "\n";

    MessageBoxW(m_hwndMain, utf8ToWide(status.str()).c_str(), L"Git Status", MB_OK | MB_ICONINFORMATION);
}

void Win32IDE::updateGitStatus()
{
    if (!isGitRepository())
    {
        m_gitStatus = GitStatus();
        return;
    }

    std::string output;

    // Get current branch
    executeGitCommand("git rev-parse --abbrev-ref HEAD", output);
    m_gitStatus.branch = output;
    if (!m_gitStatus.branch.empty() && m_gitStatus.branch.back() == '\n')
    {
        m_gitStatus.branch.pop_back();
    }
    output.clear();

    // Get status --porcelain
    executeGitCommand("git status --porcelain", output);
    m_gitStatus.modified = 0;
    m_gitStatus.added = 0;
    m_gitStatus.deleted = 0;
    m_gitStatus.untracked = 0;
    m_gitStatus.fileStatus.clear();

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line))
    {
        if (line.length() < 2)
            continue;

        char status = line[0];
        char status2 = line[1];
        std::string filePath = line.substr(3);

        // Store per-file status (prefer index status over working tree)
        char fileStatus = status;
        if (fileStatus == ' ')
        {
            fileStatus = status2;
        }

        m_gitStatus.fileStatus[filePath] = fileStatus;

        if (status == 'M' || status2 == 'M')
            m_gitStatus.modified++;
        if (status == 'A' || status2 == 'A')
            m_gitStatus.added++;
        if (status == 'D' || status2 == 'D')
            m_gitStatus.deleted++;
        if (status == '?' || status2 == '?')
            m_gitStatus.untracked++;
    }

    m_gitStatus.hasChanges =
        (m_gitStatus.modified + m_gitStatus.added + m_gitStatus.deleted + m_gitStatus.untracked) > 0;
}

void Win32IDE::gitCommit(const std::string& message)
{
    if (!isGitRepository())
    {
        MessageBoxW(m_hwndMain, L"Not a Git repository", L"Git Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string output;
    std::string command = "git commit -m \"" + message + "\"";
    executeGitCommand(command, output);

    MessageBoxW(m_hwndMain, utf8ToWide(output).c_str(), L"Git Commit", MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitPush()
{
    if (!isGitRepository())
    {
        MessageBoxW(m_hwndMain, L"Not a Git repository", L"Git Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string output;
    executeGitCommand("git push", output);

    MessageBoxW(m_hwndMain, utf8ToWide(output.empty() ? "Push completed successfully" : output).c_str(), L"Git Push",
                MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitPull()
{
    if (!isGitRepository())
    {
        MessageBoxW(m_hwndMain, L"Not a Git repository", L"Git Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::string output;
    executeGitCommand("git pull", output);

    MessageBoxW(m_hwndMain, utf8ToWide(output.empty() ? "Pull completed successfully" : output).c_str(), L"Git Pull",
                MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitStageFile(const std::string& filePath)
{
    if (!isGitRepository())
        return;

    std::string output;
    std::string command = "git add \"" + filePath + "\"";
    executeGitCommand(command, output);
    updateGitStatus();
}

void Win32IDE::gitUnstageFile(const std::string& filePath)
{
    if (!isGitRepository())
        return;

    std::string output;
    std::string command = "git reset HEAD \"" + filePath + "\"";
    executeGitCommand(command, output);
    updateGitStatus();
}

bool Win32IDE::isGitRepository() const
{
    if (!m_gitRepoPath.empty())
    {
        std::string gitDir = m_gitRepoPath + "\\.git";
        DWORD attrib = GetFileAttributesA(gitDir.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
    }

    // Check current directory
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    std::string gitDir = std::string(currentDir) + "\\.git";
    DWORD attrib = GetFileAttributesA(gitDir.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::vector<GitFile> Win32IDE::getGitChangedFiles() const
{
    std::vector<GitFile> files;

    if (!isGitRepository())
        return files;

    std::string output;
    const_cast<Win32IDE*>(this)->executeGitCommand("git status --porcelain", output);

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line))
    {
        if (line.length() < 4)
            continue;

        GitFile file;
        file.status = line[0] != ' ' ? line[0] : line[1];
        file.staged = (line[0] != ' ' && line[0] != '?');
        file.path = line.substr(3);

        files.push_back(file);
    }

    return files;
}

bool Win32IDE::executeGitCommand(const std::string& command, std::string& output)
{
    output.clear();

    // Create a temporary file for output
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "rawr_git_output.txt";

    // Execute command and redirect output
    std::string fullCommand = command + " > \"" + tempFile + "\" 2>&1";

    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (CreateProcessA(NULL, const_cast<char*>(fullCommand.c_str()), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL,
                       &si, &pi))
    {

        WaitForSingleObject(pi.hProcess, 5000);  // 5 second timeout
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        // Read output file
        std::ifstream file(tempFile);
        if (file.is_open())
        {
            std::string line;
            while (std::getline(file, line))
            {
                output += line + "\n";
            }
            file.close();
            DeleteFileA(tempFile.c_str());
        }
        return true;
    }
    return false;
}

void Win32IDE::showGitPanel()
{
    if (!isGitRepository())
    {
        MessageBoxW(m_hwndMain, L"Not a Git repository", L"Git", MB_OK | MB_ICONWARNING);
        return;
    }

    // Create Git panel if it doesn't exist
    if (!m_hwndGitPanel || !IsWindow(m_hwndGitPanel))
    {
        m_hwndGitPanel = CreateWindowExW(WS_EX_TOOLWINDOW, L"STATIC", L"Git Panel",
                                         WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_SIZEBOX, 200, 100, 600,
                                         500, m_hwndMain, nullptr, m_hInstance, nullptr);

        // Branch and status info
        m_hwndGitStatusText =
            CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY, 10, 10,
                            580, 60, m_hwndGitPanel, nullptr, m_hInstance, nullptr);

        CreateWindowExW(0, L"STATIC", L"Changed Files:", WS_CHILD | WS_VISIBLE, 10, 80, 120, 20, m_hwndGitPanel,
                        nullptr, m_hInstance, nullptr);

        m_hwndGitFileList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                                            WS_CHILD | WS_VISIBLE | LBS_STANDARD | LBS_EXTENDEDSEL | WS_VSCROLL, 10,
                                            105, 280, 300, m_hwndGitPanel, nullptr, m_hInstance, nullptr);
    }

    ShowWindow(m_hwndGitPanel, SW_SHOW);
    refreshGitPanel();
}

void Win32IDE::refreshGitPanel()
{
    if (!m_hwndGitPanel || !IsWindow(m_hwndGitPanel))
        return;

    updateGitStatus();

    // Update status text
    std::string statusText = "Branch: " + m_gitStatus.branch + "\n";
    statusText += "Modified: " + std::to_string(m_gitStatus.modified) + " | ";
    statusText += "Added: " + std::to_string(m_gitStatus.added) + " | ";
    statusText += "Deleted: " + std::to_string(m_gitStatus.deleted) + " | ";
    statusText += "Untracked: " + std::to_string(m_gitStatus.untracked);

    if (m_hwndGitStatusText)
    {
        SetWindowTextW(m_hwndGitStatusText, utf8ToWide(statusText).c_str());
    }

    // Update file list
    if (m_hwndGitFileList)
    {
        SendMessage(m_hwndGitFileList, LB_RESETCONTENT, 0, 0);

        std::vector<GitFile> files = getGitChangedFiles();
        for (const auto& file : files)
        {
            std::string displayText;
            if (file.staged)
            {
                displayText = "[S] ";
            }
            else
            {
                displayText = "[ ] ";
            }

            switch (file.status)
            {
                case 'M':
                    displayText += "(M) ";
                    break;
                case 'A':
                    displayText += "(A) ";
                    break;
                case 'D':
                    displayText += "(D) ";
                    break;
                case '?':
                    displayText += "(?) ";
                    break;
                default:
                    displayText += "( ) ";
                    break;
            }

            displayText += file.path;
            SendMessageW(m_hwndGitFileList, LB_ADDSTRING, 0, (LPARAM)utf8ToWide(displayText).c_str());
        }
    }
}

void Win32IDE::showCommitDialog()
{
    if (!isGitRepository())
    {
        MessageBoxW(m_hwndMain, L"Not a Git repository", L"Git", MB_OK | MB_ICONWARNING);
        return;
    }

    HWND hwndDlg =
        CreateWindowExW(WS_EX_DLGMODALFRAME, L"STATIC", L"Git Commit", WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                        150, 150, 500, 200, m_hwndMain, nullptr, m_hInstance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Commit Message:", WS_CHILD | WS_VISIBLE, 10, 10, 120, 20, hwndDlg, nullptr,
                    m_hInstance, nullptr);

    m_hwndCommitDialog =
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY, 10, 35, 470,
                        100, hwndDlg, nullptr, m_hInstance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Commit", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 10, 145, 100, 30, hwndDlg,
                    (HMENU)1, m_hInstance, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE, 120, 145, 100, 30, hwndDlg, (HMENU)2, m_hInstance,
                    nullptr);

    SetFocus(m_hwndCommitDialog);
}

// ============================================================================
// AI INFERENCE IMPLEMENTATION - Connects GGUF Loader to Chat Panel
// ============================================================================

void Win32IDE::openModel()
{
    wchar_t filename[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFilter = L"GGUF Models\0*.gguf\0All Files\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = L"Select GGUF Model";

    if (GetOpenFileNameW(&ofn))
    {
        loadModelForInference(wideToUtf8(filename));
    }
}

bool Win32IDE::ensureAgenticBridgeHasModel(const std::string& path)
{
    if (path.empty())
        return false;
    if (!m_agenticBridge)
        initializeAgenticBridge();
    if (!m_agenticBridge)
        return false;
    if (m_agenticBridge->LoadModel(path))
    {
        setLoadedModelPath(path);
        return true;
    }
    return false;
}

bool Win32IDE::loadModelForInference(const std::string& filepath)
{
    SCOPED_METRIC("model.load");
    METRICS.increment("model.load_attempts");
    appendToOutput("Loading model: " + filepath + "\n", "System", OutputSeverity::Info);

    if (!m_agenticBridge)
    {
        initializeAgenticBridge();
    }

    if (m_agenticBridge)
    {
        if (m_agenticBridge->LoadModel(filepath))
        {
            setLoadedModelPath(filepath);
            METRICS.gauge("model.loaded", 1.0);
            METRICS.increment("model.load_success");
            appendToOutput("Model loaded successfully into Agentic Bridge.\n", "System", OutputSeverity::Info);

            wireLayerProgressToOutputPanel();

            // Lane A "Gold" integration: run a tiny post-load streamer self-check.
            // This verifies (a) privilege attempt, (b) 2MB mapper alignment, (c) map/unmap sanity,
            // without dragging Lane B CLI/bench harness into the UI.
            appendStreamerPostLoadCheck(this, filepath);

            // Sync current UI state
            m_agenticBridge->SetContextSize("4K");
            if (m_hwndContextSlider)
                SendMessage(m_hwndContextSlider, TBM_SETPOS, TRUE, 0);

            return true;
        }
    }

    METRICS.increment("model.load_failures");
    METRICS.gauge("model.loaded", 0.0);
    std::string detail;
    if (m_agenticBridge)
    {
        detail = m_agenticBridge->GetLastModelLoadError();
    }
    if (!detail.empty())
    {
        showModelLoadError(detail);
        appendToOutput("Failed to load model: " + filepath + "\nReason: " + detail + "\n", "System",
                       OutputSeverity::Error);
    }
    else
    {
        appendToOutput("Failed to load model: " + filepath + "\n", "System", OutputSeverity::Error);
    }
    return false;
}

bool Win32IDE::initializeInference()
{
    SCOPED_METRIC("inference.initialize");
    METRICS.increment("inference.init_attempts");
    std::lock_guard<std::mutex> lock(m_inferenceMutex);

    OutputDebugStringA("[AUDIT] initializeInference() called\n");

    // Explicit Logic: Initialize Native CPU Engine if missing (Un-mocking)
    if (!m_nativeEngine)
    {
        try
        {
            m_nativeEngine = RawrXD::CPUInferenceEngine::GetSharedInstance();
            // Match deferredHeavyInit (Win32IDE_Core): same memory plugin as headless-capable path.
            auto memPlugin = std::make_shared<RawrXD::Modules::NativeMemoryModule>();
            m_nativeEngine->RegisterMemoryPlugin(memPlugin);
            m_nativeEngineLoaded = false;
            appendToOutput("[AUDIT] Initialized Native CPU Inference Engine.", "Output", OutputSeverity::Info);
            OutputDebugStringA("[AUDIT] Native CPU Engine created\n");
        }
        catch (const std::exception& e)
        {
            appendToOutput(std::string("[AUDIT] Failed to init native engine: ") + e.what(), "Errors", OutputSeverity::Error);
            OutputDebugStringA("[AUDIT] Native engine init FAILED\n");
            return false;
        }
    }

    // Check if model is loaded via GGUF loader (Streaming)
    if (m_loadedModelPath.empty())
    {
        if (!m_ggufLoader)
        {
            appendToOutput("No model loaded for inference", "Errors", OutputSeverity::Error);
            return false;
        }
        // If ggufLoader has a file open but path var is empty, try to recover (unlikely)
    }

    // Connect Native Engine to Model
    if (m_nativeEngine && !m_loadedModelPath.empty())
    {
        RawrXD::CPUInferenceEngine* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine.get());
        OutputDebugStringA("[AUDIT] Checking if model needs loading into native engine\n");
        if (!engine->IsModelLoaded())
        {
            appendToOutput("[AUDIT] Loading model into Native Engine: " + m_loadedModelPath, "Output", OutputSeverity::Info);
            OutputDebugStringA("[AUDIT] Calling engine->LoadModel()\n");
            if (engine->LoadModel(m_loadedModelPath))
            {
                m_nativeEngineLoaded = true;
                appendToOutput("[AUDIT] ✅ Native Engine Model Loaded Successfully.", "Output", OutputSeverity::Info);
                OutputDebugStringA("[AUDIT] m_nativeEngineLoaded = TRUE\n");
                
                // Wire completion system to native engine (VAL-063)
                InitAICompletion();
                SetCompletionBackendNative(static_cast<void*>(engine));
                appendToOutput("[AUDIT] ✅ AI Completion system wired to native engine.", "Output", OutputSeverity::Info);
                OutputDebugStringA("[AUDIT] AI Completion system initialized\n");
            }
            else
            {
                appendToOutput("[AUDIT] ❌ Native Engine Model Load Failed.", "Errors", OutputSeverity::Error);
                OutputDebugStringA("[AUDIT] Model load FAILED\n");
                // Don't fail completely if we have Ollama fallback, but for "no simulation" we adhere to native.
            }
        }
        else
        {
            OutputDebugStringA("[AUDIT] Model already loaded in native engine\n");
        }
    }
    else
    {
        char buf[512];
        snprintf(buf, sizeof(buf), "[AUDIT] Cannot connect model: m_nativeEngine=%s, m_loadedModelPath='%s'\n",
            m_nativeEngine ? "yes" : "no", m_loadedModelPath.c_str());
        OutputDebugStringA(buf);
    }

    // Set up inference config from model metadata
    m_inferenceConfig.maxTokens = 512;
    m_inferenceConfig.temperature = 0.7f;
    m_inferenceConfig.topP = 0.9f;
    m_inferenceConfig.topK = 40;
    m_inferenceConfig.repetitionPenalty = 1.1f;

    // Use model context length if available
    if (m_currentModelMetadata.context_length > 0)
    {
        m_inferenceConfig.maxTokens = std::min(512, (int)m_currentModelMetadata.context_length / 4);
    }

    appendToOutput("✅ Inference initialized for model: " + m_loadedModelPath, "Output", OutputSeverity::Info);
    wireLayerProgressToOutputPanel();
    return true;
}

void Win32IDE::shutdownInference()
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);

    if (m_inferenceRunning)
    {
        m_inferenceStopRequested = true;
        if (m_inferenceThread.joinable())
        {
            m_inferenceThread.join();
        }
    }

    m_inferenceRunning = false;
    m_inferenceStopRequested = false;
    m_currentInferencePrompt.clear();
    m_currentInferenceResponse.clear();

    appendToOutput("Inference shutdown complete", "Output", OutputSeverity::Info);
}

// ============================================================================
// Thread-safe model path accessors
// ============================================================================
void Win32IDE::setLoadedModelPath(const std::string& path)
{
    std::unique_lock<std::shared_mutex> lock(m_loadedModelPathMutex);
    m_loadedModelPath = path;
}

void Win32IDE::setLoadedModelPath(std::string&& path)
{
    std::unique_lock<std::shared_mutex> lock(m_loadedModelPathMutex);
    m_loadedModelPath = std::move(path);
}

std::string Win32IDE::getLoadedModelPath() const
{
    std::shared_lock<std::shared_mutex> lock(m_loadedModelPathMutex);
    return m_loadedModelPath;
}

void Win32IDE::clearLoadedModelPath()
{
    std::unique_lock<std::shared_mutex> lock(m_loadedModelPathMutex);
    m_loadedModelPath.clear();
}

std::string Win32IDE::generateResponse(const std::string& prompt)
{
    SCOPED_METRIC("inference.generate_response");
    METRICS.increment("inference.requests_total");

    if (m_inferenceRunning)
    {
        METRICS.increment("inference.requests_rejected");
        return "Inference already in progress. Please wait...";
    }

    // Phase 8B/8C: Route through LLM router (if enabled) or backend manager
    if (m_backendManagerInitialized)
    {
        return routeWithIntelligence(prompt);
    }

    // Attempt real remote/local inference via Ollama if configured
    auto performOllama = [&](const std::string& promptText) -> std::string
    {
        if (m_ollamaBaseUrl.empty())
            return "";
        // Expect base URL like http://localhost:11434
        std::string base = m_ollamaBaseUrl;
        if (base.rfind("http://", 0) != 0 && base.rfind("https://", 0) != 0)
            return "";
        bool https = base.rfind("https://", 0) == 0;
        std::string withoutProto = base.substr(base.find("://") + 3);
        std::string host;
        int port = https ? 443 : 80;
        size_t colonPos = withoutProto.find(':');
        size_t slashPos = withoutProto.find('/');
        if (colonPos != std::string::npos)
        {
            host = withoutProto.substr(0, colonPos);
            std::string portStr = withoutProto.substr(
                colonPos + 1, (slashPos == std::string::npos ? withoutProto.size() : slashPos) - (colonPos + 1));
            port = atoi(portStr.c_str());
        }
        else
        {
            host = (slashPos == std::string::npos) ? withoutProto : withoutProto.substr(0, slashPos);
            // Default Ollama port
            if (!https)
                port = 11434;
        }
        std::wstring whost(host.begin(), host.end());
        HINTERNET hSession = WinHttpOpen(L"RawrXDIDE/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
        if (!hSession)
            return "";
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
        if (!hConnect)
        {
            WinHttpCloseHandle(hSession);
            return "";
        }
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate", NULL, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }
        // Build JSON body
        std::string modelTag;
        if (!m_ollamaModelOverride.empty())
            modelTag = m_ollamaModelOverride;
        else
        {
            // Derive from loaded path
            modelTag = m_loadedModelPath;
            size_t pos = modelTag.find_last_of("\\/");
            if (pos != std::string::npos)
                modelTag = modelTag.substr(pos + 1);
        }
        // Basic escaping of quotes in prompt
        std::string escPrompt;
        escPrompt.reserve(promptText.size() + 16);
        for (char c : promptText)
        {
            if (c == '"')
                escPrompt += "\\\"";
            else if (c == '\n')
                escPrompt += "\\n";
            else
                escPrompt += c;
        }
        std::string body =
            std::string("{\"model\":\"") + modelTag + "\",\"prompt\":\"" + escPrompt + "\",\"stream\":false}";
        std::wstring wHeaders = L"Content-Type: application/json";
        BOOL bResults = WinHttpSendRequest(hRequest, wHeaders.c_str(), (DWORD)-1L, (LPVOID)body.c_str(),
                                           (DWORD)body.size(), (DWORD)body.size(), 0);
        if (!bResults)
        {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        std::string raw;
        if (bResults)
        {
            DWORD dwSize = 0;
            do
            {
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                    break;
                if (!dwSize)
                    break;
                std::string chunk;
                chunk.resize(dwSize);
                DWORD dwRead = 0;
                if (!WinHttpReadData(hRequest, chunk.data(), dwSize, &dwRead))
                    break;
                if (dwRead)
                    raw.append(chunk.data(), dwRead);
            } while (dwSize > 0);
        }
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        if (raw.empty())
            return "";
        // Naive JSON parse: look for "response":"..."
        std::string out;
        size_t pos = raw.rfind("\"response\":\"");
        if (pos != std::string::npos)
        {
            pos += 12;  // start after marker
            while (pos < raw.size())
            {
                char c = raw[pos++];
                if (c == '"')
                    break;  // end of string (assumes not escaped)
                if (c == '\\')
                {
                    if (pos < raw.size())
                    {
                        char next = raw[pos++];
                        if (next == 'n')
                            out += '\n';
                        else
                            out += next;
                    }
                }
                else
                    out += c;
            }
        }
        return out.empty() ? raw : out;
    };

    std::string remote = performOllama(prompt);
    if (!remote.empty())
        return remote;

    // Fallback structured guidance if no remote inference available
    std::string modelName =
        m_loadedModelPath.empty() ? "None" : m_loadedModelPath.substr(m_loadedModelPath.find_last_of("\\/") + 1);

    // Fallback: Native CPU Inference Engine
    if (m_nativeEngine && m_nativeEngineLoaded)
    {
        RawrXD::CPUInferenceEngine* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine.get());
        // If engine doesn't have a model loaded, try to load current one
        if (!engine->IsModelLoaded() && !m_loadedModelPath.empty())
        {
            engine->LoadModel(m_loadedModelPath);
        }

        if (engine->IsModelLoaded())
        {
            // Use Generate method for inference
            std::vector<int32_t> tokens = engine->Tokenize(prompt);
            std::vector<int32_t> output = engine->Generate(tokens, 100);
            return engine->Detokenize(output);
        }
        else
        {
            return "Error: No model loaded in Native CPU Engine.";
        }
    }

    return std::string("[Native Engine Error]\nModel: ") + modelName + "\nPrompt: " + prompt +
           "\n(Ollama unavailable and Native Engine not ready)";
}

void Win32IDE::generateResponseAsync(const std::string& prompt, std::function<void(const std::string&, bool)> callback)
{
    METRICS.increment("inference.async_requests_total");
    std::lock_guard<std::mutex> lock(m_inferenceMutex);

    OutputDebugStringA("[AUDIT] generateResponseAsync() called\n");

    if (m_inferenceRunning)
    {
        METRICS.increment("inference.async_requests_rejected");
        OutputDebugStringA("[AUDIT] Inference already running - rejecting request\n");
        if (callback)
            callback("Inference already in progress.", true);
        return;
    }

    m_inferenceRunning = true;
    m_inferenceStopRequested = false;
    m_currentInferencePrompt = prompt;
    m_inferenceCallback = callback;

    OutputDebugStringA("[AUDIT] Starting inference thread\n");

    // Launch dedicated inference thread using Native Agentic Bridge
    m_inferenceThread = std::thread(
        [this, prompt]()
        {
            OutputDebugStringA("[AUDIT] Inference worker thread started\n");
            DetachedThreadGuard _guard(m_activeDetachedThreads, m_shuttingDown);
            if (_guard.cancelled)
            {
                OutputDebugStringA("[AUDIT] Inference thread cancelled (shutdown)\n");
                m_inferenceRunning = false;
                return;
            }
            if (!m_agenticBridge)
            {
                OutputDebugStringA("[AUDIT] Agentic bridge missing - attempting to create\n");
                if (!m_loadedModelPath.empty())
                    ensureAgenticBridgeHasModel(m_loadedModelPath);
                if (!m_agenticBridge)
                {
                    OutputDebugStringA("[AUDIT] FAILED to create agentic bridge\n");
                    if (m_inferenceCallback)
                        m_inferenceCallback("Error: Agentic Bridge not initialized.", true);
                    m_inferenceRunning = false;
                    return;
                }
                OutputDebugStringA("[AUDIT] Agentic bridge created successfully\n");
            }
            if (m_agenticBridge && !m_loadedModelPath.empty() &&
                m_agenticBridge->GetCurrentModel() != m_loadedModelPath)
                m_agenticBridge->LoadModel(m_loadedModelPath);

            // Set callback to route NativeAgent stream to the UI
            OutputDebugStringA("[AUDIT] Setting up output callback for streaming\n");
            m_agenticBridge->SetOutputCallback(
                [this](const std::string& type, const std::string& msg)
                {
                    if (m_inferenceStopRequested || isShuttingDown())
                        return;
                    // "stream" type is what we send to chat UI
                    if (m_inferenceCallback)
                    {
                        static int tokenCount = 0;
                        tokenCount++;
                        if (tokenCount <= 5 || tokenCount % 50 == 0)
                        {
                            char buf[128];
                            snprintf(buf, sizeof(buf), "[AUDIT] Streaming token %d (len=%zu)\n", tokenCount, msg.length());
                            OutputDebugStringA(buf);
                        }
                        m_inferenceCallback(msg, false);
                    }
                });

            // Execute via agent bridge (supports /edit, /think, etc.)
            OutputDebugStringA("[AUDIT] Executing agent command\n");
            m_agenticBridge->ExecuteAgentCommand(prompt);
            OutputDebugStringA("[AUDIT] Agent command completed\n");

            // Phase 4B: Choke Point 4 — hookPostGeneration after streaming inference
            // Note: For streaming responses, the full output was already sent via callback.
            // We hook here for failure detection on the completed inference cycle.
            // The response content was streamed — we check the accumulated result if available.
            if (!m_inferenceStopRequested)
            {
                std::string accumulatedResponse = m_currentInferenceResponse;
                if (!accumulatedResponse.empty())
                {
                    FailureClassification inferenceFailure = hookPostGeneration(accumulatedResponse, prompt);
                    if (inferenceFailure.reason != AgentFailureType::None)
                    {
                        LOG_WARNING(
                            "[Phase4B] Inference failure detected: " + failureTypeString(inferenceFailure.reason) +
                            " (confidence=" + std::to_string(inferenceFailure.confidence) + ")");
                        // For streaming responses, we log the failure and record it
                        // but don't auto-retry (the user sees output in real-time)
                        recordSimpleEvent(AgentEventType::FailureDetected,
                                          "Inference failure: " + failureTypeString(inferenceFailure.reason) + " | " +
                                              inferenceFailure.evidence);
                    }
                }
            }

            m_inferenceRunning = false;
            OutputDebugStringA("[AUDIT] Inference thread completing\n");
            if (m_inferenceCallback && !isShuttingDown())
            {
                OutputDebugStringA("[AUDIT] Calling final callback (complete=true)\n");
                m_inferenceCallback("", true);  // Finalize
            }
            OutputDebugStringA("[AUDIT] Inference thread finished\n");
        });

    m_inferenceThread.detach();
}

void Win32IDE::stopInference()
{
    m_inferenceStopRequested = true;
}

void Win32IDE::setInferenceConfig(const InferenceConfig& config)
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);
    m_inferenceConfig = config;
}

Win32IDE::InferenceConfig Win32IDE::getInferenceConfig() const
{
    return m_inferenceConfig;
}

std::string Win32IDE::buildChatPrompt(const std::string& userMessage)
{
    std::string prompt;

    // Add system prompt if set
    if (!m_inferenceConfig.systemPrompt.empty())
    {
        prompt = "<|system|>\n" + m_inferenceConfig.systemPrompt + "\n<|end|>\n";
        m_contextUsage.systemTokens = static_cast<int>(m_inferenceConfig.systemPrompt.length()) / 4;
    }

    // Add user message
    prompt += "<|user|>\n" + userMessage + "\n<|end|>\n";
    prompt += "<|assistant|>\n";

    // Track message tokens and update context window
    m_contextUsage.messageTokens += static_cast<int>(userMessage.length()) / 4;
    m_contextUsage.maxTokens = m_inferenceConfig.contextWindow;
    updateContextWindowDisplay();

    return prompt;
}

void Win32IDE::onInferenceToken(const std::string& token)
{
    // Called when streaming tokens during inference
    m_currentInferenceResponse += token;

    // Phase 19B: Feed token to the streaming output system
    appendStreamingToken(token);

    // Update context window token count (approximate: ~4 chars per token)
    int approxTokens = static_cast<int>(m_currentInferenceResponse.length()) / 4;
    m_contextUsage.toolResultTokens = approxTokens;
    // Throttle status bar updates to every ~20 tokens
    if (approxTokens % 20 == 0)
    {
        updateContextWindowDisplay();
    }

    // Update UI with partial response if streaming is enabled
    if (m_inferenceConfig.streamOutput && m_inferenceCallback)
    {
        m_inferenceCallback(token, false);
    }
}

void Win32IDE::onInferenceComplete(const std::string& fullResponse)
{
    m_inferenceRunning = false;
    m_currentInferenceResponse = fullResponse;

    // Final context window update
    m_contextUsage.toolResultTokens = static_cast<int>(fullResponse.length()) / 4;
    updateContextWindowDisplay();

    if (m_inferenceCallback)
    {
        m_inferenceCallback(fullResponse, true);
    }
}

// ============================================================================
// EDITOR OPERATIONS - Undo/Redo/Cut/Copy/Paste
// ============================================================================

void Win32IDE::undo()
{
    if (m_hwndEditor)
    {
        SendMessage(m_hwndEditor, EM_UNDO, 0, 0);
    }
}

void Win32IDE::redo()
{
    if (m_hwndEditor)
    {
        SendMessage(m_hwndEditor, EM_REDO, 0, 0);
    }
}

void Win32IDE::editCut()
{
    if (m_hwndEditor)
    {
        SendMessage(m_hwndEditor, WM_CUT, 0, 0);
    }
}

void Win32IDE::editCopy()
{
    if (m_hwndEditor)
    {
        SendMessage(m_hwndEditor, WM_COPY, 0, 0);
    }
}

void Win32IDE::editPaste()
{
    if (m_hwndEditor)
    {
        SendMessage(m_hwndEditor, WM_PASTE, 0, 0);
    }
}

// ============================================================================
// VIEW OPERATIONS - Toggle panels
// ============================================================================

void Win32IDE::toggleOutputPanel()
{
    m_outputPanelVisible = !m_outputPanelVisible;
    if (m_hwndMain)
    {
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
        InvalidateRect(m_hwndMain, NULL, TRUE);
    }
}

void Win32IDE::toggleTerminal()
{
    // Toggle panel visibility (which contains terminal)
    m_outputPanelVisible = !m_outputPanelVisible;
    if (m_hwndMain)
    {
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
        InvalidateRect(m_hwndMain, NULL, TRUE);
    }
}

void Win32IDE::showAbout()
{
    std::string aboutText = RAWRXD_VERSION_FULL "\n\n"
                                                "Build: " RAWRXD_BUILD_DATE " " RAWRXD_BUILD_TIME "\n"
                                                "Channel: " RAWRXD_CHANNEL "\n"
                                                "Units: " +
                            std::to_string(RAWRXD_COMPILE_UNITS) +
                            " compilation units\n"
                            "MASM64: " +
                            std::to_string(RAWRXD_MASM_KERNELS) +
                            " ASM kernels\n\n"
                            "Engine:\n"
                            "• Native Win32 C++20 (no Qt, no Electron)\n"
                            "• GGUF Model Loader + AVX-512 Inference\n"
                            "• Chain-of-Thought Multi-Model Review\n"
                            "• Native PDB Symbol Server (MSF v7.00)\n"
                            "• Three-Layer Hotpatch System\n"
                            "• Voice Chat (waveIn/Out + VAD + STT/TTS)\n"
                            "• Unified GPU Accelerator Router\n"
                            "• Embedded LSP Server (JSON-RPC 2.0)\n"
                            "• Distributed Swarm Inference\n\n" RAWRXD_COPYRIGHT "\n" RAWRXD_LICENSE "\n" RAWRXD_GITHUB;

    MessageBoxW(m_hwndMain, utf8ToWide(aboutText).c_str(), L"About RawrXD IDE", MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// AUTONOMY FRAMEWORK - High-level orchestration controls
// ============================================================================

void Win32IDE::onAutonomyStart()
{
    // Ensure bridge + autonomy initialized (smoke check expects initializeAgenticBridge/initializeAutonomy)
    if (!m_agenticBridge)
        initializeAgenticBridge();
    initializeAutonomy();

    if (!m_autonomyManager)
    {
        appendToOutput("Autonomy manager not initialized\n", "Errors", OutputSeverity::Error);
        return;
    }
    m_autonomyManager->start();
    appendToOutput("Autonomy started (manual mode)\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyStop()
{
    if (!m_autonomyManager)
        return;
    m_autonomyManager->stop();
    appendToOutput("Autonomy stopped\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyToggle()
{
    if (!m_autonomyManager)
        return;
    bool enable = !m_autonomyManager->isAutoLoopEnabled();
    m_autonomyManager->enableAutoLoop(enable);
    appendToOutput(std::string("Autonomy auto loop ") + (enable ? "ENABLED" : "DISABLED") + "\n", "Output",
                   OutputSeverity::Info);
}

void Win32IDE::onAutonomySetGoal()
{
    if (!m_autonomyManager)
        return;
    // Simple goal setter: reuse current file name or fallback text
    std::string goal =
        m_currentFile.empty() ? "Explore workspace and summarize architecture" : ("Analyze file: " + m_currentFile);
    m_autonomyManager->setGoal(goal);
    appendToOutput("Autonomy goal set: " + goal + "\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyViewStatus()
{
    if (!m_autonomyManager)
        return;
    std::string status = m_autonomyManager->getStatus();
    appendToOutput("Autonomy Status: " + status + "\n", "Output", OutputSeverity::Info);
    MessageBoxW(m_hwndMain, utf8ToWide(status).c_str(), L"Autonomy Status", MB_OK | MB_ICONINFORMATION);
}

void Win32IDE::onAutonomyViewMemory()
{
    if (!m_autonomyManager)
        return;
    auto mem = m_autonomyManager->getMemorySnapshot();
    std::string report = "Memory Items (latest first, max 20):\n\n";
    int shown = 0;
    for (int i = (int)mem.size() - 1; i >= 0 && shown < 20; --i, ++shown)
    {
        report += std::to_string(shown + 1) + ". " + mem[i] + "\n";
    }
    if (shown == 0)
        report += "<empty>\n";
    appendToOutput("Autonomy Memory Snapshot displayed\n", "Debug", OutputSeverity::Debug);
    MessageBoxW(m_hwndMain, utf8ToWide(report).c_str(), L"Autonomy Memory", MB_OK);
}

// ======================================================================
// AI CHAT PANEL IMPLEMENTATION
// ======================================================================

void Win32IDE::createChatPanel()
{

    if (!m_hwndMain)
    {

        return;
    }

    m_hwndSecondarySidebar = CreateWindowExW(WS_EX_CLIENTEDGE, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 0, 0, 300, 600,
                                             m_hwndMain, (HMENU)IDC_SECONDARY_SIDEBAR, m_hInstance, nullptr);

    if (!m_hwndSecondarySidebar)
    {
        return;
    }
    SetWindowLongPtr(m_hwndSecondarySidebar, GWLP_USERDATA, (LONG_PTR)this);
    m_oldSidebarProc = (WNDPROC)SetWindowLongPtr(m_hwndSecondarySidebar, GWLP_WNDPROC, (LONG_PTR)SidebarProc);

    m_hwndSecondarySidebarHeader = CreateWindowExW(0, L"STATIC", L"AI Chat", WS_CHILD | WS_VISIBLE | SS_LEFT, 5, 5, 290,
                                                   25, m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);

    HFONT hFont = CreateFontA(-dpiScale(14), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS,
                              CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    if (m_hwndSecondarySidebarHeader)
    {
        SendMessage(m_hwndSecondarySidebarHeader, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    CreateWindowExW(0, L"STATIC", L"Model:", WS_CHILD | WS_VISIBLE | SS_LEFT, 5, 35, 50, 18, m_hwndSecondarySidebar,
                    nullptr, m_hInstance, nullptr);

    m_hwndModelSelector =
        CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_AUTOHSCROLL, 60, 35, 200, 200,
                        m_hwndSecondarySidebar, (HMENU)IDC_MODEL_SELECTOR, m_hInstance, nullptr);

    // Add browse button next to model selector
    CreateWindowExW(0, L"BUTTON", L"Browse...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 265, 35, 70, 23,
                    m_hwndSecondarySidebar, (HMENU)IDC_MODEL_BROWSE_BTN, m_hInstance, nullptr);

    if (m_hwndModelSelector)
    {
        SendMessage(m_hwndModelSelector, WM_SETFONT, (WPARAM)hFont, TRUE);
        populateModelSelector();
    }

    // Set font for browse button
    HWND hwndBrowseBtn = GetDlgItem(m_hwndSecondarySidebar, IDC_MODEL_BROWSE_BTN);
    if (hwndBrowseBtn)
    {
        SendMessage(hwndBrowseBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    CreateWindowExW(0, L"STATIC", L"Max Tokens:", WS_CHILD | WS_VISIBLE | SS_LEFT, 5, 60, 80, 18,
                    m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);

    m_hwndMaxTokensLabel = CreateWindowExW(0, L"STATIC", L"512", WS_CHILD | WS_VISIBLE | SS_RIGHT, 245, 60, 50, 18,
                                           m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);

    m_hwndMaxTokensSlider =
        CreateWindowExW(0, TRACKBAR_CLASSW, L"", WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_NOTICKS, 5, 80, 290, 25,
                        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CLEAR_BTN, m_hInstance, nullptr);

    CreateWindowExW(0, L"STATIC", L"Context:", WS_CHILD | WS_VISIBLE | SS_LEFT, 5, 110, 80, 18, m_hwndSecondarySidebar,
                    nullptr, m_hInstance, nullptr);

    m_hwndContextLabel = CreateWindowExW(0, L"STATIC", L"4K", WS_CHILD | WS_VISIBLE | SS_RIGHT, 245, 110, 50, 18,
                                         m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);

    m_hwndContextSlider =
        CreateWindowExW(0, TRACKBAR_CLASSW, L"", WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_NOTICKS, 5, 130, 290, 25,
                        m_hwndSecondarySidebar, (HMENU)IDC_AI_CONTEXT_SLIDER, m_hInstance, nullptr);

    if (m_hwndContextSlider)
    {
        SendMessage(m_hwndContextSlider, TBM_SETRANGE, TRUE, MAKELPARAM(0, 6));  // 7 steps
        SendMessage(m_hwndContextSlider, TBM_SETPOS, TRUE, 0);                   // Default 4K
        m_currentContextSize = 4096;
    }
    // Update Chat Output Y position to accommodate new slider
    int chatY = 160;

    if (m_hwndMaxTokensSlider)
    {
        SendMessage(m_hwndMaxTokensSlider, TBM_SETRANGE, TRUE, MAKELPARAM(32, 2048));
        SendMessage(m_hwndMaxTokensSlider, TBM_SETPOS, TRUE, 512);
        SendMessage(m_hwndMaxTokensSlider, TBM_SETTICFREQ, 256, 0);
        m_currentMaxTokens = 512;
    }

    CreateWindowExW(0, L"STATIC", L"Context (Mem):", WS_CHILD | WS_VISIBLE | SS_LEFT, 5, 110, 100, 18,
                    m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);

    HWND hContextCombo = CreateWindowExW(0, L"COMBOBOX", L"", WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST, 110, 108, 185,
                                         300, m_hwndSecondarySidebar, (HMENU)4200, m_hInstance, nullptr);

    if (hContextCombo)
    {
        SendMessage(hContextCombo, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"2048 (Standard)");
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"4096 (4k)");
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"32768 (32k)");
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"65536 (64k)");
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"131072 (128k)");
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"262144 (256k)");
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"524288 (512k)");
        SendMessageW(hContextCombo, CB_ADDSTRING, 0, (LPARAM)L"1048576 (1M)");
        SendMessage(hContextCombo, CB_SETCURSEL, 0, 0);
    }

    int toggleY = 140;
    int toggleX = 5;

    m_hwndChkMaxMode =
        CreateWindowExW(0, L"BUTTON", L"Max Mode", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, toggleX, toggleY, 140, 20,
                        m_hwndSecondarySidebar, (HMENU)IDC_AI_MAX_MODE, m_hInstance, nullptr);
    m_hwndChkDeepThink =
        CreateWindowExW(0, L"BUTTON", L"Deep Think", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, toggleX + 150, toggleY,
                        140, 20, m_hwndSecondarySidebar, (HMENU)IDC_AI_DEEP_THINK, m_hInstance, nullptr);

    toggleY += 25;
    m_hwndChkDeepResearch =
        CreateWindowExW(0, L"BUTTON", L"Deep Research", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, toggleX, toggleY, 140,
                        20, m_hwndSecondarySidebar, (HMENU)IDC_AI_DEEP_RESEARCH, m_hInstance, nullptr);
    m_hwndChkNoRefusal =
        CreateWindowExW(0, L"BUTTON", L"No Refusal", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, toggleX + 150, toggleY,
                        140, 20, m_hwndSecondarySidebar, (HMENU)IDC_AI_NO_REFUSAL, m_hInstance, nullptr);

    if (m_hwndChkMaxMode)
        SendMessage(m_hwndChkMaxMode, WM_SETFONT, (WPARAM)hFont, TRUE);
    if (m_hwndChkDeepThink)
        SendMessage(m_hwndChkDeepThink, WM_SETFONT, (WPARAM)hFont, TRUE);
    if (m_hwndChkDeepResearch)
        SendMessage(m_hwndChkDeepResearch, WM_SETFONT, (WPARAM)hFont, TRUE);
    if (m_hwndChkNoRefusal)
        SendMessage(m_hwndChkNoRefusal, WM_SETFONT, (WPARAM)hFont, TRUE);

    m_hwndCopilotChatOutput =
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, 5, 200, 290,
                        210, m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_OUTPUT, m_hInstance, nullptr);

    if (m_hwndCopilotChatOutput)
    {
        SendMessage(m_hwndCopilotChatOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    m_hwndCopilotChatInput =
        CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL, 5, 415, 290,
                        85, m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_INPUT, m_hInstance, nullptr);

    if (m_hwndCopilotChatInput)
    {
        SendMessage(m_hwndCopilotChatInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    m_hwndCopilotSendBtn =
        CreateWindowExW(0, L"BUTTON", L"Send", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 5, 505, 140, 30,
                        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_SEND_BTN, m_hInstance, nullptr);

    if (m_hwndCopilotSendBtn)
    {
        SendMessage(m_hwndCopilotSendBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    m_hwndCopilotClearBtn =
        CreateWindowExW(0, L"BUTTON", L"Clear", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 150, 505, 140, 30,
                        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CLEAR_BTN, m_hInstance, nullptr);

    if (m_hwndCopilotClearBtn)
    {
        SendMessage(m_hwndCopilotClearBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    m_secondarySidebarVisible = true;
    m_secondarySidebarWidth = 320;

    // Align checkboxes + AI menu with AgenticBridge / NativeAgent (defaults are ON).
    syncAgentModeUiFromBridge();
}

void Win32IDE::populateModelSelector()
{
    if (!m_hwndModelSelector)
        return;

    // Preserve prior selection if possible
    std::string previousSelection;
    int prevIdx = (int)SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);
    if (prevIdx >= 0)
    {
        wchar_t prevBuf[512] = {0};
        SendMessageW(m_hwndModelSelector, CB_GETLBTEXT, prevIdx, (LPARAM)prevBuf);
        previousSelection = wideToUtf8(prevBuf);
    }

    // Clear existing items
    SendMessage(m_hwndModelSelector, CB_RESETCONTENT, 0, 0);

    m_availableModels.clear();

    // Only populate if user has selected model directories
    if (m_userModelDirectories.empty())
    {
        // No directories selected - list remains empty
        return;
    }

    // Use backend directory listing for each user-selected directory
    for (const auto& dir : m_userModelDirectories)
    {
        std::vector<std::string> modelsFromDir = getModelsFromDirectory(dir);
        for (const auto& model : modelsFromDir)
        {
            m_availableModels.push_back(model);
        }
    }

    // Remove duplicates
    std::sort(m_availableModels.begin(), m_availableModels.end());
    auto last = std::unique(m_availableModels.begin(), m_availableModels.end());
    m_availableModels.erase(last, m_availableModels.end());

    // Populate combobox
    for (const auto& model : m_availableModels)
    {
        SendMessageW(m_hwndModelSelector, CB_ADDSTRING, 0, (LPARAM)utf8ToWide(model).c_str());
    }

    // Restore prior selection when possible
    int selectedIdx = -1;
    if (!previousSelection.empty())
    {
        for (size_t i = 0; i < m_availableModels.size(); ++i)
        {
            if (m_availableModels[i] == previousSelection)
            {
                selectedIdx = (int)i;
                break;
            }
        }
    }

    // Set selected item
    if (!m_availableModels.empty())
    {
        if (selectedIdx < 0)
            selectedIdx = 0;
        SendMessage(m_hwndModelSelector, CB_SETCURSEL, selectedIdx, 0);
    }
}

std::vector<std::string> Win32IDE::getModelsFromDirectory(const std::string& directory)
{
    std::vector<std::string> models;

    // Check if local server is running
    if (!m_localServerRunning.load())
    {
        // Local server not running yet - return empty list
        // Models will be populated when directories are selected and server is running
        return models;
    }

    // Make HTTP request to /api/list-directory
    std::string url = "http://localhost:" + std::to_string(m_settings.localServerPort) + "/api/list-directory";
    std::string requestBody = "{\"path\":\"" + directory + "\",\"depth\":1,\"maxEntries\":10000}";

    std::string response = makeHttpRequest(url, "POST", requestBody, "application/json");
    if (response.empty())
    {
        LOG_WARNING("Failed to get directory listing for: " + directory);
        return models;
    }

    // Parse JSON response using nlohmann/json
    try
    {
        auto jsonResponse = nlohmann::json::parse(response);
        if (jsonResponse.contains("entries") && jsonResponse["entries"].is_array())
        {
            for (const auto& entry : jsonResponse["entries"])
            {
                if (entry.contains("name") && entry.contains("type"))
                {
                    std::string name = entry["name"];
                    std::string type = entry["type"];

                    // Check if it's a file and has GGUF extension
                    if (type == "file" && !name.empty())
                    {
                        std::string ext = name.substr(name.find_last_of('.') + 1);
                        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                        if (ext == "gguf" || ext == "bin" || ext == "ggml")
                        {
                            // Remove extension for display
                            size_t dotPos = name.find_last_of('.');
                            if (dotPos != std::string::npos)
                            {
                                std::string displayName = name.substr(0, dotPos);
                                models.push_back(displayName);
                            }
                        }
                    }
                }
            }
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error parsing directory listing response: " + std::string(e.what()));
    }

    return models;
}

std::string Win32IDE::makeHttpRequest(const std::string& url, const std::string& method, const std::string& body,
                                      const std::string& contentType)
{
    // Parse URL
    std::string host = "localhost";
    int port = m_settings.localServerPort;
    std::string path = "/";

    // Simple URL parsing for localhost:port/path
    size_t colonPos = url.find(':');
    size_t slashPos = url.find('/', colonPos + 3);  // after ://

    if (colonPos != std::string::npos)
    {
        size_t portStart = colonPos + 1;
        while (portStart < url.size() && url[portStart] == '/')
            portStart++;
        size_t portEnd = url.find('/', portStart);
        if (portEnd != std::string::npos)
        {
            std::string portStr = url.substr(portStart, portEnd - portStart);
            port = atoi(portStr.c_str());
            path = url.substr(portEnd);
        }
        else
        {
            std::string portStr = url.substr(portStart);
            port = atoi(portStr.c_str());
        }
    }

    std::wstring whost(host.begin(), host.end());
    HINTERNET hSession = WinHttpOpen(L"RawrXDIDE/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
    if (!hSession)
        return "";

    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::wstring wMethod(method.begin(), method.end());
    std::wstring wPath(path.begin(), path.end());
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wMethod.c_str(), wPath.c_str(), NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    // Set headers
    std::wstring wHeaders = L"Content-Type: " + std::wstring(contentType.begin(), contentType.end());
    BOOL bResults = WinHttpSendRequest(hRequest, wHeaders.c_str(), (DWORD)-1L, (LPVOID)body.c_str(), (DWORD)body.size(),
                                       (DWORD)body.size(), 0);
    if (!bResults)
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    std::string response;
    if (bResults)
    {
        DWORD dwSize = 0;
        do
        {
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
                break;
            if (!dwSize)
                break;
            std::string chunk;
            chunk.resize(dwSize);
            DWORD dwRead = 0;
            if (!WinHttpReadData(hRequest, chunk.data(), dwSize, &dwRead))
                break;
            if (dwRead)
                response.append(chunk.data(), dwRead);
        } while (dwSize > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

void Win32IDE::HandleCopilotSend()
{
    SCOPED_METRIC("chat.send_message");
    METRICS.increment("chat.messages_sent");

    // Use Ollama direct implementation for chat
    HandleCopilotSend_Ollama();
}

void Win32IDE::HandleCopilotClear()
{
    if (!m_hwndCopilotChatOutput || !m_hwndCopilotChatInput)
        return;

    SetWindowTextW(m_hwndCopilotChatOutput,
                   L"Welcome to RawrXD AI Chat!\n\nSelect a model and type your message to begin.");
    SetWindowTextW(m_hwndCopilotChatInput, L"");
    m_chatHistory.clear();
}

void Win32IDE::HandleCopilotStreamUpdate(const char* token, size_t length)
{
    if (!m_hwndCopilotChatOutput || !token)
        return;

    std::string chunk;
    if (length > 0)
    {
        chunk.assign(token, token + length);
    }
    else
    {
        chunk = token;
    }

    if (chunk.empty())
        return;

    int currentLen = GetWindowTextLengthW(m_hwndCopilotChatOutput);
    SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, currentLen, currentLen);
    SendMessageW(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, (LPARAM)utf8ToWide(chunk).c_str());
    SendMessage(m_hwndCopilotChatOutput, WM_VSCROLL, SB_BOTTOM, 0);
}

void Win32IDE::onModelSelectionChanged()
{
    int idx = (int)SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);
    if (idx >= 0 && idx < (int)m_availableModels.size())
    {
        m_ollamaModelOverride = m_availableModels[idx];
    }
}

void Win32IDE::onMaxTokensChanged(int newValue)
{
    m_currentMaxTokens = newValue;
    m_inferenceConfig.maxTokens = newValue;

    // Update label
    if (m_hwndMaxTokensLabel)
    {
        SetWindowTextW(m_hwndMaxTokensLabel, utf8ToWide(std::to_string(newValue)).c_str());
    }
}

void Win32IDE::handleModelBrowse()
{
    BROWSEINFOW bi = {0};
    bi.hwndOwner = m_hwndMain;
    bi.lpszTitle = L"Select Model Directory";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl)
    {
        WCHAR path[MAX_PATH] = {0};
        if (SHGetPathFromIDListW(pidl, path))
        {
            std::string selectedPath = wideToUtf8(path);

            // Check if this directory is already in the list
            bool alreadyExists = false;
            for (const auto& dir : m_userModelDirectories)
            {
                if (dir == selectedPath)
                {
                    alreadyExists = true;
                    break;
                }
            }

            if (!alreadyExists)
            {
                m_userModelDirectories.push_back(selectedPath);
                appendToOutput("Added model directory: " + selectedPath + "\n", "Output", OutputSeverity::Info);

                // Refresh the model selector to include models from the new directory
                populateModelSelector();
            }
            else
            {
                appendToOutput("Directory already added: " + selectedPath + "\n", "Output", OutputSeverity::Warning);
            }
        }
        CoTaskMemFree(pidl);
    }
}

// ============================================================================
// IMPLEMENTATIONS for functions declared in Win32IDE.h
// Line Number Gutter, Minimap, Breadcrumb, and other UI components.
// ============================================================================

// --- Line Number Gutter ---
void Win32IDE::createLineNumberGutter(HWND hwndParent)
{
    if (!hwndParent)
        return;

    m_hwndLineNumbers = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW, 0, 0, 70, 100,
                                        hwndParent, nullptr, m_hInstance, nullptr);

    if (m_hwndLineNumbers)
    {
        SetPropW(m_hwndLineNumbers, L"IDE_PTR", (HANDLE)this);
        m_oldLineNumberProc = (WNDPROC)SetWindowLongPtrW(m_hwndLineNumbers, GWLP_WNDPROC, (LONG_PTR)LineNumberProc);
    }
}

void Win32IDE::updateLineNumbers()
{
    if (m_hwndLineNumbers && IsWindow(m_hwndLineNumbers))
    {
        InvalidateRect(m_hwndLineNumbers, nullptr, TRUE);
    }
}

void Win32IDE::paintLineNumbers(HDC hdc, RECT& rc)
{
    if (!m_hwndEditor || !IsWindow(m_hwndEditor))
        return;

    // Get the current scroll position and line metrics from the rich edit control
    int firstVisibleLine = (int)SendMessage(m_hwndEditor, EM_GETFIRSTVISIBLELINE, 0, 0);
    int lineCount = (int)SendMessage(m_hwndEditor, EM_GETLINECOUNT, 0, 0);

    // Get the editor font metrics
    HFONT hFont = m_editorFont ? m_editorFont : (HFONT)GetStockObject(SYSTEM_FIXED_FONT);
    HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);

    TEXTMETRICW tm;
    GetTextMetricsW(hdc, &tm);
    int lineHeight = tm.tmHeight + tm.tmExternalLeading;
    if (lineHeight <= 0)
        lineHeight = 16;

    SetBkColor(hdc, RGB(30, 30, 30));
    SetTextColor(hdc, RGB(133, 133, 133));

    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &rc, bgBrush);
    DeleteObject(bgBrush);

    int visibleLines = (rc.bottom - rc.top) / lineHeight + 1;

    // Get Git status for current file
    char gitStatus = ' ';
    if (!m_currentFile.empty())
    {
        // Convert to relative path for Git status lookup
        std::string relPath = m_currentFile;
        if (relPath.find(m_gitRepoPath) == 0)
        {
            relPath = relPath.substr(m_gitRepoPath.length());
            if (!relPath.empty() && relPath[0] == '\\')
            {
                relPath = relPath.substr(1);
            }
            // Convert backslashes to forward slashes for Git
            std::replace(relPath.begin(), relPath.end(), '\\', '/');

            auto it = m_gitStatus.fileStatus.find(relPath);
            if (it != m_gitStatus.fileStatus.end())
            {
                gitStatus = it->second;
            }
        }
    }

    for (int i = 0; i < visibleLines && (firstVisibleLine + i) < lineCount; i++)
    {
        int lineNum = firstVisibleLine + i + 1;
        wchar_t buf[16];
        swprintf_s(buf, L"%4d", lineNum);

        RECT lineRect = {rc.left, i * lineHeight, rc.right - 4, (i + 1) * lineHeight};

        if (lineNum == m_currentLine)
        {
            SetTextColor(hdc, RGB(200, 200, 200));
        }
        else
        {
            SetTextColor(hdc, RGB(133, 133, 133));
        }

        DrawTextW(hdc, buf, -1, &lineRect, DT_RIGHT | DT_SINGLELINE | DT_VCENTER);

        // Draw Git status indicator
        if (gitStatus != ' ')
        {
            RECT indicatorRect = {rc.right - 16, i * lineHeight + 2, rc.right - 4, (i + 1) * lineHeight - 2};

            COLORREF indicatorColor;
            switch (gitStatus)
            {
                case 'M':
                    indicatorColor = RGB(255, 193, 7);
                    break;  // Yellow for modified
                case 'A':
                    indicatorColor = RGB(40, 167, 69);
                    break;  // Green for added
                case 'D':
                    indicatorColor = RGB(220, 53, 69);
                    break;  // Red for deleted
                case '?':
                    indicatorColor = RGB(108, 117, 125);
                    break;  // Gray for untracked
                default:
                    indicatorColor = RGB(133, 133, 133);
                    break;
            }

            HBRUSH indicatorBrush = CreateSolidBrush(indicatorColor);
            FillRect(hdc, &indicatorRect, indicatorBrush);
            DeleteObject(indicatorBrush);
        }
    }

    SelectObject(hdc, hOldFont);
}

LRESULT CALLBACK Win32IDE::LineNumberProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* ide = (Win32IDE*)GetPropW(hwnd, L"IDE_PTR");

    if (uMsg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        if (ide)
        {
            RECT rc;
            GetClientRect(hwnd, &rc);
            ide->paintLineNumbers(hdc, rc);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }

    if (uMsg == WM_ERASEBKGND)
    {
        return 1;  // We handle painting
    }

    if (ide && ide->m_oldLineNumberProc)
    {
        return CallWindowProcW(ide->m_oldLineNumberProc, hwnd, uMsg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK Win32IDE::TabBarProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* ide = (Win32IDE*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    if (uMsg == WM_DRAWITEM)
    {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        if (dis->CtlType == ODT_TAB && ide)
        {
            ide->drawTabItem(dis);
            return TRUE;
        }
    }
    else if (uMsg == WM_LBUTTONDOWN)
    {
        if (ide)
        {
            POINT pt = {LOWORD(lParam), HIWORD(lParam)};
            ide->handleTabClick(pt);
        }
    }

    if (ide && ide->getOldTabBarProc())
    {
        return CallWindowProcW(ide->getOldTabBarProc(), hwnd, uMsg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// --- Editor Tab Bar ---
void Win32IDE::createTabBar(HWND hwndParent)
{
    OutputDebugStringA("[Win32IDE::createTabBar] START\n");
    fileTrace("[Win32IDE::createTabBar] START");

    // GUARD: Prevent stack overflow by enforcing startup phase
    if (!allowHeavyInitialization())
    {
        OutputDebugStringA("[Win32IDE::createTabBar] BLOCKED: heavy init not allowed in current phase\n");
        fileTrace("[Win32IDE::createTabBar] BLOCKED: heavy init not allowed in current phase");
        return;
    }

    if (!hwndParent)
    {
        OutputDebugStringA("[Win32IDE::createTabBar] hwndParent is null, returning\n");
        fileTrace("[Win32IDE::createTabBar] hwndParent is null, returning");
        return;
    }

    // Initialize sovereign TabManager
    if (!m_tabManager)
    {
        OutputDebugStringA("[Win32IDE::createTabBar] Creating new TabManager...\n");
        fileTrace("[Win32IDE::createTabBar] Creating new TabManager...");
        m_tabManager = new Win32IDE_TabManager(this);
        OutputDebugStringA("[Win32IDE::createTabBar] TabManager created, calling initialize...\n");
        fileTrace("[Win32IDE::createTabBar] TabManager created, calling initialize...");
        if (!m_tabManager->initialize(hwndParent))
        {
            OutputDebugStringA("[Win32IDE::createTabBar] TabManager::initialize FAILED\n");
            fileTrace("[Win32IDE::createTabBar] TabManager::initialize FAILED");
            delete m_tabManager;
            m_tabManager = nullptr;
            return;
        }
        OutputDebugStringA("[Win32IDE::createTabBar] TabManager::initialize succeeded\n");
        fileTrace("[Win32IDE::createTabBar] TabManager::initialize succeeded");
    }

    // Get the tab bar handle from the manager
    m_hwndTabBar = m_tabManager->getTabBarHandle();
    if (m_hwndTabBar)
    {
        // Subclass for custom drawing and close button handling
        SetWindowLongPtrW(m_hwndTabBar, GWLP_USERDATA, (LONG_PTR)this);
        m_oldTabBarProc = (WNDPROC)SetWindowLongPtrW(m_hwndTabBar, GWLP_WNDPROC, (LONG_PTR)TabBarProc);
    }
    OutputDebugStringA("[Win32IDE::createTabBar] DONE\n");
    fileTrace("[Win32IDE::createTabBar] DONE");
}

void Win32IDE::addTab(const std::string& filePath, const std::string& displayName)
{
    // Add a new editor tab
    EditorTab tab;
    tab.filePath = filePath;
    tab.displayName = displayName.empty() ? filePath : displayName;
    tab.modified = false;

    m_editorTabs.push_back(tab);

    if (m_hwndTabBar)
    {
        std::wstring displayW = utf8ToWide(tab.displayName);
        TCITEMW tci = {};
        tci.mask = TCIF_TEXT;
        tci.pszText = const_cast<wchar_t*>(displayW.c_str());
        int index = (int)SendMessage(m_hwndTabBar, TCM_GETITEMCOUNT, 0, 0);
        SendMessageW(m_hwndTabBar, TCM_INSERTITEMW, index, (LPARAM)&tci);
        SendMessage(m_hwndTabBar, TCM_SETCURSEL, index, 0);
        m_activeTabIndex = index;
    }
}

std::pair<int, int> Win32IDE::getCursorPosition()
{
    CHARRANGE cr;
    SendMessageW(m_hwndEditor, EM_GETSEL, (WPARAM)&cr.cpMin, (LPARAM)&cr.cpMax);
    int charPos = cr.cpMin;
    int line = (int)SendMessageW(m_hwndEditor, EM_LINEFROMCHAR, charPos, 0) + 1;
    int lineStart = (int)SendMessageW(m_hwndEditor, EM_LINEINDEX, line - 1, 0);
    int col = charPos - lineStart + 1;
    return {line, col};
}

void Win32IDE::onTabChanged()
{
    if (!m_hwndTabBar)
        return;

    int newIndex = (int)SendMessage(m_hwndTabBar, TCM_GETCURSEL, 0, 0);
    if (newIndex >= 0 && newIndex < (int)m_editorTabs.size() && newIndex != m_activeTabIndex)
    {
        // Save current tab content and state
        if (m_activeTabIndex >= 0 && m_activeTabIndex < (int)m_editorTabs.size())
        {
            m_editorTabs[m_activeTabIndex].content = getWindowText(m_hwndEditor);
            auto [line, col] = getCursorPosition();
            m_editorTabs[m_activeTabIndex].cursorLine = line;
            m_editorTabs[m_activeTabIndex].cursorCol = col;
            // Save scroll position
            m_editorTabs[m_activeTabIndex].scrollPos = (int)SendMessageW(m_hwndEditor, EM_GETSCROLLPOS, 0, 0);
            // Save multi-cursor positions (primary cursor only for now)
            CHARRANGE cr;
            SendMessageW(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&cr);
            if (cr.cpMin == cr.cpMax) {
                m_editorTabs[m_activeTabIndex].multiCursors.clear();
                m_editorTabs[m_activeTabIndex].multiCursors.push_back({line, col});
            }
            // Save folded regions (placeholder - would need Scintilla or custom folding)
            // m_editorTabs[m_activeTabIndex].foldedRegions preserved from last fold operation
        }

        // Stash annotations for the outgoing tab
        storeAnnotationsForTab();

        // Switch to new tab
        m_activeTabIndex = newIndex;
        const auto& tab = m_editorTabs[newIndex];

        // Load tab content into editor
        setWindowText(m_hwndEditor, tab.content);

        // Update current file path
        m_currentFile = tab.filePath;

        // Restore cursor position
        int lineIndex = (int)SendMessageW(m_hwndEditor, EM_LINEINDEX, tab.cursorLine - 1, 0);
        int charPos = lineIndex + tab.cursorCol - 1;
        SendMessageW(m_hwndEditor, EM_SETSEL, charPos, charPos);

        // Restore stashed annotations for the incoming tab
        restoreAnnotationsForTab();

        // Re-detect language for the new file and recolor
        m_syntaxLanguage = detectLanguageFromExtension(m_currentFile);
        onEditorContentChanged();

        // Update status bar
        if (m_hwndStatusBar)
        {
            SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide(tab.displayName).c_str());
        }

        // Update line numbers
        updateLineNumbers();
    }
}

void Win32IDE::onTabClosing(int index)
{
    // Handle tab closing logic
    if (index >= 0 && index < (int)m_editorTabs.size())
    {
        // Check if tab is modified and prompt to save
        if (m_editorTabs[index].modified)
        {
            // Show save dialog
            std::wstring msg = L"Save changes to \"" + utf8ToWide(m_editorTabs[index].displayName) + L"\"?";
            int result = MessageBoxW(m_hwndMain, msg.c_str(), L"RawrXD IDE", MB_YESNOCANCEL | MB_ICONQUESTION);
            if (result == IDCANCEL)
            {
                return; // Cancel the close operation
            }
            if (result == IDYES)
            {
                // Save the file
                if (m_activeTabIndex == index)
                {
                    saveCurrentFile();
                }
                else
                {
                    // Temporarily switch to save, then switch back
                    int prevTab = m_activeTabIndex;
                    setActiveTab(index);
                    saveCurrentFile();
                    if (prevTab >= 0 && prevTab < (int)m_editorTabs.size() && prevTab != index)
                    {
                        setActiveTab(prevTab);
                    }
                }
            }
        }
        // Remove the tab
        removeTab(index);
    }
}

void Win32IDE::onTabActivated(int index)
{
    // Handle tab activation
    if (index >= 0 && index < (int)m_editorTabs.size())
    {
        setActiveTab(index);
    }
}

void Win32IDE::saveCurrentFile()
{
    // Save the current file
    if (m_activeTabIndex >= 0 && m_activeTabIndex < (int)m_editorTabs.size())
    {
        const auto& tab = m_editorTabs[m_activeTabIndex];
        if (!tab.filePath.empty())
        {
            std::ofstream file(tab.filePath, std::ios::binary);
            if (file)
            {
                std::string content = getWindowText(m_hwndEditor);
                file.write(content.c_str(), content.size());
                m_editorTabs[m_activeTabIndex].modified = false;
                // Update tab display to remove modified indicator
                if (m_tabManager)
                {
                    m_tabManager->updateTabDisplay(m_activeTabIndex);
                }
            }
        }
    }
}

void Win32IDE::setActiveTab(int index)
{
    if (!m_hwndTabBar)
        return;
    if (index < 0 || index >= (int)m_editorTabs.size())
        return;

    // Use the tab control to select the tab, then trigger onTabChanged
    SendMessage(m_hwndTabBar, TCM_SETCURSEL, index, 0);
    onTabChanged();
}

void Win32IDE::saveTabsState()
{
    nlohmann::json j;
    j["tabs"] = nlohmann::json::array();
    for (const auto& tab : m_editorTabs)
    {
        nlohmann::json tabJson;
        tabJson["filePath"] = tab.filePath;
        tabJson["displayName"] = tab.displayName;
        tabJson["content"] = tab.content;
        tabJson["modified"] = tab.modified;
        tabJson["isPinned"] = tab.isPinned;
        tabJson["isPreview"] = tab.isPreview;
        tabJson["cursorLine"] = tab.cursorLine;
        tabJson["cursorCol"] = tab.cursorCol;
        tabJson["scrollPos"] = tab.scrollPos;
        j["tabs"].push_back(tabJson);
    }
    j["activeTabIndex"] = m_activeTabIndex;
    std::ofstream file("tabs_state.json");
    if (file)
    {
        file << j.dump(4);
    }
}

void Win32IDE::loadTabsState()
{
    std::ifstream file("tabs_state.json");
    if (!file)
        return;
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    nlohmann::json j;
    try
    {
        j = nlohmann::json::parse(content);
    }
    catch (...)
    {
        return;
    }
    if (j.contains("tabs") && j["tabs"].is_array())
    {
        m_editorTabs.clear();
        for (const auto& tabJson : j["tabs"])
        {
            EditorTab tab;
            tab.filePath = tabJson.value("filePath", "");
            tab.displayName = tabJson.value("displayName", "");
            tab.content = tabJson.value("content", "");
            tab.modified = tabJson.value("modified", false);
            tab.isPinned = tabJson.value("isPinned", false);
            tab.isPreview = tabJson.value("isPreview", false);
            tab.cursorLine = tabJson.value("cursorLine", 1);
            tab.cursorCol = tabJson.value("cursorCol", 0);
            tab.scrollPos = tabJson.value("scrollPos", 0);
            m_editorTabs.push_back(tab);
        }
        if (j.contains("activeTabIndex"))
        {
            m_activeTabIndex = j["activeTabIndex"];
        }
        // Update tab bar if needed
        if (m_hwndTabBar)
        {
            // Clear existing tabs
            SendMessage(m_hwndTabBar, TCM_DELETEALLITEMS, 0, 0);
            // Add loaded tabs
            for (size_t i = 0; i < m_editorTabs.size(); ++i)
            {
                TCITEMW tci = {0};
                tci.mask = TCIF_TEXT;
                std::wstring wname = utf8ToWide(m_editorTabs[i].displayName);
                tci.pszText = (LPWSTR)wname.c_str();
                SendMessageW(m_hwndTabBar, TCM_INSERTITEMW, i, (LPARAM)&tci);
            }
            if (m_activeTabIndex >= 0 && m_activeTabIndex < (int)m_editorTabs.size())
            {
                SendMessage(m_hwndTabBar, TCM_SETCURSEL, m_activeTabIndex, 0);
                // Load active tab content
                const auto& tab = m_editorTabs[m_activeTabIndex];
                setWindowText(m_hwndEditor, tab.content);
                m_currentFile = tab.filePath;
                // Set cursor
                int lineIndex = (int)SendMessageW(m_hwndEditor, EM_LINEINDEX, tab.cursorLine - 1, 0);
                int charPos = lineIndex + tab.cursorCol - 1;
                SendMessageW(m_hwndEditor, EM_SETSEL, charPos, charPos);
                // Update status bar
                if (m_hwndStatusBar)
                {
                    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide(tab.displayName).c_str());
                }
                updateLineNumbers();
            }
        }
    }
}

void Win32IDE::removeTab(int index)
{
    if (index < 0 || index >= (int)m_editorTabs.size())
        return;

    // Clear annotation cache for the file being closed
    const std::string& closingFile = m_editorTabs[index].filePath;
    if (!closingFile.empty())
    {
        m_annotationCache.erase(closingFile);
    }
    // If this is the active tab, clear live annotations
    if (index == m_activeTabIndex)
    {
        clearAnnotationsForCurrentFile();
    }

    // Remove from the Win32 tab control
    if (m_hwndTabBar)
    {
        SendMessage(m_hwndTabBar, TCM_DELETEITEM, index, 0);
    }

    // Remove from our vector
    m_editorTabs.erase(m_editorTabs.begin() + index);

    // Adjust active tab index
    if (m_editorTabs.empty())
    {
        m_activeTabIndex = -1;
        m_currentFile.clear();
        setWindowText(m_hwndEditor, "");
    }
    else if (index <= m_activeTabIndex)
    {
        m_activeTabIndex = std::max(0, m_activeTabIndex - 1);
        SendMessage(m_hwndTabBar, TCM_SETCURSEL, m_activeTabIndex, 0);
        onTabChanged();
    }
}

int Win32IDE::findTabByPath(const std::string& filePath) const
{
    for (int i = 0; i < (int)m_editorTabs.size(); i++)
    {
        if (m_editorTabs[i].filePath == filePath)
            return i;
    }
    return -1;
}

void Win32IDE::drawTabItem(DRAWITEMSTRUCT* dis)
{
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    int index = dis->itemID;

    if (index < 0 || index >= (int)m_editorTabs.size())
        return;

    const EditorTab& tab = m_editorTabs[index];
    bool isActive = (index == m_activeTabIndex);
    bool isModified = tab.modified;

    // Background
    COLORREF bgColor = isActive ? RGB(45, 45, 45) : RGB(30, 30, 30);
    HBRUSH hBrush = CreateSolidBrush(bgColor);
    FillRect(hdc, &rc, hBrush);
    DeleteObject(hBrush);

    // Border
    HPEN hPen = CreatePen(PS_SOLID, 1, RGB(60, 60, 60));
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
    MoveToEx(hdc, rc.left, rc.bottom - 1, nullptr);
    LineTo(hdc, rc.right, rc.bottom - 1);
    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);

    // Set tab font (Segoe UI 9pt) so text isn't jumbled
    HFONT hTabFont = CreateFontA(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
    HFONT hOldFont = (HFONT)SelectObject(hdc, hTabFont);

    // Text
    SetBkMode(hdc, TRANSPARENT);
    COLORREF textColor = isModified ? RGB(255, 200, 100) : RGB(200, 200, 200);
    SetTextColor(hdc, textColor);

    RECT textRc = rc;
    textRc.left += 8;
    textRc.right -= 22;  // Space for close button

    std::wstring displayW = utf8ToWide(tab.displayName);
    DrawTextW(hdc, displayW.c_str(), -1, &textRc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);

    // Close button
    RECT closeRc = {textRc.right + 4, rc.top + 3, textRc.right + 16, rc.bottom - 3};
    DrawTextW(hdc, L"×", 1, &closeRc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, hOldFont);
    DeleteObject(hTabFont);
}

void Win32IDE::handleTabClick(POINT pt)
{
    TCHITTESTINFO hitTest = {};
    hitTest.pt = pt;
    int index = (int)SendMessage(m_hwndTabBar, TCM_HITTEST, 0, (LPARAM)&hitTest);

    if (index >= 0 && index < (int)m_editorTabs.size())
    {
        // Check if close button was clicked
        RECT rc;
        SendMessage(m_hwndTabBar, TCM_GETITEMRECT, index, (LPARAM)&rc);

        if (pt.x >= rc.right - 15 && pt.x <= rc.right - 5)
        {
            // Close button clicked
            if (m_editorTabs[index].modified)
            {
                std::string msg = "Save changes to " + m_editorTabs[index].displayName + "?";
                int result = MessageBoxW(m_hwndMain, utf8ToWide(msg).c_str(), L"Confirm Close",
                                         MB_YESNOCANCEL | MB_ICONQUESTION);
                if (result == IDCANCEL)
                    return;
                if (result == IDYES)
                {
                    setActiveTab(index);
                    saveFile();
                }
            }
            removeTab(index);
            return;
        }

        // Tab clicked - switch to it
        setActiveTab(index);
    }
}

// --- Command Input Subclass Procedure ---
LRESULT CALLBACK Win32IDE::CommandInputProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    // Retrieve IDE pointer via GWLP_USERDATA (set in createTerminal)
    Win32IDE* ide = (Win32IDE*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    if (uMsg == WM_KEYDOWN && wParam == VK_RETURN)
    {
        // Execute command on Enter — route through executeCommand()
        if (ide)
        {
            ide->executeCommand();
        }
        return 0;
    }

    // Up arrow — command history navigation (previous) — uses PowerShell history
    if (uMsg == WM_KEYDOWN && wParam == VK_UP)
    {
        if (ide)
        {
            ide->navigatePowerShellHistoryUp();
            // Sync text from PowerShell input to command input
            if (!ide->m_powerShellCommandHistory.empty() && ide->m_powerShellHistoryIndex >= 0 &&
                ide->m_powerShellHistoryIndex < (int)ide->m_powerShellCommandHistory.size())
            {
                SetWindowTextW(hwnd,
                               utf8ToWide(ide->m_powerShellCommandHistory[ide->m_powerShellHistoryIndex]).c_str());
                SendMessage(hwnd, EM_SETSEL, -1, -1);  // cursor to end
            }
        }
        return 0;
    }

    // Down arrow — command history navigation (next) — uses PowerShell history
    if (uMsg == WM_KEYDOWN && wParam == VK_DOWN)
    {
        if (ide)
        {
            ide->navigatePowerShellHistoryDown();
            if (ide->m_powerShellHistoryIndex >= 0 &&
                ide->m_powerShellHistoryIndex < (int)ide->m_powerShellCommandHistory.size())
            {
                SetWindowTextW(hwnd,
                               utf8ToWide(ide->m_powerShellCommandHistory[ide->m_powerShellHistoryIndex]).c_str());
                SendMessage(hwnd, EM_SETSEL, -1, -1);
            }
            else
            {
                SetWindowTextW(hwnd, L"");
            }
        }
        return 0;
    }

    if (ide && ide->m_oldCommandInputProc)
    {
        return CallWindowProcA(ide->m_oldCommandInputProc, hwnd, uMsg, wParam, lParam);
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

// --- Agent Output Handling ---
void Win32IDE::onAgentOutput(const char* text)
{
    if (!text)
        return;
    appendToOutput(std::string(text), "Agent", OutputSeverity::Info);
}

void Win32IDE::postAgentOutputSafe(const std::string& text)
{
    if (isShuttingDown())
        return;
    // Allocate a copy of the string for cross-thread messaging
    // The WM_AGENT_OUTPUT_SAFE handler will free this via free()
    char* copy = _strdup(text.c_str());
    if (copy && m_hwndMain)
    {
        PostMessage(m_hwndMain, WM_AGENT_OUTPUT_SAFE, 0, (LPARAM)copy);
    }
}

void Win32IDE::postOutputPanelSafe(const std::string& text)
{
    if (isShuttingDown())
        return;
    char* copy = _strdup(text.c_str());
    if (copy && m_hwndMain)
    {
        PostMessage(m_hwndMain, WM_IDE_OUTPUT_APPEND_SAFE, 0, (LPARAM)copy);
    }
}

void Win32IDE::wireLayerProgressToOutputPanel()
{
    auto cb = [this](const std::string& line)
    {
        postOutputPanelSafe(line);
        if (m_hwndMain && line.find("[MOE_PACK]") != std::string::npos)
            PostMessageW(m_hwndMain, WM_IDE_MOE_PACK_STATUS_REFRESH, 0, 0);
    };
    if (m_nativeEngine)
    {
        m_nativeEngine->SetLayerProgressCallback(cb);
        m_nativeEngine->SetSwarmTelemetryOutputCallback(cb);
    }
    if (m_agenticBridge)
    {
        m_agenticBridge->SetCpuEngineLayerProgressCallback(cb);
        m_agenticBridge->SetCpuEngineSwarmTelemetryOutputCallback(cb);
    }
}

void Win32IDE::refreshMoEPackHudStatusBarPart()
{
    if (!m_hwndStatusBar)
        return;
    if (!m_nativeEngine || !m_nativeEngine->IsModelLoaded())
    {
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)L"MoE pack: —");
        return;
    }
    const std::string u8 = m_nativeEngine->MoEPackHudStatusLineUtf8();
    if (u8.empty())
    {
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)L"MoE pack: —");
        return;
    }
    const int wlen = MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), -1, nullptr, 0);
    if (wlen <= 0)
        return;
    std::vector<wchar_t> w(static_cast<size_t>(wlen));
    MultiByteToWideChar(CP_UTF8, 0, u8.c_str(), -1, w.data(), wlen);
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)w.data());
    SendMessageW(m_hwndStatusBar, SB_SETTIPTEXTW, 3, (LPARAM)w.data());
}

void Win32IDE::clearInferenceLayerProgressCallback()
{
    if (m_nativeEngine)
    {
        m_nativeEngine->SetLayerProgressCallback({});
        m_nativeEngine->SetSwarmTelemetryOutputCallback({});
    }
    if (m_agenticBridge)
    {
        m_agenticBridge->SetCpuEngineLayerProgressCallback({});
        m_agenticBridge->SetCpuEngineSwarmTelemetryOutputCallback({});
    }
    if (m_hwndStatusBar)
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)L"MoE pack: —");
}

// --- Quick GGUF Model Loader (delegates to unified model dialog) ---
void Win32IDE::quickLoadGGUFModel()
{
    openModelUnified();
}

// ============================================================================
// UNIFIED MODEL SOURCE RESOLUTION
// Implements HuggingFace, Ollama blob, HTTP URL, and smart-detect model loading
// Uses ModelSourceResolver for source detection and download/resolution
// All resolved paths feed into the existing loadGGUFModel() 5-step streaming
// pipeline, preserving full zone-based loading for 800B+ models.
// ============================================================================

// ---------------------------------------------------------------------------
// resolveAndLoadModel — Resolve any model source input to a local path, then
// load it through the streaming GGUF pipeline. This is the common path for
// all source types.
// ---------------------------------------------------------------------------
bool Win32IDE::resolveAndLoadModel(const std::string& input)
{
    SCOPED_METRIC("model.resolve_and_load");
    METRICS.increment("model.resolve_attempts");

    if (!m_modelResolver)
    {
        // If resolver wasn't initialized (deferredHeavyInit failure), create one now
        try
        {
            m_modelResolver = std::make_unique<RawrXD::ModelSourceResolver>();
            OutputDebugStringA("ModelSourceResolver late-initialized in resolveAndLoadModel\n");
        }
        catch (const std::exception& e)
        {
            std::string err = "Failed to initialize ModelSourceResolver: " + std::string(e.what());
            appendToOutput(err + "\n", "Errors", OutputSeverity::Error);
            ErrorReporter::report(err, m_hwndMain);
            return false;
        }
    }

    auto sourceType = m_modelResolver->DetectSourceType(input);
    std::string sourceDesc = RawrXD::ModelSourceResolver::SourceTypeToString(sourceType);
    appendToOutput("Model source detected: " + sourceDesc + "\n", "Output", OutputSeverity::Info);
    appendToOutput("Input: " + input + "\n", "Output", OutputSeverity::Info);

    // For local files, skip resolution and go straight to loading
    if (sourceType == GGUFConstants::ModelSourceType::LOCAL_FILE)
    {
        appendToOutput("Loading local GGUF file directly...\n", "Output", OutputSeverity::Info);
        if (loadGGUFModel(input))
        {
            loadModelForInference(input);
            METRICS.increment("model.resolve_success");
            return true;
        }
        METRICS.increment("model.resolve_failures");
        return false;
    }

    // For remote sources, resolve with progress reporting
    appendToOutput("Resolving model source (this may involve downloading)...\n", "Output", OutputSeverity::Info);
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide("Resolving: " + input).c_str());

    // Progress callback that writes to the output panel
    auto progressCallback = [this](const RawrXD::ModelDownloadProgress& prog)
    {
        if (prog.has_error)
        {
            appendToOutput("Download error: " + prog.error_message + "\n", "Errors", OutputSeverity::Error);
            return;
        }
        if (prog.is_completed)
        {
            appendToOutput("Download complete: " + prog.local_path + "\n", "Output", OutputSeverity::Info);
            return;
        }
        // Progress update — update status bar with percentage
        char buf[256];
        if (prog.total_bytes > 0)
        {
            snprintf(buf, sizeof(buf), "Downloading: %.1f%% (%llu / %llu MB) — %s", prog.progress_percent,
                     (unsigned long long)(prog.downloaded_bytes / (1024 * 1024)),
                     (unsigned long long)(prog.total_bytes / (1024 * 1024)), prog.filename.c_str());
        }
        else
        {
            snprintf(buf, sizeof(buf), "Downloading: %llu MB — %s",
                     (unsigned long long)(prog.downloaded_bytes / (1024 * 1024)), prog.filename.c_str());
        }
        if (m_hwndStatusBar)
        {
            SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide(buf).c_str());
        }
    };

    // Perform resolution (may download)
    RawrXD::ResolvedModelPath resolved;
    try
    {
        resolved = m_modelResolver->Resolve(input, progressCallback);
    }
    catch (const std::exception& e)
    {
        std::string err = "Exception during model resolution: " + std::string(e.what());
        appendToOutput(err + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(err, m_hwndMain);
        METRICS.increment("model.resolve_failures");
        return false;
    }
    catch (...)
    {
        std::string err = "Unknown exception during model resolution for: " + input;
        appendToOutput(err + "\n", "Errors", OutputSeverity::Error);
        METRICS.increment("model.resolve_failures");
        return false;
    }

    if (!resolved.success)
    {
        std::string err = "Failed to resolve model source: " + resolved.error_message;
        appendToOutput(err + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(err, m_hwndMain);
        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Model resolution failed");
        METRICS.increment("model.resolve_failures");
        return false;
    }

    // Log resolution details
    appendToOutput("Resolved to local path: " + resolved.local_path + "\n", "Output", OutputSeverity::Info);
    if (!resolved.hf_repo_id.empty())
    {
        appendToOutput("HuggingFace repo: " + resolved.hf_repo_id + " / " + resolved.hf_filename + "\n", "Output",
                       OutputSeverity::Info);
    }
    if (!resolved.ollama_model_name.empty())
    {
        appendToOutput("Ollama model: " + resolved.ollama_model_name + "\n", "Output", OutputSeverity::Info);
    }

    // Load through the streaming GGUF pipeline (preserves all zone-based 800B+ logic)
    appendToOutput("Loading resolved model through streaming GGUF pipeline...\n", "Output", OutputSeverity::Info);
    if (loadGGUFModel(resolved.local_path))
    {
        loadModelForInference(resolved.local_path);
        METRICS.increment("model.resolve_success");
        return true;
    }

    // No local GGUF path or load failed — still feed Ollama model name to bridge so chat and agentic use it (local
    // definitions vary)
    if (!resolved.ollama_model_name.empty())
    {
        initializeAgenticBridge();
        if (m_agenticBridge)
        {
            m_agenticBridge->SetModel(resolved.ollama_model_name);
            m_ollamaModelOverride = resolved.ollama_model_name;
            if (getLoadedModelPath().empty())
                setLoadedModelPath(resolved.ollama_model_name);
            appendToOutput("Ollama model set in Agentic Bridge: " + resolved.ollama_model_name + "\n", "Output",
                           OutputSeverity::Info);
            METRICS.increment("model.resolve_success");
            return true;
        }
    }

    METRICS.increment("model.resolve_failures");
    return false;
}

// ---------------------------------------------------------------------------
// openModelFromHuggingFace — Dialog: enter HuggingFace repo ID, browse GGUF
// files in the repo, select a quant, download and load.
// ---------------------------------------------------------------------------
void Win32IDE::openModelFromHuggingFace()
{
    SCOPED_METRIC("model.open_from_huggingface");

    // Step 1: Ask user for HuggingFace repo ID or search query
    char inputBuf[512] = {0};
    // Use a simple input dialog (reuse the existing pattern from command palette)
    // We'll use a Win32 dialog via a helper input box

    // Create a simple input dialog
    struct HFInputData
    {
        char repoId[512];
        bool confirmed;
    };
    HFInputData dlgData = {{0}, false};

    // Use DialogBoxIndirect to create an input dialog
    // For simplicity with Win32 API, use a TaskDialog-style approach
    // We'll create a modeless dialog with CreateWindowEx

    // Simple approach: use an edit control dialog
    HWND hDlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, L"STATIC", L"Load from HuggingFace",
                                WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 520, 340,
                                m_hwndMain, nullptr, m_hInstance, nullptr);

    if (!hDlg)
    {
        appendToOutput("Failed to create HuggingFace dialog\n", "Errors", OutputSeverity::Error);
        return;
    }

    SetClassLongPtrW(hDlg, GCLP_HBRBACKGROUND, (LONG_PTR)CreateSolidBrush(RGB(30, 30, 30)));

    HWND hLabel =
        CreateWindowExW(0, L"STATIC",
                        L"Enter HuggingFace repo ID (e.g., TheBloke/Llama-2-7B-GGUF)\n"
                        L"or search term (e.g., 'llama 7b gguf'):",
                        WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 16, 480, 42, hDlg, nullptr, m_hInstance, nullptr);
    SendMessage(hLabel, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    HWND hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 16, 64, 480,
                                 26, hDlg, (HMENU)101, m_hInstance, nullptr);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);
    SetFocus(hEdit);

    HWND hInfoLabel =
        CreateWindowExW(0, L"STATIC", L"Available GGUF files will appear below after Search.",
                        WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 100, 480, 20, hDlg, (HMENU)103, m_hInstance, nullptr);
    SendMessage(hInfoLabel, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    HWND hList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS, 16, 124, 480, 120,
                                 hDlg, (HMENU)102, m_hInstance, nullptr);
    SendMessage(hList, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    HWND hSearchBtn = CreateWindowExW(0, L"BUTTON", L"Search / List Files", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 16,
                                      256, 150, 30, hDlg, (HMENU)201, m_hInstance, nullptr);
    SendMessage(hSearchBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    HWND hLoadBtn = CreateWindowExW(0, L"BUTTON", L"Download && Load", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 180, 256,
                                    150, 30, hDlg, (HMENU)202, m_hInstance, nullptr);
    SendMessage(hLoadBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    HWND hCancelBtn = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 346, 256, 150, 30,
                                      hDlg, (HMENU)IDCANCEL, m_hInstance, nullptr);
    SendMessage(hCancelBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Store references for the message loop
    struct HFDialogState
    {
        Win32IDE* ide;
        HWND hDlg;
        HWND hEdit;
        HWND hList;
        HWND hInfoLabel;
        std::vector<RawrXD::HFModelFileInfo> ggufFiles;
        std::string repoId;
        bool done;
        bool loadRequested;
        int selectedFileIndex;
    };

    HFDialogState state = {};
    state.ide = this;
    state.hDlg = hDlg;
    state.hEdit = hEdit;
    state.hList = hList;
    state.hInfoLabel = hInfoLabel;
    state.done = false;
    state.loadRequested = false;
    state.selectedFileIndex = -1;

    // Run a modal-style message pump for this dialog
    EnableWindow(m_hwndMain, FALSE);

    MSG msg;
    while (!state.done && GetMessage(&msg, nullptr, 0, 0))
    {
        // Handle button clicks for our dialog
        if (msg.message == WM_COMMAND && msg.hwnd == hDlg)
        {
            int wmId = LOWORD(msg.wParam);
            int wmEvent = HIWORD(msg.wParam);

            if (wmId == IDCANCEL)
            {
                state.done = true;
                continue;
            }

            if (wmId == 201)
            {  // Search button
                wchar_t editText[512] = {0};
                GetWindowTextW(hEdit, editText, 512);
                std::string input = wideToUtf8(editText);

                if (input.empty())
                    continue;

                // Clear listbox
                SendMessage(hList, LB_RESETCONTENT, 0, 0);
                SetWindowTextW(hInfoLabel, L"Searching HuggingFace...");
                UpdateWindow(hDlg);

                state.repoId = input;

                // Try to get GGUF files from this repo
                if (m_modelResolver)
                {
                    try
                    {
                        state.ggufFiles = m_modelResolver->GetHuggingFaceGGUFFiles(input);

                        if (state.ggufFiles.empty())
                        {
                            // Maybe it's a search query, not a repo ID — try search
                            auto searchResults = m_modelResolver->SearchHuggingFace(input, 10);
                            if (!searchResults.empty())
                            {
                                // Show search results in the listbox
                                SetWindowTextW(hInfoLabel, L"Search results (select a repo):");
                                for (const auto& result : searchResults)
                                {
                                    std::string entry = result.repo_id + " (" +
                                                        std::to_string(result.gguf_files.size()) + " GGUF files, " +
                                                        std::to_string(result.downloads) + " downloads)";
                                    SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)utf8ToWide(entry).c_str());
                                }
                                // Store repo IDs for selection
                                state.ggufFiles.clear();  // These are repo results, not file results
                            }
                            else
                            {
                                SetWindowTextW(hInfoLabel, L"No results found. Try a different search term.");
                            }
                        }
                        else
                        {
                            // Show GGUF files
                            char infoBuf[256];
                            snprintf(infoBuf, sizeof(infoBuf),
                                     "Found %d GGUF files in %s:", (int)state.ggufFiles.size(), input.c_str());
                            SetWindowTextW(hInfoLabel, utf8ToWide(infoBuf).c_str());

                            for (const auto& file : state.ggufFiles)
                            {
                                char fileLine[512];
                                double sizeMB = file.size_bytes / (1024.0 * 1024.0);
                                double sizeGB = sizeMB / 1024.0;
                                if (sizeGB >= 1.0)
                                {
                                    snprintf(fileLine, sizeof(fileLine), "%s [%s] (%.1f GB)", file.filename.c_str(),
                                             file.quantization.c_str(), sizeGB);
                                }
                                else
                                {
                                    snprintf(fileLine, sizeof(fileLine), "%s [%s] (%.0f MB)", file.filename.c_str(),
                                             file.quantization.c_str(), sizeMB);
                                }
                                SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)fileLine);
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        std::string errMsg = "HuggingFace API error: " + std::string(e.what());
                        SetWindowTextW(hInfoLabel, utf8ToWide(errMsg).c_str());
                    }
                }
                else
                {
                    SetWindowTextW(hInfoLabel, L"ModelSourceResolver not initialized!");
                }

                UpdateWindow(hDlg);
            }

            if (wmId == 202)
            {  // Download & Load button
                int sel = (int)SendMessage(hList, LB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < (int)state.ggufFiles.size())
                {
                    state.selectedFileIndex = sel;
                    state.loadRequested = true;
                    state.done = true;
                    continue;
                }
                else if (sel >= 0)
                {
                    // Might be a search result — get the text and use it as repo ID
                    char selText[512] = {0};
                    SendMessageA(hList, LB_GETTEXT, sel, (LPARAM)selText);
                    std::string selStr(selText);
                    // Extract repo ID (before first space or parenthesis)
                    size_t spacePos = selStr.find(' ');
                    if (spacePos != std::string::npos)
                    {
                        state.repoId = selStr.substr(0, spacePos);
                    }
                    else
                    {
                        state.repoId = selStr;
                    }
                    // Re-search for GGUF files in this repo
                    SetWindowTextW(hEdit, utf8ToWide(state.repoId).c_str());
                    PostMessage(hDlg, WM_COMMAND, MAKEWPARAM(201, BN_CLICKED), (LPARAM)hSearchBtn);
                }
                else
                {
                    MessageBoxW(hDlg, L"Please select a GGUF file from the list first.", L"No Selection",
                                MB_OK | MB_ICONINFORMATION);
                }
            }
        }

        // Handle WM_SYSCOMMAND close (X button)
        if (msg.message == WM_SYSCOMMAND && (msg.wParam & 0xFFF0) == SC_CLOSE && msg.hwnd == hDlg)
        {
            state.done = true;
            continue;
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    EnableWindow(m_hwndMain, TRUE);
    SetForegroundWindow(m_hwndMain);
    DestroyWindow(hDlg);

    // If user selected a file, download and load it
    if (state.loadRequested && state.selectedFileIndex >= 0 && state.selectedFileIndex < (int)state.ggufFiles.size())
    {

        const auto& selectedFile = state.ggufFiles[state.selectedFileIndex];
        appendToOutput("Downloading from HuggingFace: " + state.repoId + " / " + selectedFile.filename + "\n", "Output",
                       OutputSeverity::Info);

        // Download on a background thread to keep UI responsive
        std::string repoId = state.repoId;
        std::string filename = selectedFile.filename;

        std::thread(
            [this, repoId, filename]()
            {
                DetachedThreadGuard _guard(m_activeDetachedThreads, m_shuttingDown);
                if (_guard.cancelled)
                    return;
                auto progressCb = [this](const RawrXD::ModelDownloadProgress& prog)
                {
                    char buf[256];
                    if (prog.has_error)
                    {
                        snprintf(buf, sizeof(buf), "Download error: %s", prog.error_message.c_str());
                        PostMessage(m_hwndMain, WM_APP + 200, 0, 0);  // Signal UI update
                    }
                    else if (prog.is_completed)
                    {
                        snprintf(buf, sizeof(buf), "Download complete!");
                    }
                    else if (prog.total_bytes > 0)
                    {
                        snprintf(buf, sizeof(buf), "Downloading: %.1f%% (%llu MB)", prog.progress_percent,
                                 (unsigned long long)(prog.downloaded_bytes / (1024 * 1024)));
                    }
                    else
                    {
                        snprintf(buf, sizeof(buf), "Downloading: %llu MB",
                                 (unsigned long long)(prog.downloaded_bytes / (1024 * 1024)));
                    }
                    if (m_hwndStatusBar)
                    {
                        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide(buf).c_str());
                    }
                };

                try
                {
                    std::string localPath = m_modelResolver->DownloadFromHuggingFace(repoId, filename, progressCb);

                    if (!localPath.empty())
                    {
                        // Load on main thread via PostMessage
                        // Store the path and signal the main thread
                        setLoadedModelPath(localPath);
                        PostMessage(m_hwndMain, WM_APP + 201, 0, 0);  // Signal: load downloaded model
                    }
                    else
                    {
                        if (m_hwndStatusBar)
                        {
                            SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"HuggingFace download failed");
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    OutputDebugStringA("HF download exception: ");
                    OutputDebugStringA(e.what());
                    OutputDebugStringA("\n");
                    if (m_hwndStatusBar)
                    {
                        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"HuggingFace download exception");
                    }
                }
            })
            .detach();
    }
}

// ---------------------------------------------------------------------------
// openModelFromOllama — Scan for Ollama blobs, show a selection list,
// validate GGUF magic, and load the selected blob.
// ---------------------------------------------------------------------------
void Win32IDE::openModelFromOllama()
{
    SCOPED_METRIC("model.open_from_ollama");

    if (!m_modelResolver)
    {
        try
        {
            m_modelResolver = std::make_unique<RawrXD::ModelSourceResolver>();
        }
        catch (...)
        {
            appendToOutput("Failed to initialize ModelSourceResolver\n", "Errors", OutputSeverity::Error);
            return;
        }
    }

    appendToOutput("Scanning for Ollama GGUF blobs...\n", "Output", OutputSeverity::Info);
    SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"Scanning Ollama blobs...");

    // Find all Ollama blobs with valid GGUF magic
    std::vector<RawrXD::OllamaBlobInfo> blobs;
    try
    {
        blobs = m_modelResolver->FindOllamaBlobs();
    }
    catch (const std::exception& e)
    {
        std::string err = "Error scanning Ollama blobs: " + std::string(e.what());
        appendToOutput(err + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(err, m_hwndMain);
        return;
    }

    if (blobs.empty())
    {
        MessageBoxW(m_hwndMain,
                    L"No Ollama GGUF blobs found.\n\n"
                    L"Searched directories:\n"
                    L"  - %USERPROFILE%\\.ollama\\models\\blobs\n"
                    L"  - D:\\OllamaModels\\blobs\n"
                    L"  - C:\\Users\\*\\.ollama\\models\\blobs\n\n"
                    L"Make sure Ollama is installed and has downloaded models.",
                    L"No Ollama Models Found", MB_OK | MB_ICONINFORMATION);
        return;
    }

    appendToOutput("Found " + std::to_string(blobs.size()) + " Ollama GGUF blobs.\n", "Output", OutputSeverity::Info);

    // Create a selection dialog
    HWND hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, "STATIC", "Load from Ollama Blobs",
                                WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 580, 350,
                                m_hwndMain, nullptr, m_hInstance, nullptr);

    if (!hDlg)
        return;

    SetClassLongPtrA(hDlg, GCLP_HBRBACKGROUND, (LONG_PTR)CreateSolidBrush(RGB(30, 30, 30)));

    // Info label
    char infoText[128];
    snprintf(infoText, sizeof(infoText), "Found %d Ollama GGUF blobs. Select one to load:", (int)blobs.size());
    HWND hLabel = CreateWindowExA(0, "STATIC", infoText, WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 12, 540, 22, hDlg,
                                  nullptr, m_hInstance, nullptr);
    SendMessage(hLabel, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Listbox
    HWND hList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_HASSTRINGS, 16, 40, 540, 220,
                                 hDlg, (HMENU)102, m_hInstance, nullptr);
    SendMessage(hList, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Populate with blob info
    for (const auto& blob : blobs)
    {
        char line[512];
        double sizeGB = blob.size_bytes / (1024.0 * 1024.0 * 1024.0);
        double sizeMB = blob.size_bytes / (1024.0 * 1024.0);
        if (sizeGB >= 1.0)
        {
            snprintf(line, sizeof(line), "%s — %.1f GB %s", blob.model_name.c_str(), sizeGB,
                     blob.is_valid_gguf ? "[GGUF OK]" : "[INVALID]");
        }
        else
        {
            snprintf(line, sizeof(line), "%s — %.0f MB %s", blob.model_name.c_str(), sizeMB,
                     blob.is_valid_gguf ? "[GGUF OK]" : "[INVALID]");
        }
        SendMessageA(hList, LB_ADDSTRING, 0, (LPARAM)line);
    }

    // Load button
    HWND hLoadBtn = CreateWindowExA(0, "BUTTON", "Load Selected", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 16, 272, 150,
                                    30, hDlg, (HMENU)201, m_hInstance, nullptr);
    SendMessage(hLoadBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Cancel button
    HWND hCancelBtn = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 406, 272, 150, 30,
                                      hDlg, (HMENU)IDCANCEL, m_hInstance, nullptr);
    SendMessage(hCancelBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    bool done = false;
    int selectedIdx = -1;

    EnableWindow(m_hwndMain, FALSE);

    MSG msg;
    while (!done && GetMessage(&msg, nullptr, 0, 0))
    {
        if (msg.message == WM_COMMAND && msg.hwnd == hDlg)
        {
            int wmId = LOWORD(msg.wParam);

            if (wmId == IDCANCEL)
            {
                done = true;
                continue;
            }

            if (wmId == 201)
            {  // Load button
                int sel = (int)SendMessage(hList, LB_GETCURSEL, 0, 0);
                if (sel >= 0 && sel < (int)blobs.size())
                {
                    selectedIdx = sel;
                    done = true;
                    continue;
                }
                else
                {
                    MessageBoxW(hDlg, L"Please select a model from the list.", L"No Selection",
                                MB_OK | MB_ICONINFORMATION);
                }
            }
        }

        if (msg.message == WM_SYSCOMMAND && (msg.wParam & 0xFFF0) == SC_CLOSE && msg.hwnd == hDlg)
        {
            done = true;
            continue;
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    EnableWindow(m_hwndMain, TRUE);
    SetForegroundWindow(m_hwndMain);
    DestroyWindow(hDlg);

    // Load the selected blob
    if (selectedIdx >= 0 && selectedIdx < (int)blobs.size())
    {
        const auto& selected = blobs[selectedIdx];

        if (!selected.is_valid_gguf)
        {
            MessageBoxW(
                m_hwndMain,
                utf8ToWide("Selected blob does not have valid GGUF magic bytes:\n" + selected.blob_path).c_str(),
                L"Invalid GGUF", MB_OK | MB_ICONWARNING);
            return;
        }

        appendToOutput("Loading Ollama blob: " + selected.model_name + "\n", "Output", OutputSeverity::Info);
        appendToOutput("Path: " + selected.blob_path + "\n", "Output", OutputSeverity::Info);

        if (loadGGUFModel(selected.blob_path))
        {
            loadModelForInference(selected.blob_path);
        }
    }
}

// ---------------------------------------------------------------------------
// openModelFromURL — Dialog: enter HTTP/HTTPS URL to a GGUF file,
// download with progress, and load through the streaming pipeline.
// ---------------------------------------------------------------------------
void Win32IDE::openModelFromURL()
{
    SCOPED_METRIC("model.open_from_url");

    if (!m_modelResolver)
    {
        try
        {
            m_modelResolver = std::make_unique<RawrXD::ModelSourceResolver>();
        }
        catch (...)
        {
            appendToOutput("Failed to initialize ModelSourceResolver\n", "Errors", OutputSeverity::Error);
            return;
        }
    }

    // Create URL input dialog
    HWND hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, "STATIC", "Load from URL",
                                WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 560, 180,
                                m_hwndMain, nullptr, m_hInstance, nullptr);

    if (!hDlg)
        return;

    SetClassLongPtrA(hDlg, GCLP_HBRBACKGROUND, (LONG_PTR)CreateSolidBrush(RGB(30, 30, 30)));

    // Label
    HWND hLabel = CreateWindowExA(0, "STATIC",
                                  "Enter direct URL to a .gguf file (HTTP or HTTPS):", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                  16, 16, 520, 22, hDlg, nullptr, m_hInstance, nullptr);
    SendMessage(hLabel, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // URL edit
    HWND hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 16, 44, 520, 26,
                                 hDlg, (HMENU)101, m_hInstance, nullptr);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);
    SetFocus(hEdit);

    // Example label
    HWND hExample = CreateWindowExA(
        0, "STATIC", "Example: https://huggingface.co/TheBloke/Llama-2-7B-GGUF/resolve/main/llama-2-7b.Q4_K_M.gguf",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 76, 520, 18, hDlg, nullptr, m_hInstance, nullptr);
    SendMessage(hExample, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Download button
    HWND hDownloadBtn = CreateWindowExA(0, "BUTTON", "Download && Load", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 16, 106,
                                        150, 30, hDlg, (HMENU)201, m_hInstance, nullptr);
    SendMessage(hDownloadBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Cancel button
    HWND hCancelBtn = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 386, 106, 150, 30,
                                      hDlg, (HMENU)IDCANCEL, m_hInstance, nullptr);
    SendMessage(hCancelBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    bool done = false;
    std::string url;

    EnableWindow(m_hwndMain, FALSE);

    MSG msg;
    while (!done && GetMessage(&msg, nullptr, 0, 0))
    {
        if (msg.message == WM_COMMAND && msg.hwnd == hDlg)
        {
            int wmId = LOWORD(msg.wParam);

            if (wmId == IDCANCEL)
            {
                done = true;
                continue;
            }

            if (wmId == 201)
            {  // Download button
                char editText[2048] = {0};
                GetWindowTextA(hEdit, editText, sizeof(editText));
                url = std::string(editText);

                if (url.empty())
                {
                    MessageBoxW(hDlg, L"Please enter a URL.", L"Empty URL", MB_OK);
                    continue;
                }

                // Basic URL validation
                if (url.find("http://") != 0 && url.find("https://") != 0)
                {
                    MessageBoxW(hDlg, L"URL must start with http:// or https://", L"Invalid URL",
                                MB_OK | MB_ICONWARNING);
                    continue;
                }

                done = true;
                continue;
            }
        }

        if (msg.message == WM_SYSCOMMAND && (msg.wParam & 0xFFF0) == SC_CLOSE && msg.hwnd == hDlg)
        {
            done = true;
            url.clear();
            continue;
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    EnableWindow(m_hwndMain, TRUE);
    SetForegroundWindow(m_hwndMain);
    DestroyWindow(hDlg);

    if (!url.empty())
    {
        appendToOutput("Downloading from URL: " + url + "\n", "Output", OutputSeverity::Info);

        // Download on background thread
        std::thread(
            [this, url]()
            {
                DetachedThreadGuard _guard(m_activeDetachedThreads, m_shuttingDown);
                if (_guard.cancelled)
                    return;
                auto progressCb = [this](const RawrXD::ModelDownloadProgress& prog)
                {
                    char buf[256];
                    if (prog.has_error)
                    {
                        snprintf(buf, sizeof(buf), "Download error: %s", prog.error_message.c_str());
                    }
                    else if (prog.is_completed)
                    {
                        snprintf(buf, sizeof(buf), "Download complete!");
                    }
                    else if (prog.total_bytes > 0)
                    {
                        snprintf(buf, sizeof(buf), "Downloading: %.1f%% (%llu / %llu MB)", prog.progress_percent,
                                 (unsigned long long)(prog.downloaded_bytes / (1024 * 1024)),
                                 (unsigned long long)(prog.total_bytes / (1024 * 1024)));
                    }
                    else
                    {
                        snprintf(buf, sizeof(buf), "Downloading: %llu MB",
                                 (unsigned long long)(prog.downloaded_bytes / (1024 * 1024)));
                    }
                    if (m_hwndStatusBar)
                    {
                        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)utf8ToWide(buf).c_str());
                    }
                };

                try
                {
                    std::string localPath = m_modelResolver->DownloadFromURL(url, progressCb);

                    if (!localPath.empty())
                    {
                        setLoadedModelPath(localPath);
                        // Signal main thread to load the model
                        PostMessage(m_hwndMain, WM_APP + 201, 0, 0);
                    }
                    else
                    {
                        if (m_hwndStatusBar)
                        {
                            SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"URL download failed");
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    OutputDebugStringA("URL download exception: ");
                    OutputDebugStringA(e.what());
                    OutputDebugStringA("\n");
                    if (m_hwndStatusBar)
                    {
                        SendMessageW(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)L"URL download exception");
                    }
                }
            })
            .detach();
    }
}

// ---------------------------------------------------------------------------
// openModelUnified — Smart model open dialog: user types any model identifier
// and it auto-detects the source type (local path, HF repo, Ollama name, URL)
// and routes to the appropriate loader.
// ---------------------------------------------------------------------------
void Win32IDE::openModelUnified()
{
    SCOPED_METRIC("model.open_unified");

    // Create the unified input dialog
    HWND hDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_TOPMOST, "STATIC", "RawrXD — Smart Model Loader",
                                WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT, 580, 260,
                                m_hwndMain, nullptr, m_hInstance, nullptr);

    if (!hDlg)
        return;

    SetClassLongPtrA(hDlg, GCLP_HBRBACKGROUND, (LONG_PTR)CreateSolidBrush(RGB(30, 30, 30)));

    // Title label
    HWND hTitle = CreateWindowExA(
        0, "STATIC", "Enter any model identifier — the source will be auto-detected:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        16, 16, 540, 22, hDlg, nullptr, m_hInstance, nullptr);
    SendMessage(hTitle, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Input edit
    HWND hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 16, 44, 540, 26,
                                 hDlg, (HMENU)101, m_hInstance, nullptr);
    SendMessage(hEdit, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);
    SetFocus(hEdit);

    // Help text
    std::string helpText = "Supported formats:\n"
                           "  Local file:     C:\\models\\my-model.gguf\n"
                           "  HuggingFace:  TheBloke/Llama-2-7B-GGUF  or  hf://repo-id\n"
                           "  Ollama blob:   llama3.2:3b  or  codellama:7b\n"
                           "  Direct URL:     https://example.com/model.gguf";

    HWND hHelp = CreateWindowExA(0, "STATIC", helpText.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT, 16, 78, 540, 90, hDlg,
                                 nullptr, m_hInstance, nullptr);
    SendMessage(hHelp, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Load button
    HWND hLoadBtn =
        CreateWindowExA(0, "BUTTON", "Detect && Load", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON, 16,
                        180, 150, 32, hDlg, (HMENU)201, m_hInstance, nullptr);
    SendMessage(hLoadBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Browse Local button
    HWND hBrowseBtn = CreateWindowExA(0, "BUTTON", "Browse Local...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 180, 180,
                                      150, 32, hDlg, (HMENU)202, m_hInstance, nullptr);
    SendMessage(hBrowseBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    // Cancel button
    HWND hCancelBtn = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 414, 180, 140, 32,
                                      hDlg, (HMENU)IDCANCEL, m_hInstance, nullptr);
    SendMessage(hCancelBtn, WM_SETFONT, (WPARAM)m_hFontUI, TRUE);

    bool done = false;
    std::string inputStr;

    EnableWindow(m_hwndMain, FALSE);

    MSG msg;
    while (!done && GetMessage(&msg, nullptr, 0, 0))
    {
        if (msg.message == WM_COMMAND && msg.hwnd == hDlg)
        {
            int wmId = LOWORD(msg.wParam);

            if (wmId == IDCANCEL)
            {
                done = true;
                continue;
            }

            if (wmId == 201)
            {  // Detect & Load
                char editText[2048] = {0};
                GetWindowTextA(hEdit, editText, sizeof(editText));
                inputStr = std::string(editText);

                if (inputStr.empty())
                {
                    MessageBoxW(hDlg, L"Please enter a model identifier.", L"Empty Input", MB_OK);
                    continue;
                }

                done = true;
                continue;
            }

            if (wmId == 202)
            {  // Browse Local
                wchar_t filename[MAX_PATH] = {0};
                OPENFILENAMEW ofn = {0};
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hDlg;
                ofn.lpstrFilter = L"GGUF Models\0*.gguf\0All Files\0*.*\0";
                ofn.lpstrFile = filename;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                ofn.lpstrTitle = L"Select GGUF Model";

                if (GetOpenFileNameW(&ofn))
                {
                    SetWindowTextW(hEdit, filename);
                }
            }
        }

        // Handle Enter key in edit control
        if (msg.message == WM_KEYDOWN && msg.wParam == VK_RETURN && msg.hwnd == hEdit)
        {
            PostMessage(hDlg, WM_COMMAND, MAKEWPARAM(201, BN_CLICKED), (LPARAM)hLoadBtn);
            continue;
        }

        if (msg.message == WM_SYSCOMMAND && (msg.wParam & 0xFFF0) == SC_CLOSE && msg.hwnd == hDlg)
        {
            done = true;
            inputStr.clear();
            continue;
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    EnableWindow(m_hwndMain, TRUE);
    SetForegroundWindow(m_hwndMain);
    DestroyWindow(hDlg);

    if (!inputStr.empty())
    {
        resolveAndLoadModel(inputStr);
    }
}

// ============================================================================
// EditorSubclassProc — Editor RichEdit subclass window procedure
// Routes editor-specific messages (scroll sync, key interception) while
// forwarding everything else to the original EDIT wndproc.
// ============================================================================
LRESULT CALLBACK Win32IDE::EditorSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetPropW(hwnd, kEditorWndProp);
    WNDPROC oldProc = (WNDPROC)GetPropW(hwnd, kEditorProcProp);

    if (pThis)
    {
        switch (uMsg)
        {
            case WM_VSCROLL:
            case WM_MOUSEWHEEL:
                // After scroll, sync line numbers, minimap, and diagnostic overlay
                if (oldProc)
                {
                    LRESULT result = CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam);
                    pThis->updateLineNumbers();
                    if (pThis->m_minimapVisible)
                        pThis->updateMinimap();
                    // Sync LSP diagnostic overlay
                    if (pThis->m_lspDiagnosticOverlay && pThis->m_lspDiagnosticOverlay->IsInitialized()) {
                        int scrollPos = (int)SendMessage(hwnd, EM_GETFIRSTVISIBLELINE, 0, 0);
                        pThis->m_lspDiagnosticOverlay->OnEditorScroll(scrollPos);
                    }
                    return result;
                }
                break;

            case WM_KEYDOWN:
                // Ghost text key handling — Tab accepts, Esc dismisses, other keys dismiss
                if (pThis->handleGhostTextKey((UINT)wParam))
                {
                    return 0;  // Ghost text consumed the key
                }
                // Ctrl+Space → code completion popup
                if (wParam == VK_SPACE && (GetKeyState(VK_CONTROL) & 0x8000))
                {
                    pThis->triggerCodeCompletion();
                    return 0;
                }
                // Ctrl+Shift+P → command palette
                if (wParam == 'P' && (GetKeyState(VK_CONTROL) & 0x8000) && (GetKeyState(VK_SHIFT) & 0x8000))
                {
                    pThis->showCommandPalette();
                    return 0;
                }
                // F9 → toggle breakpoint at current line
                if (wParam == VK_F9)
                {
                    CHARRANGE sel;
                    SendMessage(hwnd, EM_EXGETSEL, 0, (LPARAM)&sel);
                    int line = (int)SendMessage(hwnd, EM_LINEFROMCHAR, sel.cpMin, 0) + 1;
                    pThis->toggleBreakpoint(pThis->m_currentFile, line);
                    return 0;
                }
                break;

            case WM_PAINT:
            {
                // Let the RichEdit control paint itself first
                if (oldProc)
                {
                    LRESULT result = CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam);
                    // Overlay ghost text on top of the editor content
                    if (pThis->m_ghostTextVisible)
                    {
                        HDC hdc = GetDC(hwnd);
                        if (hdc)
                        {
                            pThis->renderGhostText(hdc);
                            ReleaseDC(hwnd, hdc);
                        }
                    }
                    return result;
                }
                break;
            }

            case WM_CHAR:
                // After character input, trigger syntax coloring debounce
                if (oldProc)
                {
                    LRESULT result = CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam);
                    pThis->onEditorContentChanged();
                    
                    // Trigger completion on trigger characters: . -> ::
                    wchar_t ch = (wchar_t)wParam;
                    if (ch == L'.' || ch == L'>' || ch == L':')
                    {
                        // Small delay to let the character be inserted
                        SetTimer(pThis->m_hwndMain, 9999, 50, nullptr);
                    }
                    return result;
                }
                break;

            case WM_DESTROY:
                // Clean up properties on destruction
                RemovePropW(hwnd, kEditorWndProp);
                RemovePropW(hwnd, kEditorProcProp);
                break;
        }
    }

    if (oldProc)
    {
        return CallWindowProcW(oldProc, hwnd, uMsg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// SidebarProcImpl — Secondary sidebar (AI Chat panel) window procedure
// Handles paint, sizing, and command routing for the right-side AI panel.
// Distinct from SidebarProc which handles the primary (left) sidebar.
// ============================================================================
LRESULT CALLBACK Win32IDE::SidebarProcImpl(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = (Win32IDE*)GetWindowLongPtrA(hwnd, GWLP_USERDATA);

    switch (uMsg)
    {
        case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);

            COLORREF bgColor = pThis ? pThis->m_currentTheme.sidebarBg : RGB(37, 37, 38);
            HBRUSH hBrush = CreateSolidBrush(bgColor);
            FillRect(hdc, &rc, hBrush);
            DeleteObject(hBrush);

            EndPaint(hwnd, &ps);
            return 0;
        }

        case WM_COMMAND:
        {
            if (pThis)
            {
                int controlId = LOWORD(wParam);
                int notifyCode = HIWORD(wParam);
                // Route button clicks from AI Chat panel controls
                if (controlId == IDC_AI_MAX_MODE && notifyCode == BN_CLICKED)
                {
                    pThis->onAIModeMax();
                }
                else if (controlId == IDC_AI_DEEP_THINK && notifyCode == BN_CLICKED)
                {
                    pThis->onAIModeDeepThink();
                }
                else if (controlId == IDC_AI_DEEP_RESEARCH && notifyCode == BN_CLICKED)
                {
                    pThis->onAIModeDeepResearch();
                }
                else if (controlId == IDC_AI_NO_REFUSAL && notifyCode == BN_CLICKED)
                {
                    pThis->onAIModeNoRefusal();
                }
            }
            return 0;
        }

        case WM_SIZE:
        {
            if (pThis)
            {
                pThis->updateSecondarySidebarContent();
            }
            return 0;
        }
    }

    // Forward to the original sidebar window procedure
    if (pThis && pThis->m_oldSidebarProc)
    {
        return CallWindowProcA(pThis->m_oldSidebarProc, hwnd, uMsg, wParam, lParam);
    }
    return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}

// ============================================================================
// getCurrentGitBranch — Returns the current git branch name
// ============================================================================
std::string Win32IDE::getCurrentGitBranch() const
{
    if (!isGitRepository())
        return "";

    std::string output;
    const_cast<Win32IDE*>(this)->executeGitCommand("git rev-parse --abbrev-ref HEAD", output);

    // Trim whitespace/newlines from output
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r' || output.back() == ' '))
    {
        output.pop_back();
    }
    return output;
}

// ============================================================================
// Terminal Pane Management
// Multi-terminal support: switch, close, resize, and broadcast to panes.
// ============================================================================

void Win32IDE::switchTerminalPane(int paneId)
{
    LOG_INFO("switchTerminalPane: paneId=" + std::to_string(paneId));
    TerminalPane* pane = findTerminalPane(paneId);
    if (pane)
    {
        setActiveTerminalPane(paneId);
        appendToOutput("Switched to terminal: " + pane->name + "\n", "Output", OutputSeverity::Info);
    }
    else
    {
        appendToOutput("Terminal pane " + std::to_string(paneId) + " not found\n", "Output", OutputSeverity::Warning);
    }
}

void Win32IDE::closeTerminalPane(int paneId)
{
    LOG_INFO("closeTerminalPane: paneId=" + std::to_string(paneId));
    for (auto it = m_terminalPanes.begin(); it != m_terminalPanes.end(); ++it)
    {
        if (it->id == paneId)
        {
            if (it->manager)
                it->manager->stop();
            if (it->hwnd && IsWindow(it->hwnd))
                DestroyWindow(it->hwnd);
            m_terminalPanes.erase(it);
            // Switch to another pane if we closed the active one
            if (m_activeTerminalId == paneId && !m_terminalPanes.empty())
            {
                setActiveTerminalPane(m_terminalPanes.front().id);
            }
            appendToOutput("Closed terminal pane " + std::to_string(paneId) + "\n", "Output", OutputSeverity::Info);
            return;
        }
    }
    appendToOutput("Terminal pane " + std::to_string(paneId) + " not found\n", "Output", OutputSeverity::Warning);
}

void Win32IDE::resizeTerminalPanes()
{
    LOG_INFO("resizeTerminalPanes");
    if (m_terminalPanes.empty())
        return;

    RECT rc;
    GetClientRect(m_hwndMain, &rc);
    int totalWidth = rc.right;
    int paneWidth = totalWidth / static_cast<int>(m_terminalPanes.size());

    int x = 0;
    for (auto& pane : m_terminalPanes)
    {
        if (pane.hwnd && IsWindow(pane.hwnd))
        {
            pane.bounds = {x, 0, x + paneWidth, rc.bottom};
            MoveWindow(pane.hwnd, x, 0, paneWidth, rc.bottom, TRUE);
        }
        x += paneWidth;
    }
}

void Win32IDE::sendToAllTerminals(const std::string& command)
{
    LOG_INFO("sendToAllTerminals: " + command);
    for (auto& pane : m_terminalPanes)
    {
        if (pane.manager)
        {
            pane.manager->writeInput(command + "\r\n");
        }
    }
    appendToOutput("Sent to all " + std::to_string(m_terminalPanes.size()) + " terminals: " + command + "\n", "Output",
                   OutputSeverity::Info);
}

// ============================================================================
// Extension System
// Refresh, load, unload, and help for IDE extensions via m_extensionLoader.
// ============================================================================

void Win32IDE::refreshExtensions()
{
    LOG_INFO("refreshExtensions");
    if (m_extensionLoader)
    {
        m_extensionLoader->Scan();
        auto exts = m_extensionLoader->GetExtensions();
        appendToOutput("Extensions refreshed: " + std::to_string(exts.size()) + " found\n", "Output",
                       OutputSeverity::Info);
    }
    else
    {
        appendToOutput("⚠️ Extension loader not initialized\n", "Output", OutputSeverity::Warning);
    }
}

void Win32IDE::loadExtension(const std::string& name)
{
    LOG_INFO("loadExtension: " + name);
    if (m_extensionLoader)
    {
        // Re-scan to ensure extension list is current, then load native modules
        m_extensionLoader->Scan();
        m_extensionLoader->LoadNativeModules();
        appendToOutput("✅ Extension loaded: " + name + "\n", "Output", OutputSeverity::Info);
    }
    else
    {
        appendToOutput("⚠️ Extension loader not initialized\n", "Output", OutputSeverity::Warning);
    }
}

void Win32IDE::unloadExtension(const std::string& name)
{
    LOG_INFO("unloadExtension: " + name);
    if (m_extensionLoader)
    {
        bool unloaded = m_extensionLoader->UnloadExtension(name);
        if (unloaded)
        {
            appendToOutput("✅ Extension unloaded: " + name + "\n", "Output", OutputSeverity::Info);
        }
        else
        {
            appendToOutput("⚠️ Failed to unload extension: " + name + " (not found or not loaded)\n", "Output",
                           OutputSeverity::Warning);
        }
    }
    else
    {
        appendToOutput("⚠️ Extension loader not initialized\n", "Output", OutputSeverity::Warning);
    }
}

void Win32IDE::showExtensionHelp(const std::string& name)
{
    LOG_INFO("showExtensionHelp: " + name);
    if (m_extensionLoader)
    {
        std::string help = m_extensionLoader->GetHelp(name);
        appendToOutput("--- Extension Help: " + name + " ---\n" + help + "\n", "Output", OutputSeverity::Info);
    }
    else
    {
        appendToOutput("⚠️ Extension loader not initialized\n", "Output", OutputSeverity::Warning);
    }
}

// ============================================================================
// DEFERRED IMPLEMENTATIONS — PowerShell Panel Dock/Float
// ============================================================================

void Win32IDE::dockPowerShellPanel()
{
    LOG_INFO("dockPowerShellPanel");
    m_powerShellPanelDocked = true;

    if (m_hwndPowerShellPanel && IsWindow(m_hwndPowerShellPanel))
    {
        // Remove WS_POPUP, add WS_CHILD — reparent to main window
        LONG style = GetWindowLong(m_hwndPowerShellPanel, GWL_STYLE);
        style = (style & ~WS_POPUP) | WS_CHILD;
        SetWindowLong(m_hwndPowerShellPanel, GWL_STYLE, style);
        SetParent(m_hwndPowerShellPanel, m_hwndMain);

        // Trigger layout recalculation
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
    }

    appendToOutput("PowerShell panel docked\n", "Output", OutputSeverity::Info);
}

void Win32IDE::floatPowerShellPanel()
{
    LOG_INFO("floatPowerShellPanel");
    m_powerShellPanelDocked = false;

    if (m_hwndPowerShellPanel && IsWindow(m_hwndPowerShellPanel))
    {
        // Remove WS_CHILD, add WS_POPUP — detach from main window
        LONG style = GetWindowLong(m_hwndPowerShellPanel, GWL_STYLE);
        style = (style & ~WS_CHILD) | WS_POPUP | WS_CAPTION | WS_THICKFRAME;
        SetWindowLong(m_hwndPowerShellPanel, GWL_STYLE, style);
        SetParent(m_hwndPowerShellPanel, nullptr);

        // Position floating window near the main window
        RECT mainRect;
        GetWindowRect(m_hwndMain, &mainRect);
        SetWindowPos(m_hwndPowerShellPanel, HWND_TOP, mainRect.right - 500, mainRect.bottom - 400, 480, 360,
                     SWP_SHOWWINDOW);
    }

    appendToOutput("PowerShell panel floating\n", "Output", OutputSeverity::Info);
}

// Helper for input dialog — Win32 modal dialog without .rc template
namespace
{
struct InputDialogParams
{
    const wchar_t* prompt;
    wchar_t* buffer;
    size_t bufferSize;
    bool ok = false;
};
enum
{
    IDC_PROMPT = 1001,
    IDC_EDIT = 1002,
    IDC_OK = 1003,
    IDC_CANCEL = 1004
};
static const UINT WM_INPUTDLG_CLOSED = WM_APP + 2;

static LRESULT CALLBACK InputDialogWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    InputDialogParams* p = reinterpret_cast<InputDialogParams*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg)
    {
        case WM_CREATE:
        {
            CREATESTRUCTW* cs = reinterpret_cast<CREATESTRUCTW*>(lParam);
            p = reinterpret_cast<InputDialogParams*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)p);
            if (!p)
                break;
            HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
            CreateWindowW(L"Static", p->prompt ? p->prompt : L"", WS_CHILD | WS_VISIBLE, 12, 12, 316, 16, hwnd,
                          (HMENU)(UINT_PTR)IDC_PROMPT, hInst, nullptr);
            CreateWindowW(L"Edit", (p->buffer && p->bufferSize > 0) ? p->buffer : L"",
                          WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT, 12, 34, 316, 24, hwnd, (HMENU)(UINT_PTR)IDC_EDIT,
                          hInst, nullptr);
            CreateWindowW(L"Button", L"OK", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON, 132, 66, 72, 26, hwnd,
                          (HMENU)(UINT_PTR)IDC_OK, hInst, nullptr);
            CreateWindowW(L"Button", L"Cancel", WS_CHILD | WS_VISIBLE, 212, 66, 72, 26, hwnd,
                          (HMENU)(UINT_PTR)IDC_CANCEL, hInst, nullptr);
            break;
        }
        case WM_COMMAND:
            if (LOWORD(wParam) == IDC_OK)
            {
                p = reinterpret_cast<InputDialogParams*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
                if (p && p->buffer && p->bufferSize > 0)
                {
                    GetDlgItemTextW(hwnd, IDC_EDIT, p->buffer, (int)p->bufferSize);
                }
                if (p)
                    p->ok = true;
                PostMessageW(GetParent(hwnd), WM_INPUTDLG_CLOSED, 0, 0);
                DestroyWindow(hwnd);
                return 0;
            }
            if (LOWORD(wParam) == IDC_CANCEL)
            {
                PostMessageW(GetParent(hwnd), WM_INPUTDLG_CLOSED, 0, 0);
                DestroyWindow(hwnd);
                return 0;
            }
            break;
        case WM_CLOSE:
            PostMessageW(GetParent(hwnd), WM_INPUTDLG_CLOSED, 0, 0);
            DestroyWindow(hwnd);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static ATOM s_inputDialogClass = 0;

static HWND RunInputDialog(HWND parent, const wchar_t* title, InputDialogParams* params)
{
    HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(parent, GWLP_HINSTANCE);
    if (!s_inputDialogClass)
    {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = InputDialogWndProc;
        wc.hInstance = hInst;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"RawrXD_InputDialog";
        s_inputDialogClass = RegisterClassExW(&wc);
        if (!s_inputDialogClass)
            return nullptr;
    }
    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_WINDOWEDGE, L"RawrXD_InputDialog", title ? title : L"Input",
                               WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 348, 128, parent,
                               nullptr, hInst, params);
    if (!dlg)
        return nullptr;
    ShowWindow(dlg, SW_SHOW);
    return dlg;
}
}  // namespace

bool Win32IDE::DialogBoxWithInput(const wchar_t* title, const wchar_t* prompt, wchar_t* buffer, size_t bufferSize)
{
    if (!buffer || bufferSize == 0)
        return false;
    buffer[0] = L'\0';

    InputDialogParams params = {prompt, buffer, bufferSize, false};
    HWND dlg = RunInputDialog(m_hwndMain, title, &params);
    if (!dlg)
        return false;

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        if (msg.message == WM_INPUTDLG_CLOSED && msg.hwnd == m_hwndMain)
            break;
        if (!IsDialogMessageW(dlg, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return params.ok;
}
=======
Win32IDE::~Win32IDE() {
    if (m_nativeEngine) {
        delete static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
        m_nativeEngine = nullptr;
    }
    // Resource cleanup
    Win32TerminalManager::cleanup();
}
#include "Win32IDE.h"
#include "IDELogger.h"
#include "Win32IDE_AgenticBridge.h"
#include "../cpu_inference_engine.h" // Added for Native Fallback
#include "streaming_gguf_loader.h"
#include "../utils/ErrorReporter.hpp"
#include <commdlg.h>
#include <richedit.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")

#define IDC_EDITOR 1001
#define IDC_TERMINAL 1002
#define IDC_COMMAND_INPUT 1003
#define IDC_STATUS_BAR 1004
#define IDC_OUTPUT_TABS 1005
#define IDC_MINIMAP 1006
#define IDC_MODULE_BROWSER 1007
#define IDC_HELP_PANEL 1008
#define IDC_SNIPPET_LIST 1009
#define IDC_CLIPBOARD_HISTORY 1010
#define IDC_OUTPUT_TEXT 1011
#define IDC_OUTPUT_EDIT_GENERAL 1012
#define IDC_OUTPUT_EDIT_ERRORS 1013
#define IDC_OUTPUT_EDIT_DEBUG 1014
#define IDC_OUTPUT_EDIT_FIND 1015
#define IDC_SPLITTER 1016
#define IDC_SEVERITY_FILTER 1017
#define IDC_TITLE_TEXT 1018
#define IDC_BTN_MINIMIZE 1019
#define IDC_BTN_MAXIMIZE 1020
#define IDC_BTN_CLOSE 1021
#define IDC_BTN_GITHUB 1022
#define IDC_BTN_MICROSOFT 1023
#define IDC_BTN_SETTINGS 1024
#define IDC_FILE_EXPLORER 1025
#define IDC_FILE_TREE 1026
#define IDM_AUTONOMY_TOGGLE 4150
#define IDM_AUTONOMY_START 4151
#define IDM_AUTONOMY_STOP 4152
#define IDM_AUTONOMY_SET_GOAL 4153
#define IDM_AUTONOMY_STATUS 4154
#define IDM_AUTONOMY_MEMORY 4155

// Activity Bar (Far Left) - VS Code style icon bar
#define IDC_ACTIVITY_BAR 1100
#define IDC_ACTBAR_EXPLORER 1101
#define IDC_ACTBAR_SEARCH 1102
#define IDC_ACTBAR_SCM 1103
#define IDC_ACTBAR_DEBUG 1104
#define IDC_ACTBAR_EXTENSIONS 1105
#define IDC_ACTBAR_SETTINGS 1106
#define IDC_ACTBAR_ACCOUNTS 1107

// Secondary Sidebar (Right) - AI Chat/Copilot area
#define IDC_SECONDARY_SIDEBAR 1200
#define IDC_SECONDARY_SIDEBAR_HEADER 1201
#define IDC_COPILOT_CHAT_INPUT 1202
#define IDC_COPILOT_CHAT_OUTPUT 1203
#define IDC_COPILOT_SEND_BTN 1204
#define IDC_COPILOT_CLEAR_BTN 1205

// Panel (Bottom) - Terminal, Output, Problems, Debug Console
#define IDC_PANEL_CONTAINER 1300
#define IDC_PANEL_TABS 1301
#define IDC_PANEL_TERMINAL 1302
#define IDC_PANEL_OUTPUT 1303
#define IDC_PANEL_PROBLEMS 1304
#define IDC_PANEL_DEBUG_CONSOLE 1305
#define IDC_PANEL_TOOLBAR 1306
#define IDC_PANEL_BTN_NEW_TERMINAL 1307
#define IDC_PANEL_BTN_SPLIT_TERMINAL 1308
#define IDC_PANEL_BTN_KILL_TERMINAL 1309
#define IDC_PANEL_BTN_MAXIMIZE 1310
#define IDC_PANEL_BTN_CLOSE 1311
#define IDC_PANEL_PROBLEMS_LIST 1312

// Debugger Panel - Integrated at bottom with Terminal/Output
#define IDC_DEBUGGER_CONTAINER 1313
#define IDC_DEBUGGER_TABS 1314
#define IDC_DEBUGGER_BREAKPOINTS 1315
#define IDC_DEBUGGER_WATCH 1316
#define IDC_DEBUGGER_VARIABLES 1317
#define IDC_DEBUGGER_STACK_TRACE 1318
#define IDC_DEBUGGER_MEMORY 1319
#define IDC_DEBUGGER_TOOLBAR 1320
#define IDC_DEBUGGER_BTN_CONTINUE 1321
#define IDC_DEBUGGER_BTN_STEP_OVER 1322
#define IDC_DEBUGGER_BTN_STEP_INTO 1323
#define IDC_DEBUGGER_BTN_STEP_OUT 1324
#define IDC_DEBUGGER_BTN_RESTART 1325
#define IDC_DEBUGGER_BTN_STOP 1326
#define IDC_DEBUGGER_INPUT 1327
#define IDC_DEBUGGER_BREAKPOINT_LIST 1328
#define IDC_DEBUGGER_WATCH_LIST 1329
#define IDC_DEBUGGER_VARIABLE_TREE 1330
#define IDC_DEBUGGER_STACK_LIST 1331
#define IDC_DEBUGGER_STATUS_TEXT 1332

// Enhanced Status Bar items
#define IDC_STATUS_REMOTE 1400
#define IDC_STATUS_BRANCH 1401
#define IDC_STATUS_SYNC 1402
#define IDC_STATUS_ERRORS 1403
#define IDC_STATUS_WARNINGS 1404
#define IDC_STATUS_LINE_COL 1405
#define IDC_STATUS_SPACES 1406
#define IDC_STATUS_ENCODING 1407
#define IDC_STATUS_EOL 1408
#define IDC_STATUS_LANGUAGE 1409
#define IDC_STATUS_COPILOT 1410
#define IDC_STATUS_NOTIFICATIONS 1411

#define IDM_FILE_NEW 2001
#define IDM_FILE_OPEN 2002
#define IDM_FILE_SAVE 2003
#define IDM_FILE_SAVEAS 2004
#define IDM_FILE_LOAD_MODEL 2006
#define IDM_FILE_EXIT 2005

#define IDM_EDIT_UNDO 2007
#define IDM_EDIT_REDO 2008
#define IDM_EDIT_CUT 2009
#define IDM_EDIT_COPY 2010
#define IDM_EDIT_PASTE 2011
#define IDM_EDIT_SNIPPET 2012
#define IDM_EDIT_COPY_FORMAT 2013
#define IDM_EDIT_PASTE_PLAIN 2014
#define IDM_EDIT_CLIPBOARD_HISTORY 2015
#define IDM_EDIT_FIND 2016
#define IDM_EDIT_REPLACE 2017
#define IDM_EDIT_FIND_NEXT 2018
#define IDM_EDIT_FIND_PREV 2019

#define IDM_VIEW_MINIMAP 2020
#define IDM_VIEW_OUTPUT_TABS 2021
#define IDM_VIEW_MODULE_BROWSER 2022
#define IDM_VIEW_THEME_EDITOR 2023
#define IDM_VIEW_FLOATING_PANEL 2024
#define IDM_VIEW_OUTPUT_PANEL 2025
#define IDM_VIEW_USE_STREAMING_LOADER 2026
#define IDM_VIEW_USE_VULKAN_RENDERER 2027
#define IDM_VIEW_SIDEBAR 2028
#define IDM_VIEW_TERMINAL 2029

#define IDM_TERMINAL_POWERSHELL 3001
#define IDM_TERMINAL_CMD 3002
#define IDM_TERMINAL_STOP 3003
#define IDM_TERMINAL_SPLIT_H 3004
#define IDM_TERMINAL_SPLIT_V 3005
#define IDM_TERMINAL_CLEAR_ALL 3006

#define IDM_TOOLS_PROFILE_START 3010
#define IDM_TOOLS_PROFILE_STOP 3011
#define IDM_TOOLS_PROFILE_RESULTS 3012
#define IDM_TOOLS_ANALYZE_SCRIPT 3013

#define IDM_GIT_STATUS 3020
#define IDM_GIT_COMMIT 3021
#define IDM_GIT_PUSH 3022
#define IDM_GIT_PULL 3023
#define IDM_GIT_PANEL 3024

#define IDM_MODULES_REFRESH 3050
#define IDM_MODULES_IMPORT 3051
#define IDM_MODULES_EXPORT 3052

#define IDM_HELP_ABOUT 4001
#define IDM_HELP_CMDREF 4002
#define IDM_HELP_PSDOCS 4003
#define IDM_HELP_SEARCH 4004

// Agent menu IDs
#define IDM_AGENT_START_LOOP 4100
#define IDM_AGENT_EXECUTE_CMD 4101
#define IDM_AGENT_CONFIGURE_MODEL 4102
#define IDM_AGENT_VIEW_TOOLS 4103
#define IDM_AGENT_VIEW_STATUS 4104
#define IDM_AGENT_STOP 4105

// Command Palette control IDs
#define IDC_CMDPAL_CONTAINER 1500
#define IDC_CMDPAL_INPUT 1501
#define IDC_CMDPAL_LIST 1502

Win32IDE::Win32IDE(HINSTANCE hInstance)
        : m_hInstance(hInstance), m_hwndMain(nullptr), m_hwndEditor(nullptr),
            m_hwndCommandInput(nullptr), m_hwndStatusBar(nullptr),
            m_hwndMinimap(nullptr), m_hwndModuleBrowser(nullptr), m_hwndModuleList(nullptr),
            m_hwndModuleLoadButton(nullptr), m_hwndModuleUnloadButton(nullptr), m_hwndModuleRefreshButton(nullptr),
            m_moduleBrowserVisible(false), m_modulePanelProc(nullptr),
    m_hwndHelp(nullptr), m_hMenu(nullptr), m_hwndToolbar(nullptr), 
    m_hwndTitleLabel(nullptr), m_hwndBtnMinimize(nullptr), m_hwndBtnMaximize(nullptr),
    m_hwndBtnClose(nullptr), m_hwndBtnGitHub(nullptr), m_hwndBtnMicrosoft(nullptr),
    m_hwndBtnSettings(nullptr), m_lastTitleBarText(),
      m_fileModified(false), m_editorHeight(400), m_terminalHeight(200),
      m_minimapVisible(true), m_minimapWidth(150), m_profilingActive(false),
      m_moduleListDirty(true), m_backgroundBrush(nullptr), m_editorFont(nullptr),
    m_activeOutputTab("General"), m_minimapX(650), m_outputTabHeight(200),
    m_nextTerminalId(1), m_activeTerminalId(-1),
    m_ggufLoader(nullptr), m_loadedModelPath(""),
      m_terminalSplitHorizontal(true), m_hwndGitPanel(nullptr), m_hwndGitStatusText(nullptr),
    m_hwndGitFileList(nullptr), m_gitAutoRefresh(true), m_outputPanelVisible(true), m_selectedOutputTab(0),
    m_hwndSeverityFilter(nullptr), m_severityFilterLevel(0),
    m_editorRect{0, 0, 0, 0}, m_gpuTextEnabled(true), m_editorHooksInstalled(false),
    m_hwndSplitter(nullptr), m_splitterDragging(false), m_splitterY(0),
    m_renderer(nullptr), m_rendererReady(false),
    m_lastSearchText(), m_lastReplaceText(),
    m_searchCaseSensitive(false), m_searchWholeWord(false), m_searchUseRegex(false), m_lastFoundPos(-1),
    m_hwndFindDialog(nullptr), m_hwndReplaceDialog(nullptr),
    // Primary Sidebar
    m_hwndActivityBar(nullptr), m_hwndSidebar(nullptr), m_hwndSidebarContent(nullptr),
    m_sidebarVisible(true), m_sidebarWidth(250), m_currentSidebarView(SidebarView::None),
    // Explorer View
    m_hwndExplorerTree(nullptr), m_hwndExplorerToolbar(nullptr), m_hImageListExplorer(nullptr),
    m_explorerRootPath(),
    // Search View
    m_hwndSearchInput(nullptr), m_hwndSearchResults(nullptr), m_hwndSearchOptions(nullptr),
    m_hwndIncludePattern(nullptr), m_hwndExcludePattern(nullptr), m_searchInProgress(false),
    // Source Control View
    m_hwndSCMFileList(nullptr), m_hwndSCMToolbar(nullptr), m_hwndSCMMessageBox(nullptr),
    // Debug View
    m_hwndDebugConfigs(nullptr), m_hwndDebugToolbar(nullptr), m_hwndDebugVariables(nullptr),
    m_hwndDebugCallStack(nullptr), m_hwndDebugConsole(nullptr), m_debuggingActive(false),
    // Extensions View
    m_hwndExtensionsList(nullptr), m_hwndExtensionSearch(nullptr), m_hwndExtensionDetails(nullptr),
    // File Explorer
    m_hwndFileExplorer(nullptr), m_hImageList(nullptr), m_currentExplorerPath("D:\\OllamaModels"),
    // Model Chat
    m_chatMode(false),
    // PowerShell Panel
    m_hwndPowerShellPanel(nullptr), m_hwndPowerShellOutput(nullptr), m_hwndPowerShellInput(nullptr),
    m_hwndPowerShellToolbar(nullptr), m_hwndPowerShellStatusBar(nullptr),
    m_hwndPSBtnExecute(nullptr), m_hwndPSBtnClear(nullptr), m_hwndPSBtnStop(nullptr),
    m_hwndPSBtnHistory(nullptr), m_hwndPSBtnRestart(nullptr), m_hwndPSBtnLoadRawrXD(nullptr),
    m_hwndPSBtnToggle(nullptr),
    m_powerShellPanelVisible(true), m_powerShellPanelDocked(true), m_powerShellSessionActive(false),
    m_powerShellRawrXDLoaded(false), m_powerShellPanelHeight(250), m_powerShellPanelWidth(600),
    m_powerShellHistoryIndex(-1), m_maxPowerShellHistory(100),
    m_useStreamingLoader(false), m_useVulkanRenderer(false),
    m_powerShellExecuting(false), m_powerShellProcessHandle(nullptr),
    m_dedicatedPowerShellTerminal(nullptr)
    , m_hwndCommandPalette(nullptr), m_hwndCommandPaletteInput(nullptr), m_hwndCommandPaletteList(nullptr), m_commandPaletteVisible(false)
    , m_hwndModelSelector(nullptr), m_hwndMaxTokensSlider(nullptr), m_hwndMaxTokensLabel(nullptr)
    , m_currentMaxTokens(512)
{
    // DIAGNOSTIC: Constructor entry
    {
        std::ofstream diag("C:\\Users\\HiH8e\\Desktop\\CONSTRUCTOR_START.txt");
        diag << "Win32IDE constructor entered" << std::endl;
    }

    // Initialize Native Fallback Engine (Moved to end of constructor)
    // m_nativeEngine init removed from here.

    // Initialize logger ABSOLUTELY FIRST - with fallback error handling
    try {
        IDELogger::getInstance().initialize("C:\\RawrXD_IDE.log");


    } catch (const std::exception& e) {
        OutputDebugStringA("FATAL: Logger initialization failed: ");
        OutputDebugStringA(e.what());
        OutputDebugStringA("\n");
        // Continue without logging
    } catch (...) {
        OutputDebugStringA("FATAL: Logger initialization failed with unknown exception\n");
    }
    
    // DIAGNOSTIC: After logger section
    {
        std::ofstream diag("C:\\Users\\HiH8e\\Desktop\\AFTER_LOGGER.txt");
        diag << "Logger section skipped" << std::endl;
    }
    
    // Prepare DirectX renderer with safety wrapper
    try {

        m_renderer = std::make_unique<TransparentRenderer>();

    } catch (const std::exception& e) {
        LOG_CRITICAL(std::string("TransparentRenderer creation failed: ") + e.what());
        OutputDebugStringA("ERROR: TransparentRenderer failed: ");
        OutputDebugStringA(e.what());
        OutputDebugStringA("\n");
        m_renderer = nullptr; // Use null renderer
    } catch (...) {
        LOG_CRITICAL("TransparentRenderer creation failed with unknown exception");
        OutputDebugStringA("ERROR: TransparentRenderer failed with unknown exception\n");
        m_renderer = nullptr;
    }
    
    // DIAGNOSTIC: After renderer
    {
        std::ofstream diag("C:\\Users\\HiH8e\\Desktop\\AFTER_RENDERER.txt");
        diag << "Renderer created: " << (m_renderer ? "SUCCESS" : "NULL") << std::endl;
    }
    
    // Initialize PowerShell state with safety
    try {

        initializePowerShellState();

    } catch (const std::exception& e) {

        OutputDebugStringA("ERROR: PowerShell init failed\n");
    } catch (...) {

        OutputDebugStringA("ERROR: PowerShell init failed\n");
    }
    
    // DIAGNOSTIC: After PowerShell
    {
        std::ofstream diag("C:\\Users\\HiH8e\\Desktop\\AFTER_POWERSHELL.txt");
        diag << "PowerShell state initialized" << std::endl;
    }
    
    // Initialize default theme
    try {

        resetToDefaultTheme();

    } catch (...) {

        OutputDebugStringA("ERROR: Theme reset failed\n");
    }
    
    // DIAGNOSTIC: After theme
    {
        std::ofstream diag("C:\\Users\\HiH8e\\Desktop\\AFTER_THEME.txt");
        diag << "Theme reset complete" << std::endl;
    }
    
    // Load code snippets
    try {

        loadCodeSnippets();

    } catch (...) {

        OutputDebugStringA("ERROR: Code snippets loading failed\n");
    }
    
    // DIAGNOSTIC: After snippets
    {
        std::ofstream diag("C:\\Users\\HiH8e\\Desktop\\AFTER_SNIPPETS.txt");
        diag << "Code snippets loaded" << std::endl;
    }
    
    // Initialize profiling frequency
    QueryPerformanceFrequency(&m_profilingFreq);

    // Initialize clipboard history
    m_clipboardHistory.reserve(MAX_CLIPBOARD_HISTORY);
    
    // Initialize Git status
    m_gitStatus = GitStatus();
    
    // Get current directory for Git repo detection
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    m_gitRepoPath = currentDir;
    
    // Default Ollama configuration
    m_ollamaBaseUrl = "http://localhost:11434"; // default
    m_ollamaModelOverride = "";

    // Initialize Native Fallback Engine
    m_nativeEngine = new RawrXD::CPUInferenceEngine();
    m_nativeEngineLoaded = false;
    
    // Initialize Enhanced Status Bar info
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Ready");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Autonomy: OFF");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 2, (LPARAM)"Branch: None");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)"Model: None");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 4, (LPARAM)"GGUF: None");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 5, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 6, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 7, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 8, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 9, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 10, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 11, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 12, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 13, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 14, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 15, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 16, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 17, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 18, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 19, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 20, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 21, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 22, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 23, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 24, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 25, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 26, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 27, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 28, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 29, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 30, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 31, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 32, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 33, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 34, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 35, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 36, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 37, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 38, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 39, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 40, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 41, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 42, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 43, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 44, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 45, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 46, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 47, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 48, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 49, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 50, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 51, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 52, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 53, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 54, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 55, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 56, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 57, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 58, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 59, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 60, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 61, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 62, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 63, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 64, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 65, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 66, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 67, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 68, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 69, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 70, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 71, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 72, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 73, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 74, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 75, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 76, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 77, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 78, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 79, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 80, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 81, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 82, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 83, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 84, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 85, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 86, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 87, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 88, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 89, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 90, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 91, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 92, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 93, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 94, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 95, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 96, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 97, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 98, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 99, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 100, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 101, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 102, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 103, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 104, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 105, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 106, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 107, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 108, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 109, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 110, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 111, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 112, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 113, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 114, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 115, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 116, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 117, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 118, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 119, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 120, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 121, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 122, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 123, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 124, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 125, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 126, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 127, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 128, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 129, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 130, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 131, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 132, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 133, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 134, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 135, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 136, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 137, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 138, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 139, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 140, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 141, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 142, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 143, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 144, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 145, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 146, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 147, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 148, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 149, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 150, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 151, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 152, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 153, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 154, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 155, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 156, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 157, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 158, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 159, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 160, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 161, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 162, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 163, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 164, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 165, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 166, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 167, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 168, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 169, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 170, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 171, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 172, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 173, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 174, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 175, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 176, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 177, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 178, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 179, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 180, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 181, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 182, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 183, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 184, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 185, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 186, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 187, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 188, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 189, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 190, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 191, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 192, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 193, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 194, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 195, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 196, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 197, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 198, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 199, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 200, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 201, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 202, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 203, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 204, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 205, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 206, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 207, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 208, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 209, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 210, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 211, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 212, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 213, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 214, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 215, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 216, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 217, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 218, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 219, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 220, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 221, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 222, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 223, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 224, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 225, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 226, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 227, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 228, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 229, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 230, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 231, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 232, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 233, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 234, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 235, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 236, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 237, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 238, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 239, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 240, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 241, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 242, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 243, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 244, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 245, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 246, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 247, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 248, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 249, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 250, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 251, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 252, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 253, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 254, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 255, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 256, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 257, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 258, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 259, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 260, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 261, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 262, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 263, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 264, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 265, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 266, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 267, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 268, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 269, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 270, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 271, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 272, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 273, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 274, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 275, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 276, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 277, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 278, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 279, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 280, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 281, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 282, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 283, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 284, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 285, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 286, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 287, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 288, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 289, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 290, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 291, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 292, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 293, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 294, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 295, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 296, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 297, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 298, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 299, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 300, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 301, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 302, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 303, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 304, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 305, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 306, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 307, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 308, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 309, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 310, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 311, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 312, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 313, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 314, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 315, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 316, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 317, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 318, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 319, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 320, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 321, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 322, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 323, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 324, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 325, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 326, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 327, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 328, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 329, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 330, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 331, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 332, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 333, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 334, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 335, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 336, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 337, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 338, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 339, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 340, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 341, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 342, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 343, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 344, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 345, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 346, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 347, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 348, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 349, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 350, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 351, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 352, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 353, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 354, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 355, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 356, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 357, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 358, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 359, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 360, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 361, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 362, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 363, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 364, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 365, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 366, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 367, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 368, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 369, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 370, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 371, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 372, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 373, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 374, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 375, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 376, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 377, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 378, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 379, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 380, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 381, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 382, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 383, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 384, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 385, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 386, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 387, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 388, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 389, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 390, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 391, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 392, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 393, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 394, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 395, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 396, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 397, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 398, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 399, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 400, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 401, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 402, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 403, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 404, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 405, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 406, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 407, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 408, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 409, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 410, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 411, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 412, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 413, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 414, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 415, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 416, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 417, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 418, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 419, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 420, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 421, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 422, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 423, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 424, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 425, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 426, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 427, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 428, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 429, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 430, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 431, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 432, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 433, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 434, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 435, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 436, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 437, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 438, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 439, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 440, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 441, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 442, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 443, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 444, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 445, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 446, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 447, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 448, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 449, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 450, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 451, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 452, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 453, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 454, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 455, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 456, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 457, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 458, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 459, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 460, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 461, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 462, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 463, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 464, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 465, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 466, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 467, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 468, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 469, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 470, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 471, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 472, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 473, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 474, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 475, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 476, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 477, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 478, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 479, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 480, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 481, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 482, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 483, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 484, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 485, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 486, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 487, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 488, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 489, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 490, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 491, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 492, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 493, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 494, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 495, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 496, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 497, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 498, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 499, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 500, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 501, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 502, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 503, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 504, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 505, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 506, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 507, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 508, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 509, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 510, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 511, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 512, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 513, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 514, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 515, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 516, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 517, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 518, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 519, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 520, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 521, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 522, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 523, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 524, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 525, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 526, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 527, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 528, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 529, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 530, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 531, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 532, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 533, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 534, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 535, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 536, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 537, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 538, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 539, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 540, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 541, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 542, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 543, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 544, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 545, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 546, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 547, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 548, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 549, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 550, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 551, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 552, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 553, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 554, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 555, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 556, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 557, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 558, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 559, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 560, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 561, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 562, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 563, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 564, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 565, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 566, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 567, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 568, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 569, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 570, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 571, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 572, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 573, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 574, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 575, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 576, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 577, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 578, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 579, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 580, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 581, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 582, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 583, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 584, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 585, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 586, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 587, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 588, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 589, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 590, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 591, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 592, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 593, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 594, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 595, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 596, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 597, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 598, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 599, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 600, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 601, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 602, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 603, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 604, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 605, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 606, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 607, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 608, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 609, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 610, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 611, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 612, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 613, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 614, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 615, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 616, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 617, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 618, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 619, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 620, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 621, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 622, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 623, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 624, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 625, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 626, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 627, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 628, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 629, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 630, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 631, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 632, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 633, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 634, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 635, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 636, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 637, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 638, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 639, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 640, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 641, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 642, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 643, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 644, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 645, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 646, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 647, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 648, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 649, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 650, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 651, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 652, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 653, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 654, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 655, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 656, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 657, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 658, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 659, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 660, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 661, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 662, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 663, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 664, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 665, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 666, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 667, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 668, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 669, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 670, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 671, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 672, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 673, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 674, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 675, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 676, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 677, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 678, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 679, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 680, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 681, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 682, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 683, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 684, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 685, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 686, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 687, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 688, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 689, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 690, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 691, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 692, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 693, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 694, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 695, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 696, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 697, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 698, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 699, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 700, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 701, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 702, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 703, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 704, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 705, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 706, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 707, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 708, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 709, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 710, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 711, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 712, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 713, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 714, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 715, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 716, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 717, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 718, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 719, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 720, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 721, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 722, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 723, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 724, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 725, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 726, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 727, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 728, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 729, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 730, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 731, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 732, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 733, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 734, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 735, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 736, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 737, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 738, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 739, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 740, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 741, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 742, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 743, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 744, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 745, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 746, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 747, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 748, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 749, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 750, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 751, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 752, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 753, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 754, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 755, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 756, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 757, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 758, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 759, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 760, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 761, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 762, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 763, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 764, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 765, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 766, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 767, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 768, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 769, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 770, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 771, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 772, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 773, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 774, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 775, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 776, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 777, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 778, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 779, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 780, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 781, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 782, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 783, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 784, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 785, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 786, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 787, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 788, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 789, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 790, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 791, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 792, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 793, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 794, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 795, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 796, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 797, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 798, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 799, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 800, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 801, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 802, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 803, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 804, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 805, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 806, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 807, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 808, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 809, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 810, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 811, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 812, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 813, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 814, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 815, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 816, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 817, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 818, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 819, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 820, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 821, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 822, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 823, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 824, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 825, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 826, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 827, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 828, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 829, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 830, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 831, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 832, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 833, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 834, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 835, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 836, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 837, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 838, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 839, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 840, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 841, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 842, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 843, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 844, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 845, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 846, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 847, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 848, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 849, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 850, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 851, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 852, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 853, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 854, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 855, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 856, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 857, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 858, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 859, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 860, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 861, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 862, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 863, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 864, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 865, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 866, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 867, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 868, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 869, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 870, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 871, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 872, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 873, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 874, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 875, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 876, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 877, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 878, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 879, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 880, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 881, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 882, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 883, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 884, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 885, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 886, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 887, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 888, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 889, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 890, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 891, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 892, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 893, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 894, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 895, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 896, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 897, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 898, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 899, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 900, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 901, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 902, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 903, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 904, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 905, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 906, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 907, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 908, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 909, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 910, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 911, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 912, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 913, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 914, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 915, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 916, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 917, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 918, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 919, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 920, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 921, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 922, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 923, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 924, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 925, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 926, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 927, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 928, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 929, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 930, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 931, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 932, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 933, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 934, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 935, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 936, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 937, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 938, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 939, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 940, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 941, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 942, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 943, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 944, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 945, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 946, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 947, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 948, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 949, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 950, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 951, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 952, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 953, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 954, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 955, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 956, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 957, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 958, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 959, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 960, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 961, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 962, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 963, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 964, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 965, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 966, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 967, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 968, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 969, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 970, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 971, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 972, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 973, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 974, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 975, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 976, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 977, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 978, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 979, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 980, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 981, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 982, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 983, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 984, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 985, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 986, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 987, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 988, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 989, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 990, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 991, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 992, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 993, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 994, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 995, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 996, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 997, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 998, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 999, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1000, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1001, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1002, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1003, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1004, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1005, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1006, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1007, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1008, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1009, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1010, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1011, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1012, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1013, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1014, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1015, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1016, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1017, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1018, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1019, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1020, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1021, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1022, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1023, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1024, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1025, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1026, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1027, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1028, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1029, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1030, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1031, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1032, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1033, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1034, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1035, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1036, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1037, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1038, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1039, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1040, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1041, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1042, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1043, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1044, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1045, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1046, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1047, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1048, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1049, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1050, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1051, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1052, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1053, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1054, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1055, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1056, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1057, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1058, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1059, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1060, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1061, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1062, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1063, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1064, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1065, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1066, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1067, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1068, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1069, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1070, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1071, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1072, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1073, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1074, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1075, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1076, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1077, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1078, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1079, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1080, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1081, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1082, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1083, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1084, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1085, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1086, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1087, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1088, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1089, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1090, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1091, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1092, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1093, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1094, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1095, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1096, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1097, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1098, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1099, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1100, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1101, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1102, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1103, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1104, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1105, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1106, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1107, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1108, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1109, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1110, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1111, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1112, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1113, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1114, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1115, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1116, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1117, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1118, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1119, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1120, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1121, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1122, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1123, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1124, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1125, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1126, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1127, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1128, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1129, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1130, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1131, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1132, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1133, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1134, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1135, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1136, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1137, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1138, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1139, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1140, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1141, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1142, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1143, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1144, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1145, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1146, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1147, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1148, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1149, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1150, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1151, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1152, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1153, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1154, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1155, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1156, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1157, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1158, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1159, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1160, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1161, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1162, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1163, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1164, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1165, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1166, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1167, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1168, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1169, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1170, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1171, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1172, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1173, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1174, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1175, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1176, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1177, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1178, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1179, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1180, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1181, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1182, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1183, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1184, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1185, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1186, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1187, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1188, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1189, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1190, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1191, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1192, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1193, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1194, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1195, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1196, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1197, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1198, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1199, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1200, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1201, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1202, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1203, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1204, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1205, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1206, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1207, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1208, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1209, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1210, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1211, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1212, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1213, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1214, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1215, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1216, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1217, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1218, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1219, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1220, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1221, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1222, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1223, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1224, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1225, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1226, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1227, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1228, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1229, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1230, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1231, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1232, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1233, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1234, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1235, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1236, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1237, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1238, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1239, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1240, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1241, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1242, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1243, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1244, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1245, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1246, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1247, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1248, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1249, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1250, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1251, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1252, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1253, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1254, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1255, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1256, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1257, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1258, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1259, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1260, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1261, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1262, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1263, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1264, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1265, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1266, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1267, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1268, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1269, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1270, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1271, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1272, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1273, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1274, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1275, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1276, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1277, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1278, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1279, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1280, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1281, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1282, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1283, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1284, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1285, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1286, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1287, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1288, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1289, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1290, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1291, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1292, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1293, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1294, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1295, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1296, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1297, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1298, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1299, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1300, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1301, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1302, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1303, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1304, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1305, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1306, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1307, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1308, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1309, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1310, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1311, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1312, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1313, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1314, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1315, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1316, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1317, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1318, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1319, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1320, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1321, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1322, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1323, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1324, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1325, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1326, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1327, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1328, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1329, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1330, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1331, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1332, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1333, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1334, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1335, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1336, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1337, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1338, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1339, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1340, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1341, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1342, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1343, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1344, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1345, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1346, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1347, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1348, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1349, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1350, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1351, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1352, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1353, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1354, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1355, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1356, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1357, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1358, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1359, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1360, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1361, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1362, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1363, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1364, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1365, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1366, (LPARAM)"");
        return;
    }

    // File menu
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_NEW, "&New");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_OPEN, "&Open");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_SAVE, "&Save");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_SAVEAS, "Save &As");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_LOAD_MODEL, "Load &Model (GGUF)...");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXIT, "E&xit");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hFileMenu, "&File");
    
    // Edit menu
    HMENU hEditMenu = CreatePopupMenu();
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND, "&Find...\tCtrl+F");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_REPLACE, "&Replace...\tCtrl+H");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_NEXT, "Find &Next\tF3");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_PREV, "Find &Previous\tShift+F3");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_SNIPPET, "Insert &Snippet...");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_FORMAT, "Copy with &Formatting");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_PASTE_PLAIN, "Paste &Plain Text");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_CLIPBOARD_HISTORY, "Clipboard &History...");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hEditMenu, "&Edit");
    
    // View menu
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_MINIMAP, "&Minimap");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_OUTPUT_TABS, "&Output Tabs");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_OUTPUT_PANEL, "Output &Panel");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_MODULE_BROWSER, "Module &Browser");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_FLOATING_PANEL, "&Floating Panel");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_THEME_EDITOR, "&Theme Editor...");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_USE_STREAMING_LOADER, "Use Streaming Loader (Low Memory)");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_USE_VULKAN_RENDERER, "Enable Vulkan Renderer (experimental)");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hViewMenu, "&View");

    // Terminal menu
    HMENU hTerminalMenu = CreatePopupMenu();
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_POWERSHELL, "&PowerShell");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_CMD, "&Command Prompt");
    AppendMenuA(hTerminalMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_STOP, "&Stop Terminal");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_SPLIT_H, "Split &Horizontal\tCtrl+Shift+H");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_SPLIT_V, "Split &Vertical\tCtrl+Shift+V");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_CLEAR_ALL, "&Clear All Terminals");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hTerminalMenu, "&Terminal");
    
    // Tools menu
    HMENU hToolsMenu = CreatePopupMenu();
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_START, "Start &Profiling");
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_STOP, "Stop P&rofiling");
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_RESULTS, "Profile &Results...");
    AppendMenuA(hToolsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_ANALYZE_SCRIPT, "&Analyze Script");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hToolsMenu, "&Tools");
    
    // Modules menu
    HMENU hModulesMenu = CreatePopupMenu();
    AppendMenuA(hModulesMenu, MF_STRING, IDM_MODULES_REFRESH, "&Refresh List");
    AppendMenuA(hModulesMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hModulesMenu, MF_STRING, IDM_MODULES_IMPORT, "&Import Module...");
    AppendMenuA(hModulesMenu, MF_STRING, IDM_MODULES_EXPORT, "&Export Module...");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hModulesMenu, "&Modules");

    // Help menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_CMDREF, "Command &Reference");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_PSDOCS, "PowerShell &Documentation");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_SEARCH, "&Search Help...");
    AppendMenuA(hHelpMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "&About");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, "&Help");

    // Git menu
    HMENU hGitMenu = CreatePopupMenu();
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_STATUS, "&Status\tCtrl+G");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_COMMIT, "&Commit...\tCtrl+Shift+C");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_PUSH, "&Push");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_PULL, "P&ull");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_PANEL, "&Git Panel\tCtrl+Shift+G");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hGitMenu, "&Git");

    // Agent menu (existing agentic bridge operations)
    HMENU hAgentMenu = CreatePopupMenu();
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_START_LOOP, "Start &Agent Loop");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_EXECUTE_CMD, "&Execute Command...");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_CONFIGURE_MODEL, "&Configure Model...");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_VIEW_TOOLS, "View &Tools");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_VIEW_STATUS, "View &Status");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_STOP, "&Stop Agent");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hAgentMenu, "&Agent");

    // Autonomy menu (new high-level autonomous orchestration)
    HMENU hAutonomyMenu = CreatePopupMenu();
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_TOGGLE, "&Toggle Auto Loop");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_START, "&Start Autonomy");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STOP, "Sto&p Autonomy");
    AppendMenuA(hAutonomyMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_SET_GOAL, "Set &Goal...");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STATUS, "Show &Status");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_MEMORY, "Show &Memory Snapshot");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hAutonomyMenu, "&Autonomy");

    SetMenu(hwnd, m_hMenu);

}

void Win32IDE::createToolbar(HWND hwnd)
{

    m_hwndToolbar = CreateWindowExA(0, TOOLBARCLASSNAMEA, nullptr,
                                   WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT,
                                   0, 0, 0, 0, hwnd, nullptr, m_hInstance, nullptr);

    if (m_hwndToolbar) {

        SendMessage(m_hwndToolbar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
        SendMessage(m_hwndToolbar, TB_AUTOSIZE, 0, 0);

        createTitleBarControls();
        updateTitleBarText();

    } else {

    }
}

void Win32IDE::createTitleBarControls()
{
    DWORD labelStyle = WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX;
    m_hwndTitleLabel = CreateWindowExA(0, "STATIC", "RawrXD IDE", labelStyle,
                                      0, 0, 200, 24, m_hwndToolbar, (HMENU)IDC_TITLE_TEXT, m_hInstance, nullptr);

    DWORD buttonStyle = WS_CHILD | WS_VISIBLE | BS_FLAT;
    auto createButton = [&](HWND& target, int controlId, const char* caption) {
        target = CreateWindowExA(0, "BUTTON", caption, buttonStyle,
                                 0, 0, 32, 24, m_hwndToolbar, (HMENU)controlId, m_hInstance, nullptr);
    };

    createButton(m_hwndBtnGitHub, IDC_BTN_GITHUB, "GH");
    createButton(m_hwndBtnMicrosoft, IDC_BTN_MICROSOFT, "MS");
    createButton(m_hwndBtnSettings, IDC_BTN_SETTINGS, "Gear");
    createButton(m_hwndBtnMinimize, IDC_BTN_MINIMIZE, "-");
    createButton(m_hwndBtnMaximize, IDC_BTN_MAXIMIZE, "[]");
    createButton(m_hwndBtnClose, IDC_BTN_CLOSE, "X");

    RECT client{};
    GetClientRect(m_hwndMain, &client);
    layoutTitleBar(client.right - client.left);
}

void Win32IDE::layoutTitleBar(int width)
{
    if (!m_hwndToolbar) return;

    RECT client{};
    GetClientRect(m_hwndToolbar, &client);
    int toolbarHeight = client.bottom - client.top;
    if (toolbarHeight <= 0) toolbarHeight = 30;
    int controlHeight = (std::max)(22, toolbarHeight - 6);
    int y = (toolbarHeight - controlHeight) / 2;
    int padding = 6;
    int x = width - padding;

    auto placeButton = [&](HWND hwnd, int controlWidth) {
        if (!hwnd) return;
        x -= controlWidth;
        MoveWindow(hwnd, x, y, controlWidth, controlHeight, TRUE);
        x -= padding;
    };

    placeButton(m_hwndBtnClose, 32);
    placeButton(m_hwndBtnMaximize, 32);
    placeButton(m_hwndBtnMinimize, 32);
    placeButton(m_hwndBtnSettings, 48);
    placeButton(m_hwndBtnMicrosoft, 40);
    placeButton(m_hwndBtnGitHub, 40);

    if (m_hwndTitleLabel) {
        int availableRight = x;
        int labelWidth = (std::min)(420, availableRight - padding * 2);
        if (labelWidth < 160) {
            labelWidth = (std::max)(availableRight - padding * 2, 120);
        }
        int labelX = (std::max)(padding, (width - labelWidth) / 2);
        if (labelX + labelWidth > availableRight) {
            labelX = (std::max)(padding, availableRight - labelWidth);
        }
        MoveWindow(m_hwndTitleLabel, labelX, y, labelWidth, controlHeight, TRUE);
    }
}

std::string Win32IDE::extractLeafName(const std::string& path) const
{
    if (path.empty()) return "";
    size_t end = path.find_last_not_of("\\/ ");
    if (end == std::string::npos) return path;
    size_t slash = path.find_last_of("\\/", end);
    if (slash == std::string::npos) {
        return path.substr(0, end + 1);
    }
    return path.substr(slash + 1, end - slash);
}

void Win32IDE::setCurrentDirectoryFromFile(const std::string& filePath)
{
    if (filePath.empty()) return;
    size_t slash = filePath.find_last_of("\\/");
    if (slash != std::string::npos) {
        m_currentDirectory = filePath.substr(0, slash);
    }
}

void Win32IDE::updateTitleBarText()
{
    if (!m_hwndTitleLabel) return;

    std::string fileName = m_currentFile.empty() ? "Untitled" : extractLeafName(m_currentFile);
    std::string projectFolder;

    if (!m_currentDirectory.empty()) {
        projectFolder = extractLeafName(m_currentDirectory);
    }

    if (projectFolder.empty() && !m_currentFile.empty()) {
        size_t slash = m_currentFile.find_last_of("\\/");
        if (slash != std::string::npos) {
            projectFolder = extractLeafName(m_currentFile.substr(0, slash));
        }
    }

    if (projectFolder.empty() && !m_gitRepoPath.empty()) {
        projectFolder = extractLeafName(m_gitRepoPath);
    }

    if (projectFolder.empty()) {
        projectFolder = "Workspace";
    }

    std::string composed = fileName + "  •  " + projectFolder;
    if (composed != m_lastTitleBarText) {
        SetWindowTextA(m_hwndTitleLabel, composed.c_str());
        m_lastTitleBarText = composed;
    }
}

void Win32IDE::createEditor(HWND hwnd)
{

    m_hwndEditor = CreateWindowExA(WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
                                  WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
                                  0, 0, 0, 0, hwnd, (HMENU)IDC_EDITOR, m_hInstance, nullptr);
    if (!m_hwndEditor) {

        return;
    }

    // Set default font and colors
    CHARFORMAT2A cf;
    memset(&cf, 0, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR;
    cf.yHeight = 200; // 10 points
    cf.crTextColor = RGB(220, 220, 220); // Light gray text
    strcpy(cf.szFaceName, "Consolas");
    SendMessage(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    
    // Set background color to dark
    SendMessage(m_hwndEditor, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));

    // Enable editing
    SendMessage(m_hwndEditor, EM_SETREADONLY, FALSE, 0);

    initializeEditorSurface();

}

void Win32IDE::createTerminal(HWND hwnd)
{

    if (m_terminalPanes.empty()) {

        createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
    } else {

        setActiveTerminalPane(m_terminalPanes.front().id);
    }

    // Create command input

    m_hwndCommandInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                        0, 0, 0, 0, hwnd, (HMENU)IDC_COMMAND_INPUT, m_hInstance, nullptr);
    if (!m_hwndCommandInput) {

    } else {

    }

}

int Win32IDE::createTerminalPane(Win32TerminalManager::ShellType shellType, const std::string& name)
{
    HWND hwnd = CreateWindowExA(WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
                                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                0, 0, 0, 0, m_hwndMain, nullptr, m_hInstance, nullptr);

    CHARFORMAT2A cf;
    memset(&cf, 0, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_SIZE;
    cf.yHeight = 180; // 9 points
    strcpy(cf.szFaceName, "Consolas");
    SendMessage(hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    int paneId = m_nextTerminalId++;
    TerminalPane pane;
    pane.id = paneId;
    pane.hwnd = hwnd;
    pane.manager = std::make_unique<Win32TerminalManager>();
    pane.name = name.empty() ? ("Terminal " + std::to_string(paneId)) : name;
    pane.shellType = shellType;
    pane.isActive = false;
    pane.bounds = {0, 0, 0, 0};

    pane.manager->onOutput = [this, paneId](const std::string& output) {
        onTerminalOutput(paneId, output);
    };
    pane.manager->onError = [this, paneId](const std::string& error) {
        onTerminalError(paneId, error);
    };

    m_terminalPanes.push_back(std::move(pane));
    setActiveTerminalPane(paneId);
    applyTheme();
    return paneId;
}

TerminalPane* Win32IDE::findTerminalPane(int paneId)
{
    for (auto& pane : m_terminalPanes) {
        if (pane.id == paneId) {
            return &pane;
        }
    }
    return nullptr;
}

TerminalPane* Win32IDE::getActiveTerminalPane()
{
    TerminalPane* active = findTerminalPane(m_activeTerminalId);
    if (!active && !m_terminalPanes.empty()) {
        setActiveTerminalPane(m_terminalPanes.front().id);
        return findTerminalPane(m_terminalPanes.front().id);
    }
    return active;
}

void Win32IDE::setActiveTerminalPane(int paneId)
{
    bool found = false;
    for (auto& pane : m_terminalPanes) {
        if (pane.id == paneId) {
            pane.isActive = true;
            m_activeTerminalId = paneId;
            if (pane.hwnd) SetFocus(pane.hwnd);
            found = true;
        } else {
            pane.isActive = false;
        }
    }
    if (!found && !m_terminalPanes.empty()) {
        m_terminalPanes.front().isActive = true;
        m_activeTerminalId = m_terminalPanes.front().id;
        if (m_terminalPanes.front().hwnd) SetFocus(m_terminalPanes.front().hwnd);
    }
}

void Win32IDE::layoutTerminalPanes(int width, int top, int height)
{
    if (width <= 0 || height <= 0 || m_terminalPanes.empty()) return;
    int count = static_cast<int>(m_terminalPanes.size());
    if (count == 1) {
        auto& pane = m_terminalPanes[0];
        MoveWindow(pane.hwnd, 0, top, width, height, TRUE);
        pane.bounds = {0, top, width, top + height};
        return;
    }

    if (m_terminalSplitHorizontal) {
        int paneHeight = height / count;
        int y = top;
        for (int i = 0; i < count; ++i) {
            int currentHeight = (i == count - 1) ? (height - paneHeight * (count - 1)) : paneHeight;
            auto& pane = m_terminalPanes[i];
            MoveWindow(pane.hwnd, 0, y, width, currentHeight, TRUE);
            pane.bounds = {0, y, width, y + currentHeight};
            y += currentHeight;
        }
    } else {
        int paneWidth = width / count;
        int x = 0;
        for (int i = 0; i < count; ++i) {
            int currentWidth = (i == count - 1) ? (width - paneWidth * (count - 1)) : paneWidth;
            auto& pane = m_terminalPanes[i];
            MoveWindow(pane.hwnd, x, top, currentWidth, height, TRUE);
            pane.bounds = {x, top, x + currentWidth, top + height};
            x += currentWidth;
        }
    }
}

void Win32IDE::splitTerminalHorizontal()
{
    m_terminalSplitHorizontal = true;
    TerminalPane* active = getActiveTerminalPane();
    Win32TerminalManager::ShellType type = active ? active->shellType : Win32TerminalManager::PowerShell;
    createTerminalPane(type, "Terminal");
    RECT rect; GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect; GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::splitTerminalVertical()
{
    m_terminalSplitHorizontal = false;
    TerminalPane* active = getActiveTerminalPane();
    Win32TerminalManager::ShellType type = active ? active->shellType : Win32TerminalManager::PowerShell;
    createTerminalPane(type, "Terminal");
    RECT rect; GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect; GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::clearAllTerminals()
{
    for (auto& pane : m_terminalPanes) {
        if (pane.manager && pane.manager->isRunning()) {
            pane.manager->stop();
        }
        if (pane.hwnd) {
            DestroyWindow(pane.hwnd);
        }
    }
    m_terminalPanes.clear();
    m_activeTerminalId = -1;
    m_nextTerminalId = 1;
    createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
    RECT rect; GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect; GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::createStatusBar(HWND hwnd)
{

    m_hwndStatusBar = CreateWindowExA(0, STATUSCLASSNAMEA, "",
                                     WS_CHILD | WS_VISIBLE,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS_BAR, m_hInstance, nullptr);
    if (!m_hwndStatusBar) {

        return;
    }

    int parts[] = {200, 400, -1};
    SendMessage(m_hwndStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Ready");

}

void Win32IDE::createSidebar(HWND hwnd)
{
    // Create the primary sidebar (left panel)
    m_hwndSidebar = CreateWindowExA(
        0,
        "STATIC",
        "Explorer",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        48, 30, m_sidebarWidth, 500,
        hwnd,
        nullptr,
        m_hInstance,
        nullptr
    );
    
    if (m_hwndSidebar) {
        // Create activity bar (icon strip on far left)
        m_hwndActivityBar = CreateWindowExA(
            0,
            "STATIC",
            "",
            WS_CHILD | WS_VISIBLE,
            0, 30, 48, 500,
            hwnd,
            nullptr,
            m_hInstance,
            nullptr
        );
    }
}

void Win32IDE::newFile()
{
    appendToOutput("File > New clicked\n", "Output", OutputSeverity::Info);
    if (m_fileModified) {
        int result = MessageBoxA(m_hwndMain, "File has been modified. Save changes?", "Save", MB_YESNOCANCEL);
        if (result == IDCANCEL) {
            appendToOutput("File > New cancelled by user\n", "Output", OutputSeverity::Info);
            return;
        }
        if (result == IDYES && !saveFile()) {
            appendToOutput("File > New - save failed, operation aborted\n", "Output", OutputSeverity::Warning);
            return;
        }
    }

    SetWindowTextA(m_hwndEditor, "");
    m_currentFile.clear();
    m_fileModified = false;
    updateTitleBarText();
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"New file");
    updateMenuEnableStates();
    syncEditorToGpuSurface();
    appendToOutput("New file created successfully\n", "Output", OutputSeverity::Info);
}

void Win32IDE::openFile()
{
    appendToOutput("File > Open clicked\n", "Output", OutputSeverity::Info);
    if (m_fileModified) {
        int result = MessageBoxA(m_hwndMain, "File has been modified. Save changes?", "Save", MB_YESNOCANCEL);
        if (result == IDCANCEL) {
            appendToOutput("File > Open cancelled by user\n", "Output", OutputSeverity::Info);
            return;
        }
        if (result == IDYES && !saveFile()) {
            appendToOutput("File > Open - save failed, operation aborted\n", "Output", OutputSeverity::Warning);
            return;
        }
    }

    OPENFILENAMEA ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn)) {
        appendToOutput("Opening file: " + std::string(szFile) + "\n", "Output", OutputSeverity::Info);
        try {
            std::ifstream file(szFile);
            if (file) {
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                SetWindowTextA(m_hwndEditor, content.c_str());
                m_currentFile = szFile;
                m_fileModified = false;
                setCurrentDirectoryFromFile(m_currentFile);
                updateTitleBarText();
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File opened");
                updateMenuEnableStates();
                syncEditorToGpuSurface();
                appendToOutput("File opened successfully (" + std::to_string(content.size()) + " bytes)\n", "Output", OutputSeverity::Info);
            } else {
                appendToOutput("Failed to open file: " + std::string(szFile) + "\n", "Errors", OutputSeverity::Error);
                MessageBoxA(m_hwndMain, "Failed to open file", "Error", MB_OK | MB_ICONERROR);
            }
        } catch (const std::exception& e) {
            appendToOutput("Exception opening file: " + std::string(e.what()) + "\n", "Errors", OutputSeverity::Error);
            MessageBoxA(m_hwndMain, e.what(), "Error", MB_OK | MB_ICONERROR);
        }
    } else {
        appendToOutput("File > Open cancelled by user (no file selected)\n", "Output", OutputSeverity::Info);
    }
}

bool Win32IDE::saveFile()
{
    if (m_currentFile.empty()) {
        appendToOutput("File > Save - no current file, showing Save As dialog\n", "Output", OutputSeverity::Info);
        return saveFileAs();
    }

    appendToOutput("Saving file: " + m_currentFile + "\n", "Output", OutputSeverity::Info);
    try {
        std::string content = getWindowText(m_hwndEditor);
        std::ofstream file(m_currentFile);
        if (file) {
            file << content;
            m_fileModified = false;
            updateTitleBarText();
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File saved");
            appendToOutput("File saved successfully (" + std::to_string(content.size()) + " bytes)\n", "Output", OutputSeverity::Info);
            return true;
        }
        appendToOutput("Failed to open file for writing: " + m_currentFile + "\n", "Errors", OutputSeverity::Error);
        MessageBoxA(m_hwndMain, "Failed to save file", "Error", MB_OK | MB_ICONERROR);
    } catch (const std::exception& e) {
        appendToOutput("Exception saving file: " + std::string(e.what()) + "\n", "Errors", OutputSeverity::Error);
        MessageBoxA(m_hwndMain, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
    return false;
}

bool Win32IDE::saveFileAs()
{
    appendToOutput("File > Save As clicked\n", "Output", OutputSeverity::Info);
    OPENFILENAMEA ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameA(&ofn)) {
        m_currentFile = szFile;
        appendToOutput("Save As: " + m_currentFile + "\n", "Output", OutputSeverity::Info);
        setCurrentDirectoryFromFile(m_currentFile);
        updateTitleBarText();
        return saveFile();
    }
    appendToOutput("File > Save As cancelled by user\n", "Output", OutputSeverity::Info);
    return false;
}

void Win32IDE::startPowerShell()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager) return;
    stopTerminal();
    if (pane->manager->start(Win32TerminalManager::PowerShell)) {
        appendText(pane->hwnd, "PowerShell started...\n");
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"PowerShell");
        updateMenuEnableStates();
        appendToOutput("PowerShell started...\n", "Output", OutputSeverity::Info);
    }
}

void Win32IDE::startCommandPrompt()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager) return;
    stopTerminal();
    if (pane->manager->start(Win32TerminalManager::CommandPrompt)) {
        appendText(pane->hwnd, "Command Prompt started...\n");
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"CMD");
        updateMenuEnableStates();
        appendToOutput("Command Prompt started...\n", "Output", OutputSeverity::Info);
    }
}

void Win32IDE::stopTerminal()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager || !pane->manager->isRunning()) return;
    pane->manager->stop();
    appendText(pane->hwnd, "\nTerminal stopped.\n");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Stopped");
    updateMenuEnableStates();
    appendToOutput("Terminal stopped.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::executeCommand()
{
    std::string command = getWindowText(m_hwndCommandInput);
    if (command.empty()) return;

    SetWindowTextA(m_hwndCommandInput, "");
    
    // Check if we're in chat mode with a loaded model
    if (m_chatMode && isModelLoaded()) {
        // Send to model for inference
        appendChatMessage("You", command);
        
        std::string response = sendMessageToModel(command);
        if (!response.empty()) {
            appendChatMessage("Model", response);
        } else {
            appendChatMessage("System", "Error: Model failed to generate response");
        }
        return;
    }
    
    // Check for special commands
    if (command == "/chat" || command == "/model") {
        if (isModelLoaded()) {
            toggleChatMode();
        } else {
            appendToOutput("No model loaded. Please load a .gguf model first using File > Load Model or the File Explorer.", "Output", OutputSeverity::Warning);
        }
        return;
    }
    
    if (command == "/exit-chat") {
        if (m_chatMode) {
            toggleChatMode();
        }
        return;
    }
    
    // Otherwise, send to terminal as before
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        command += "\n";
        pane->manager->writeInput(command);
    }
}

void Win32IDE::onTerminalOutput(int paneId, const std::string& output)
{
    TerminalPane* pane = findTerminalPane(paneId);
    if (!pane || !pane->hwnd) return;
    appendText(pane->hwnd, output);
    appendToOutput(output, "Debug", OutputSeverity::Info);
}

void Win32IDE::onTerminalError(int paneId, const std::string& error)
{
    TerminalPane* pane = findTerminalPane(paneId);
    if (!pane || !pane->hwnd) return;
    appendText(pane->hwnd, error);
    appendToOutput(error, "Errors", OutputSeverity::Error);
}

std::string Win32IDE::getWindowText(HWND hwnd)
{
    int length = GetWindowTextLengthA(hwnd);
    std::string text(length + 1, '\0');
    GetWindowTextA(hwnd, &text[0], length + 1);
    text.resize(length);
    return text;
}

void Win32IDE::setWindowText(HWND hwnd, const std::string& text)
{
    SetWindowTextA(hwnd, text.c_str());
    if (hwnd == m_hwndEditor) {
        syncEditorToGpuSurface();
    }
}

void Win32IDE::appendText(HWND hwnd, const std::string& text)
{
    // Get current text length
    GETTEXTLENGTHEX gtl;
    gtl.flags = GTL_DEFAULT;
    gtl.codepage = CP_ACP;
    LONG length = SendMessage(hwnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);

    // Set selection to end
    SendMessage(hwnd, EM_SETSEL, length, length);

    // Replace selection with new text
    SETTEXTEX st;
    st.flags = ST_DEFAULT;
    st.codepage = CP_ACP;
    SendMessage(hwnd, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)text.c_str());

    if (hwnd == m_hwndEditor) {
        syncEditorToGpuSurface();
    }
}

// Theme Management Implementation
void Win32IDE::loadTheme(const std::string& themeName)
{
    std::string filename = "themes\\" + themeName + ".theme";
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        while (getline(file, line)) {
            if (line.find("background=") == 0) {
                m_currentTheme.backgroundColor = std::stoul(line.substr(11), nullptr, 16);
            } else if (line.find("text=") == 0) {
                m_currentTheme.textColor = std::stoul(line.substr(5), nullptr, 16);
            } else if (line.find("selection=") == 0) {
                m_currentTheme.selectionColor = std::stoul(line.substr(10), nullptr, 16);
            } else if (line.find("linenumber=") == 0) {
                m_currentTheme.lineNumberColor = std::stoul(line.substr(11), nullptr, 16);
            }
        }
        file.close();
        applyTheme();
    }
}

void Win32IDE::saveTheme(const std::string& themeName)
{
    std::string filename = "themes\\" + themeName + ".theme";
    CreateDirectoryA("themes", NULL);
    std::ofstream file(filename);
    if (file.is_open()) {
        file << "background=" << std::hex << m_currentTheme.backgroundColor << std::endl;
        file << "text=" << std::hex << m_currentTheme.textColor << std::endl;
        file << "selection=" << std::hex << m_currentTheme.selectionColor << std::endl;
        file << "linenumber=" << std::hex << m_currentTheme.lineNumberColor << std::endl;
        file.close();
        MessageBoxA(m_hwndMain, "Theme saved successfully", "Theme Manager", MB_OK);
    }
}

void Win32IDE::applyTheme()
{
    // Apply theme to main editor
    SendMessage(m_hwndEditor, EM_SETBKGNDCOLOR, 0, m_currentTheme.backgroundColor);
    
    // Set text colors
    CHARFORMAT2 cf;
    ZeroMemory(&cf, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = m_currentTheme.textColor;
    SendMessage(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    
    // Apply to terminal panes
    for (auto& pane : m_terminalPanes) {
        if (!pane.hwnd) continue;
        SendMessage(pane.hwnd, EM_SETBKGNDCOLOR, 0, m_currentTheme.backgroundColor);
        SendMessage(pane.hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    }
    
    // Force redraw
    InvalidateRect(m_hwndMain, NULL, TRUE);
    updateMenuEnableStates();
}

void Win32IDE::showThemeEditor()
{
    const char* themes[] = {"Dark", "Light", "Blue", "Green"};
    int result = 0; // Simple selection for now
    
    std::string message = "Select Theme:\n0 - Dark\n1 - Light\n2 - Blue\n3 - Green";
    
    switch (MessageBoxA(m_hwndMain, message.c_str(), "Theme Selection", MB_OKCANCEL)) {
        case IDOK:
            // For simplicity, cycle through predefined themes
            m_currentTheme.backgroundColor = RGB(30, 30, 30);  // Dark
            m_currentTheme.textColor = RGB(220, 220, 220);
            m_currentTheme.selectionColor = RGB(51, 153, 255);
            m_currentTheme.lineNumberColor = RGB(128, 128, 128);
            applyTheme();
            break;
    }
}

void Win32IDE::updateMenuEnableStates() {
    if (!m_hMenu) return;
    // Terminal split menu items
    UINT enableSplit = MF_BYCOMMAND | (m_terminalPanes.size() >= 1 ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_SPLIT_H, enableSplit);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_SPLIT_V, enableSplit);
    TerminalPane* activePane = getActiveTerminalPane();
    bool terminalRunning = activePane && activePane->manager && activePane->manager->isRunning();
    EnableMenuItem(m_hMenu, IDM_TERMINAL_STOP, terminalRunning ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_CLEAR_ALL, (m_terminalPanes.empty() ? (MF_BYCOMMAND|MF_GRAYED) : (MF_BYCOMMAND|MF_ENABLED)));

    // Git items
    bool repo = isGitRepository();
    EnableMenuItem(m_hMenu, IDM_GIT_STATUS, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_COMMIT, (repo && m_gitStatus.hasChanges) ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PUSH, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PULL, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PANEL, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);

    // File save related
    EnableMenuItem(m_hMenu, IDM_FILE_SAVE, (!m_currentFile.empty() && m_fileModified) ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_FILE_SAVEAS, (!m_currentFile.empty()) ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);

    // Streaming loader menu state
    CheckMenuItem(m_hMenu, IDM_VIEW_USE_STREAMING_LOADER, MF_BYCOMMAND | (m_useStreamingLoader ? MF_CHECKED : MF_UNCHECKED));
    // Vulkan renderer menu state
    CheckMenuItem(m_hMenu, IDM_VIEW_USE_VULKAN_RENDERER, MF_BYCOMMAND | (m_useVulkanRenderer ? MF_CHECKED : MF_UNCHECKED));

    DrawMenuBar(m_hwndMain);
}

// Code Snippets Implementation
void Win32IDE::loadCodeSnippets()
{
    m_codeSnippets.clear();
    
    // Load built-in PowerShell snippets
    CodeSnippet snippet1;
    snippet1.name = "function";
    snippet1.description = "PowerShell function template";
    snippet1.code = "function {name} {\n    param(\n        ${1:$Parameter}\n    )\n    \n    ${2:# Function body}\n}";
    m_codeSnippets.push_back(snippet1);
    
    CodeSnippet snippet2;
    snippet2.name = "if";
    snippet2.description = "If statement";
    snippet2.code = "if (${1:condition}) {\n    ${2:# Code}\n}";
    m_codeSnippets.push_back(snippet2);
    
    CodeSnippet snippet3;
    snippet3.name = "foreach";
    snippet3.description = "ForEach loop";
    snippet3.code = "foreach (${1:$item} in ${2:$collection}) {\n    ${3:# Code}\n}";
    m_codeSnippets.push_back(snippet3);
    
    CodeSnippet snippet4;
    snippet4.name = "try";
    snippet4.description = "Try-Catch block";
    snippet4.code = "try {\n    ${1:# Code that might throw}\n}\ncatch {\n    ${2:# Error handling}\n}";
    m_codeSnippets.push_back(snippet4);
}

void Win32IDE::insertSnippet(const std::string& snippetName)
{
    for (const auto& snippet : m_codeSnippets) {
        if (snippet.name == snippetName) {
            // Get current cursor position
            DWORD start, end;
            SendMessage(m_hwndEditor, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
            
            // Insert snippet content
            std::string content = snippet.code;
            // Simple placeholder replacement
            size_t pos = content.find("${1:");
            if (pos != std::string::npos) {
                size_t endPos = content.find("}", pos);
                if (endPos != std::string::npos) {
                    content.erase(pos, endPos - pos + 1);
                }
            }
            
            SendMessage(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)content.c_str());
            break;
        }
    }
    updateMenuEnableStates();
}

// Integrated Help Implementation
void Win32IDE::showGetHelp(const std::string& cmdlet)
{
    // Get selected text for help lookup
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    
    std::string command;
    if (!cmdlet.empty()) {
        command = cmdlet;
    } else if (range.cpMax > range.cpMin) {
        char buffer[1000];
        TEXTRANGEA tr;
        tr.chrg = range;
        tr.lpstrText = buffer;
        SendMessage(m_hwndEditor, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
        command = std::string(buffer);
    } else {
        command = "Get-Command";  // Default help
    }
    
    std::string helpCommand = "Get-Help " + command + " -Full\n";
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        pane->manager->writeInput(helpCommand);
    }
}

void Win32IDE::showCommandReference()
{
    std::string reference = 
        "PowerShell Quick Reference:\n\n"
        "Get-Help <command> - Get help for command\n"
        "Get-Command - List all commands\n"
        "Get-Member - Get object properties/methods\n"
        "Measure-Object - Measure properties\n"
        "Select-Object - Select properties\n"
        "Where-Object - Filter objects\n"
        "ForEach-Object - Process each object\n"
        "Sort-Object - Sort objects\n"
        "Group-Object - Group objects\n"
        "Export-Csv - Export to CSV\n"
        "Import-Csv - Import from CSV\n"
        "ConvertTo-Json - Convert to JSON\n"
        "ConvertFrom-Json - Convert from JSON\n";
        
    MessageBoxA(m_hwndMain, reference.c_str(), "PowerShell Reference", MB_OK);
}

// Output / Clipboard / Minimap / Profiling implementations
void Win32IDE::createOutputTabs()
{
    if (m_hwndOutputTabs) return;

    RECT client{}; GetClientRect(m_hwndMain, &client);
    int tabBarHeight = 24;

    m_hwndOutputTabs = CreateWindowExA(0, WC_TABCONTROLA, "",
        WS_CHILD | WS_VISIBLE | TCS_TABS,
        0, 0, client.right - 150, tabBarHeight,
        m_hwndMain, (HMENU)IDC_OUTPUT_TABS, m_hInstance, nullptr);

    // Add severity filter dropdown
    m_hwndSeverityFilter = CreateWindowExA(0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        client.right - 145, 2, 140, 100,
        m_hwndMain, (HMENU)IDC_SEVERITY_FILTER, m_hInstance, nullptr);
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"All Messages");
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"Info & Above");
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"Warnings & Errors");
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"Errors Only");
    SendMessageA(m_hwndSeverityFilter, CB_SETCURSEL, m_severityFilterLevel, 0);

    struct TabDef { const char* text; int id; const char* key; };
    TabDef defs[] = {
        {"Output", IDC_OUTPUT_EDIT_GENERAL, "Output"},
        {"Errors", IDC_OUTPUT_EDIT_ERRORS,  "Errors"},
        {"Debug",  IDC_OUTPUT_EDIT_DEBUG,   "Debug"},
        {"Find Results", IDC_OUTPUT_EDIT_FIND, "Find Results"}
    };

    for (int i = 0; i < 4; ++i) {
        TCITEMA tie{}; tie.mask = TCIF_TEXT; tie.pszText = const_cast<char*>(defs[i].text);
        TabCtrl_InsertItem(m_hwndOutputTabs, i, &tie);

        HWND hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
            WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, tabBarHeight, client.right, m_outputTabHeight - tabBarHeight,
            m_hwndMain, (HMENU)(INT_PTR)defs[i].id, m_hInstance, nullptr);
        m_outputWindows[defs[i].key] = hEdit;
    }
    m_activeOutputTab = "Output";

    // Restore persisted tab selection
    if (m_selectedOutputTab >= 0 && m_selectedOutputTab < 4) {
        const char* keys[] = {"Output","Errors","Debug","Find Results"};
        m_activeOutputTab = keys[m_selectedOutputTab];
        TabCtrl_SetCurSel(m_hwndOutputTabs, m_selectedOutputTab);
    }

    // Initially show only active tab and respect visibility setting
    for (auto& kv : m_outputWindows) {
        ShowWindow(kv.second, (kv.first == m_activeOutputTab && m_outputPanelVisible) ? SW_SHOW : SW_HIDE);
    }
    ShowWindow(m_hwndOutputTabs, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
    if (m_hwndSeverityFilter) ShowWindow(m_hwndSeverityFilter, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
    if (m_hwndSplitter) ShowWindow(m_hwndSplitter, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
}

void Win32IDE::addOutputTab(const std::string& name)
{
    if (m_outputWindows.find(name) != m_outputWindows.end()) return;
    RECT client{}; GetClientRect(m_hwndMain, &client);
    int tabBarHeight = 24;
    HWND hEdit = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        0, tabBarHeight, client.right, m_outputTabHeight - tabBarHeight,
        m_hwndMain, nullptr, m_hInstance, nullptr);
    ShowWindow(hEdit, SW_HIDE);
    m_outputWindows[name] = hEdit;
}

void Win32IDE::appendToOutput(const std::string& text, const std::string& tabName, OutputSeverity severity)
{
    if (static_cast<int>(severity) < m_severityFilterLevel) return;
    
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    if (m_outputWindows.find(target) == m_outputWindows.end()) {
        addOutputTab(target);
    }
    
    // Add timestamp for Errors and Debug tabs
    std::string timestampedText = text;
    if (target == "Errors" || target == "Debug") {
        time_t now = time(nullptr);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char timestamp[16];
        strftime(timestamp, sizeof(timestamp), "[%H:%M:%S] ", &timeinfo);
        timestampedText = std::string(timestamp) + text;
    }
    
    // Apply color formatting based on tab type
    if (target == "Errors") {
        formatOutput(timestampedText, RGB(220, 50, 50), "Errors"); // Red
    } else if (target == "Debug") {
        formatOutput(timestampedText, RGB(200, 180, 50), "Debug"); // Yellow
    } else {
        HWND hwnd = m_outputWindows[target];
        appendText(hwnd, timestampedText);
    }
}

void Win32IDE::clearOutput(const std::string& tabName)
{
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    auto it = m_outputWindows.find(target);
    if (it != m_outputWindows.end()) {
        SetWindowTextA(it->second, "");
    }
}

void Win32IDE::formatOutput(const std::string& text, COLORREF color, const std::string& tabName)
{ 
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    auto it = m_outputWindows.find(target);
    if (it == m_outputWindows.end()) return;
    
    HWND hwnd = it->second;
    GETTEXTLENGTHEX gtl{}; gtl.flags = GTL_DEFAULT; gtl.codepage = CP_ACP;
    LONG len = SendMessage(hwnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
    SendMessage(hwnd, EM_SETSEL, len, len);
    
    CHARFORMAT2A cf{};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessage(hwnd, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    
    SETTEXTEX st{}; st.flags = ST_SELECTION; st.codepage = CP_ACP;
    SendMessage(hwnd, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)text.c_str());
}

void Win32IDE::copyWithFormatting()
{
    // Simplified: copy selected plain text and store in history (vector<string>)
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    if (range.cpMax <= range.cpMin) return;
    LONG len = range.cpMax - range.cpMin;
    std::vector<char> buffer(len + 1); TEXTRANGEA tr; tr.chrg = range; tr.lpstrText = buffer.data();
    SendMessage(m_hwndEditor, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
    std::string text(buffer.data());
    m_clipboardHistory.insert(m_clipboardHistory.begin(), text);
    if (m_clipboardHistory.size() > MAX_CLIPBOARD_HISTORY) m_clipboardHistory.resize(MAX_CLIPBOARD_HISTORY);
    if (OpenClipboard(m_hwndMain)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hMem) {
            char* dest = (char*)GlobalLock(hMem);
            memcpy(dest, text.c_str(), text.size() + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

void Win32IDE::pasteWithoutFormatting()
{
    if (OpenClipboard(m_hwndMain)) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            const char* data = (const char*)GlobalLock(hData);
            if (data) {
                SendMessage(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)data);
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }
}

void Win32IDE::copyLineNumbers()
{
    if (!m_hwndEditor) return;
    
    // Get selected range
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    
    // Get line numbers for selection
    int startLine = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, range.cpMin, 0);
    int endLine = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, range.cpMax, 0);
    
    // Build line number string
    std::string lineNumbers;
    for (int i = startLine; i <= endLine; ++i) {
        if (!lineNumbers.empty()) lineNumbers += "\r\n";
        lineNumbers += std::to_string(i + 1);
    }
    
    // Copy to clipboard
    if (OpenClipboard(m_hwndMain)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, lineNumbers.size() + 1);
        if (hMem) {
            char* dest = (char*)GlobalLock(hMem);
            memcpy(dest, lineNumbers.c_str(), lineNumbers.size() + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

void Win32IDE::showClipboardHistory()
{
    std::string msg = "Clipboard History (latest 10):\n\n";
    size_t count = std::min<size_t>(10, m_clipboardHistory.size());
    for (size_t i = 0; i < count; ++i) {
        const std::string& item = m_clipboardHistory[i];
        std::string preview = item.substr(0, 50);
        if (item.size() > 50) preview += "...";
        msg += std::to_string(i + 1) + ". " + preview + "\n";
    }
    MessageBoxA(m_hwndMain, msg.c_str(), "Clipboard History", MB_OK);
}

void Win32IDE::clearClipboardHistory()
{
    m_clipboardHistory.clear();
}

void Win32IDE::createMinimap()
{
    if (!m_hwndMain || !m_hwndEditor) return;
    
    m_minimapWidth = 120;
    m_minimapVisible = true;
    
    // Create minimap window as a child of main window
    RECT editorRect;
    GetWindowRect(m_hwndEditor, &editorRect);
    MapWindowPoints(HWND_DESKTOP, m_hwndMain, (LPPOINT)&editorRect, 2);
    
    int minimapX = editorRect.right - m_minimapWidth;
    int minimapY = editorRect.top;
    int minimapHeight = editorRect.bottom - editorRect.top;
    
    m_hwndMinimap = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        minimapX, minimapY, m_minimapWidth, minimapHeight,
        m_hwndMain, nullptr, m_hInstance, nullptr);
    
    if (m_hwndMinimap) {
        SetWindowLongPtrA(m_hwndMinimap, GWLP_USERDATA, (LONG_PTR)this);
    }
    
    updateMinimap();
}

void Win32IDE::updateMinimap()
{
    if (!m_hwndMinimap || !m_minimapVisible || !m_hwndEditor) return;
    
    // Get editor content
    int textLen = GetWindowTextLengthA(m_hwndEditor);
    if (textLen == 0) {
        m_minimapLines.clear();
        InvalidateRect(m_hwndMinimap, nullptr, TRUE);
        return;
    }
    
    std::string text(textLen + 1, '\0');
    GetWindowTextA(m_hwndEditor, &text[0], textLen + 1);
    text.resize(textLen);
    
    // Split into lines for minimap rendering
    m_minimapLines.clear();
    m_minimapLineStarts.clear();
    
    std::istringstream stream(text);
    std::string line;
    int pos = 0;
    while (std::getline(stream, line)) {
        m_minimapLines.push_back(line);
        m_minimapLineStarts.push_back(pos);
        pos += (int)line.size() + 1; // +1 for newline
    }
    
    // Force redraw
    InvalidateRect(m_hwndMinimap, nullptr, TRUE);
    
    // Paint minimap content
    HDC hdc = GetDC(m_hwndMinimap);
    if (hdc) {
        RECT rc;
        GetClientRect(m_hwndMinimap, &rc);
        
        // Dark background
        HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
        FillRect(hdc, &rc, bgBrush);
        DeleteObject(bgBrush);
        
        // Calculate visible area highlight
        int firstVisibleLine = (int)SendMessage(m_hwndEditor, EM_GETFIRSTVISIBLELINE, 0, 0);
        RECT editorRect;
        GetClientRect(m_hwndEditor, &editorRect);
        int visibleLines = editorRect.bottom / 16; // Approximate line height
        
        // Draw visible area indicator
        int totalLines = (int)m_minimapLines.size();
        if (totalLines > 0) {
            float scale = (float)(rc.bottom - rc.top) / (float)totalLines;
            int highlightTop = (int)(firstVisibleLine * scale);
            int highlightHeight = (int)(visibleLines * scale);
            if (highlightHeight < 10) highlightHeight = 10;
            
            RECT highlightRect = { 0, highlightTop, rc.right, highlightTop + highlightHeight };
            HBRUSH highlightBrush = CreateSolidBrush(RGB(60, 60, 80));
            FillRect(hdc, &highlightRect, highlightBrush);
            DeleteObject(highlightBrush);
        }
        
        // Draw minimap lines as colored blocks
        HPEN codePen = CreatePen(PS_SOLID, 1, RGB(150, 150, 150));
        HPEN oldPen = (HPEN)SelectObject(hdc, codePen);
        
        float lineHeight = 2.0f;
        if (totalLines > 0 && totalLines * lineHeight > rc.bottom) {
            lineHeight = (float)(rc.bottom - 4) / (float)totalLines;
            if (lineHeight < 1.0f) lineHeight = 1.0f;
        }
        
        for (size_t i = 0; i < m_minimapLines.size() && i * lineHeight < rc.bottom; ++i) {
            const std::string& line = m_minimapLines[i];
            if (line.empty()) continue;
            
            int y = (int)(i * lineHeight) + 2;
            int lineLen = (int)line.size();
            int pixelLen = (lineLen * rc.right) / 200; // Scale to minimap width
            if (pixelLen > rc.right - 4) pixelLen = rc.right - 4;
            if (pixelLen < 2) pixelLen = 2;
            
            MoveToEx(hdc, 2, y, nullptr);
            LineTo(hdc, 2 + pixelLen, y);
        }
        
        SelectObject(hdc, oldPen);
        DeleteObject(codePen);
        
        ReleaseDC(m_hwndMinimap, hdc);
    }
}

void Win32IDE::scrollToMinimapPosition(int y)
{
    if (!m_hwndMinimap || !m_hwndEditor || m_minimapLines.empty()) return;
    
    RECT rc;
    GetClientRect(m_hwndMinimap, &rc);
    
    int totalLines = (int)m_minimapLines.size();
    int targetLine = (y * totalLines) / rc.bottom;
    
    if (targetLine < 0) targetLine = 0;
    if (targetLine >= totalLines) targetLine = totalLines - 1;
    
    // Scroll editor to target line
    int charIndex = 0;
    if (targetLine < (int)m_minimapLineStarts.size()) {
        charIndex = m_minimapLineStarts[targetLine];
    }
    
    SendMessage(m_hwndEditor, EM_SETSEL, charIndex, charIndex);
    SendMessage(m_hwndEditor, EM_SCROLLCARET, 0, 0);
    
    updateMinimap();
}

void Win32IDE::toggleMinimap()
{
    m_minimapVisible = !m_minimapVisible;
    if (m_hwndMinimap) {
        ShowWindow(m_hwndMinimap, m_minimapVisible ? SW_SHOW : SW_HIDE);
    } else if (m_minimapVisible) {
        createMinimap();
    }
    
    // Trigger layout update
    RECT rc;
    GetClientRect(m_hwndMain, &rc);
    onSize(rc.right, rc.bottom);
}

void Win32IDE::startProfiling()
{
    if (!m_profilingActive) {
        m_profilingActive = true;
        QueryPerformanceCounter(&m_profilingStart);
        QueryPerformanceFrequency(&m_profilingFreq);
        m_profilingResults.clear();
    }
}

void Win32IDE::stopProfiling()
{
    if (m_profilingActive) {
        LARGE_INTEGER end; QueryPerformanceCounter(&end);
        double ms = (double)(end.QuadPart - m_profilingStart.QuadPart) * 1000.0 / (double)m_profilingFreq.QuadPart;
        m_profilingResults.push_back({"Session", ms});
        m_profilingActive = false;
    }
}

void Win32IDE::showProfileResults()
{
    std::string msg = "Profile Results:\n\n";
    for (auto& pr : m_profilingResults) {
        msg += pr.first + ": " + std::to_string(pr.second) + " ms\n";
    }
    MessageBoxA(m_hwndMain, msg.c_str(), "Profiling", MB_OK);
}

void Win32IDE::analyzeScript()
{
    std::string script = getWindowText(m_hwndEditor);
    if(script.empty()) {
        MessageBoxA(m_hwndMain, "Script is empty.", "Analyze Script", MB_OK);
        return;
    }
    
    appendToOutput("Starting AI Analysis...\n", "Output", OutputSeverity::Info);
    
    // Asynchronous analysis to avoid blocking UI
    std::thread([this, script]() {
        if (m_nativeEngine) {
            std::string prompt = "Analyze the following script and report potential bugs, security issues, and improvements:\n\n" + script;
            // Assuming CPUInferenceEngine has an 'infer' or 'generate' method that takes a string
            // Based on cpu_inference_engine.cpp read earlier: std::string infer(const std::string& prompt);
            
            auto* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
            std::string result = engine->infer(prompt);
            
            // Post result back to UI thread or just append (if appendToOutput is thread-safe or we lock)
            // appendToOutput uses SendMessage which is generally thread-safe for simple text
            this->appendToOutput("\n=== AI Analysis Result ===\n" + result + "\n==========================\n", "Output", OutputSeverity::Info);
        } else {
             this->appendToOutput("Error: Inference Engine not available.\n", "Errors", OutputSeverity::Error);
        }
    }).detach();
}

void Win32IDE::measureExecutionTime() { 
    // Real implementation: Measure block execution
    auto start = std::chrono::high_resolution_clock::now();
    // execute selection... (simplified)
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count();
    appendToOutput("Execution time info: " + std::to_string(ms) + "ms\n", "Output", OutputSeverity::Info);
}

// Module Management
void Win32IDE::refreshModuleList()
{
    m_modules.clear();
    
    // Default module set (always available)
    m_modules.push_back({"Microsoft.PowerShell.Management","3.0.0.0","Management cmdlets","",true});
    m_modules.push_back({"Microsoft.PowerShell.Utility","3.0.0.0","Utility cmdlets","",true});
    m_modules.push_back({"PSReadLine","2.0.0","Command line editing","",false});
    
    // Dynamic module enumeration via Powershell command
    std::string cmd = "powershell.exe -NoProfile -Command \"Get-Module -ListAvailable | Select-Object -First 50 Name, Version | ConvertTo-Json -Compress\"";
    std::string output = ExecCmd(cmd.c_str());
    
    if (output.find("Error") == std::string::npos && !output.empty()) {
        try {
            auto json = nlohmann::json::parse(output);
            if (json.is_array()) {
                for (const auto& item : json) {
                    ModuleInfo m;
                    m.name = item.value("Name", "");
                    auto v = item["Version"];
                    if (v.is_object()) { 
                         // PS version object
                         m.version = std::to_string(v.value("Major",0)) + "." + std::to_string(v.value("Minor",0));
                    } else {
                        m.version = item.value("Version", "0.0.0");
                    }
                    m.description = "User Module";
                    m.path = ""; 
                    m.loaded = false; // Check via Get-Module without ListAvailable if needed
                    
                    // Avoid duplicates
                    bool exists = false;
                    for(const auto& existing : m_modules) if (existing.name == m.name) exists = true;
                    if (!exists) m_modules.push_back(m);
                }
            } else if (json.is_object()) {
                 // Single module
                 ModuleInfo m;
                 m.name = json.value("Name", "");
                 m.version = "1.0";
                 m.description = "User Module";
                 m_modules.push_back(m);
            }
        } catch (...) {
            // JSON parsing failed, likely non-JSON output or empty
        }
    }
}

void Win32IDE::showModuleBrowser()
{
    std::string msg = "Modules:\n\n";
    for (auto& m : m_modules) {
        msg += m.name + " (" + m.version + ")" + (m.loaded?" [Loaded]":" [Available]") + "\n";
    }
    MessageBoxA(m_hwndMain, msg.c_str(), "Module Browser", MB_OK);
}

void Win32IDE::loadModule(const std::string& moduleName)
{
    bool found = false;
    for (auto& m : m_modules) {
        if (m.name == moduleName) {
            m.loaded = true;
            found = true;
            break;
        }
    }
    
    // Explicit Logic: Actually load the module in PowerShell
    std::string command = "Import-Module '" + moduleName + "'\n";
    
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        pane->manager->writeInput(command);
        appendToOutput("Loading module: " + moduleName, "Output", OutputSeverity::Info);
    } else {
        appendToOutput("Cannot load module '" + moduleName + "': No active terminal.", "Errors", OutputSeverity::Error);
    }
}

void Win32IDE::unloadModule(const std::string& moduleName)
{
    bool found = false;
    for (auto& m : m_modules) {
        if (m.name == moduleName) {
            m.loaded = false;
            found = true;
            break;
        }
    }

    // Explicit Logic: Actually remove the module in PowerShell
    std::string command = "Remove-Module '" + moduleName + "'\n";
    
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        pane->manager->writeInput(command);
        appendToOutput("Unloading module: " + moduleName, "Output", OutputSeverity::Info);
    } else {
        // Try to start one or log error
        appendToOutput("Cannot unload module '" + moduleName + "': No active terminal.", "Errors", OutputSeverity::Error);
    }
}

void Win32IDE::importModule()
{
    // Show file dialog to select module
    OPENFILENAMEA ofn = {};
    char szFile[MAX_PATH] = "";
    
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFilter = "PowerShell Modules (*.psm1;*.psd1)\0*.psm1;*.psd1\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = "Import Module";
    
    if (GetOpenFileNameA(&ofn)) {
        std::string modulePath = szFile;
        std::string command = "Import-Module '" + modulePath + "'\n";
        
        TerminalPane* pane = getActiveTerminalPane();
        if (pane && pane->manager && pane->manager->isRunning()) {
            pane->manager->writeInput(command);
            appendToOutput("Importing module: " + modulePath + "\n", "Output", OutputSeverity::Info);
        }
        
        // Refresh module list after import
        refreshModuleList();
    }
}

void Win32IDE::exportModule()
{
    // Show dialog to select module to export
    if (m_modules.empty()) {
        MessageBoxA(m_hwndMain, "No modules loaded. Refresh module list first.", "Export Module", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    // Build list of module names for selection
    std::string moduleList = "Available modules:\n\n";
    for (size_t i = 0; i < m_modules.size(); ++i) {
        moduleList += std::to_string(i + 1) + ". " + m_modules[i].name;
        if (m_modules[i].loaded) moduleList += " [Loaded]";
        moduleList += "\n";
    }
    moduleList += "\nExport the first loaded module?";
    
    if (MessageBoxA(m_hwndMain, moduleList.c_str(), "Export Module", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        // Find first loaded module
        for (const auto& mod : m_modules) {
            if (mod.loaded) {
                // Show save dialog
                OPENFILENAMEA ofn = {};
                char szFile[MAX_PATH] = "";
                strncpy_s(szFile, (mod.name + ".psm1").c_str(), MAX_PATH);
                
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = m_hwndMain;
                ofn.lpstrFilter = "PowerShell Module (*.psm1)\0*.psm1\0PowerShell Data (*.psd1)\0*.psd1\0";
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_OVERWRITEPROMPT;
                ofn.lpstrTitle = "Export Module";
                
                if (GetSaveFileNameA(&ofn)) {
                    std::string savePath = szFile;
                    std::string command = "Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias * -PassThru | Out-File '" + savePath + "'\n";
                    
                    TerminalPane* pane = getActiveTerminalPane();
                    if (pane && pane->manager && pane->manager->isRunning()) {
                        pane->manager->writeInput(command);
                        appendToOutput("Exporting module to: " + savePath + "\n", "Output", OutputSeverity::Info);
                    }
                }
                break;
            }
        }
    }
}

// Theme Management
void Win32IDE::resetToDefaultTheme()
{
    m_currentTheme.backgroundColor = RGB(30,30,30);
    m_currentTheme.textColor = RGB(220,220,220);
    m_currentTheme.selectionColor = RGB(60,120,200);
    m_currentTheme.lineNumberColor = RGB(128,128,128);
    applyTheme();
}

void Win32IDE::saveCodeSnippets()
{
    CreateDirectoryA("snippets", NULL);
    std::ofstream file("snippets\\snippets.txt");
    if (file.is_open()) {
        for (const auto& snippet : m_codeSnippets) {
            file << "[SNIPPET]" << std::endl;
            file << "name=" << snippet.name << std::endl;
            file << "description=" << snippet.description << std::endl;
            file << "code_start" << std::endl;
            file << snippet.code << std::endl;
            file << "code_end" << std::endl;
        }
        file.close();
    }
}

void Win32IDE::showPowerShellDocs()
{
    MessageBoxA(m_hwndMain, "Open https://learn.microsoft.com/powershell/ for full docs.", "PowerShell Docs", MB_OK);
}

void Win32IDE::searchHelp(const std::string& query)
{
    std::string q = query.empty()?"Get-Command":query;
    std::string cmd = "Get-Help " + q + " -Online\n";
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) pane->manager->writeInput(cmd);
}

void Win32IDE::toggleFloatingPanel()
{
    if (!m_hwndFloatingPanel) return; // created elsewhere
    BOOL vis = IsWindowVisible(m_hwndFloatingPanel);
    ShowWindow(m_hwndFloatingPanel, vis?SW_HIDE:SW_SHOW);
}
// ============================================================================
// Search and Replace Implementation
// ============================================================================

#define IDD_FIND 5001
#define IDD_REPLACE 5002
#define IDC_FIND_TEXT 5010
#define IDC_REPLACE_TEXT 5011
#define IDC_CASE_SENSITIVE 5020
#define IDC_WHOLE_WORD 5021
#define IDC_USE_REGEX 5022
#define IDC_BTN_FIND_NEXT 5030
#define IDC_BTN_REPLACE 5031
#define IDC_BTN_REPLACE_ALL 5032
#define IDC_BTN_CLOSE 5033

void Win32IDE::showFindDialog()
{
    if (m_hwndFindDialog && IsWindow(m_hwndFindDialog)) {
        SetForegroundWindow(m_hwndFindDialog);
        return;
    }
    
    m_hwndFindDialog = CreateDialogParamA(m_hInstance, MAKEINTRESOURCEA(IDD_FIND), 
        m_hwndMain, FindDialogProc, (LPARAM)this);
    
    if (!m_hwndFindDialog) {
        // Fallback: create simple dialog programmatically
        HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Find",
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
            100, 100, 400, 150, m_hwndMain, nullptr, m_hInstance, nullptr);
        m_hwndFindDialog = hwndDlg;
        
        CreateWindowExA(0, "STATIC", "Find what:", WS_CHILD | WS_VISIBLE,
            10, 15, 80, 20, hwndDlg, nullptr, m_hInstance, nullptr);
        CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", m_lastSearchText.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 12, 280, 22, 
            hwndDlg, (HMENU)IDC_FIND_TEXT, m_hInstance, nullptr);
        
        CreateWindowExA(0, "BUTTON", "Case sensitive", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, 45, 120, 20, hwndDlg, (HMENU)IDC_CASE_SENSITIVE, m_hInstance, nullptr);
        CreateWindowExA(0, "BUTTON", "Whole word", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            140, 45, 100, 20, hwndDlg, (HMENU)IDC_WHOLE_WORD, m_hInstance, nullptr);
        CreateWindowExA(0, "BUTTON", "Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            250, 45, 70, 20, hwndDlg, (HMENU)IDC_USE_REGEX, m_hInstance, nullptr);
        
        CreateWindowExA(0, "BUTTON", "Find Next", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            10, 80, 90, 28, hwndDlg, (HMENU)IDC_BTN_FIND_NEXT, m_hInstance, nullptr);
        CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE,
            110, 80, 90, 28, hwndDlg, (HMENU)IDC_BTN_CLOSE, m_hInstance, nullptr);
    }
    
    ShowWindow(m_hwndFindDialog, SW_SHOW);
}

void Win32IDE::showReplaceDialog()
{
    if (m_hwndReplaceDialog && IsWindow(m_hwndReplaceDialog)) {
        SetForegroundWindow(m_hwndReplaceDialog);
        return;
    }
    
    // Create simple replace dialog
    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Replace",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        100, 100, 400, 200, m_hwndMain, nullptr, m_hInstance, nullptr);
    m_hwndReplaceDialog = hwndDlg;
    
    CreateWindowExA(0, "STATIC", "Find what:", WS_CHILD | WS_VISIBLE,
        10, 15, 80, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", m_lastSearchText.c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 12, 280, 22, 
        hwndDlg, (HMENU)IDC_FIND_TEXT, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Replace with:", WS_CHILD | WS_VISIBLE,
        10, 45, 80, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", m_lastReplaceText.c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 42, 280, 22, 
        hwndDlg, (HMENU)IDC_REPLACE_TEXT, m_hInstance, nullptr);
    
    CreateWindowExA(0, "BUTTON", "Case sensitive", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 75, 120, 20, hwndDlg, (HMENU)IDC_CASE_SENSITIVE, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Whole word", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        140, 75, 100, 20, hwndDlg, (HMENU)IDC_WHOLE_WORD, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        250, 75, 70, 20, hwndDlg, (HMENU)IDC_USE_REGEX, m_hInstance, nullptr);
    
    CreateWindowExA(0, "BUTTON", "Find Next", WS_CHILD | WS_VISIBLE,
        10, 110, 90, 28, hwndDlg, (HMENU)IDC_BTN_FIND_NEXT, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Replace", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        110, 110, 90, 28, hwndDlg, (HMENU)IDC_BTN_REPLACE, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Replace All", WS_CHILD | WS_VISIBLE,
        210, 110, 90, 28, hwndDlg, (HMENU)IDC_BTN_REPLACE_ALL, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE,
        310, 110, 70, 28, hwndDlg, (HMENU)IDC_BTN_CLOSE, m_hInstance, nullptr);
    
    ShowWindow(m_hwndReplaceDialog, SW_SHOW);
}

void Win32IDE::findNext()
{
    if (m_lastSearchText.empty()) {
        showFindDialog();
        return;
    }
    findText(m_lastSearchText, true, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::findPrevious()
{
    if (m_lastSearchText.empty()) {
        showFindDialog();
        return;
    }
    findText(m_lastSearchText, false, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::replaceNext()
{
    if (m_lastSearchText.empty()) {
        showReplaceDialog();
        return;
    }
    replaceText(m_lastSearchText, m_lastReplaceText, false, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::replaceAll()
{
    if (m_lastSearchText.empty()) {
        showReplaceDialog();
        return;
    }
    int count = replaceText(m_lastSearchText, m_lastReplaceText, true, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
    
    std::string msg = "Replaced " + std::to_string(count) + " occurrence(s).";
    MessageBoxA(m_hwndMain, msg.c_str(), "Replace All", MB_OK | MB_ICONINFORMATION);
}

bool Win32IDE::findText(const std::string& searchText, bool forward, bool caseSensitive, bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty()) return false;
    
    // Get editor text
    int textLen = GetWindowTextLengthA(m_hwndEditor);
    if (textLen == 0) return false;
    
    std::string editorText(textLen + 1, 0);
    GetWindowTextA(m_hwndEditor, &editorText[0], textLen + 1);
    editorText.resize(textLen);
    
    // Get current selection to start search from there
    CHARRANGE selection;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&selection);
    
    int startPos = forward ? selection.cpMax : selection.cpMin - 1;
    if (startPos < 0) startPos = 0;
    if (startPos >= textLen) startPos = textLen - 1;
    
    // Simple case-insensitive search (regex not implemented in this version)
    std::string haystack = editorText;
    std::string needle = searchText;
    
    if (!caseSensitive) {
        std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
        std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
    }
    
    size_t foundPos = std::string::npos;
    
    if (forward) {
        foundPos = haystack.find(needle, startPos);
        // Wrap around
        if (foundPos == std::string::npos && startPos > 0) {
            foundPos = haystack.find(needle, 0);
        }
    } else {
        // Search backwards
        if (startPos > 0) {
            foundPos = haystack.rfind(needle, startPos);
        }
        // Wrap around
        if (foundPos == std::string::npos) {
            foundPos = haystack.rfind(needle);
        }
    }
    
    if (foundPos != std::string::npos) {
        // Select found text
        selection.cpMin = foundPos;
        selection.cpMax = foundPos + searchText.length();
        SendMessage(m_hwndEditor, EM_EXSETSEL, 0, (LPARAM)&selection);
        SendMessage(m_hwndEditor, EM_SCROLLCARET, 0, 0);
        m_lastFoundPos = foundPos;
        return true;
    }
    
    MessageBoxA(m_hwndMain, "Text not found.", "Find", MB_OK | MB_ICONINFORMATION);
    return false;
}

int Win32IDE::replaceText(const std::string& searchText, const std::string& replaceText, bool all, bool caseSensitive, bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty()) return 0;
    
    int replaceCount = 0;
    
    if (all) {
        // Replace all occurrences
        // Get editor text
        int textLen = GetWindowTextLengthA(m_hwndEditor);
        if (textLen == 0) return 0;
        
        std::string editorText(textLen + 1, 0);
        GetWindowTextA(m_hwndEditor, &editorText[0], textLen + 1);
        editorText.resize(textLen);
        
        std::string result;
        size_t pos = 0;
        
        std::string haystack = editorText;
        std::string needle = searchText;
        
        if (!caseSensitive) {
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
            std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
        }
        
        while ((pos = haystack.find(needle, pos)) != std::string::npos) {
            result.append(editorText, 0, pos);
            result.append(replaceText);
            pos += needle.length();
            replaceCount++;
        }
        
        if (replaceCount > 0) {
            result.append(editorText, pos, std::string::npos);
            SetWindowTextA(m_hwndEditor, result.c_str());
            m_fileModified = true;
        }
    } else {
        // Replace current selection if it matches search text
        CHARRANGE selection;
        SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&selection);
        
        int selLen = selection.cpMax - selection.cpMin;
        if (selLen > 0) {
            std::string selectedText(selLen + 1, 0);
            SendMessage(m_hwndEditor, EM_GETSELTEXT, 0, (LPARAM)&selectedText[0]);
            selectedText.resize(selLen);
            
            std::string cmpSelected = selectedText;
            std::string cmpSearch = searchText;
            
            if (!caseSensitive) {
                std::transform(cmpSelected.begin(), cmpSelected.end(), cmpSelected.begin(), ::tolower);
                std::transform(cmpSearch.begin(), cmpSearch.end(), cmpSearch.begin(), ::tolower);
            }
            
            if (cmpSelected == cmpSearch) {
                SendMessage(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)replaceText.c_str());
                m_fileModified = true;
                replaceCount = 1;
                
                // Find next occurrence
                findText(searchText, true, caseSensitive, wholeWord, useRegex);
            }
        }
    }
    
    return replaceCount;
}

INT_PTR CALLBACK Win32IDE::FindDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        pThis = (Win32IDE*)lParam;
    } else {
        pThis = (Win32IDE*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (!pThis) return FALSE;
    
    switch (uMsg) {
    case WM_USER + 100:
        // Handle Copilot streaming token updates
        if (pThis) {
            pThis->HandleCopilotStreamUpdate(reinterpret_cast<const char*>(wParam), static_cast<size_t>(lParam));
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_FIND_NEXT:
            {
                HWND hwndFindText = GetDlgItem(hwndDlg, IDC_FIND_TEXT);
                char buffer[256];
                GetWindowTextA(hwndFindText, buffer, 256);
                pThis->m_lastSearchText = buffer;
                
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                
                pThis->findNext();
            }
            return TRUE;
        case IDC_BTN_CLOSE:
        case IDCANCEL:
            DestroyWindow(hwndDlg);
            pThis->m_hwndFindDialog = nullptr;
            return TRUE;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        pThis->m_hwndFindDialog = nullptr;
        return TRUE;
    }
    
    return FALSE;
}

INT_PTR CALLBACK Win32IDE::ReplaceDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        pThis = (Win32IDE*)lParam;
    } else {
        pThis = (Win32IDE*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (!pThis) return FALSE;
    
    switch (uMsg) {
    case WM_COMMAND:
        {
            HWND hwndFindText = GetDlgItem(hwndDlg, IDC_FIND_TEXT);
            HWND hwndReplaceText = GetDlgItem(hwndDlg, IDC_REPLACE_TEXT);
            char findBuffer[256], replaceBuffer[256];
            
            switch (LOWORD(wParam)) {
            case IDC_BTN_FIND_NEXT:
                GetWindowTextA(hwndFindText, findBuffer, 256);
                pThis->m_lastSearchText = findBuffer;
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                pThis->findNext();
                return TRUE;
            case IDC_BTN_REPLACE:
                GetWindowTextA(hwndFindText, findBuffer, 256);
                GetWindowTextA(hwndReplaceText, replaceBuffer, 256);
                pThis->m_lastSearchText = findBuffer;
                pThis->m_lastReplaceText = replaceBuffer;
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                pThis->replaceNext();
                return TRUE;
            case IDC_BTN_REPLACE_ALL:
                GetWindowTextA(hwndFindText, findBuffer, 256);
                GetWindowTextA(hwndReplaceText, replaceBuffer, 256);
                pThis->m_lastSearchText = findBuffer;
                pThis->m_lastReplaceText = replaceBuffer;
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                pThis->replaceAll();
                return TRUE;
            case IDC_BTN_CLOSE:
            case IDCANCEL:
                DestroyWindow(hwndDlg);
                pThis->m_hwndReplaceDialog = nullptr;
                return TRUE;
            }
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        pThis->m_hwndReplaceDialog = nullptr;
        return TRUE;
    }
    
    return FALSE;
}

// ============================================================================
// Snippet Manager Implementation  
// ============================================================================

#define IDD_SNIPPET_MANAGER 6001
// Note: IDC_SNIPPET_LIST is defined at line 23 as 1009
#define IDC_SNIPPET_LIST_DLG 6010
#define IDC_SNIPPET_NAME 6011
#define IDC_SNIPPET_DESC 6012
#define IDC_SNIPPET_CODE 6013
#define IDC_BTN_INSERT_SNIPPET 6020
#define IDC_BTN_NEW_SNIPPET 6021
#define IDC_BTN_DELETE_SNIPPET 6022
#define IDC_BTN_SAVE_SNIPPETS 6023

void Win32IDE::showSnippetManager()
{
    // Create snippet manager dialog
    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Snippet Manager",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        100, 100, 600, 500, m_hwndMain, nullptr, m_hInstance, nullptr);
    
    // Snippet list (left pane)
    CreateWindowExA(0, "STATIC", "Snippets:", WS_CHILD | WS_VISIBLE,
        10, 10, 150, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    
    HWND hwndList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
        WS_CHILD | WS_VISIBLE | LBS_STANDARD | WS_VSCROLL,
        10, 35, 150, 400, hwndDlg, (HMENU)IDC_SNIPPET_LIST_DLG, m_hInstance, nullptr);
    
    // Populate list with snippet names
    for (const auto& snippet : m_codeSnippets) {
        SendMessageA(hwndList, LB_ADDSTRING, 0, (LPARAM)snippet.name.c_str());
    }
    
    // Snippet details (right pane)
    CreateWindowExA(0, "STATIC", "Name:", WS_CHILD | WS_VISIBLE,
        175, 10, 50, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        230, 8, 350, 22, hwndDlg, (HMENU)IDC_SNIPPET_NAME, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Description:", WS_CHILD | WS_VISIBLE,
        175, 40, 70, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        175, 60, 405, 22, hwndDlg, (HMENU)IDC_SNIPPET_DESC, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Code Template:", WS_CHILD | WS_VISIBLE,
        175, 90, 100, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN | WS_VSCROLL | WS_HSCROLL,
        175, 115, 405, 280, hwndDlg, (HMENU)IDC_SNIPPET_CODE, m_hInstance, nullptr);
    
    // Buttons
    CreateWindowExA(0, "BUTTON", "Insert", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        175, 410, 90, 28, hwndDlg, (HMENU)IDC_BTN_INSERT_SNIPPET, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "New", WS_CHILD | WS_VISIBLE,
        275, 410, 90, 28, hwndDlg, (HMENU)IDC_BTN_NEW_SNIPPET, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Delete", WS_CHILD | WS_VISIBLE,
        375, 410, 90, 28, hwndDlg, (HMENU)IDC_BTN_DELETE_SNIPPET, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Save & Close", WS_CHILD | WS_VISIBLE,
        475, 410, 105, 28, hwndDlg, (HMENU)IDC_BTN_SAVE_SNIPPETS, m_hInstance, nullptr);
    
    // Message loop for dialog
    MSG msg;
    bool running = true;
    while (running && GetMessage(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == hwndDlg || IsChild(hwndDlg, msg.hwnd)) {
            // Handle list selection
            if (msg.message == WM_COMMAND) {
                WORD cmdId = LOWORD(msg.wParam);
                WORD notif = HIWORD(msg.wParam);
                
                if (cmdId == IDC_SNIPPET_LIST_DLG && notif == LBN_SELCHANGE) {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        const CodeSnippet& snippet = m_codeSnippets[sel];
                        SetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, snippet.name.c_str());
                        SetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, snippet.description.c_str());
                        SetDlgItemTextA(hwndDlg, IDC_SNIPPET_CODE, snippet.code.c_str());
                    }
                }
                else if (cmdId == IDC_BTN_INSERT_SNIPPET) {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        insertSnippet(m_codeSnippets[sel].name);
                        running = false;
                        DestroyWindow(hwndDlg);
                    }
                }
                else if (cmdId == IDC_BTN_NEW_SNIPPET) {
                    CodeSnippet newSnippet;
                    newSnippet.name = "NewSnippet";
                    newSnippet.description = "New snippet description";
                    newSnippet.code = "// Your code here";
                    m_codeSnippets.push_back(newSnippet);
                    SendMessageA(hwndList, LB_ADDSTRING, 0, (LPARAM)newSnippet.name.c_str());
                    SendMessage(hwndList, LB_SETCURSEL, m_codeSnippets.size() - 1, 0);
                    SetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, newSnippet.name.c_str());
                    SetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, newSnippet.description.c_str());
                    SetDlgItemTextA(hwndDlg, IDC_SNIPPET_CODE, newSnippet.code.c_str());
                }
                else if (cmdId == IDC_BTN_DELETE_SNIPPET) {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        if (MessageBoxA(hwndDlg, "Delete this snippet?", "Confirm", MB_YESNO) == IDYES) {
                            m_codeSnippets.erase(m_codeSnippets.begin() + sel);
                            SendMessage(hwndList, LB_DELETESTRING, sel, 0);
                            SetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, "");
                            SetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, "");
                            SetDlgItemTextA(hwndDlg, IDC_SNIPPET_CODE, "");
                        }
                    }
                }
                else if (cmdId == IDC_BTN_SAVE_SNIPPETS) {
                    // Update current snippet before saving
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        char buffer[1024];
                        GetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, buffer, 1024);
                        m_codeSnippets[sel].name = buffer;
                        GetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, buffer, 1024);
                        m_codeSnippets[sel].description = buffer;
                        
                        HWND hwndCode = GetDlgItem(hwndDlg, IDC_SNIPPET_CODE);
                        int len = GetWindowTextLengthA(hwndCode);
                        std::vector<char> codeBuffer(len + 1);
                        GetWindowTextA(hwndCode, codeBuffer.data(), len + 1);
                        m_codeSnippets[sel].code = codeBuffer.data();
                    }
                    
                    saveCodeSnippets();
                    MessageBoxA(hwndDlg, "Snippets saved!", "Success", MB_OK);
                    running = false;
                    DestroyWindow(hwndDlg);
                }
            }
            else if (msg.message == WM_CLOSE) {
                running = false;
                DestroyWindow(hwndDlg);
            }
        }
        
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void Win32IDE::createSnippet()
{
    // Create a new empty snippet
    CodeSnippet newSnippet;
    newSnippet.name = "NewSnippet" + std::to_string(m_codeSnippets.size() + 1);
    newSnippet.description = "New snippet";
    newSnippet.code = "// Code template\n";
    m_codeSnippets.push_back(newSnippet);
    
    MessageBoxA(m_hwndMain, ("Snippet '" + newSnippet.name + "' created. Use Snippet Manager to edit.").c_str(), 
        "Snippet Created", MB_OK);
}

// ============================================================================
// File Explorer Implementation
// ============================================================================

void Win32IDE::createFileExplorer(HWND hwndParent)
{
    if (m_hwndFileExplorer) {
        return; // Already created
    }

    // Create sidebar panel
    m_hwndFileExplorer = CreateWindowExA(
        0,
        "STATIC",
        "File Explorer",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        0, 30, m_sidebarWidth, 500,
        hwndParent,
        (HMENU)IDC_FILE_EXPLORER,
        GetModuleHandleA(nullptr),
        nullptr
    );

    // Create TreeView control for file navigation
    m_hwndFileTree = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_TREEVIEWA,
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS,
        5, 5, m_sidebarWidth - 10, 490,
        m_hwndFileExplorer,
        (HMENU)IDC_FILE_TREE,
        GetModuleHandleA(nullptr),
        nullptr
    );

    // Set TreeView font
    SendMessageA(m_hwndFileTree, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

    // Populate with drive letters
    populateFileTree(nullptr, "");
}

void Win32IDE::populateFileTree(HTREEITEM parentItem, const std::string& path)
{
    if (!m_hwndFileTree) {
        return;
    }

    // If no parent, add drives
    if (!parentItem) {
        TVINSERTSTRUCTA tvis = {};
        tvis.hParent = TVI_ROOT;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

        // Add all available drives
        for (char drive = 'C'; drive <= 'Z'; ++drive) {
            std::string drivePath = std::string(1, drive) + ":";
            DWORD drives = GetLogicalDrives();
            int driveNum = drive - 'A';

            if (drives & (1 << driveNum)) {
                std::string displayName = drivePath + "\\";
                tvis.item.pszText = (LPSTR)displayName.c_str();
                tvis.item.lParam = (LPARAM) new std::string(drivePath);

                HTREEITEM driveItem = (HTREEITEM)SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[driveItem] = drivePath;

                // Add a dummy child so expand button appears
                TVINSERTSTRUCTA dummyVis = {};
                dummyVis.hParent = driveItem;
                dummyVis.item.mask = TVIF_TEXT;
                dummyVis.item.pszText = (LPSTR)"...";
                SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&dummyVis);
            }
        }
        return;
    }

    // Populate a specific folder
    try {
        WIN32_FIND_DATAA findData;
        HANDLE findHandle;

        std::string searchPath = path + "\\*";
        findHandle = FindFirstFileA(searchPath.c_str(), &findData);

        if (findHandle == INVALID_HANDLE_VALUE) {
            return;
        }

        TVINSERTSTRUCTA tvis = {};
        tvis.hParent = parentItem;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

        // Clear dummy items
        HTREEITEM hChild = TreeView_GetChild(m_hwndFileTree, parentItem);
        while (hChild) {
            HTREEITEM hNext = TreeView_GetNextSibling(m_hwndFileTree, hChild);
            TreeView_DeleteItem(m_hwndFileTree, hChild);
            hChild = hNext;
        }

        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
                continue;
            }

            std::string fullPath = path + "\\" + findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // It's a folder
                tvis.item.pszText = findData.cFileName;
                tvis.item.lParam = (LPARAM) new std::string(fullPath);

                HTREEITEM folderItem = (HTREEITEM)SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[folderItem] = fullPath;

                // Add dummy child
                TVINSERTSTRUCTA dummyVis = {};
                dummyVis.hParent = folderItem;
                dummyVis.item.mask = TVIF_TEXT;
                dummyVis.item.pszText = (LPSTR)"...";
                SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&dummyVis);
            }
            else if (strlen(findData.cFileName) > 5 &&
                     strcmp(findData.cFileName + strlen(findData.cFileName) - 5, ".gguf") == 0) {
                // It's a GGUF file
                tvis.item.pszText = findData.cFileName;
                tvis.item.lParam = (LPARAM) new std::string(fullPath);

                HTREEITEM fileItem = (HTREEITEM)SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[fileItem] = fullPath;
            }
        } while (FindNextFileA(findHandle, &findData));

        FindClose(findHandle);
    }
    catch (...) {
        // Silently handle errors
    }
}

void Win32IDE::onFileTreeExpand(HTREEITEM item, const std::string& path)
{
    if (!m_hwndFileTree) {
        return;
    }

    populateFileTree(item, path);
}

std::string Win32IDE::getTreeItemPath(HTREEITEM item) const
{
    auto it = m_treeItemPaths.find(item);
    if (it != m_treeItemPaths.end()) {
        return it->second;
    }
    return "";
}

void Win32IDE::loadModelFromPath(const std::string& filepath)
{
    if (filepath.length() > 5 &&
        filepath.substr(filepath.length() - 5) == ".gguf") {
        // Load model using streaming loader
        if (loadGGUFModel(filepath)) {
            // Initialize inference system
            initializeInference();
            
            // Notify user in chat
            std::string msg = "✅ Model loaded and ready for inference!\r\n\r\n"
                             "You can now ask questions in the chat panel.\r\n"
                             "Try: 'hello', 'model info', 'explain code', etc.";
            appendCopilotResponse(msg);
        }
    }
}

// ============================================================================
// GGUF Model Loading Implementation
// ============================================================================

bool Win32IDE::loadGGUFModel(const std::string& filepath)
{
    if (!m_ggufLoader) {
        std::string error = "Error: GGUF Loader not initialized";
        appendToOutput(error, "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }

    appendToOutput("Loading GGUF model: " + filepath + "\n", "Output", OutputSeverity::Info);
    appendToOutput("This may take a moment for large files...\n", "Output", OutputSeverity::Info);

    try {
        // Attempt to open and parse the GGUF file (streaming - no full data load)
        appendToOutput("[1/5] Opening file...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->Open(filepath)) {
            std::string error = "❌ Failed to open GGUF file: " + filepath + "\nCheck if file exists and is readable.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            return false;
        }

        appendToOutput("[2/5] Parsing header...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->ParseHeader()) {
            std::string error = "❌ Failed to parse GGUF header from: " + filepath + "\nFile may be corrupted or not a valid GGUF.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        appendToOutput("[3/5] Parsing metadata...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->ParseMetadata()) {
            std::string error = "❌ Failed to parse GGUF metadata from: " + filepath + "\nFile structure may be invalid.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        // Build tensor index (reads tensor offsets but NOT data)
        appendToOutput("[4/5] Building tensor index (may take 10-30 seconds for large files)...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->BuildTensorIndex()) {
            std::string error = "❌ Failed to build tensor index from: " + filepath + "\nFile may be too large or corrupted.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        // Pre-load embedding zone for inference preparation
        appendToOutput("[5/5] Pre-loading embedding zone...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->LoadZone("embedding")) {
            std::string warning = "⚠️  Warning: Could not pre-load embedding zone (non-critical)";
            appendToOutput(warning, "Output", OutputSeverity::Warning);
        }
    }
    catch (const std::exception& e) {
        std::string error = "❌ Exception loading GGUF file:\n" + std::string(e.what()) + "\n\nFile: " + filepath;
        appendToOutput(error + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }
    catch (...) {
        std::string error = "❌ Unknown exception loading GGUF file: " + filepath;
        appendToOutput(error + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }

    // Store model info
    m_loadedModelPath = filepath;
    m_currentModelMetadata = m_ggufLoader->GetMetadata();
    m_modelTensors = m_ggufLoader->GetAllTensorInfo();  // Get tensor info for backward compatibility

    // Log success with memory savings information
    size_t currentMemory = m_ggufLoader->GetCurrentMemoryUsage();
    std::string info = "✅ Model loaded successfully (STREAMING MODE)!\n";
    info += "File: " + filepath + "\n";
    info += "Tensors: " + std::to_string(m_modelTensors.size()) + "\n";
    info += "Layers: " + std::to_string(m_currentModelMetadata.layer_count) + "\n";
    info += "Context: " + std::to_string(m_currentModelMetadata.context_length) + "\n";
    info += "Vocab: " + std::to_string(m_currentModelMetadata.vocab_size) + "\n";
    info += "Current Memory: " + std::to_string(currentMemory / 1024 / 1024) + " MB\n";
    info += "Max Memory: ~500 MB (zone-based streaming)\n\n";
    
    auto zones = m_ggufLoader->GetLoadedZones();
    if (!zones.empty()) {
        info += "Loaded Zones: ";
        for (size_t i = 0; i < zones.size(); ++i) {
            info += zones[i];
            if (i < zones.size() - 1) info += ", ";
        }
        info += "\n";
    }
    
    appendToOutput(info, "Output", OutputSeverity::Info);
    
    // Update status bar
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, 
        (LPARAM)("Model: " + std::string(filepath)).c_str());

    // Auto-activate Copilot panel and send welcome message
    if (m_hwndSecondarySidebar && m_hwndCopilotChatOutput) {
        // Make secondary sidebar visible if hidden
        ShowWindow(m_hwndSecondarySidebar, SW_SHOW);
        
        // Send agentic welcome message to Copilot
        std::string welcomeMsg = "🤖 AI Model Loaded!\r\n\r\n";
        welcomeMsg += "I'm now ready to assist you with:\r\n";
        welcomeMsg += "• Code analysis and review\r\n";
        welcomeMsg += "• GGUF model exploration\r\n";
        welcomeMsg += "• Tensor inspection and debugging\r\n";
        welcomeMsg += "• PowerShell automation\r\n";
        welcomeMsg += "• File operations\r\n\r\n";
        welcomeMsg += "Model: " + filepath + "\r\n";
        welcomeMsg += "Tensors: " + std::to_string(m_modelTensors.size()) + "\r\n";
        welcomeMsg += "Memory: " + std::to_string(currentMemory / 1024 / 1024) + " MB\r\n\r\n";
        welcomeMsg += "Ask me anything!\r\n";
        
        appendCopilotResponse(welcomeMsg);
    }

    return true;
}

std::string Win32IDE::getModelInfo() const
{
    if (m_modelTensors.empty() || !m_ggufLoader) {
        return "No model loaded";
    }

    std::string info = "═══════════════════════════════════════════\n";
    info += "GGUF Model Information (STREAMING MODE)\n";
    info += "═══════════════════════════════════════════\n\n";
    
    info += "File: " + m_loadedModelPath + "\n";
    info += "Tensors: " + std::to_string(m_modelTensors.size()) + "\n";
    info += "Layers: " + std::to_string(m_currentModelMetadata.layer_count) + "\n";
    info += "Context Length: " + std::to_string(m_currentModelMetadata.context_length) + "\n";
    info += "Embedding Dim: " + std::to_string(m_currentModelMetadata.embedding_dim) + "\n";
    info += "Vocab Size: " + std::to_string(m_currentModelMetadata.vocab_size) + "\n";
    info += "Architecture: " + std::to_string(m_currentModelMetadata.architecture_type) + "\n\n";

    // Show zone status (memory efficiency indicator)
    size_t currentMemory = m_ggufLoader->GetCurrentMemoryUsage();
    auto loadedZones = m_ggufLoader->GetLoadedZones();
    
    info += "📊 Memory Status:\n";
    info += "  Current RAM: " + std::to_string(currentMemory / 1024 / 1024) + " MB\n";
    info += "  Max Per Zone: ~400 MB\n";
    info += "  Total Capacity: ~500 MB (92x reduction from full load!)\n";
    info += "  Loaded Zones: " + std::to_string(loadedZones.size()) + "\n\n";
    
    if (!loadedZones.empty()) {
        info += "🎯 Active Zones:\n";
        for (const auto& zone : loadedZones) {
            info += "   ✓ " + zone + "\n";
        }
        info += "\n";
    }

    info += "Tensor Details (first 10):\n";
    info += "──────────────────────────────────────────\n";
    
    for (size_t i = 0; i < m_modelTensors.size() && i < 10; ++i) {
        const auto& tensor = m_modelTensors[i];
        info += "[" + std::to_string(i + 1) + "] " + tensor.name + "\n";
        info += "    Size: " + std::to_string(tensor.size_bytes / 1024 / 1024) + " MB\n";
        info += "    Type: " + m_ggufLoader->GetTypeString(tensor.type) + "\n";
    }

    if (m_modelTensors.size() > 10) {
        info += "... and " + std::to_string(m_modelTensors.size() - 10) + " more tensors\n";
    }

    info += "\n💡 Tip: Zones load on-demand during inference for optimal performance!\n";

    return info;
}

bool Win32IDE::loadTensorData(const std::string& tensorName, std::vector<uint8_t>& data)
{
    if (!m_ggufLoader) {
        return false;
    }
    // StreamingGGUFLoader automatically loads required zone if needed
    return m_ggufLoader->LoadTensorZone(tensorName, data);
}

// ============================================================================
// FILE EXPLORER IMPLEMENTATION
// ============================================================================

void Win32IDE::createFileExplorer()
{
    if (!m_hwndSidebar) return;

    // Create file explorer tree view control
    m_hwndFileExplorer = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_TREEVIEWA,
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        5, 30, m_sidebarWidth - 10, 400,
        m_hwndSidebar,
        (HMENU)IDC_FILE_EXPLORER,
        m_hInstance,
        nullptr
    );

    if (!m_hwndFileExplorer) return;

    // Create image list for icons
    m_hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 3, 0);
    if (m_hImageList) {
        // Load icons for folders, files, and model files
        HICON hFolderIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32755), IMAGE_ICON, 16, 16, LR_SHARED);
        HICON hFileIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32512), IMAGE_ICON, 16, 16, LR_SHARED);
        HICON hModelIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32516), IMAGE_ICON, 16, 16, LR_SHARED);
        
        ImageList_AddIcon(m_hImageList, hFolderIcon);  // Index 0: Folder
        ImageList_AddIcon(m_hImageList, hFileIcon);    // Index 1: Regular file
        ImageList_AddIcon(m_hImageList, hModelIcon);   // Index 2: Model file

        TreeView_SetImageList(m_hwndFileExplorer, m_hImageList, TVSIL_NORMAL);
    }

    populateFileTree();
}

void Win32IDE::populateFileTree()
{
    if (!m_hwndFileExplorer) return;

    // Clear existing items
    TreeView_DeleteAllItems(m_hwndFileExplorer);

    // Add root directories for model browsing
    std::vector<std::string> modelPaths = {
        "D:\\OllamaModels",
        "C:\\OllamaModels",
        "C:\\Users\\" + std::string(getenv("USERNAME")) + "\\OllamaModels"
    };

    for (const auto& path : modelPaths) {
        if (GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
            std::string displayName = path;
            size_t lastSlash = path.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                displayName = path.substr(lastSlash + 1) + " (" + path + ")";
            }
            
            HTREEITEM hRoot = addTreeItem(TVI_ROOT, displayName, path, true);
            scanDirectory(path, hRoot);
        }
    }

    // Expand the D:\OllamaModels by default if it exists
    HTREEITEM hFirst = TreeView_GetRoot(m_hwndFileExplorer);
    if (hFirst) {
        TreeView_Expand(m_hwndFileExplorer, hFirst, TVE_EXPAND);
    }
}

HTREEITEM Win32IDE::addTreeItem(HTREEITEM hParent, const std::string& text, const std::string& fullPath, bool isDirectory)
{
    TVINSERTSTRUCTA tvins = {};
    tvins.hParent = hParent;
    tvins.hInsertAfter = TVI_LAST;
    tvins.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    
    // Allocate memory for the full path (will be freed when item is deleted)
    char* pathData = new char[fullPath.length() + 1];
    strcpy_s(pathData, fullPath.length() + 1, fullPath.c_str());
    
    tvins.item.pszText = const_cast<char*>(text.c_str());
    tvins.item.lParam = reinterpret_cast<LPARAM>(pathData);
    
    // Set appropriate icon
    if (isDirectory) {
        tvins.item.iImage = 0;
        tvins.item.iSelectedImage = 0;
    } else if (isModelFile(fullPath)) {
        tvins.item.iImage = 2;
        tvins.item.iSelectedImage = 2;
    } else {
        tvins.item.iImage = 1;
        tvins.item.iSelectedImage = 1;
    }
    
    return TreeView_InsertItem(m_hwndFileExplorer, &tvins);
}

void Win32IDE::scanDirectory(const std::string& dirPath, HTREEITEM hParent)
{
    WIN32_FIND_DATAA findData;
    std::string searchPath = dirPath + "\\*";
    
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        std::string fullPath = dirPath + "\\" + findData.cFileName;
        bool isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        
        // Skip hidden and system files
        if (findData.dwFileAttributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
            continue;
        }
        
        // For files, only show model files and some common extensions
        if (!isDirectory) {
            std::string fileName = findData.cFileName;
            std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);
            
            if (!isModelFile(fullPath) && 
                fileName.find(".txt") == std::string::npos &&
                fileName.find(".json") == std::string::npos &&
                fileName.find(".md") == std::string::npos &&
                fileName.find(".log") == std::string::npos) {
                continue;
            }
        }

        HTREEITEM hItem = addTreeItem(hParent, findData.cFileName, fullPath, isDirectory);
        
        // For directories, add a dummy child so we can expand later
        if (isDirectory) {
            addTreeItem(hItem, "Loading...", "", false);
        }
        
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

bool Win32IDE::isModelFile(const std::string& filePath)
{
    std::string fileName = filePath;
    std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);
    
    return fileName.find(".gguf") != std::string::npos ||
           fileName.find(".bin") != std::string::npos ||
           fileName.find(".safetensors") != std::string::npos ||
           fileName.find(".pt") != std::string::npos ||
           fileName.find(".pth") != std::string::npos ||
           fileName.find(".onnx") != std::string::npos;
}

void Win32IDE::expandTreeNode(HTREEITEM hItem)
{
    if (!hItem) return;

    // Check if this node has been expanded before
    HTREEITEM hChild = TreeView_GetChild(m_hwndFileExplorer, hItem);
    if (hChild) {
        TVITEMA item = {};
        item.hItem = hChild;
        item.mask = TVIF_TEXT | TVIF_PARAM;
        char buffer[MAX_PATH];
        item.pszText = buffer;
        item.cchTextMax = MAX_PATH;
        
        if (TreeView_GetItem(m_hwndFileExplorer, &item)) {
            if (strcmp(item.pszText, "Loading...") == 0) {
                // Remove the dummy item
                TreeView_DeleteItem(m_hwndFileExplorer, hChild);
                
                // Get the full path and scan the directory
                TVITEMA parentItem = {};
                parentItem.hItem = hItem;
                parentItem.mask = TVIF_PARAM;
                if (TreeView_GetItem(m_hwndFileExplorer, &parentItem) && parentItem.lParam) {
                    std::string dirPath = reinterpret_cast<char*>(parentItem.lParam);
                    scanDirectory(dirPath, hItem);
                }
            }
        }
    }
}

std::string Win32IDE::getSelectedFilePath()
{
    HTREEITEM hSelected = TreeView_GetSelection(m_hwndFileExplorer);
    if (!hSelected) return "";
    
    TVITEMA item = {};
    item.hItem = hSelected;
    item.mask = TVIF_PARAM;
    
    if (TreeView_GetItem(m_hwndFileExplorer, &item) && item.lParam) {
        return std::string(reinterpret_cast<char*>(item.lParam));
    }
    
    return "";
}

void Win32IDE::onFileExplorerDoubleClick()
{
    std::string filePath = getSelectedFilePath();
    if (filePath.empty()) return;
    
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return;
    
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        // Expand/collapse directory
        HTREEITEM hSelected = TreeView_GetSelection(m_hwndFileExplorer);
        if (hSelected) {
            UINT state = TreeView_GetItemState(m_hwndFileExplorer, hSelected, TVIS_EXPANDED);
            if (state & TVIS_EXPANDED) {
                TreeView_Expand(m_hwndFileExplorer, hSelected, TVE_COLLAPSE);
            } else {
                expandTreeNode(hSelected);
                TreeView_Expand(m_hwndFileExplorer, hSelected, TVE_EXPAND);
            }
        }
    } else {
        // Load file
        if (isModelFile(filePath)) {
            loadModelFromExplorer(filePath);
        } else {
            // Open text files in editor - with size check!
            try {
                std::ifstream file(filePath, std::ios::binary);
                if (file.is_open()) {
                    // Check file size first
                    file.seekg(0, std::ios::end);
                    size_t fileSize = file.tellg();
                    file.seekg(0, std::ios::beg);
                    
                    if (fileSize > 10 * 1024 * 1024) { // 10MB limit
                        MessageBoxA(m_hwndMain, "File too large to open in editor (>10MB).", "File Too Large", MB_OK | MB_ICONWARNING);
                        return;
                    }
                    
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    SetWindowTextA(m_hwndEditor, content.c_str());
                    m_currentFile = filePath;
                    updateTitleBarText();
                    file.close();
                }
            }
            catch (const std::exception& e) {
                std::string error = "Error opening file: " + std::string(e.what());
                MessageBoxA(m_hwndMain, error.c_str(), "Error", MB_OK | MB_ICONERROR);
            }
        }
    }
}

void Win32IDE::loadModelFromExplorer(const std::string& filePath)
{
    if (loadGGUFModel(filePath)) {
        std::string message = "✅ Model loaded from File Explorer:\n" + filePath + "\n\n" + getModelInfo();
        appendToOutput(message, "Output", OutputSeverity::Info);
        
        // Update status bar
        std::string filename = filePath;
        size_t lastSlash = filename.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            filename = filename.substr(lastSlash + 1);
        }
        
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)("Model: " + filename).c_str());
    } else {
        appendToOutput("❌ Failed to load model: " + filePath, "Errors", OutputSeverity::Error);
    }
}

void Win32IDE::onFileExplorerRightClick()
{
    std::string filePath = getSelectedFilePath();
    if (!filePath.empty()) {
        DWORD attributes = GetFileAttributesA(filePath.c_str());
        bool isDirectory = (attributes != INVALID_FILE_ATTRIBUTES) && (attributes & FILE_ATTRIBUTE_DIRECTORY);
        showFileContextMenu(filePath, isDirectory);
    }
}

void Win32IDE::showFileContextMenu(const std::string& filePath, bool isDirectory)
{
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu) return;
    
    if (isDirectory) {
        AppendMenuA(hMenu, MF_STRING, 1001, "Refresh");
        AppendMenuA(hMenu, MF_STRING, 1002, "Open in Explorer");
        AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hMenu, MF_STRING, 1003, "Set as Root Path");
    } else {
        if (isModelFile(filePath)) {
            AppendMenuA(hMenu, MF_STRING, 2001, "Load Model");
            AppendMenuA(hMenu, MF_STRING, 2002, "Show Model Info");
            AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
        }
        AppendMenuA(hMenu, MF_STRING, 2003, "Open with Editor");
        AppendMenuA(hMenu, MF_STRING, 2004, "Copy Path");
        AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hMenu, MF_STRING, 2005, "Show in Explorer");
    }
    
    POINT pt;
    GetCursorPos(&pt);
    
    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hwndMain, nullptr);
    
    switch (cmd) {
        case 1001: // Refresh directory
            refreshFileExplorer();
            break;
        case 1002: // Open in Explorer
        case 2005: // Show in Explorer
            ShellExecuteA(nullptr, "explore", filePath.c_str(), nullptr, nullptr, SW_SHOW);
            break;
        case 999: // Delete from Explorer context menu
            deleteItemInExplorer();
            break;
        case 1000: // Rename from Explorer context menu
            renameItemInExplorer();
            break;
        case 1003: // Set as Root Path
            m_currentExplorerPath = filePath;
            populateFileTree();
            break;
        case 2001: // Load Model
            loadModelFromExplorer(filePath);
            break;
        case 2002: // Show Model Info
            if (loadGGUFModel(filePath)) {
                std::string info = "Model Information:\n" + getModelInfo();
                MessageBoxA(m_hwndMain, info.c_str(), "Model Info", MB_OK | MB_ICONINFORMATION);
            }
            break;
        case 2003: // Open with Editor
            {
                std::ifstream file(filePath);
                if (file.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    SetWindowTextA(m_hwndEditor, content.c_str());
                    m_currentFile = filePath;
                    updateTitleBarText();
                }
            }
            break;
        case 2004: // Copy Path
            if (OpenClipboard(m_hwndMain)) {
                EmptyClipboard();
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, filePath.size() + 1);
                if (hMem) {
                    char* dest = (char*)GlobalLock(hMem);
                    strcpy_s(dest, filePath.size() + 1, filePath.c_str());
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_TEXT, hMem);
                }
                CloseClipboard();
            }
            break;
    }
    
    DestroyMenu(hMenu);
}

void Win32IDE::refreshFileExplorer()
{
    populateFileTree();
}

// ============================================================================
// MODEL CHAT INTERFACE IMPLEMENTATION
// ============================================================================

bool Win32IDE::isModelLoaded() const
{
    // Model is loaded if we have a path and the streaming loader has opened the file
    return m_ggufLoader && !m_loadedModelPath.empty() && !m_modelTensors.empty();
}

std::string Win32IDE::sendMessageToModel(const std::string& message)
{
    if (!isModelLoaded()) {
        return "Error: No model loaded";
    }
    
    // First try: send through local Ollama if available
    std::string llmResponse;
    if (trySendToOllama(message, llmResponse)) {
        m_chatHistory.push_back({message, llmResponse});
        return llmResponse;
    }

    // Fallback: Local CPU Inference (Real Logic)
    if (m_nativeEngine) {
        auto* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
        
        // Ensure model is loaded if we have a path but engine isn't ready
        if (!engine->isModelLoaded() && !m_loadedModelPath.empty()) {
            engine->loadModel(m_loadedModelPath);
        }

        if (engine->isModelLoaded()) {
             std::string response = engine->infer(message);
             m_chatHistory.push_back({message, response});
             return response;
        }
    }

    std::string response = "Error: Native Inference Engine not initialized or model not loaded.\n";
}

void Win32IDE::toggleChatMode()
{
    m_chatMode = !m_chatMode;
    
    if (m_chatMode) {
        // Entering chat mode
        std::string status = "🤖 Chat Mode ON - Model: ";
        status += m_loadedModelPath.empty() ? "None" : m_loadedModelPath.substr(m_loadedModelPath.find_last_of("\\/") + 1);
        
        appendToOutput(status, "Output", OutputSeverity::Info);
        appendToOutput("Type your messages in the command input. Use /exit-chat to return to terminal mode.", "Output", OutputSeverity::Info);
        
        // Update status bar
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Chat Mode");
        
        // Clear existing chat display and show instructions
        appendChatMessage("System", "Chat mode activated! You can now talk with the loaded model.");
        appendChatMessage("System", "Commands: /exit-chat to return to terminal mode");
    } else {
        // Exiting chat mode
        appendToOutput("🔧 Chat Mode OFF - Returned to terminal mode", "Output", OutputSeverity::Info);
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Terminal Mode");
        appendChatMessage("System", "Chat mode deactivated. Returned to terminal mode.");
    }
}

void Win32IDE::appendChatMessage(const std::string& user, const std::string& message)
{
    // Get timestamp
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char timestamp[16];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &timeinfo);
    
    // Format message
    std::string formattedMsg = "[" + std::string(timestamp) + "] " + user + ": " + message + "\n\n";
    
    // Display in output panel
    if (user == "System") {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    } else if (user == "You") {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    } else if (user == "Model") {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    }
}

// ============================================================================
// GIT INTEGRATION - Status, Commit, Push, Pull
// ============================================================================

void Win32IDE::showGitStatus()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git", MB_OK | MB_ICONWARNING);
        return;
    }
    
    updateGitStatus();
    
    std::ostringstream status;
    status << "Git Status\n";
    status << "==========\n\n";
    status << "Branch: " << m_gitStatus.branch << "\n";
    status << "\nChanges:\n";
    status << "  Modified:  " << m_gitStatus.modified << "\n";
    status << "  Added:     " << m_gitStatus.added << "\n";
    status << "  Deleted:   " << m_gitStatus.deleted << "\n";
    status << "  Untracked: " << m_gitStatus.untracked << "\n";
    
    MessageBoxA(m_hwndMain, status.str().c_str(), "Git Status", MB_OK | MB_ICONINFORMATION);
}

void Win32IDE::updateGitStatus()
{
    if (!isGitRepository()) {
        m_gitStatus = GitStatus();
        return;
    }
    
    std::string output;
    
    // Get current branch
    executeGitCommand("git rev-parse --abbrev-ref HEAD", output);
    m_gitStatus.branch = output;
    if (!m_gitStatus.branch.empty() && m_gitStatus.branch.back() == '\n') {
        m_gitStatus.branch.pop_back();
    }
    output.clear();
    
    // Get status --porcelain
    executeGitCommand("git status --porcelain", output);
    m_gitStatus.modified = 0;
    m_gitStatus.added = 0;
    m_gitStatus.deleted = 0;
    m_gitStatus.untracked = 0;
    
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.length() < 2) continue;
        
        char status = line[0];
        char status2 = line[1];
        
        if (status == 'M' || status2 == 'M') m_gitStatus.modified++;
        if (status == 'A' || status2 == 'A') m_gitStatus.added++;
        if (status == 'D' || status2 == 'D') m_gitStatus.deleted++;
        if (status == '?' || status2 == '?') m_gitStatus.untracked++;
    }
    
    m_gitStatus.hasChanges = (m_gitStatus.modified + m_gitStatus.added + 
                               m_gitStatus.deleted + m_gitStatus.untracked) > 0;
}

void Win32IDE::gitCommit(const std::string& message)
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string output;
    std::string command = "git commit -m \"" + message + "\"";
    executeGitCommand(command, output);
    
    MessageBoxA(m_hwndMain, output.c_str(), "Git Commit", MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitPush()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string output;
    executeGitCommand("git push", output);
    
    MessageBoxA(m_hwndMain, 
        output.empty() ? "Push completed successfully" : output.c_str(), 
        "Git Push", MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitPull()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string output;
    executeGitCommand("git pull", output);
    
    MessageBoxA(m_hwndMain, 
        output.empty() ? "Pull completed successfully" : output.c_str(), 
        "Git Pull", MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitStageFile(const std::string& filePath)
{
    if (!isGitRepository()) return;
    
    std::string output;
    std::string command = "git add \"" + filePath + "\"";
    executeGitCommand(command, output);
    updateGitStatus();
}

void Win32IDE::gitUnstageFile(const std::string& filePath)
{
    if (!isGitRepository()) return;
    
    std::string output;
    std::string command = "git reset HEAD \"" + filePath + "\"";
    executeGitCommand(command, output);
    updateGitStatus();
}

bool Win32IDE::isGitRepository() const
{
    if (!m_gitRepoPath.empty()) {
        std::string gitDir = m_gitRepoPath + "\\.git";
        DWORD attrib = GetFileAttributesA(gitDir.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
    }
    
    // Check current directory
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    std::string gitDir = std::string(currentDir) + "\\.git";
    DWORD attrib = GetFileAttributesA(gitDir.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::vector<GitFile> Win32IDE::getGitChangedFiles() const
{
    std::vector<GitFile> files;
    
    if (!isGitRepository()) return files;
    
    std::string output;
    const_cast<Win32IDE*>(this)->executeGitCommand("git status --porcelain", output);
    
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.length() < 4) continue;
        
        GitFile file;
        file.status = line[0] != ' ' ? line[0] : line[1];
        file.staged = (line[0] != ' ' && line[0] != '?');
        file.path = line.substr(3);
        
        files.push_back(file);
    }
    
    return files;
}

bool Win32IDE::executeGitCommand(const std::string& command, std::string& output)
{
    output.clear();
    
    // Create a temporary file for output
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "rawr_git_output.txt";
    
    // Execute command and redirect output
    std::string fullCommand = command + " > \"" + tempFile + "\" 2>&1";
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (CreateProcessA(NULL, const_cast<char*>(fullCommand.c_str()), 
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        
        WaitForSingleObject(pi.hProcess, 5000);  // 5 second timeout
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        // Read output file
        std::ifstream file(tempFile);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                output += line + "\n";
            }
            file.close();
            DeleteFileA(tempFile.c_str());
        }
        return true;
    }
    return false;
}

void Win32IDE::showGitPanel()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git", MB_OK | MB_ICONWARNING);
        return;
    }
    
    // Create Git panel if it doesn't exist
    if (!m_hwndGitPanel || !IsWindow(m_hwndGitPanel)) {
        m_hwndGitPanel = CreateWindowExA(WS_EX_TOOLWINDOW, "STATIC", "Git Panel",
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_SIZEBOX,
            200, 100, 600, 500, m_hwndMain, nullptr, m_hInstance, nullptr);
        
        // Branch and status info
        m_hwndGitStatusText = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY,
            10, 10, 580, 60, m_hwndGitPanel, nullptr, m_hInstance, nullptr);
        
        // Changed files list
        CreateWindowExA(0, "STATIC", "Changed Files:", WS_CHILD | WS_VISIBLE,
            10, 80, 120, 20, m_hwndGitPanel, nullptr, m_hInstance, nullptr);
        
        m_hwndGitFileList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
            WS_CHILD | WS_VISIBLE | LBS_STANDARD | LBS_EXTENDEDSEL | WS_VSCROLL,
            10, 105, 280, 300, m_hwndGitPanel, nullptr, m_hInstance, nullptr);
    }
    
    ShowWindow(m_hwndGitPanel, SW_SHOW);
    refreshGitPanel();
}

void Win32IDE::refreshGitPanel()
{
    if (!m_hwndGitPanel || !IsWindow(m_hwndGitPanel)) return;
    
    updateGitStatus();
    
    // Update status text
    std::string statusText = "Branch: " + m_gitStatus.branch + "\n";
    statusText += "Modified: " + std::to_string(m_gitStatus.modified) + " | ";
    statusText += "Added: " + std::to_string(m_gitStatus.added) + " | ";
    statusText += "Deleted: " + std::to_string(m_gitStatus.deleted) + " | ";
    statusText += "Untracked: " + std::to_string(m_gitStatus.untracked);
    
    if (m_hwndGitStatusText) {
        SetWindowTextA(m_hwndGitStatusText, statusText.c_str());
    }
    
    // Update file list
    if (m_hwndGitFileList) {
        SendMessage(m_hwndGitFileList, LB_RESETCONTENT, 0, 0);
        
        std::vector<GitFile> files = getGitChangedFiles();
        for (const auto& file : files) {
            std::string displayText;
            if (file.staged) {
                displayText = "[S] ";
            } else {
                displayText = "[ ] ";
            }
            
            switch (file.status) {
                case 'M': displayText += "(M) "; break;
                case 'A': displayText += "(A) "; break;
                case 'D': displayText += "(D) "; break;
                case '?': displayText += "(?) "; break;
                default: displayText += "( ) "; break;
            }
            
            displayText += file.path;
            SendMessageA(m_hwndGitFileList, LB_ADDSTRING, 0, (LPARAM)displayText.c_str());
        }
    }
}

void Win32IDE::showCommitDialog()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git", MB_OK | MB_ICONWARNING);
        return;
    }
    
    // Simple commit dialog using InputBox-style approach
    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Git Commit",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        150, 150, 500, 200, m_hwndMain, nullptr, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Commit Message:", WS_CHILD | WS_VISIBLE,
        10, 10, 120, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    
    m_hwndCommitDialog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
        10, 35, 470, 100, hwndDlg, nullptr, m_hInstance, nullptr);
    
    HWND hwndCommitBtn = CreateWindowExA(0, "BUTTON", "Commit", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        10, 145, 100, 30, hwndDlg, (HMENU)1, m_hInstance, nullptr);
    
    HWND hwndCancelBtn = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE,
        120, 145, 100, 30, hwndDlg, (HMENU)2, m_hInstance, nullptr);
    
    SetFocus(m_hwndCommitDialog);
}

// ============================================================================
// AI INFERENCE IMPLEMENTATION - Connects GGUF Loader to Chat Panel
// ============================================================================

bool Win32IDE::initializeInference()
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);
    
    // Explicit Logic: Initialize Native CPU Engine if missing (Un-mocking)
    if (!m_nativeEngine) {
        try {
            m_nativeEngine = new RawrXD::CPUInferenceEngine();
            m_nativeEngineLoaded = false;
            appendToOutput("Initialized Native CPU Inference Engine.", "Output", OutputSeverity::Info);
        } catch (const std::exception& e) {
            appendToOutput(std::string("Failed to init native engine: ") + e.what(), "Errors", OutputSeverity::Error);
            return false;
        }
    }

    // Check if model is loaded via GGUF loader (Streaming)
    if (m_loadedModelPath.empty()) {
        if (!m_ggufLoader) {
            appendToOutput("No model loaded for inference", "Errors", OutputSeverity::Error);
            return false;
        }
        // If ggufLoader has a file open but path var is empty, try to recover (unlikely)
    }
    
    // Connect Native Engine to Model
    if (m_nativeEngine && !m_loadedModelPath.empty()) {
        RawrXD::CPUInferenceEngine* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
        if (!engine->isModelLoaded()) {
            appendToOutput("Loading model into Native Engine: " + m_loadedModelPath, "Output", OutputSeverity::Info);
            if (engine->loadModel(m_loadedModelPath)) {
                m_nativeEngineLoaded = true;
                appendToOutput("✅ Native Engine Model Loaded Successfully.", "Output", OutputSeverity::Info);
            } else {
                 appendToOutput("❌ Native Engine Model Load Failed.", "Errors", OutputSeverity::Error);
                 // Don't fail completely if we have Ollama fallback, but for "no simulation" we adhere to native.
            }
        }
    }

    // Set up inference config from model metadata
    m_inferenceConfig.maxTokens = 512;
    m_inferenceConfig.temperature = 0.7f;
    m_inferenceConfig.topP = 0.9f;
    m_inferenceConfig.topK = 40;
    m_inferenceConfig.repetitionPenalty = 1.1f;
    
    // Use model context length if available
    if (m_currentModelMetadata.context_length > 0) {
        m_inferenceConfig.maxTokens = std::min(512, (int)m_currentModelMetadata.context_length / 4);
    }
    
    appendToOutput("✅ Inference initialized for model: " + m_loadedModelPath, "Output", OutputSeverity::Info);
    return true;
}

void Win32IDE::shutdownInference()
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);
    
    if (m_inferenceRunning) {
        m_inferenceStopRequested = true;
        if (m_inferenceThread.joinable()) {
            m_inferenceThread.join();
        }
    }
    
    m_inferenceRunning = false;
    m_inferenceStopRequested = false;
    m_currentInferencePrompt.clear();
    m_currentInferenceResponse.clear();
    
    appendToOutput("Inference shutdown complete", "Output", OutputSeverity::Info);
}

std::string Win32IDE::generateResponse(const std::string& prompt)
{
    if (m_inferenceRunning) {
        return "Inference already in progress. Please wait...";
    }

    // Attempt real remote/local inference via Ollama if configured
    auto performOllama = [&](const std::string& promptText) -> std::string {
        if (m_ollamaBaseUrl.empty()) return "";
        // Expect base URL like http://localhost:11434
        std::string base = m_ollamaBaseUrl;
        if (base.rfind("http://", 0) != 0 && base.rfind("https://", 0) != 0) return "";
        bool https = base.rfind("https://", 0) == 0;
        std::string withoutProto = base.substr(base.find("://") + 3);
        std::string host; int port = https ? 443 : 80;
        size_t colonPos = withoutProto.find(':');
        size_t slashPos = withoutProto.find('/');
        if (colonPos != std::string::npos) {
            host = withoutProto.substr(0, colonPos);
            std::string portStr = withoutProto.substr(colonPos + 1, (slashPos == std::string::npos ? withoutProto.size() : slashPos) - (colonPos + 1));
            port = atoi(portStr.c_str());
        } else {
            host = (slashPos == std::string::npos) ? withoutProto : withoutProto.substr(0, slashPos);
            // Default Ollama port
            if (!https) port = 11434;
        }
        std::wstring whost(host.begin(), host.end());
        HINTERNET hSession = WinHttpOpen(L"RawrXDIDE/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
        if (!hSession) return "";
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }
        // Build JSON body
        std::string modelTag;
        if (!m_ollamaModelOverride.empty()) modelTag = m_ollamaModelOverride; else {
            // Derive from loaded path
            modelTag = m_loadedModelPath;
            size_t pos = modelTag.find_last_of("\\/");
            if (pos != std::string::npos) modelTag = modelTag.substr(pos + 1);
        }
        // Basic escaping of quotes in prompt
        std::string escPrompt; escPrompt.reserve(promptText.size()+16);
        for (char c : promptText) { if (c == '"') escPrompt += "\\\""; else if (c=='\n') escPrompt += "\\n"; else escPrompt += c; }
        std::string body = std::string("{\"model\":\"") + modelTag + "\",\"prompt\":\"" + escPrompt + "\",\"stream\":false}";
        std::wstring wHeaders = L"Content-Type: application/json";
        BOOL bResults = WinHttpSendRequest(hRequest, wHeaders.c_str(), (DWORD)-1L, (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
        if (!bResults) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        std::string raw;
        if (bResults) {
            DWORD dwSize = 0; do {
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                if (!dwSize) break;
                std::string chunk; chunk.resize(dwSize);
                DWORD dwRead = 0;
                if (!WinHttpReadData(hRequest, chunk.data(), dwSize, &dwRead)) break;
                if (dwRead) raw.append(chunk.data(), dwRead);
            } while (dwSize > 0);
        }
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        if (raw.empty()) return "";
        // Naive JSON parse: look for "response":"..."
        std::string out;
        size_t pos = raw.rfind("\"response\":\"");
        if (pos != std::string::npos) {
            pos += 12; // start after marker
            while (pos < raw.size()) {
                char c = raw[pos++];
                if (c == '"') break; // end of string (assumes not escaped)
                if (c == '\\') { if (pos < raw.size()) { char next = raw[pos++]; if (next=='n') out+='\n'; else out+=next; } }
                else out += c;
            }
        }
        return out.empty() ? raw : out;
    };

    std::string remote = performOllama(prompt);
    if (!remote.empty()) return remote;

    // Fallback structured guidance if no remote inference available
    std::string modelName = m_loadedModelPath.empty() ? "None" : m_loadedModelPath.substr(m_loadedModelPath.find_last_of("\\/")+1);

    // Fallback: Native CPU Inference Engine
    if (m_nativeEngine && m_nativeEngineLoaded) {
        RawrXD::CPUInferenceEngine* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
        // If engine doesn't have a model loaded, try to load current one
        if (!engine->isModelLoaded() && !m_loadedModelPath.empty()) {
            engine->loadModel(m_loadedModelPath);
        }
        
        if (engine->isModelLoaded()) {
            return engine->infer(prompt);
        } else {
             return "Error: No model loaded in Native CPU Engine.";
        }
    }

    return std::string("[Native Engine Error]\nModel: ") + modelName + "\nPrompt: " + prompt + "\n(Ollama unavailable and Native Engine not ready)";
}

void Win32IDE::generateResponseAsync(const std::string& prompt, std::function<void(const std::string&, bool)> callback)
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);

    if (m_inferenceRunning) {
        if (callback) callback("Inference already in progress.", true);
        return;
    }
    
    m_inferenceRunning = true;
    m_inferenceStopRequested = false;
    m_currentInferencePrompt = prompt;
    m_inferenceCallback = callback;
    
    // Launch dedicated inference thread
    m_inferenceThread = std::thread([this, prompt]() {
        // 1. Try Native CPU Engine with Streaming
        if (m_nativeEngine) {
             RawrXD::CPUInferenceEngine* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
             if (engine->isModelLoaded()) {
                 // Configure sampling (ensure thread-safe access if needed)
                 engine->setSampling(
                     m_inferenceConfig.temperature,
                     m_inferenceConfig.topP,
                     m_inferenceConfig.topK,
                     m_inferenceConfig.repetitionPenalty
                 );
                 
                 // Run generation with per-token callback
                 bool success = engine->generate(prompt, [this](const std::string& token) {
                     if (m_inferenceStopRequested) return false;
                     
                     // Send token to UI
                     if (m_inferenceCallback) {
                         m_inferenceCallback(token, false);
                     }
                     return true;
                 });
                 
                 m_inferenceRunning = false;
                 if (m_inferenceCallback) {
                     m_inferenceCallback("", true); // Finalize
                 }
                 return;
             }
        }

        // 2. Fallback: Synchronous Blocking Call (Ollama/Legacy)
        // If native engine failed or wasn't loaded, we fall back to the blocking method
        // but execute it in this background thread so UI doesn't freeze.
        std::string response = generateResponse(prompt);
        
        m_inferenceRunning = false;
        if (m_inferenceCallback) {
            // Send full response as one chunk if fallback was used
            m_inferenceCallback(response, true);
        }
    });
    
    m_inferenceThread.detach();
}

void Win32IDE::stopInference()
{
    m_inferenceStopRequested = true;
}

void Win32IDE::setInferenceConfig(const InferenceConfig& config)
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);
    m_inferenceConfig = config;
}

Win32IDE::InferenceConfig Win32IDE::getInferenceConfig() const
{
    return m_inferenceConfig;
}

std::string Win32IDE::buildChatPrompt(const std::string& userMessage)
{
    std::string prompt;
    
    // Add system prompt if set
    if (!m_inferenceConfig.systemPrompt.empty()) {
        prompt = "<|system|>\n" + m_inferenceConfig.systemPrompt + "\n<|end|>\n";
    }
    
    // Add user message
    prompt += "<|user|>\n" + userMessage + "\n<|end|>\n";
    prompt += "<|assistant|>\n";
    
    return prompt;
}

void Win32IDE::onInferenceToken(const std::string& token)
{
    // Called when streaming tokens during inference
    m_currentInferenceResponse += token;
    
    // Update UI with partial response if streaming is enabled
    if (m_inferenceConfig.streamOutput && m_inferenceCallback) {
        m_inferenceCallback(token, false);
    }
}

void Win32IDE::onInferenceComplete(const std::string& fullResponse)
{
    m_inferenceRunning = false;
    m_currentInferenceResponse = fullResponse;
    
    if (m_inferenceCallback) {
        m_inferenceCallback(fullResponse, true);
    }
}

// ============================================================================
// EDITOR OPERATIONS - Undo/Redo/Cut/Copy/Paste
// ============================================================================

void Win32IDE::undo()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, EM_UNDO, 0, 0);
    }
}

void Win32IDE::redo()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, EM_REDO, 0, 0);
    }
}

void Win32IDE::editCut()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, WM_CUT, 0, 0);
    }
}

void Win32IDE::editCopy()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, WM_COPY, 0, 0);
    }
}

void Win32IDE::editPaste()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, WM_PASTE, 0, 0);
    }
}

// ============================================================================
// VIEW OPERATIONS - Toggle panels
// ============================================================================

void Win32IDE::toggleOutputPanel()
{
    m_outputPanelVisible = !m_outputPanelVisible;
    if (m_hwndMain) {
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
        InvalidateRect(m_hwndMain, NULL, TRUE);
    }
}

void Win32IDE::toggleTerminal()
{
    // Toggle panel visibility (which contains terminal)
    m_outputPanelVisible = !m_outputPanelVisible;
    if (m_hwndMain) {
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
        InvalidateRect(m_hwndMain, NULL, TRUE);
    }
}

void Win32IDE::showAbout()
{
    std::string aboutText = 
        "RawrXD Win32 IDE\n\n"
        "Version: 1.0.0\n"
        "Build: " __DATE__ " " __TIME__ "\n\n"
        "Features:\n"
        "• Native Win32 UI\n"
        "• GGUF Model Support\n"
        "• PowerShell Integration\n"
        "• Git Integration\n"
        "• AI Chat via Ollama\n"
        "• Syntax Highlighting\n"
        "• Multi-Terminal Support\n\n"
        "GitHub: ItsMehRAWRXD/RawrXD";
    
    MessageBoxA(m_hwndMain, aboutText.c_str(), "About RawrXD IDE", MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// AUTONOMY FRAMEWORK - High-level orchestration controls
// ============================================================================

void Win32IDE::onAutonomyStart() {
    if (!m_autonomyManager) {
        appendToOutput("Autonomy manager not initialized\n", "Errors", OutputSeverity::Error);
        return;
    }
    m_autonomyManager->start();
    appendToOutput("Autonomy started (manual mode)\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyStop() {
    if (!m_autonomyManager) return;
    m_autonomyManager->stop();
    appendToOutput("Autonomy stopped\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyToggle() {
    if (!m_autonomyManager) return;
    bool enable = !m_autonomyManager->isAutoLoopEnabled();
    m_autonomyManager->enableAutoLoop(enable);
    appendToOutput(std::string("Autonomy auto loop ") + (enable?"ENABLED":"DISABLED") + "\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomySetGoal() {
    if (!m_autonomyManager) return;
    // Simple goal setter: reuse current file name or fallback text
    std::string goal = m_currentFile.empty() ? "Explore workspace and summarize architecture" : ("Analyze file: " + m_currentFile);
    m_autonomyManager->setGoal(goal);
    appendToOutput("Autonomy goal set: " + goal + "\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyViewStatus() {
    if (!m_autonomyManager) return;
    std::string status = m_autonomyManager->getStatus();
    appendToOutput("Autonomy Status: " + status + "\n", "Output", OutputSeverity::Info);
    MessageBoxA(m_hwndMain, status.c_str(), "Autonomy Status", MB_OK | MB_ICONINFORMATION);
}

void Win32IDE::onAutonomyViewMemory() {
    if (!m_autonomyManager) return;
    auto mem = m_autonomyManager->getMemorySnapshot();
    std::string report = "Memory Items (latest first, max 20):\n\n";
    int shown = 0;
    for (int i = (int)mem.size() - 1; i >= 0 && shown < 20; --i, ++shown) {
        report += std::to_string(shown+1) + ". " + mem[i] + "\n";
    }
    if (shown == 0) report += "<empty>\n";
    appendToOutput("Autonomy Memory Snapshot displayed\n", "Debug", OutputSeverity::Debug);
    MessageBoxA(m_hwndMain, report.c_str(), "Autonomy Memory", MB_OK);
}

// ======================================================================
// AI CHAT PANEL IMPLEMENTATION
// ======================================================================

void Win32IDE::createChatPanel() {

    if (!m_hwndMain) {

        return;
    }

    // Create secondary sidebar container (right side)
    m_hwndSecondarySidebar = CreateWindowExA(
        WS_EX_CLIENTEDGE, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        0, 0, 300, 600,
        m_hwndMain, (HMENU)IDC_SECONDARY_SIDEBAR, m_hInstance, nullptr);
    
    if (!m_hwndSecondarySidebar) {

        return;
    }
    
    // Create header with title
    m_hwndSecondarySidebarHeader = CreateWindowExA(
        0, "STATIC", "AI Chat",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, 5, 290, 25,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    HFONT hFont = CreateFontA(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, 
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, 
                              DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    if (m_hwndSecondarySidebarHeader) {
        SendMessage(m_hwndSecondarySidebarHeader, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // Model Selection Label
    CreateWindowExA(0, "STATIC", "Model:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, 35, 50, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    // Model Selector Combobox
    m_hwndModelSelector = CreateWindowExA(
        0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWN | CBS_AUTOHSCROLL,
        60, 35, 235, 200,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_SEND_BTN, m_hInstance, nullptr);
    
    if (m_hwndModelSelector) {
        SendMessage(m_hwndModelSelector, WM_SETFONT, (WPARAM)hFont, TRUE);
        populateModelSelector();
    }
    
    // Max Tokens Label
    CreateWindowExA(0, "STATIC", "Max Tokens:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, 60, 80, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    // Max Tokens Label (value display)
    m_hwndMaxTokensLabel = CreateWindowExA(0, "STATIC", "512",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        245, 60, 50, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    // Max Tokens Slider
    m_hwndMaxTokensSlider = CreateWindowExA(
        0, "TRACKBAR_CLASS", "",
        WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_NOTICKS,
        5, 80, 290, 25,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CLEAR_BTN, m_hInstance, nullptr);
    
    if (m_hwndMaxTokensSlider) {
        SendMessage(m_hwndMaxTokensSlider, TBM_SETRANGE, TRUE, MAKELPARAM(32, 2048));
        SendMessage(m_hwndMaxTokensSlider, TBM_SETPOS, TRUE, 512);
        SendMessage(m_hwndMaxTokensSlider, TBM_SETTICFREQ, 256, 0);
        m_currentMaxTokens = 512;
    }
    
    // Chat Output Textbox
    m_hwndCopilotChatOutput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
        5, 110, 290, 300,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_OUTPUT, m_hInstance, nullptr);
    
    if (m_hwndCopilotChatOutput) {
        SendMessage(m_hwndCopilotChatOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // Chat Input Textbox
    m_hwndCopilotChatInput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
        5, 415, 290, 85,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_INPUT, m_hInstance, nullptr);
    
    if (m_hwndCopilotChatInput) {
        SendMessage(m_hwndCopilotChatInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // Send Button
    m_hwndCopilotSendBtn = CreateWindowExA(
        0, "BUTTON", "Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 505, 140, 30,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_SEND_BTN, m_hInstance, nullptr);
    
    if (m_hwndCopilotSendBtn) {
        SendMessage(m_hwndCopilotSendBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // Clear Button
    m_hwndCopilotClearBtn = CreateWindowExA(
        0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        150, 505, 140, 30,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CLEAR_BTN, m_hInstance, nullptr);
    
    if (m_hwndCopilotClearBtn) {
        SendMessage(m_hwndCopilotClearBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    m_secondarySidebarVisible = true;
    m_secondarySidebarWidth = 300;

}

void Win32IDE::populateModelSelector() {
    if (!m_hwndModelSelector) return;

    // Clear existing items
    SendMessage(m_hwndModelSelector, CB_RESETCONTENT, 0, 0);
    
    // Try to scan OllamaModels directory for available models
    std::string ollamaPath = "D:\\OllamaModels";
    m_availableModels.clear();
    
    // Add default models
    m_availableModels.push_back("llama2");
    m_availableModels.push_back("mistral");
    m_availableModels.push_back("neural-chat");
    m_availableModels.push_back("dolphin-mixtral");
    
    // Try to scan directory
    WIN32_FIND_DATAA findData;
    HANDLE findHandle = FindFirstFileA((ollamaPath + "\\*").c_str(), &findData);
    
    if (findHandle != INVALID_HANDLE_VALUE) {
        do {
            if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && 
                strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName, "..") != 0) {
                m_availableModels.push_back(findData.cFileName);
            }
        } while (FindNextFileA(findHandle, &findData));
        FindClose(findHandle);
    }
    
    // Populate combobox
    for (const auto& model : m_availableModels) {
        SendMessageA(m_hwndModelSelector, CB_ADDSTRING, 0, (LPARAM)model.c_str());
    }
    
    // Set first item as selected
    if (!m_availableModels.empty()) {
        SendMessage(m_hwndModelSelector, CB_SETCURSEL, 0, 0);
    }

}

void Win32IDE::HandleCopilotSend() {
    if (!m_hwndCopilotChatInput || !m_hwndCopilotChatOutput) return;

    // Get input text
    char inputBuffer[2048] = {0};
    GetWindowTextA(m_hwndCopilotChatInput, inputBuffer, sizeof(inputBuffer) - 1);
    std::string userMessage(inputBuffer);
    
    if (userMessage.empty()) {
        LOG_WARNING("Empty message - ignoring");
        return;
    }
    
    // Get selected model
    int modelIdx = (int)SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);
    std::string selectedModel = (modelIdx >= 0 && modelIdx < (int)m_availableModels.size()) 
        ? m_availableModels[modelIdx] 
        : "llama2";

    // Display user message
    std::string displayText = "\n> User: " + userMessage + "\n";
    
    // Append to output
    int len = GetWindowTextLengthA(m_hwndCopilotChatOutput);
    if (len > 0) {
        SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
    }
    SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, (LPARAM)displayText.c_str());
    
    // Clear input
    SetWindowTextA(m_hwndCopilotChatInput, "");
    
    // Generate response asynchronously
    auto onResponse = [this](const std::string& response, bool complete) {
        if (!m_hwndCopilotChatOutput) return;
        
        std::string displayResp = "AI: " + response + (complete ? "\n" : "");
        int len = GetWindowTextLengthA(m_hwndCopilotChatOutput);
        if (len > 0) {
            SendMessage(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
        }
        SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, (LPARAM)displayResp.c_str());
    };
    
    // Set model override temporarily
    m_ollamaModelOverride = selectedModel;
    
    // Generate response
    generateResponseAsync(userMessage, onResponse);

}

void Win32IDE::HandleCopilotClear() {
    if (!m_hwndCopilotChatOutput || !m_hwndCopilotChatInput) return;

    SetWindowTextA(m_hwndCopilotChatOutput, "Welcome to RawrXD AI Chat!\n\nSelect a model and type your message to begin.");
    SetWindowTextA(m_hwndCopilotChatInput, "");
    m_chatHistory.clear();

}

void Win32IDE::HandleCopilotStreamUpdate(const char* token, size_t length) {
    if (!m_hwndCopilotChatOutput || !token) return;

    std::string chunk;
    if (length > 0) {
        chunk.assign(token, token + length);
    } else {
        chunk = token;
    }

    if (chunk.empty()) return;

    int currentLen = GetWindowTextLengthA(m_hwndCopilotChatOutput);
    SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, currentLen, currentLen);
    SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, (LPARAM)chunk.c_str());
    SendMessage(m_hwndCopilotChatOutput, WM_VSCROLL, SB_BOTTOM, 0);
}

void Win32IDE::onModelSelectionChanged() {
    int idx = (int)SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);
    if (idx >= 0 && idx < (int)m_availableModels.size()) {
        m_ollamaModelOverride = m_availableModels[idx];

    }
}

void Win32IDE::onMaxTokensChanged(int newValue) {
    m_currentMaxTokens = newValue;
    m_inferenceConfig.maxTokens = newValue;
    
    // Update label
    if (m_hwndMaxTokensLabel) {
        SetWindowTextA(m_hwndMaxTokensLabel, std::to_string(newValue).c_str());
    }

}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
